"""USOC governance: policy decisions and human approvals.

USOC's core rule is that an AI recommendation is not execution authority. Every
consequential task therefore passes a deterministic policy gate before it runs:

    identity -> mission -> scope -> target -> risk -> HITL -> policy -> execution

LLM output never decides a policy outcome. ``PolicyEngine`` is plain code with
explicit rules, and a DENY here cannot be overridden by any agent, prompt or
model response.

Decisions follow the in-repo governance contract
(``toolbox/CONSTITUTION.md`` and ``docs/architecture.md``): ALLOW, HOLD, DENY,
CONTAIN.
"""

from __future__ import annotations

import asyncio
import fnmatch
import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from enum import Enum
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .contracts import ActionClass, Classification, RiskLevel
from .security import SecurityError, Signer, async_exclusive_lock, canonical, secure_dir, secure_file

GOVERNED = frozenset({ActionClass.EXECUTE, ActionClass.CONTAIN})
TIER_RANK = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


def tier_allows(max_tier: RiskLevel | None, risk: RiskLevel) -> bool:
    """An approver may only authorize work at or below their registry tier."""
    return max_tier is not None and TIER_RANK[max_tier] >= TIER_RANK[risk]


def parse_money(value: Any) -> Decimal | None:
    """Parse and bound a monetary value; None means 'not a transaction'.

    Parsing is strict: NaN, infinities and negative amounts are refused, and a
    value with more than four decimal places cannot be smuggled past the gate
    by rounding differences between a proposal and its approval.
    """
    if value is None or value == "":
        return None
    text = str(value).strip()
    if text and text[0] in "+-":
        raise ValueError("transaction amount cannot be signed")
    try:
        amount = Decimal(text)
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise ValueError(f"invalid transaction amount {value!r}: {exc}") from exc
    if not amount.is_finite() or amount < 0:
        raise ValueError(f"transaction amount must be finite and non-negative: {value!r}")
    if -amount.as_tuple().exponent > 4:
        raise ValueError("transaction amount supports at most four decimal places")
    return amount


def canonical_money(value: Any) -> str | None:
    amount = parse_money(value)
    return str(amount) if amount is not None else None


def taint_disclosure_hash(provenance: list[str] | None, tainted: bool) -> str:
    """Cryptographic summary of what a human was told about tainted input.

    Two payloads with the same provenance labels but different contents are not
    distinguishable here - provenance is a disclosure, not the payload itself -
    but a changed label set or a switched taint flag invalidates the approval.
    """
    body = {
        "provenance": sorted(set(str(p) for p in (provenance or []))),
        "tainted": bool(tainted),
    }
    blob = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


AUTHORIZATION_TTL_S = 900

# Defensive-only boundary for the CYBER DEFENSE subsystem, as declared in
# ``subsystems.yaml`` and ``docs/architecture.md``. These are screening signals,
# not a content filter.
PROHIBITED_PATTERNS = (
    "credential theft",
    "steal credentials",
    "install ransomware",
    "deploy ransomware",
    "unauthorized intrusion",
    "establish persistence",
    "lateral movement",
    "exfiltrate",
    "data extortion",
    "attack a third party",
    "disable logging",
    "wipe logs",
)


class DecisionType(str, Enum):
    ALLOW = "ALLOW"
    HOLD = "HOLD"
    DENY = "DENY"
    CONTAIN = "CONTAIN"


class GovernanceDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: DecisionType
    policy_ref: str
    reasons: list[str] = Field(default_factory=list)
    approval_ref: str | None = None
    authorization_ref: str | None = None
    expires_at: datetime | None = None
    provenance: list[str] = Field(default_factory=list)
    tainted: bool = False

    @property
    def allowed(self) -> bool:
        return self.decision is DecisionType.ALLOW


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"


class ApprovalCredential(BaseModel):
    """The cryptographic proof a human supplies with a decision.

    ``detached`` is an Ed25519 signature over the canonical approval payload,
    verified with the public key in the signed approver registry. ``oidc`` is
    an Okta/Entra id_token verified against the configured JWKS. The credential
    is stored on the signed approval record so evidence and ADRs carry it.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["detached", "oidc"] = "detached"
    signature: str | None = Field(default=None, max_length=2048)
    id_token: str | None = Field(default=None, max_length=16_384)


class ApprovalVerification(BaseModel):
    """Audit record of how an approver credential was verified."""

    model_config = ConfigDict(extra="forbid")

    verified: bool
    method: Literal["none", "detached", "oidc"]
    approver_id: str
    role: str | None = None
    max_tier: RiskLevel | None = None
    kid: str | None = None
    fingerprint: str | None = None
    subject: str | None = None
    detail: str = ""

    def __bool__(self) -> bool:
        # The approval store's verifier hook is a truthy/falsy callable, so a
        # failed verification must be false even though the object exists.
        return self.verified


class ApprovalDecision(BaseModel):
    """One human's signed decision on a (possibly multi-party) approval."""

    model_config = ConfigDict(extra="forbid")

    approver: str
    approved: bool
    decided_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    note: str | None = None
    credential: ApprovalCredential | None = None
    verification: ApprovalVerification | None = None


def approval_verifications(req: "ApprovalRequest") -> list[ApprovalVerification]:
    """Every verified human identity that backs an approval.

    Legacy single-approver records have no ``decisions`` list, so fall back to
    the top-level verification to keep old evidence valid.
    """
    if req.decisions:
        return [d.verification for d in req.decisions if d.verification is not None]
    return [req.verification] if req.verification is not None else []


class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: f"apr-{uuid.uuid4().hex[:10]}")
    action_class: ActionClass
    target: str
    risk: RiskLevel
    mission_id: str | None = None
    requested_by: str
    justification: str = ""
    correlation_id: str = ""
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    decided_by: str | None = None
    decided_at: datetime | None = None
    note: str | None = None
    # Taint disclosure: the human approving this action must see which upstream
    # subsystems produced it and that untrusted telemetry is in the chain.
    provenance: list[str] = Field(default_factory=list, max_length=32)
    tainted: bool = False
    # Binding fields for red-team replay defence. ``taint_hash`` commits to the
    # exact disclosure; ``nonce`` is single-use and is recorded in OEKP when the
    # approval executes. An empty nonce is legacy data and falls back to the id.
    taint_hash: str = Field(default="", max_length=64)
    nonce: str = Field(default="", max_length=64)
    consumed_at: datetime | None = None
    consumed_by: str | None = Field(default=None, max_length=200)
    # Human credential and the result of verifying it. Both are covered by the
    # record signature, so neither can be swapped after the decision is signed.
    credential: ApprovalCredential | None = None
    verification: ApprovalVerification | None = None
    # Dual-approver HITL: distinct verified humans must sign before the status
    # becomes APPROVED. ``decisions`` is covered by the record signature, so a
    # partial quorum cannot be replayed or silently extended.
    quorum: int = Field(default=1, ge=1, le=9)
    decisions: list[ApprovalDecision] = Field(default_factory=list, max_length=9)
    # Transaction limit binding: an approval for one amount cannot authorize a
    # different wire, and limit checks are re-run at execution time.
    amount: str | None = Field(default=None, max_length=40, pattern=r"^\d+(\.\d{1,4})?$")
    currency: str | None = Field(default=None, max_length=12, pattern=r"^[A-Z]{3}$")
    # External-egress binding. A verified sign-off authorizes publication of
    # exactly this decision payload to exactly this destination. Both fields are
    # covered by the record signature and the human credential, so a sign-off
    # for one sink or one payload cannot be replayed for another.
    egress_target: str | None = Field(default=None, max_length=500)
    egress_payload_digest: str | None = Field(
        default=None, max_length=64, pattern=r"^[0-9a-f]{64}$"
    )
    # HMAC or Ed25519 over the canonical record. Unsigned/tampered never grants.
    signature: str | None = Field(default=None, max_length=128)

    def matches(self, action: ActionClass, target: str) -> bool:
        # Bind to the exact target. A wildcard approval would let one human
        # sign-off authorize every host the pattern matches, so it is refused.
        return self.action_class is action and target == self.target


def decision_payload_digest(req: ApprovalRequest) -> str:
    """Stable digest of the irreversible decision scope approved for egress.

    Only request-time fields are included: decisions, verification, status and
    consumption metadata change as humans sign and the approval executes. The
    digest is computed when the request is created and recomputed from the same
    fields at publication, so it cannot drift between the two.
    """
    scope = {
        "id": req.id,
        "action_class": req.action_class.value,
        "target": req.target,
        "risk": req.risk.value,
        "mission_id": req.mission_id,
        "requested_by": req.requested_by,
        "justification": req.justification,
        "provenance": list(req.provenance),
        "tainted": bool(req.tainted),
        "taint_hash": req.taint_hash,
        "quorum": req.quorum,
        "amount": req.amount,
        "currency": req.currency,
    }
    return hashlib.sha256(canonical(scope)).hexdigest()


class ApprovalStore(Protocol):
    async def request(self, req: ApprovalRequest) -> ApprovalRequest: ...
    async def get(self, approval_id: str) -> ApprovalRequest | None: ...
    async def decide(
        self,
        approval_id: str,
        *,
        approved: bool,
        approver: str,
        note: str | None = None,
        credential: ApprovalCredential | None = None,
    ) -> ApprovalRequest: ...
    async def pending(self) -> list[ApprovalRequest]: ...
    async def consume(
        self, approval_id: str, *, nonce: str, correlation_id: str = ""
    ) -> ApprovalRequest | None: ...
    async def close(self) -> None: ...


class InMemoryApprovalStore:
    """Approval queue with identity policy and optional record signing.

    ``approvers`` is an allowlist of human names. ``require_allowlist`` makes an
    empty allowlist a hard failure, which is what production should use. A
    requester can never approve their own request, regardless of allowlist.
    """

    def __init__(
        self,
        *,
        signer: Signer | None = None,
        approvers: set[str] | None = None,
        require_allowlist: bool = False,
        ttl_s: int = 86_400,
        approver_verifier: Any = None,
    ) -> None:
        self._items: dict[str, ApprovalRequest] = {}
        self._lock = asyncio.Lock()
        self.signer = signer
        self.approvers = {a for a in (approvers or set()) if a}
        self.require_allowlist = require_allowlist
        self.ttl_s = ttl_s
        self.approver_verifier = approver_verifier

    def _sign(self, req: ApprovalRequest) -> ApprovalRequest:
        if self.signer is None:
            return req
        signature = self.signer.sign_record(
            "approval", req.model_dump(mode="json", exclude={"signature"})
        )
        return req.model_copy(update={"signature": signature})

    def _check_approver(self, req: ApprovalRequest, approver: str) -> str:
        name = (approver or "").strip()
        if not name:
            raise ValueError("approver identity is required")
        if self.require_allowlist and not self.approvers:
            raise ValueError("approver allowlist is not configured (AGENT_APPROVERS)")
        if self.approvers and name not in self.approvers:
            raise ValueError(f"approver {name!r} is not in the allowlist")
        if self.approver_verifier is not None:
            # The verifier sees the credential on the candidate record and may
            # return a rich ApprovalVerification; persist it so OEKP and ADRs
            # can audit exactly how identity was established.
            result = self.approver_verifier(name, req)
            if isinstance(result, ApprovalVerification):
                req.verification = result
            if not result:
                detail = result.detail if isinstance(result, ApprovalVerification) else ""
                raise ValueError(
                    f"approver {name!r} failed cryptographic verification"
                    + (f": {detail}" if detail else "")
                )
        if name == req.requested_by:
            raise ValueError("the requester cannot approve their own request")
        return name

    async def request(self, req: ApprovalRequest) -> ApprovalRequest:
        if not req.requested_by.strip():
            raise ValueError("requested_by is required")
        # A caller must never be able to inject a pre-decided record. The only
        # way to approve is ``decide()``, which enforces identity and four eyes.
        issued = {
            "status": ApprovalStatus.PENDING,
            "decided_by": None,
            "decided_at": None,
            "note": None,
            "signature": None,
            "consumed_at": None,
            "consumed_by": None,
            "decisions": [],
        }
        if not req.nonce:
            issued["nonce"] = uuid.uuid4().hex
        if not req.taint_hash:
            issued["taint_hash"] = taint_disclosure_hash(req.provenance, req.tainted)
        req = req.model_copy(update=issued)
        req = self._sign(req)
        async with self._lock:
            if req.id in self._items:
                raise ValueError(f"approval {req.id} already exists")
            self._items[req.id] = req
        return req

    async def get(self, approval_id: str) -> ApprovalRequest | None:
        return self._items.get(approval_id)

    async def decide(
        self,
        approval_id: str,
        *,
        approved: bool,
        approver: str,
        note: str | None = None,
        credential: ApprovalCredential | None = None,
    ) -> ApprovalRequest:
        async with self._lock:
            req = self._items.get(approval_id)
            if req is None:
                raise KeyError(f"no such approval: {approval_id}")
            if req.status is not ApprovalStatus.PENDING:
                raise ValueError(f"approval {approval_id} already {req.status.value}")
            created = req.created_at
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - created).total_seconds()
            if self.ttl_s and age > self.ttl_s:
                raise ValueError(f"approval {approval_id} expired after {self.ttl_s}s")
            name_candidate = (approver or "").strip()
            if any(d.approver.strip() == name_candidate for d in req.decisions):
                raise ValueError(
                    f"approver {name_candidate!r} has already decided this approval; "
                    "dual-approver quorum requires distinct humans"
                )
            now = datetime.now(timezone.utc)
            # The verifier sees the human's *intent*, not the record's eventual
            # quorum status. A first approver on a two-person quorum still signs
            # an "approved" credential; only the stored status stays PENDING.
            candidate = req.model_copy(
                update={
                    "status": ApprovalStatus.APPROVED if approved else ApprovalStatus.DENIED,
                    "decided_by": name_candidate,
                    "decided_at": now,
                    "note": note,
                    "credential": credential,
                    "verification": None,
                }
            )
            name = self._check_approver(candidate, approver)
            decision = ApprovalDecision(
                approver=name,
                approved=bool(approved),
                decided_at=now,
                note=note,
                credential=credential,
                verification=candidate.verification,
            )
            decisions = [*req.decisions, decision]
            sufficient = all(d.approved for d in decisions) and len(decisions) >= req.quorum
            final_status = (
                ApprovalStatus.DENIED
                if not approved
                else ApprovalStatus.APPROVED
                if sufficient
                else ApprovalStatus.PENDING
            )
            updated = req.model_copy(
                update={
                    "status": final_status,
                    "decided_by": name,
                    "decided_at": now,
                    "note": note,
                    "credential": credential,
                    "verification": candidate.verification,
                    "decisions": decisions,
                }
            )
            updated = self._sign(updated)
            self._items[approval_id] = updated
            return updated

    async def consume(
        self, approval_id: str, *, nonce: str, correlation_id: str = ""
    ) -> ApprovalRequest | None:
        """Atomically spend an approval's single-use nonce.

        Returns the consumed record on success, or ``None`` when the approval is
        unknown, its nonce does not match, or it was already spent. The caller
        must treat ``None`` as a hard DENY.
        """
        async with self._lock:
            req = self._items.get(approval_id)
            if req is None:
                return None
            # A partial quorum is still PENDING: the first human's signature
            # must never spend the nonce and must never become a cached terminal
            # verdict. Only a fully decided approval can be consumed.
            if req.status is not ApprovalStatus.APPROVED:
                return None
            if req.quorum > 1 and (
                len(req.decisions) < req.quorum
                or len({d.approver for d in req.decisions}) != len(req.decisions)
                or any(not d.approved for d in req.decisions)
            ):
                return None
            expected = req.nonce or req.id
            if nonce != expected or req.consumed_at is not None:
                return None
            spent = req.model_copy(
                update={
                    "consumed_at": datetime.now(timezone.utc),
                    "consumed_by": correlation_id or None,
                }
            )
            spent = self._sign(spent)
            self._items[approval_id] = spent
            return spent

    async def pending(self) -> list[ApprovalRequest]:
        return [r for r in self._items.values() if r.status is ApprovalStatus.PENDING]

    async def close(self) -> None:
        return None


class FileApprovalStore(InMemoryApprovalStore):
    """Persisted queue that stays correct across processes.

    The file is re-read whenever its mtime/size changes, so a long-running mesh
    sees an approval made by the CLI in another process. Writes take a
    cross-process lock and replace atomically. Records whose signature does not
    verify are dropped: a tampered approval never becomes an ALLOW.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        signer: Signer | None = None,
        approvers: set[str] | None = None,
        require_allowlist: bool = False,
        ttl_s: int = 86_400,
        approver_verifier: Any = None,
    ) -> None:
        super().__init__(
            signer=signer,
            approvers=approvers,
            require_allowlist=require_allowlist,
            ttl_s=ttl_s,
            approver_verifier=approver_verifier,
        )
        self.path = Path(path)
        secure_dir(self.path.parent)
        self._stamp: tuple[int, int] | None = None
        self.rejected = 0

    def _read(self) -> None:
        items: dict[str, ApprovalRequest] = {}
        if not self.path.is_file():
            self._items = items
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            for item in raw.get("approvals", []):
                try:
                    req = ApprovalRequest.model_validate(item)
                except ValueError:
                    self.rejected += 1
                    continue
                if self.signer is not None:
                    ok, _ = self.signer.verify_record(
                        "approval",
                        req.model_dump(mode="json", exclude={"signature"}),
                        req.signature,
                    )
                    if not ok:
                        self.rejected += 1
                        continue
                items[req.id] = req
        except (AttributeError, TypeError, json.JSONDecodeError, OSError):
            # Fail closed and keep the last known-good state. Clearing the map
            # here would let the next _save() overwrite every pending approval
            # with only the newest record after a transient shared-volume fault.
            self.rejected += 1
            raise SecurityError(
                "approval store is unreadable; failing closed until an operator repairs it"
            ) from None
        self._items = items

    def _refresh(self) -> None:
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            if self._stamp is not None:
                raise SecurityError(
                    "approval store disappeared; failing closed until an operator restores it"
                ) from None
            return
        stamp = (stat.st_mtime_ns, stat.st_size)
        if stamp != self._stamp:
            self._read()
            self._stamp = stamp

    def _save(self) -> None:
        payload = {"approvals": [r.model_dump(mode="json") for r in self._items.values()]}
        secure_dir(self.path.parent)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        secure_file(tmp)
        tmp.replace(self.path)
        secure_file(self.path)
        stat = self.path.stat()
        self._stamp = (stat.st_mtime_ns, stat.st_size)

    async def request(self, req: ApprovalRequest) -> ApprovalRequest:
        async with async_exclusive_lock(self.path):
            self._refresh()
            result = await super().request(req)
            self._save()
            return result

    async def get(self, approval_id: str) -> ApprovalRequest | None:
        self._refresh()
        return self._items.get(approval_id)

    async def decide(
        self,
        approval_id: str,
        *,
        approved: bool,
        approver: str,
        note: str | None = None,
        credential: ApprovalCredential | None = None,
    ) -> ApprovalRequest:
        async with async_exclusive_lock(self.path):
            self._refresh()
            result = await super().decide(
                approval_id,
                approved=approved,
                approver=approver,
                note=note,
                credential=credential,
            )
            self._save()
            return result

    async def consume(
        self, approval_id: str, *, nonce: str, correlation_id: str = ""
    ) -> ApprovalRequest | None:
        async with async_exclusive_lock(self.path):
            self._refresh()
            result = await super().consume(
                approval_id, nonce=nonce, correlation_id=correlation_id
            )
            if result is not None:
                self._save()
            return result

    async def pending(self) -> list[ApprovalRequest]:
        self._refresh()
        return await super().pending()


class PolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed_targets: list[str] = Field(default_factory=lambda: ["sandbox/*", "staging/*"])
    governed_actions: list[ActionClass] = Field(default_factory=lambda: [ActionClass.EXECUTE, ActionClass.CONTAIN])
    authorization_ttl_s: int = AUTHORIZATION_TTL_S
    approval_ttl_s: int = 86_400
    # FinOps/Banking controls. ``max_transaction_amount`` is a hard ceiling:
    # no approval can authorize a governed transaction above it.
    max_transaction_amount: Decimal | None = None
    transaction_currency: str = "USD"
    approval_quorum: int = Field(default=1, ge=1, le=9)
    # Destination whose restricted decisions this engine authorizes for signed
    # external publication. Bound into every approval it creates.
    egress_target: str | None = None

    @field_validator("max_transaction_amount")
    @classmethod
    def _valid_ceiling(cls, value: Decimal | None) -> Decimal | None:
        if value is not None and (not value.is_finite() or value < 0):
            raise ValueError("max_transaction_amount must be finite and non-negative")
        return value

    @field_validator("governed_actions")
    @classmethod
    def _non_empty_governed(cls, value: list[ActionClass]) -> list[ActionClass]:
        if not value:
            raise ValueError("governed_actions must not be empty")
        return value

    @field_validator("approval_ttl_s", "authorization_ttl_s")
    @classmethod
    def _positive_ttl(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("ttl must be positive")
        return value


class PolicyEngine:
    """Deterministic policy evaluation. No model, no network, no exceptions."""

    def __init__(
        self,
        config: PolicyConfig,
        approvals: ApprovalStore,
        approver_registry: Any = None,
        consumption_audit: Any = None,
    ) -> None:
        self.config = config
        self.approvals = approvals
        self.approver_registry = approver_registry
        # OEKP hook: called with the spent approval after a successful ALLOW so
        # the consumed nonce is immutable evidence, never just process memory.
        self.consumption_audit = consumption_audit

    @staticmethod
    def policy_ref(action: ActionClass, target: str | None, risk: RiskLevel) -> str:
        digest = uuid.uuid5(uuid.NAMESPACE_URL, f"{action.value}|{target}|{risk.value}").hex[:12]
        return f"pol-{digest}"

    def target_allowed(self, target: str | None) -> bool:
        if not target:
            return False
        if ".." in target or target.startswith("/") or target.startswith("\\\\"):
            return False
        import posixpath

        normalized = posixpath.normpath(target.replace("\\\\", "/"))
        if normalized.startswith("../") or normalized == "..":
            return False
        return any(fnmatch.fnmatchcase(normalized, pattern) for pattern in self.config.allowed_targets)

    async def evaluate(
        self,
        *,
        action: ActionClass,
        target: str | None,
        risk: RiskLevel,
        mission_id: str | None,
        classification: Classification,
        approval_ref: str | None,
        requested_by: str,
        justification: str = "",
        correlation_id: str = "",
        provenance: list[str] | None = None,
        tainted: bool = False,
        amount: str | Decimal | None = None,
        currency: str | None = None,
    ) -> GovernanceDecision:
        ref = self.policy_ref(action, target, risk)
        governed = action in self.config.governed_actions
        provenance = provenance or []
        try:
            parsed_amount = parse_money(amount)
        except ValueError as exc:
            return GovernanceDecision(
                decision=DecisionType.DENY,
                policy_ref=ref,
                reasons=[str(exc)],
                provenance=provenance,
                tainted=tainted,
            )
        canonical_amount = str(parsed_amount) if parsed_amount is not None else None
        want_currency = str(currency or self.config.transaction_currency).upper()

        if classification is Classification.RESTRICTED and not mission_id:
            return GovernanceDecision(
                decision=DecisionType.DENY,
                policy_ref=ref,
                reasons=["restricted data requires a mission_id"],
            )
        if governed and not target:
            return GovernanceDecision(
                decision=DecisionType.DENY,
                policy_ref=ref,
                reasons=[f"{action.value} requires an explicit target"],
            )
        if governed and not self.target_allowed(target):
            return GovernanceDecision(
                decision=DecisionType.DENY,
                policy_ref=ref,
                reasons=[f"target {target!r} is outside the authorized target list"],
            )
        # Transaction limits are re-evaluated at execution time. An approval
        # never relaxes the configured ceiling, and an unsupported currency is
        # refused rather than silently converted.
        if governed and parsed_amount is not None:
            ceiling = self.config.max_transaction_amount
            if ceiling is not None and parsed_amount > ceiling:
                return GovernanceDecision(
                    decision=DecisionType.DENY,
                    policy_ref=ref,
                    reasons=[
                        f"transaction {parsed_amount} {want_currency} exceeds the "
                        f"configured ceiling {ceiling} {self.config.transaction_currency}"
                    ],
                    provenance=provenance,
                    tainted=tainted,
                )
            if want_currency != self.config.transaction_currency.upper():
                return GovernanceDecision(
                    decision=DecisionType.DENY,
                    policy_ref=ref,
                    reasons=[
                        f"currency {want_currency!r} is not authorized; "
                        f"expected {self.config.transaction_currency}"
                    ],
                    provenance=provenance,
                    tainted=tainted,
                )
        if not governed and not tainted:
            return GovernanceDecision(
                decision=DecisionType.ALLOW,
                policy_ref=ref,
                reasons=[f"{action.value} is non-consequential and needs no approval"],
                provenance=provenance,
                tainted=tainted,
            )
        # Consequential OR tainted: a human approval is mandatory. A tainted
        # read/recommend/simulate step can seed a later mutating step, so it is
        # not "harmless" and must not bypass the HITL gate.
        # Consequential: a human approval is mandatory, regardless of risk.
        # Tainted provenance is disclosed on the approval request itself (see
        # below) so the approver sees the poisoned upstream chain, and a tainted
        # action may never reuse an approval issued without that disclosure.
        if approval_ref:
            request = await self.approvals.get(approval_ref)
            if request is None:
                return GovernanceDecision(
                    decision=DecisionType.DENY,
                    policy_ref=ref,
                    reasons=[f"approval {approval_ref!r} not found"],
                    approval_ref=approval_ref,
                )
            # Transaction binding: the human signed a specific amount and
            # currency. Neither side may be changed after the signature, and
            # an approval for a different sum cannot authorize this execution.
            try:
                approved_amount = parse_money(request.amount)
            except ValueError as exc:
                return GovernanceDecision(
                    decision=DecisionType.DENY,
                    policy_ref=ref,
                    reasons=[f"approval {approval_ref} has an invalid amount: {exc}"],
                    approval_ref=approval_ref,
                )
            approved_currency = str(
                request.currency or self.config.transaction_currency
            ).upper()
            if approved_amount != parsed_amount or (
                parsed_amount is not None and approved_currency != want_currency
            ):
                return GovernanceDecision(
                    decision=DecisionType.DENY,
                    policy_ref=ref,
                    reasons=[
                        f"approval {approval_ref} is bound to "
                        f"{approved_amount if approved_amount is not None else 'no amount'} "
                        f"{approved_currency}, not {parsed_amount} {want_currency}"
                    ],
                    approval_ref=approval_ref,
                    provenance=provenance,
                    tainted=tainted,
                )
            # A tainted action may only use an approval that disclosed the same
            # taint. Otherwise an attacker could launder poisoned telemetry
            # through an approval a human granted for a seemingly clean action.
            if tainted and not request.tainted:
                return GovernanceDecision(
                    decision=DecisionType.DENY,
                    policy_ref=ref,
                    reasons=[
                        f"approval {approval_ref} was issued without taint disclosure; "
                        "request a fresh approval for the tainted chain"
                    ],
                    approval_ref=approval_ref,
                    provenance=provenance,
                    tainted=True,
                )
            if tainted and set(request.provenance) != set(provenance):
                return GovernanceDecision(
                    decision=DecisionType.DENY,
                    policy_ref=ref,
                    reasons=[
                        f"approval {approval_ref} covers different provenance; "
                        "request a fresh approval for this chain"
                    ],
                    approval_ref=approval_ref,
                    provenance=provenance,
                    tainted=True,
                )
            # The approval commits to the exact taint disclosure. A human who
            # saw one provenance set cannot authorise a different one by simply
            # relabelling the same untrusted payload.
            expected_taint_hash = taint_disclosure_hash(provenance, tainted)
            if (
                request.taint_hash
                and (tainted or request.tainted)
                and request.taint_hash != expected_taint_hash
            ):
                return GovernanceDecision(
                    decision=DecisionType.DENY,
                    policy_ref=ref,
                    reasons=[
                        f"approval {approval_ref} covers a different taint disclosure; "
                        "request a fresh approval for this provenance"
                    ],
                    approval_ref=approval_ref,
                    provenance=provenance,
                    tainted=tainted,
                )
            # Risk is a ceiling, not an exact match: a human who reviewed a
            # high-risk action also covered lower-risk variants of the same
            # scope, but a low-risk sign-off can never escalate to high/critical.
            if TIER_RANK[risk] > TIER_RANK[request.risk]:
                return GovernanceDecision(
                    decision=DecisionType.DENY,
                    policy_ref=ref,
                    reasons=[
                        f"approval {approval_ref} was issued for at most "
                        f"{request.risk.value} risk, but this action is {risk.value}"
                    ],
                    approval_ref=approval_ref,
                    provenance=provenance,
                    tainted=tainted,
                )
            if request.status is ApprovalStatus.DENIED:
                return GovernanceDecision(
                    decision=DecisionType.DENY,
                    policy_ref=ref,
                    reasons=[f"approval {approval_ref} was denied by {request.decided_by}"],
                    approval_ref=approval_ref,
                )
            if request.status is ApprovalStatus.PENDING:
                created = request.created_at
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                age = (datetime.now(timezone.utc) - created).total_seconds()
                if self.config.approval_ttl_s and age > self.config.approval_ttl_s:
                    return GovernanceDecision(
                        decision=DecisionType.DENY,
                        policy_ref=ref,
                        reasons=[
                            f"approval {approval_ref} expired after {self.config.approval_ttl_s}s; "
                            "request a new approval"
                        ],
                        approval_ref=approval_ref,
                    )
                return GovernanceDecision(
                    decision=DecisionType.HOLD,
                    policy_ref=ref,
                    reasons=[f"approval {approval_ref} is still pending"],
                    approval_ref=approval_ref,
                )
            # An approval is a point-in-time human decision, not a permanent
            # grant. Expire it from the moment it was decided.
            decided = request.decided_at or request.created_at
            if decided.tzinfo is None:
                decided = decided.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - decided).total_seconds()
            if self.config.approval_ttl_s and age > self.config.approval_ttl_s:
                return GovernanceDecision(
                    decision=DecisionType.DENY,
                    policy_ref=ref,
                    reasons=[
                        f"approval {approval_ref} expired {int(age)}s after it was decided; "
                        "request a new approval"
                    ],
                    approval_ref=approval_ref,
                )
            # Dual-approver HITL: every required human must have signed, they
            # must be distinct, and each individual credential/tier is checked.
            # The store only marks a record APPROVED at quorum; this is the
            # execution-time recheck for records restored from disk.
            if request.quorum > 1:
                if len(request.decisions) < request.quorum or any(
                    not d.approved for d in request.decisions
                ):
                    return GovernanceDecision(
                        decision=DecisionType.DENY,
                        policy_ref=ref,
                        reasons=[
                            f"approval {approval_ref} needs {request.quorum} approvers, "
                            f"but only {len(request.decisions)} signed decision(s) are recorded"
                        ],
                        approval_ref=approval_ref,
                    )
                names = [d.approver for d in request.decisions]
                if len(set(names)) != len(names):
                    return GovernanceDecision(
                        decision=DecisionType.DENY,
                        policy_ref=ref,
                        reasons=["dual-approver quorum requires distinct humans"],
                        approval_ref=approval_ref,
                    )
            else:
                names = [d.approver for d in request.decisions]
                if not names and request.decided_by:
                    names = [request.decided_by]
            if not names:
                return GovernanceDecision(
                    decision=DecisionType.DENY,
                    policy_ref=ref,
                    reasons=[f"approval {approval_ref} has no approver"],
                    approval_ref=approval_ref,
                )
            verifications = approval_verifications(request)
            if any(not v.verified for v in verifications):
                return GovernanceDecision(
                    decision=DecisionType.DENY,
                    policy_ref=ref,
                    reasons=["an approver credential failed cryptographic verification"],
                    approval_ref=approval_ref,
                )
            # Tiers are rechecked at execution time from the signed verification
            # or the signed registry. A dev-mode record with neither is left
            # alone; a configured registry is always authoritative.
            tier_by_name: dict[str, RiskLevel | None] = {
                v.approver_id: v.max_tier for v in verifications
            }
            for name in names:
                tier = tier_by_name.get(name)
                if tier is None and self.approver_registry is not None:
                    entry = self.approver_registry.get(name)
                    tier = entry.max_tier if entry is not None else None
                if tier is None and self.approver_registry is not None:
                    return GovernanceDecision(
                        decision=DecisionType.DENY,
                        policy_ref=ref,
                        reasons=[f"approver {name!r} is not in the signed registry"],
                        approval_ref=approval_ref,
                    )
                if tier is not None and not tier_allows(tier, risk):
                    return GovernanceDecision(
                        decision=DecisionType.DENY,
                        policy_ref=ref,
                        reasons=[
                            f"approver {name!r} may authorize at most "
                            f"{tier.value if tier else 'no'} tier, "
                            f"but this action is {risk.value}"
                        ],
                        approval_ref=approval_ref,
                    )
            if not request.matches(action, target or ""):
                return GovernanceDecision(
                    decision=DecisionType.DENY,
                    policy_ref=ref,
                    reasons=["approval does not cover this action and target"],
                    approval_ref=approval_ref,
                )
            # Fail closed on mission scope: an approval issued without a mission
            # must not authorize work that now belongs to a mission.
            if (request.mission_id or None) != (mission_id or None):
                return GovernanceDecision(
                    decision=DecisionType.DENY,
                    policy_ref=ref,
                    reasons=[
                        f"approval {approval_ref} is scoped to mission {request.mission_id!r}, "
                        f"not {mission_id!r}"
                    ],
                    approval_ref=approval_ref,
                )
            # Single-use: the nonce is spent atomically before any execution
            # authority is issued. A redelivery of the same task is collapsed by
            # the runtime idempotency cache before it reaches this gate again.
            try:
                spent = await self.approvals.consume(
                    approval_ref,
                    nonce=request.nonce or request.id,
                    correlation_id=correlation_id,
                )
            except Exception as exc:  # never fail open on an audit/store error
                return GovernanceDecision(
                    decision=DecisionType.DENY,
                    policy_ref=ref,
                    reasons=[f"approval consumption failed: {exc}"],
                    approval_ref=approval_ref,
                    provenance=provenance,
                    tainted=tainted,
                )
            if spent is None:
                return GovernanceDecision(
                    decision=DecisionType.DENY,
                    policy_ref=ref,
                    reasons=[
                        f"approval {approval_ref} nonce was already consumed; "
                        "a single-use approval cannot be replayed"
                    ],
                    approval_ref=approval_ref,
                    provenance=provenance,
                    tainted=tainted,
                )
            if self.consumption_audit is not None:
                try:
                    await self.consumption_audit(
                        spent,
                        action=action,
                        target=target,
                        mission_id=mission_id,
                        correlation_id=correlation_id,
                        provenance=provenance,
                        tainted=tainted,
                    )
                except Exception as exc:
                    return GovernanceDecision(
                        decision=DecisionType.DENY,
                        policy_ref=ref,
                        reasons=[f"approval consumption could not be recorded: {exc}"],
                        approval_ref=approval_ref,
                        provenance=provenance,
                        tainted=tainted,
                    )
            expires = datetime.now(timezone.utc) + timedelta(seconds=self.config.authorization_ttl_s)
            return GovernanceDecision(
                decision=DecisionType.ALLOW,
                policy_ref=ref,
                reasons=[f"approved by {request.decided_by} (nonce consumed)"],
                approval_ref=approval_ref,
                authorization_ref=f"auth-{uuid.uuid4().hex[:12]}",
                expires_at=expires,
                provenance=provenance,
                tainted=tainted,
            )

        # A redelivered task must not flood the human queue with duplicates.
        duplicate = next(
            (
                r
                for r in await self.approvals.pending()
                if r.action_class is action
                and r.target == (target or "")
                and r.correlation_id == correlation_id
                and (r.mission_id or None) == (mission_id or None)
                and r.tainted == tainted
                and (r.amount or None) == canonical_amount
                and str(r.currency or self.config.transaction_currency).upper() == want_currency
                and set(r.provenance) == set(provenance)
            ),
            None,
        )
        if duplicate is not None:
            return GovernanceDecision(
                decision=DecisionType.HOLD,
                policy_ref=ref,
                reasons=[f"approval {duplicate.id} is still pending"],
                approval_ref=duplicate.id,
            )

        request = ApprovalRequest(
            action_class=action,
            target=target or "",
            risk=risk,
            mission_id=mission_id,
            requested_by=requested_by,
            justification=justification,
            correlation_id=correlation_id,
            provenance=provenance,
            tainted=tainted,
            taint_hash=taint_disclosure_hash(provenance, tainted),
            quorum=self.config.approval_quorum,
            amount=canonical_amount,
            currency=want_currency,
            egress_target=self.config.egress_target,
        )
        request = request.model_copy(
            update={"egress_payload_digest": decision_payload_digest(request)}
        )
        request = await self.approvals.request(request)
        reasons = [
            f"{action.value} on {target!r} requires human approval",
            "an AI recommendation is not execution authority",
        ]
        if tainted and not governed:
            reasons.append(
                "tainted output is not a harmless read: mandatory HITL approval "
                "before it can seed a downstream step"
            )
        if tainted:
            reasons.append(
                "upstream provenance is tainted: " + (", ".join(provenance) or "unknown")
            )
        if parsed_amount is not None:
            reasons.append(
                f"transaction limit gate: {parsed_amount} {want_currency} must be "
                f"approved by {self.config.approval_quorum} distinct human(s)"
            )
        return GovernanceDecision(
            decision=DecisionType.HOLD,
            policy_ref=ref,
            reasons=reasons,
            approval_ref=request.id,
            provenance=provenance,
            tainted=tainted,
        )

    @staticmethod
    def screen_text(text: str) -> list[str]:
        import unicodedata

        normalized = unicodedata.normalize("NFKC", str(text)).casefold()
        lowered = " ".join(normalized.split())
        return [pattern for pattern in PROHIBITED_PATTERNS if pattern in lowered]
