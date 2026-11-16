"""USOC governance: policy decisions and human approvals.

USOC's core rule is that an AI recommendation is not execution authority. Every
consequential task therefore passes a deterministic policy gate before it runs:

    identity -> mission -> scope -> target -> risk -> HITL -> policy -> execution

LLM output never decides a policy outcome. ``PolicyEngine`` is plain code with
explicit rules, and a DENY here cannot be overridden by any agent, prompt or
model response.

Decisions match the master prompt: ALLOW, HOLD, DENY, CONTAIN.
"""

from __future__ import annotations

import asyncio
import fnmatch
import json
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .contracts import ActionClass, Classification, RiskLevel
from .security import Signer, exclusive_lock, secure_dir, secure_file

GOVERNED = frozenset({ActionClass.EXECUTE, ActionClass.CONTAIN})
AUTHORIZATION_TTL_S = 900

# Defensive-only boundary from the USOC master prompt. These are screening
# signals for the CYBER STRIKE subsystem, not a content filter.
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

    @property
    def allowed(self) -> bool:
        return self.decision is DecisionType.ALLOW


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"


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
    # HMAC over the canonical record. Unsigned or tampered records never grant.
    signature: str | None = Field(default=None, max_length=128)

    def matches(self, action: ActionClass, target: str) -> bool:
        # Bind to the exact target. A wildcard approval would let one human
        # sign-off authorize every host the pattern matches, so it is refused.
        return self.action_class is action and target == self.target


class ApprovalStore(Protocol):
    async def request(self, req: ApprovalRequest) -> ApprovalRequest: ...
    async def get(self, approval_id: str) -> ApprovalRequest | None: ...
    async def decide(self, approval_id: str, *, approved: bool, approver: str, note: str | None = None) -> ApprovalRequest: ...
    async def pending(self) -> list[ApprovalRequest]: ...
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
        if self.approver_verifier is not None and not self.approver_verifier(name, req):
            raise ValueError(f"approver {name!r} failed cryptographic verification")
        if name == req.requested_by:
            raise ValueError("the requester cannot approve their own request")
        return name

    async def request(self, req: ApprovalRequest) -> ApprovalRequest:
        if not req.requested_by.strip():
            raise ValueError("requested_by is required")
        # A caller must never be able to inject a pre-decided record. The only
        # way to approve is ``decide()``, which enforces identity and four eyes.
        req = req.model_copy(
            update={
                "status": ApprovalStatus.PENDING,
                "decided_by": None,
                "decided_at": None,
                "note": None,
                "signature": None,
            }
        )
        req = self._sign(req)
        async with self._lock:
            if req.id in self._items:
                raise ValueError(f"approval {req.id} already exists")
            self._items[req.id] = req
        return req

    async def get(self, approval_id: str) -> ApprovalRequest | None:
        return self._items.get(approval_id)

    async def decide(self, approval_id: str, *, approved: bool, approver: str, note: str | None = None) -> ApprovalRequest:
        async with self._lock:
            req = self._items.get(approval_id)
            if req is None:
                raise KeyError(f"no such approval: {approval_id}")
            if req.status is not ApprovalStatus.PENDING:
                raise ValueError(f"approval {approval_id} already {req.status.value}")
            name = self._check_approver(req, approver)
            created = req.created_at
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - created).total_seconds()
            if self.ttl_s and age > self.ttl_s:
                raise ValueError(f"approval {approval_id} expired after {self.ttl_s}s")
            updated = req.model_copy(
                update={
                    "status": ApprovalStatus.APPROVED if approved else ApprovalStatus.DENIED,
                    "decided_by": name,
                    "decided_at": datetime.now(timezone.utc),
                    "note": note,
                }
            )
            updated = self._sign(updated)
            self._items[approval_id] = updated
            return updated

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
        except (json.JSONDecodeError, OSError):
            # A corrupt approval log must not silently grant anything.
            items = {}
            self.rejected += 1
        self._items = items

    def _refresh(self) -> None:
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            if self._stamp is not None:
                self._items = {}
                self._stamp = None
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
        with exclusive_lock(self.path):
            self._refresh()
            result = await super().request(req)
            self._save()
            return result

    async def get(self, approval_id: str) -> ApprovalRequest | None:
        self._refresh()
        return self._items.get(approval_id)

    async def decide(self, approval_id: str, *, approved: bool, approver: str, note: str | None = None) -> ApprovalRequest:
        with exclusive_lock(self.path):
            self._refresh()
            result = await super().decide(
                approval_id, approved=approved, approver=approver, note=note
            )
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

    def __init__(self, config: PolicyConfig, approvals: ApprovalStore) -> None:
        self.config = config
        self.approvals = approvals

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
    ) -> GovernanceDecision:
        ref = self.policy_ref(action, target, risk)
        governed = action in self.config.governed_actions

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
        if not governed:
            return GovernanceDecision(
                decision=DecisionType.ALLOW,
                policy_ref=ref,
                reasons=[f"{action.value} is non-consequential and needs no approval"],
            )

        # Consequential: a human approval is mandatory, regardless of risk.
        if approval_ref:
            request = await self.approvals.get(approval_ref)
            if request is None:
                return GovernanceDecision(
                    decision=DecisionType.DENY,
                    policy_ref=ref,
                    reasons=[f"approval {approval_ref!r} not found"],
                    approval_ref=approval_ref,
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
            if not request.decided_by:
                return GovernanceDecision(
                    decision=DecisionType.DENY,
                    policy_ref=ref,
                    reasons=[f"approval {approval_ref} has no approver"],
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
            expires = datetime.now(timezone.utc) + timedelta(seconds=self.config.authorization_ttl_s)
            return GovernanceDecision(
                decision=DecisionType.ALLOW,
                policy_ref=ref,
                reasons=[f"approved by {request.decided_by}"],
                approval_ref=approval_ref,
                authorization_ref=f"auth-{uuid.uuid4().hex[:12]}",
                expires_at=expires,
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

        request = await self.approvals.request(
            ApprovalRequest(
                action_class=action,
                target=target or "",
                risk=risk,
                mission_id=mission_id,
                requested_by=requested_by,
                justification=justification,
                correlation_id=correlation_id,
            )
        )
        return GovernanceDecision(
            decision=DecisionType.HOLD,
            policy_ref=ref,
            reasons=[
                f"{action.value} on {target!r} requires human approval",
                "an AI recommendation is not execution authority",
            ],
            approval_ref=request.id,
        )

    @staticmethod
    def screen_text(text: str) -> list[str]:
        import unicodedata

        normalized = unicodedata.normalize("NFKC", str(text)).casefold()
        lowered = " ".join(normalized.split())
        return [pattern for pattern in PROHIBITED_PATTERNS if pattern in lowered]
