"""Production trust: per-coordinator bus keys and bound human approvers.

Two independent trust anchors live here:

1. ``CoordinatorKeyring`` selects an Ed25519 signer/verifier by message sender.
   Every node mounts the same ``{agent_id: {kid: public_key}}`` bundle, but only
   the node acting as a given coordinator mounts that coordinator's private key
   (or a KMS signing URL). A compromised connector worker therefore cannot mint
   messages as ``seraphim`` or ``hitl``: it has no key for those sender ids.

2. ``ApproverRegistry`` is a signed ``approver_id -> {role, public_key,
   max_tier}`` document. ``ApprovalVerifier`` checks a human's detached
   Ed25519 signature or OIDC id_token against that registry and returns an
   ``ApprovalVerification`` that is stored on the signed approval record and
   copied into OEKP by the CLI.

The legacy HMAC path remains for local development and tests. ``AGENT_STRICT_PROD``
disables every fallback and ``agents doctor`` fails closed instead of warning.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .asymmetric import (
    Ed25519KMSSigner,
    Ed25519Signer,
    Ed25519Verifier,
    PublicKeySet,
    fingerprint,
    kms_http_signer,
    load_private_key,
    load_public_key,
    public_key_hex,
)
from .contracts import Message, RiskLevel
from .governance import (
    ApprovalCredential,
    ApprovalRequest,
    ApprovalVerification,
)
from .oidc import OIDCConfig, verify_id_token
from .security import (
    SecurityError,
    Signer,
    build_signer,
    canonical,
    is_ephemeral_secret,
    read_secret,
    uses_managed_secrets,
)

MESSAGE_ALG = "ed25519"
CREDENTIAL_SCOPE = "approval-credential/v1"


# -- per-coordinator bus identities ------------------------------------------

class CoordinatorKeyring:
    """Sender-aware signer/verifier for the bus.

    Implements the same ``sign_message``/``verify_message`` pair as ``Signer``,
    so the buses, the mesh and ``Shell`` need no special-casing.
    """

    def __init__(
        self,
        public: dict[str, PublicKeySet],
        signers: dict[str, Signer],
        *,
        strict: bool = False,
        max_age_s: int = 0,
    ) -> None:
        if not public:
            raise SecurityError("coordinator trust bundle is empty")
        self.public = public
        self.signers = signers
        self.strict = strict
        self.max_age_s = max(0, int(max_age_s))

    @classmethod
    def load(cls, settings: Any) -> "CoordinatorKeyring":
        inline = getattr(settings, "bus_public_keys", None)
        path = getattr(settings, "bus_public_keys_file", None)
        if inline is not None:
            payload = inline
        elif path is not None:
            try:
                payload = json.loads(Path(path).read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise SecurityError(f"cannot read AGENT_BUS_PUBLIC_KEYS_FILE: {exc}") from exc
        else:
            raise SecurityError(
                "per-coordinator bus mode requires AGENT_BUS_PUBLIC_KEYS_FILE "
                "(or inline AGENT_BUS_PUBLIC_KEYS for tests)"
            )
        if not isinstance(payload, dict) or not payload:
            raise SecurityError("AGENT_BUS_PUBLIC_KEYS must be a non-empty JSON object")

        public: dict[str, PublicKeySet] = {}
        for agent, bundle in payload.items():
            name = str(agent).strip()
            if not name or not isinstance(bundle, dict) or not bundle:
                raise SecurityError(f"invalid bus trust entry for {name!r}")
            keys: dict[str, Any] = {}
            for kid, material in bundle.items():
                key = load_public_key(str(material), None)
                keys[str(kid).strip()] = key
            public[name] = PublicKeySet(keys)

        signing_agent = str(getattr(settings, "bus_signing_agent", "") or "").strip()
        if not signing_agent and len(public) == 1 and not getattr(settings, "strict_prod", False):
            signing_agent = next(iter(public))
        if not signing_agent:
            signing_agent = ""

        signers: dict[str, Signer] = {}
        if signing_agent:
            if signing_agent not in public:
                raise SecurityError(
                    f"AGENT_BUS_SIGNING_AGENT {signing_agent!r} is not in the trust bundle"
                )
            kid = str(getattr(settings, "bus_signing_kid", "default") or "default")
            keys = public[signing_agent]
            if kid not in keys.keys:
                raise SecurityError(
                    f"AGENT_BUS_SIGNING_KID {kid!r} is not in the trust bundle for {signing_agent!r}"
                )
            key_set = PublicKeySet(keys.keys, active_key_id=kid)
            private_file = getattr(settings, "bus_signing_key_file", None)
            private_inline = getattr(settings, "bus_signing_key", None)
            kms_url = getattr(settings, "bus_kms_sign_url", None)
            if private_file or private_inline:
                private = load_private_key(private_inline, private_file)
                signers[signing_agent] = Ed25519Signer(
                    private, key_id=kid, key_set=key_set
                )
            elif kms_url:
                signers[signing_agent] = Ed25519KMSSigner(
                    key_set,
                    kms_http_signer(
                        str(kms_url),
                        token=read_secret(
                            getattr(settings, "bus_kms_sign_token", None),
                            getattr(settings, "bus_kms_sign_token_file", None),
                        ),
                        timeout_s=float(getattr(settings, "bus_kms_sign_timeout_s", 5.0)),
                        allowed_key_ids=set(keys.keys),
                    ),
                    key_id=kid,
                )
        return cls(
            public,
            signers,
            strict=bool(getattr(settings, "strict_prod", False)),
            max_age_s=int(getattr(settings, "max_message_age_s", 0) or 0),
        )

    def sign_message(self, msg: Message) -> Message:
        signer = self.signers.get(msg.sender)
        if signer is None:
            raise SecurityError(
                f"no managed signing key for coordinator {msg.sender!r}; "
                "a worker cannot publish as another agent"
            )
        # Set the metadata BEFORE signing: every field except `signature` is
        # covered, so an attacker cannot relabel a message with another kid.
        prepared = msg.model_copy(
            update={
                "signature_alg": MESSAGE_ALG,
                "signing_kid": signer.key_id,
                "signature": None,
            }
        )
        return signer.sign_message(prepared)

    def verify_message(self, msg: Message) -> tuple[bool, str]:
        if msg.signature_alg != MESSAGE_ALG:
            return False, f"unexpected message algorithm {msg.signature_alg!r}"
        keys = self.public.get(msg.sender)
        if keys is None:
            return False, f"unknown coordinator {msg.sender!r}"
        kid = msg.signing_kid
        if kid:
            if kid not in keys.keys:
                return False, f"untrusted key id {kid!r} for {msg.sender!r}"
            # Restrict verification to the claimed key so a message cannot be
            # attributed to a different key than the one that signed it.
            keys = PublicKeySet({kid: keys.keys[kid]}, active_key_id=kid)
        verifier = Ed25519Verifier(keys)
        verifier.max_age_s = self.max_age_s
        return verifier.verify_message(msg)

    def describe(self) -> dict[str, dict[str, str]]:
        return {agent: keys.describe() for agent, keys in self.public.items()}


def build_message_authority(settings: Any) -> Signer | CoordinatorKeyring | None:
    """Return the bus signer: sender-aware in managed mode, HMAC in dev."""
    from .security import build_signer

    if not getattr(settings, "message_auth", True):
        return None
    managed = bool(
        getattr(settings, "bus_public_keys_file", None)
        or getattr(settings, "bus_public_keys", None)
    )
    if not managed:
        if getattr(settings, "strict_prod", False):
            raise SecurityError(
                "AGENT_STRICT_PROD requires AGENT_BUS_PUBLIC_KEYS_FILE with "
                "per-coordinator Ed25519 keys"
            )
        return build_signer(settings)
    if getattr(settings, "strict_prod", False) and not getattr(
        settings, "bus_public_keys_file", None
    ):
        raise SecurityError(
            "AGENT_STRICT_PROD requires a mounted AGENT_BUS_PUBLIC_KEYS_FILE, "
            "not inline key material"
        )
    return CoordinatorKeyring.load(settings)


# -- signed approver registry -------------------------------------------------

class ApproverEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: str = Field(min_length=1, max_length=64)
    public_key: str | None = Field(default=None, max_length=4096)
    public_keys: dict[str, str] | None = None
    max_tier: RiskLevel = RiskLevel.LOW


class ApproverRegistry:
    """Human approvers bound to roles, public keys and a maximum risk tier."""

    def __init__(
        self,
        entries: dict[str, ApproverEntry],
        keys: dict[str, PublicKeySet],
        *,
        source: str,
        signature_kid: str | None = None,
        digest: str | None = None,
    ) -> None:
        self.entries = entries
        self.keys = keys
        self.source = source
        self.signature_kid = signature_kid
        self.digest = digest

    def get(self, approver_id: str) -> ApproverEntry | None:
        return self.entries.get(str(approver_id).strip())

    def ids(self) -> set[str]:
        return set(self.entries)

    def verify_detached(self, approver_id: str, data: bytes, signature: str) -> tuple[bool, str | None, str | None]:
        keys = self.keys.get(str(approver_id).strip())
        if keys is None:
            return False, None, None
        ok, kid = keys.verify_bytes(data, signature)
        if not ok:
            return False, None, None
        return True, kid, fingerprint(keys.keys[kid or keys.active_key_id])


def _registry_key_set(settings: Any) -> PublicKeySet | None:
    inline = getattr(settings, "approver_registry_public_keys", None)
    inline_single = getattr(settings, "approver_registry_public_key", None)
    file_multi = getattr(settings, "approver_registry_public_keys_file", None)
    file_single = getattr(settings, "approver_registry_public_key_file", None)
    if not any((inline, inline_single, file_multi, file_single)):
        return None
    keys: dict[str, Any] = {}
    if inline or file_multi:
        payload = inline
        if payload is None:
            try:
                payload = json.loads(Path(file_multi).read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise SecurityError(
                    f"cannot read AGENT_APPROVER_REGISTRY_PUBLIC_KEYS_FILE: {exc}"
                ) from exc
        if not isinstance(payload, dict) or not payload:
            raise SecurityError("approver registry public keys must be a non-empty object")
        for kid, material in payload.items():
            keys[str(kid).strip()] = load_public_key(str(material), None)
    if inline_single or file_single:
        key = load_public_key(inline_single, file_single)
        keys.setdefault("default", key)
    return PublicKeySet(keys)


def load_approver_registry(settings: Any) -> ApproverRegistry | None:
    """Load and verify the signed registry; fail closed on tampering."""
    strict = bool(getattr(settings, "strict_prod", False))
    path = getattr(settings, "approver_registry_file", None)
    inline = getattr(settings, "approver_registry", None)
    key_set = _registry_key_set(settings)
    signature = read_secret(
        getattr(settings, "approver_registry_signature", None),
        getattr(settings, "approver_registry_signature_file", None),
    )

    if strict:
        if not path:
            raise SecurityError(
                "AGENT_STRICT_PROD requires AGENT_APPROVER_REGISTRY_FILE"
            )
        if not key_set:
            raise SecurityError(
                "AGENT_STRICT_PROD requires AGENT_APPROVER_REGISTRY_PUBLIC_KEY_FILE "
                "(or the multi-key bundle file)"
            )
        if not signature:
            raise SecurityError(
                "AGENT_STRICT_PROD requires AGENT_APPROVER_REGISTRY_SIGNATURE_FILE"
            )

    if path is not None:
        try:
            data = Path(path).read_bytes()
        except OSError as exc:
            raise SecurityError(f"cannot read AGENT_APPROVER_REGISTRY_FILE: {exc}") from exc
        if key_set is not None or signature:
            if not signature:
                raise SecurityError("approver registry trust key configured but signature is missing")
            ok, kid = key_set.verify_bytes(data, signature)
            if not ok:
                raise SecurityError("approver registry signature verification failed")
        else:
            # No trust anchor configured: this is an unsigned dev registry.
            kid = None
        digest = hashlib.sha256(data).hexdigest()
        try:
            payload = json.loads(data)
        except ValueError as exc:
            raise SecurityError(f"approver registry is not valid JSON: {exc}") from exc
        source = str(path)
    elif inline is not None:
        if strict:
            raise SecurityError(
                "AGENT_STRICT_PROD does not allow an inline approver registry"
            )
        payload = inline
        digest = None
        source = "inline"
    else:
        return None

    if not isinstance(payload, dict) or not payload:
        raise SecurityError("approver registry must be a non-empty JSON object")
    entries: dict[str, ApproverEntry] = {}
    keys: dict[str, PublicKeySet] = {}
    for name, raw in payload.items():
        approver = str(name).strip()
        if not approver or not isinstance(raw, dict):
            raise SecurityError(f"invalid approver registry entry {name!r}")
        try:
            entry = ApproverEntry.model_validate(raw)
        except ValueError as exc:
            raise SecurityError(f"invalid approver registry entry {approver!r}: {exc}") from exc
        entries[approver] = entry
        materials: dict[str, str] = {}
        if entry.public_keys:
            materials.update({str(k).strip(): str(v) for k, v in entry.public_keys.items()})
        if entry.public_key:
            materials.setdefault("default", entry.public_key)
        if materials:
            keys[approver] = PublicKeySet(
                {kid: load_public_key(value, None) for kid, value in materials.items()}
            )
    if strict and not entries:
        raise SecurityError("AGENT_STRICT_PROD requires at least one approver")
    return ApproverRegistry(
        entries, keys, source=source, signature_kid=kid, digest=digest
    )


# -- approval credentials ----------------------------------------------------

def approval_credential_payload(
    req: ApprovalRequest, *, approved: bool, approver: str
) -> bytes:
    """Exact bytes a human signs for a detached approval credential.

    Exposed by ``python -m agents approval-payload`` so a signer never has to
    guess the canonical shape. The verifier recomputes it from the stored
    approval record, so a credential cannot be replayed for a different
    approval, target, mission or decision.
    """
    return canonical(
        {
            "scope": CREDENTIAL_SCOPE,
            "approval_id": req.id,
            "action_class": req.action_class.value,
            "target": req.target,
            "risk": req.risk.value,
            "mission_id": req.mission_id,
            "requested_by": req.requested_by,
            "decided_by": str(approver).strip(),
            "approved": bool(approved),
        }
    )


class ApprovalVerifier:
    """Callable verifier for ``ApprovalStore(approver_verifier=...)``."""

    def __init__(
        self,
        registry: ApproverRegistry | None,
        *,
        mode: str = "either",
        require_credential: bool = False,
        oidc: OIDCConfig | None = None,
    ) -> None:
        if mode not in ("detached", "oidc", "either"):
            raise SecurityError(f"unknown approval credential mode {mode!r}")
        self.registry = registry
        self.mode = mode
        self.require_credential = require_credential
        self.oidc = oidc

    def _verification(
        self,
        *,
        name: str,
        method: str,
        entry: ApproverEntry | None,
        detail: str = "",
        kid: str | None = None,
        fingerprint_value: str | None = None,
        subject: str | None = None,
        verified: bool = True,
    ) -> ApprovalVerification:
        return ApprovalVerification(
            verified=verified,
            method=method,  # type: ignore[arg-type]
            approver_id=name,
            role=entry.role if entry else None,
            max_tier=entry.max_tier if entry else None,
            kid=kid,
            fingerprint=fingerprint_value,
            subject=subject,
            detail=detail,
        )

    def _fail(
        self, name: str, method: str, detail: str, entry: ApproverEntry | None = None
    ) -> ApprovalVerification:
        return self._verification(
            name=name, method=method, entry=entry, detail=detail, verified=False
        )

    def __call__(self, name: str, req: ApprovalRequest) -> ApprovalVerification:
        approver = str(name).strip()
        credential = req.credential
        entry = self.registry.get(approver) if self.registry else None

        if self.registry is not None and entry is None:
            return self._fail(approver, "detached", "approver is not in the signed registry")
        if credential is None:
            if self.require_credential:
                return self._fail(
                    approver, "detached", "a detached signature or id_token is required"
                )
            return self._verification(
                name=approver,
                method="none",
                entry=entry,
                detail="no credential required in this configuration",
            )

        if credential.kind == "detached":
            if self.mode not in ("detached", "either"):
                return self._fail(approver, "detached", "detached signatures are disabled")
            if not credential.signature:
                return self._fail(approver, "detached", "detached signature is missing")
            if self.registry is None:
                return self._fail(
                    approver, "detached", "no signed approver registry is configured"
                )
            data = approval_credential_payload(
                req,
                approved=req.status.value == "approved",
                approver=approver,
            )
            ok, kid, fp = self.registry.verify_detached(
                approver, data, credential.signature
            )
            if not ok:
                return self._fail(approver, "detached", "detached signature verification failed", entry)
            return self._verification(
                name=approver,
                method="detached",
                entry=entry,
                kid=kid,
                fingerprint_value=fp,
                detail="verified against the signed approver registry",
            )

        if self.mode not in ("oidc", "either"):
            return self._fail(approver, "oidc", "OIDC id_tokens are disabled")
        if not credential.id_token:
            return self._fail(approver, "oidc", "OIDC id_token is missing")
        if self.oidc is None:
            return self._fail(approver, "oidc", "OIDC issuer/JWKS is not configured")
        try:
            claims = verify_id_token(credential.id_token, self.oidc)
        except SecurityError as exc:
            return self._fail(approver, "oidc", str(exc), entry)
        subject = str(claims.get(self.oidc.sub_claim, ""))
        if subject != approver:
            return self._fail(
                approver, "oidc", f"id_token subject {subject!r} does not match approver", entry
            )
        if self.oidc.role_claim and entry:
            roles = claims.get(self.oidc.role_claim)
            roles = roles if isinstance(roles, list) else [roles]
            if entry.role not in roles:
                return self._fail(
                    approver, "oidc", f"id_token lacks required role {entry.role!r}", entry
                )
        return self._verification(
            name=approver,
            method="oidc",
            entry=entry,
            subject=subject,
            detail=f"verified id_token from {self.oidc.issuer}",
        )


def build_approval_verifier(
    settings: Any, registry: ApproverRegistry | None
) -> ApprovalVerifier | None:
    """Build the verifier used by both the mesh and the decision CLI."""
    from .security import SecurityError as _SecurityError

    mode = str(getattr(settings, "approval_credential_mode", "either") or "either")
    issuer = getattr(settings, "approval_oidc_issuer", None)
    audience = getattr(settings, "approval_oidc_audience", None)
    jwks_url = getattr(settings, "approval_oidc_jwks_url", None)
    strict = bool(getattr(settings, "strict_prod", False))
    if strict and not (registry is not None and registry.signature_kid):
        raise _SecurityError(
            "AGENT_STRICT_PROD requires a detached-signature-verified approver registry"
        )
    oidc: OIDCConfig | None = None
    if issuer or audience or jwks_url:
        if not (issuer and audience and jwks_url):
            raise _SecurityError(
                "OIDC verification requires issuer, audience and JWKS URL"
            )
        oidc = OIDCConfig(
            issuer=str(issuer),
            audience=str(audience),
            jwks_url=str(jwks_url),
            sub_claim=str(getattr(settings, "approval_oidc_sub_claim", "sub") or "sub"),
            role_claim=getattr(settings, "approval_oidc_role_claim", None),
            leeway_s=int(getattr(settings, "approval_oidc_leeway_s", 60) or 0),
            timeout_s=float(getattr(settings, "approval_oidc_timeout_s", 5.0)),
        )
    elif mode == "oidc":
        raise _SecurityError("AGENT_APPROVAL_CREDENTIAL_MODE=oidc requires OIDC settings")
    require_credential = bool(
        getattr(settings, "approval_require_credential", False) or strict
    )
    return ApprovalVerifier(
        registry, mode=mode, require_credential=require_credential, oidc=oidc
    )


def validate_strict_prod(settings: Any) -> list[str]:
    """Return every reason this configuration is unfit for strict production."""
    problems: list[str] = []
    if not getattr(settings, "message_auth", True):
        problems.append("AGENT_MESSAGE_AUTH must be enabled")
    mode = str(getattr(settings, "signing_mode", "hmac") or "hmac").lower()
    if mode != "ed25519":
        problems.append("AGENT_SIGNING_MODE=ed25519 is required")
    if is_ephemeral_secret(settings):
        problems.append("bus/approval signing uses an ephemeral secret")
    if not uses_managed_secrets(settings):
        problems.append("key material must come from mounted files or KMS")
    if not (
        getattr(settings, "bus_public_keys_file", None)
        or getattr(settings, "bus_public_keys", None)
    ):
        problems.append("AGENT_BUS_PUBLIC_KEYS_FILE is required")
    elif getattr(settings, "strict_prod", False) and not getattr(
        settings, "bus_public_keys_file", None
    ):
        problems.append("inline AGENT_BUS_PUBLIC_KEYS is not allowed in strict mode")
    if not getattr(settings, "approver_registry_file", None):
        problems.append("AGENT_APPROVER_REGISTRY_FILE is required")
    if not (
        getattr(settings, "approver_registry_public_keys_file", None)
        or getattr(settings, "approver_registry_public_key_file", None)
    ):
        problems.append("AGENT_APPROVER_REGISTRY_PUBLIC_KEY_FILE is required")
    if not getattr(settings, "approver_registry_signature_file", None):
        problems.append("AGENT_APPROVER_REGISTRY_SIGNATURE_FILE is required")
    return problems
