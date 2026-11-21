"""External egress control for tainted / PII-PHI data.

Connectors are read-only, but publishing a decision to Atlassian (or any other
external sink) moves governed data outside the mesh. The Clinical pack turns on
a hard rule: tainted or restricted data may not leave unless a *verified signed
human sign-off* covers the exact egress target. A plain approval name, an
unverified credential or a mismatched target never counts.
"""

from __future__ import annotations

from typing import Any, Iterable

from .contracts import Classification
from .governance import ApprovalRequest, ApprovalStatus, approval_verifications
from .security import SecurityError


class EgressError(SecurityError):
    """Raised when tainted data would leave the mesh without a signed sign-off."""


class EgressGuard:
    def __init__(self, *, block_tainted: bool = False, shadow: bool = False) -> None:
        self.block_tainted = bool(block_tainted)
        self.shadow = bool(shadow)

    @staticmethod
    def is_restricted(*, tainted: bool, classification: Classification | str) -> bool:
        return bool(tainted) or str(getattr(classification, "value", classification)).lower() in {
            "restricted",
            "phi",
            "pii",
        }

    def assert_allowed(
        self,
        *,
        target: str,
        tainted: bool = False,
        classification: Classification | str = Classification.INTERNAL,
        signoffs: Iterable[Any] = (),
        payload_digest: str | None = None,
        also_targets: Iterable[str] = (),
    ) -> None:
        """Fail closed unless a verified sign-off binds to this exact egress.

        A restricted sign-off must commit to both the destination endpoint
        (``egress_target``) and the exact decision payload (``egress_payload_digest``)
        at request time; both are covered by the approval record signature and
        by the human's detached/OIDC credential. ``also_targets`` is retained for
        callers that also name the governed action, but it never satisfies a
        restricted egress — otherwise an approval for one governed action could
        be replayed against a different external sink.
        """
        if self.shadow:
            raise EgressError("shadow mode: external egress is disabled")
        if not self.block_tainted or not self.is_restricted(
            tainted=tainted, classification=classification
        ):
            return
        for req in signoffs:
            if not isinstance(req, ApprovalRequest):
                continue
            if req.status is not ApprovalStatus.APPROVED:
                continue
            if not req.egress_target or req.egress_target != target:
                continue
            if (
                not req.egress_payload_digest
                or not payload_digest
                or req.egress_payload_digest != payload_digest
            ):
                continue
            verified = [
                v
                for v in approval_verifications(req)
                if v.verified and v.method in ("detached", "oidc")
            ]
            if verified:
                return
        raise EgressError(
            "external egress of tainted/restricted data requires a verified signed "
            f"sign-off bound to target {target!r} and the exact payload digest "
            "(use --signoff with an approved approval carrying a detached "
            "signature or id_token and matching egress binding)"
        )
