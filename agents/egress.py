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
    def __init__(self, *, block_tainted: bool = False) -> None:
        self.block_tainted = bool(block_tainted)

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
        also_targets: Iterable[str] = (),
    ) -> None:
        """Fail closed unless a verified signed sign-off covers this egress."""
        if not self.block_tainted or not self.is_restricted(
            tainted=tainted, classification=classification
        ):
            return
        for req in signoffs:
            if not isinstance(req, ApprovalRequest):
                continue
            if req.status is not ApprovalStatus.APPROVED:
                continue
            # The sign-off must name the exact egress destination (or the
            # governed action whose decision is being published). A generic
            # approval for unrelated work cannot authorize publication.
            if req.target not in {target, *also_targets}:
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
            f"sign-off for target {target!r} (use --signoff with an approved "
            "approval carrying a detached signature or id_token)"
        )
