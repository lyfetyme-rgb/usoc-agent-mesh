"""Opt-in Atlassian publishing bridge for governed HITL decisions.

OEKP and HITL normally keep their records inside the mesh. This module is the
one place where a *decided* approval can be published outward as:

* a signed ADR + evidence-bundle envelope, stored as a Confluence page, and
* a JSM request recording the same decision.

Publication is deliberately approval-gated: :func:`publish_decision` requires
an already-decided :class:`~agents.governance.ApprovalRequest`, so no AI
recommendation or pending approval can create an external record. The whole
envelope is signed with the mesh signer under its own scope, which lets a reader
verify that the published ADR is the one the mesh decided.

Nothing happens unless ``AGENT_ATLASSIAN_BRIDGE_ENABLED=true`` and complete
configuration is present. Credentials come from env or a mounted file; they are
never stored in config. HTTP calls are injected as a transport so tests never
touch the network.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

from pydantic import BaseModel, ConfigDict, Field

from .governance import ApprovalRequest
from .security import (
    SecurityError,
    canonical,
    exclusive_lock,
    read_secret,
    secure_dir,
    secure_file,
)

PUBLICATION_SCOPE = "atlassian-publication"


class PublicationEnvelope(BaseModel):
    """Signed, self-contained record of one HITL decision."""

    model_config = ConfigDict(extra="forbid")

    version: int = 1
    kind: str = "usoc.adr"
    approval_id: str
    decision: str
    decided_by: str | None = None
    decided_at: str | None = None
    action_class: str
    target: str
    mission_id: str | None = None
    tainted: bool = False
    provenance: list[str] = []
    approval_record: dict[str, Any]
    evidence_head: dict[str, Any]
    adr_markdown: str
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    signature: str | None = None

    def body(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"signature"})


class PublicationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    page_id: str | None = None
    page_url: str | None = None
    jsm_key: str | None = None
    idempotent: bool = False


class HttpTransport(Protocol):
    def __call__(
        self,
        method: str,
        url: str,
        payload: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> tuple[int, Any]: ...


def render_adr(approval: ApprovalRequest, evidence_head: dict[str, Any]) -> str:
    """Render the decision as a compact, human-readable ADR."""
    taint = (
        "YES — upstream provenance was tainted; the approver saw this disclosure."
        if approval.tainted
        else "no"
    )
    provenance = ", ".join(approval.provenance) or "none disclosed"
    lines = [
        "# USOC decision record",
        "",
        f"- **Status**: {approval.status.value.upper()}",
        f"- **Approval**: {approval.id}",
        f"- **Decision by**: {approval.decided_by or 'unknown'}",
        f"- **Decided at**: {approval.decided_at or 'unknown'}",
        f"- **Action**: {approval.action_class.value} on {approval.target!r}",
        f"- **Risk**: {approval.risk.value}",
        f"- **Mission**: {approval.mission_id or 'none'}",
        f"- **Tainted**: {taint}",
        f"- **Provenance**: {provenance}",
        "",
        "## Justification",
        "",
        approval.justification or "No justification was recorded.",
        "",
        "## Approver note",
        "",
        approval.note or "No note was recorded.",
        "",
        "## Evidence bundle",
        "",
        f"- **Chain head**: seq={evidence_head.get('seq')} hash={evidence_head.get('hash')}",
        "",
        "This record is accompanied by a mesh-signed envelope covering the exact "
        "approval record, evidence head and this ADR text.",
    ]
    return "\n".join(lines)


def build_publication_envelope(
    approval: ApprovalRequest,
    evidence_head: dict[str, Any],
    signer: Any,
    *,
    adr_markdown: str | None = None,
) -> PublicationEnvelope:
    """Build and sign a publication envelope, failing on a pending decision."""
    if approval.status.value not in ("approved", "denied"):
        raise SecurityError("only decided approvals may be published")
    if not approval.decided_by or not approval.decided_at:
        raise SecurityError("decided approval is missing approver identity or time")
    if signer is None:
        raise SecurityError("an Ed25519/HMAC signer is required to publish ADRs")
    envelope = PublicationEnvelope(
        approval_id=approval.id,
        decision=approval.status.value,
        decided_by=approval.decided_by,
        decided_at=approval.decided_at.isoformat() if approval.decided_at else None,
        action_class=approval.action_class.value,
        target=approval.target,
        mission_id=approval.mission_id,
        tainted=approval.tainted,
        provenance=list(approval.provenance),
        approval_record=approval.model_dump(mode="json"),
        evidence_head=dict(evidence_head),
        adr_markdown=adr_markdown or render_adr(approval, evidence_head),
        created_at=approval.decided_at.isoformat() if approval.decided_at else None,
    )
    envelope.signature = signer.sign_record(PUBLICATION_SCOPE, envelope.body())
    return envelope


def verify_publication_envelope(envelope: PublicationEnvelope, signer: Any) -> bool:
    ok, _ = signer.verify_record(PUBLICATION_SCOPE, envelope.body(), envelope.signature)
    return ok


class AtlassianBridge:
    """Publish signed decisions to Confluence and (optionally) JSM."""

    def __init__(
        self,
        settings: Any,
        signer: Any,
        *,
        transport: HttpTransport | None = None,
        state_path: str | Path | None = None,
    ) -> None:
        if not getattr(settings, "atlassian_bridge_enabled", False):
            raise SecurityError("Atlassian bridge is disabled")
        base_url = str(getattr(settings, "atlassian_base_url", "") or "").strip().rstrip("/")
        if not base_url.startswith("https://"):
            raise SecurityError("AGENT_ATLASSIAN_BASE_URL must be an https:// URL")
        api_key = read_secret(
            getattr(settings, "atlassian_api_key", None),
            getattr(settings, "atlassian_api_key_file", None),
        )
        if not api_key:
            raise SecurityError(
                "AGENT_ATLASSIAN_API_KEY(_FILE) is required when the bridge is enabled"
            )
        if signer is None:
            raise SecurityError("Atlassian bridge requires a mesh signer")

        space_key = str(getattr(settings, "atlassian_confluence_space_key", "") or "").strip()
        if not space_key:
            raise SecurityError("AGENT_ATLASSIAN_CONFLUENCE_SPACE_KEY is required")

        self.jsm_enabled = bool(getattr(settings, "atlassian_jsm_enabled", False))
        self.service_desk_id = str(
            getattr(settings, "atlassian_jsm_service_desk_id", "") or ""
        ).strip()
        self.request_type_id = str(
            getattr(settings, "atlassian_jsm_request_type_id", "") or ""
        ).strip()
        if self.jsm_enabled and not (self.service_desk_id and self.request_type_id):
            raise SecurityError(
                "AGENT_ATLASSIAN_JSM_SERVICE_DESK_ID and _REQUEST_TYPE_ID are "
                "required when JSM publishing is enabled"
            )

        auth_mode = str(getattr(settings, "atlassian_auth_mode", "bearer") or "bearer").lower()
        if auth_mode == "bearer":
            auth = f"Bearer {api_key}"
        elif auth_mode == "basic":
            email = str(getattr(settings, "atlassian_email", "") or "").strip()
            if not email:
                raise SecurityError("AGENT_ATLASSIAN_EMAIL is required for Basic auth")
            auth = "Basic " + base64.b64encode(f"{email}:{api_key}".encode()).decode()
        else:
            raise SecurityError(f"unknown AGENT_ATLASSIAN_AUTH_MODE {auth_mode!r}")

        self.settings = settings
        self.signer = signer
        self.base_url = base_url
        self.space_key = space_key
        self.jira_project_key = str(
            getattr(settings, "atlassian_jira_project_key", "") or ""
        ).strip()
        self.timeout_s = float(getattr(settings, "atlassian_timeout_s", 10.0) or 10.0)
        self._headers = {
            "Authorization": auth,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self._transport = transport or self._httpx_transport()
        self.state_path = Path(
            state_path or getattr(settings, "atlassian_publish_state_file", None)
            or Path(getattr(settings, "workspace", "workspace")) / "atlassian_publish_state.json"
        )

    def _httpx_transport(self) -> HttpTransport:
        def send(method, url, payload=None, params=None):
            import httpx

            response = httpx.request(
                method,
                url,
                json=payload,
                params=params,
                headers=self._headers,
                timeout=self.timeout_s,
            )
            body = response.json() if response.content else {}
            return response.status_code, body

        return send

    def _call(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        status, body = self._transport(method, self.base_url + path, payload, params)
        if status < 200 or status >= 300:
            raise SecurityError(f"Atlassian {method} {path} failed with HTTP {status}")
        return body

    def _load_state(self) -> dict[str, Any]:
        if not self.state_path.is_file():
            return {}
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            # A corrupt state file must not cause duplicate external writes;
            # publication fails closed until an operator resolves it.
            raise SecurityError("Atlassian publish state is corrupt")
        if not isinstance(data, dict):
            raise SecurityError("Atlassian publish state is not an object")
        return data

    def _save_state(self, state: dict[str, Any]) -> None:
        secure_dir(self.state_path.parent)
        with exclusive_lock(self.state_path):
            tmp = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
            tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
            secure_file(tmp)
            tmp.replace(self.state_path)
            secure_file(self.state_path)

    @staticmethod
    def _page_title(envelope: PublicationEnvelope) -> str:
        return f"[USOC] {envelope.approval_id} — {envelope.decision.upper()}"

    @staticmethod
    def _page_body(envelope: PublicationEnvelope) -> str:
        return (
            "<h2>Decision record</h2><pre>"
            + html.escape(envelope.adr_markdown)
            + "</pre><h2>Signed envelope</h2><pre>"
            + html.escape(json.dumps(envelope.model_dump(mode="json"), indent=2))
            + "</pre>"
        )

    def _upsert_page(self, envelope: PublicationEnvelope) -> tuple[str, str]:
        title = self._page_title(envelope)
        found = self._call(
            "GET",
            "/wiki/rest/api/content",
            params={"title": title, "spaceKey": self.space_key, "limit": 1},
        )
        results = found.get("results", []) if isinstance(found, dict) else []
        if results:
            page_id = str(results[0]["id"])
            version = int(results[0].get("version", {}).get("number", 1)) + 1
            created = self._call(
                "PUT",
                f"/wiki/rest/api/content/{page_id}",
                payload={
                    "version": {"number": version},
                    "title": title,
                    "type": "page",
                    "body": {"storage": {"value": self._page_body(envelope), "representation": "storage"}},
                },
            )
        else:
            created = self._call(
                "POST",
                "/wiki/rest/api/content",
                payload={
                    "type": "page",
                    "title": title,
                    "space": {"key": self.space_key},
                    "body": {"storage": {"value": self._page_body(envelope), "representation": "storage"}},
                },
            )
            page_id = str(created["id"])
        links = (created.get("_links") if isinstance(created, dict) else None) or {}
        page_url = str(links.get("webui") or f"/spaces/{self.space_key}/pages/{page_id}")
        return page_id, page_url

    def _create_jsm_request(self, envelope: PublicationEnvelope, page_url: str) -> str:
        summary = f"[USOC] {envelope.decision.upper()} {envelope.approval_id}"
        description = (
            envelope.adr_markdown
            + f"\n\nConfluence ADR: {page_url}\n"
            + f"Signature: {envelope.signature}\n"
        )
        created = self._call(
            "POST",
            "/rest/servicedeskapi/request",
            payload={
                "serviceDeskId": self.service_desk_id,
                "requestTypeId": self.request_type_id,
                "requestFieldValues": {"summary": summary, "description": description},
            },
        )
        return str(created.get("key") or created.get("issueKey") or "")

    def publish_decision(
        self,
        approval: ApprovalRequest,
        evidence_head: dict[str, Any],
        *,
        adr_markdown: str | None = None,
    ) -> PublicationResult:
        """Publish one decided approval, idempotently."""
        envelope = build_publication_envelope(
            approval, evidence_head, self.signer, adr_markdown=adr_markdown
        )
        key = hashlib.sha256(
            (envelope.signature or canonical(envelope.body())).encode("utf-8")
        ).hexdigest()
        state = self._load_state()
        if key in state:
            saved = state[key]
            return PublicationResult(
                page_id=saved.get("page_id"),
                page_url=saved.get("page_url"),
                jsm_key=saved.get("jsm_key"),
                idempotent=True,
            )

        page_id, page_url = self._upsert_page(envelope)
        jsm_key = (
            self._create_jsm_request(envelope, page_url) if self.jsm_enabled else None
        )
        state[key] = {"page_id": page_id, "page_url": page_url, "jsm_key": jsm_key}
        self._save_state(state)
        return PublicationResult(page_id=page_id, page_url=page_url, jsm_key=jsm_key)


def build_bridge(settings: Any, signer: Any, **kwargs: Any) -> AtlassianBridge | None:
    """Return a bridge when enabled, otherwise ``None`` (no external writes)."""
    if not getattr(settings, "atlassian_bridge_enabled", False):
        return None
    return AtlassianBridge(settings, signer, **kwargs)
