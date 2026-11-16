"""Approval-gated Atlassian publishing: signed ADRs, evidence bundles, JSM."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

import pytest

from agents.atlassian_bridge import (
    AtlassianBridge,
    build_bridge,
    build_publication_envelope,
    render_adr,
    verify_publication_envelope,
)
from agents.config import Settings
from agents.contracts import ActionClass, RiskLevel
from agents.governance import ApprovalRequest, FileApprovalStore
from agents.security import SecurityError, Signer


class FakeTransport:
    def __init__(self, existing: list[dict] | None = None) -> None:
        self.calls: list[tuple] = []
        self.existing = existing or []

    def __call__(self, method, url, payload=None, params=None):
        self.calls.append((method, url, payload, params))
        if method == "GET" and "/wiki/rest/api/content" in url:
            return 200, {"results": self.existing}
        if method in ("POST", "PUT") and "/wiki/rest/api/content" in url:
            return 200, {
                "id": "778899",
                "_links": {"webui": "/spaces/SD/pages/778899"},
            }
        if method == "POST" and "/rest/servicedeskapi/request" in url:
            return 201, {"key": "SD-42"}
        raise AssertionError(f"unexpected request: {method} {url}")


def bridge_settings(tmp_path: Path, **extra) -> Settings:
    values = dict(
        atlassian_bridge_enabled=True,
        atlassian_base_url="https://testing-bay.atlassian.net",
        atlassian_api_key="service-account-key",
        atlassian_confluence_space_key="SD",
        atlassian_publish_state_file=tmp_path / "state.json",
        atlassian_jsm_enabled=True,
        atlassian_jsm_service_desk_id="1",
        atlassian_jsm_request_type_id="2",
    )
    values.update(extra)
    return Settings(**values)


def decided_approval(tmp_path: Path, signer: Signer, *, approved: bool = True):
    async def run():
        store = FileApprovalStore(
            tmp_path / "approvals.json",
            signer=signer,
            approvers={"alice"},
        )
        req = await store.request(
            ApprovalRequest(
                action_class=ActionClass.EXECUTE,
                target="sandbox/example",
                risk=RiskLevel.HIGH,
                requested_by="bob",
                justification="governed test action",
                tainted=True,
                provenance=["ACIE", "AICEE"],
            )
        )
        return await store.decide(
            req.id, approved=approved, approver="alice", note="reviewed"
        )

    return asyncio.run(run())


def test_bridge_is_opt_in(tmp_path: Path):
    signer = Signer("test-secret-that-is-long-enough-32")
    assert build_bridge(Settings(), signer) is None
    with pytest.raises(SecurityError, match="disabled"):
        AtlassianBridge(Settings(), signer)


def test_bridge_fails_closed_without_credentials_or_space(tmp_path: Path):
    signer = Signer("test-secret-that-is-long-enough-32")
    with pytest.raises(SecurityError, match="API_KEY"):
        AtlassianBridge(
            Settings(
                atlassian_bridge_enabled=True,
                atlassian_base_url="https://testing-bay.atlassian.net",
                atlassian_confluence_space_key="SD",
            ),
            signer,
        )
    with pytest.raises(SecurityError, match="SPACE_KEY"):
        AtlassianBridge(
            Settings(
                atlassian_bridge_enabled=True,
                atlassian_base_url="https://testing-bay.atlassian.net",
                atlassian_api_key="key",
            ),
            signer,
        )


def test_publish_creates_signed_adr_and_jsm_then_is_idempotent(tmp_path: Path):
    signer = Signer("test-secret-that-is-long-enough-32")
    approval = decided_approval(tmp_path, signer)
    transport = FakeTransport()
    bridge = AtlassianBridge(
        bridge_settings(tmp_path), signer, transport=transport
    )

    first = bridge.publish_decision(approval, {"seq": 7, "hash": "abc123"})
    assert first.page_id == "778899"
    assert first.jsm_key == "SD-42"
    assert first.idempotent is False
    methods = [c[0] for c in transport.calls]
    assert methods == ["GET", "POST", "POST"]

    page_payload = transport.calls[1][2]
    stored = page_payload["body"]["storage"]["value"]
    assert "USOC decision record" in stored
    assert approval.id in stored
    assert "atlassian-publication" not in stored  # scope is signed, not displayed
    assert "&quot;signature&quot;" in stored

    second = bridge.publish_decision(approval, {"seq": 7, "hash": "abc123"})
    assert second.idempotent is True
    assert len(transport.calls) == 3

    state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    assert len(state) == 1


def test_envelope_signature_covers_adr_and_evidence_head(tmp_path: Path):
    signer = Signer("test-secret-that-is-long-enough-32")
    approval = decided_approval(tmp_path, signer)
    envelope = build_publication_envelope(
        approval, {"seq": 7, "hash": "abc123"}, signer
    )
    assert verify_publication_envelope(envelope, signer)

    tampered = envelope.model_copy(
        update={"adr_markdown": envelope.adr_markdown + "\nforged"}
    )
    assert not verify_publication_envelope(tampered, signer)
    assert "tainted" in render_adr(approval, {"seq": 7, "hash": "abc123"}).lower()


def test_pending_approval_cannot_be_published(tmp_path: Path):
    signer = Signer("test-secret-that-is-long-enough-32")
    pending = ApprovalRequest(
        action_class=ActionClass.EXECUTE,
        target="sandbox/example",
        risk=RiskLevel.HIGH,
        requested_by="bob",
    )
    with pytest.raises(SecurityError, match="decided"):
        build_publication_envelope(pending, {"seq": 1, "hash": "x"}, signer)


def test_jsm_disabled_skips_ticket_creation(tmp_path: Path):
    signer = Signer("test-secret-that-is-long-enough-32")
    approval = decided_approval(tmp_path, signer)
    transport = FakeTransport()
    bridge = AtlassianBridge(
        bridge_settings(tmp_path, atlassian_jsm_enabled=False),
        signer,
        transport=transport,
    )
    result = bridge.publish_decision(approval, {"seq": 1, "hash": "x"})
    assert result.jsm_key is None
    assert [c[0] for c in transport.calls] == ["GET", "POST"]


def test_publish_decision_cli_fails_cleanly_when_bridge_is_disabled(
    tmp_path: Path, capsys, monkeypatch
):
    from agents.__main__ import cmd_publish_decision
    from agents.config import get_settings

    get_settings.cache_clear()  # get_settings() is process-cached; honour the env
    monkeypatch.setenv("AGENT_SHARED_SECRET", "test-secret-that-is-long-enough-32")
    signer = Signer("test-secret-that-is-long-enough-32")
    req = decided_approval(tmp_path / "ws", signer)
    args = argparse.Namespace(
        approval_id=req.id,
        registry=None,
        workspace=str(tmp_path / "ws"),
        json_logs=False,
    )
    assert cmd_publish_decision(args) == 1
    assert "bridge is disabled" in capsys.readouterr().out


def test_existing_page_is_updated_with_a_new_version(tmp_path: Path):
    signer = Signer("test-secret-that-is-long-enough-32")
    approval = decided_approval(tmp_path, signer, approved=False)
    transport = FakeTransport(
        existing=[{"id": "556677", "version": {"number": 4}}]
    )
    bridge = AtlassianBridge(
        bridge_settings(tmp_path), signer, transport=transport
    )
    result = bridge.publish_decision(approval, {"seq": 2, "hash": "y"})
    assert result.page_id == "556677"
    put = next(c for c in transport.calls if c[0] == "PUT")
    assert put[2]["version"]["number"] == 5
