"""Connector tests: read-only boundaries, normalization and fault isolation."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from agents.config import Settings
from agents.connectors import (
    ConnectorConfigError,
    ConnectorDataError,
    EntityType,
    FieldMap,
    HttpJsonConnector,
    JsonlConnector,
    MappingAdapter,
    Provenance,
    Severity,
    SourceType,
    build_fixture_connectors,
    ingest_connectors,
    load_connectors,
)
from agents.contracts import Classification

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "fragmentation"


def settings(**overrides) -> Settings:
    params = dict(
        log_level="CRITICAL",
        connector_allowed_hosts="",
        connector_max_records=100,
        connector_max_bytes=1_000_000,
    )
    params.update(overrides)
    return Settings(**params)


def provenance(name: str = "test") -> Provenance:
    return Provenance(
        connector=name,
        location="fixture.jsonl",
        fetched_at=datetime.now(timezone.utc),
    )


def test_mapping_adapter_normalizes_and_redacts() -> None:
    adapter = MappingAdapter()
    signal = adapter.adapt(
        {
            "id": "evt-1",
            "timestamp": "2026-11-14T11:00:00Z",
            "host": "EDGE-02.",
            "aliases": ["i-0abc123", "EDGE-02"],
            "severity": "P1",
            "category": "c2_beacon",
            "title": "beacon",
            "access_token": "super-secret",
            "max_tokens": 4096,
        },
        source="soc",
        source_type=SourceType.SOC,
        provenance=provenance("soc"),
    )

    assert signal.entity == "edge-02"
    assert "i-0abc123" in signal.aliases
    assert "edge-02" in signal.aliases
    assert signal.severity is Severity.CRITICAL
    assert signal.external_id == "evt-1"
    assert signal.observed_at.tzinfo is timezone.utc
    assert signal.attributes["access_token"] == "***"
    assert signal.attributes["max_tokens"] == 4096
    assert len(signal.fingerprint) == 32
    assert signal.classification is Classification.INTERNAL


def test_mapping_adapter_rejects_record_without_entity() -> None:
    with pytest.raises(ConnectorDataError):
        MappingAdapter().adapt(
            {"id": "x", "title": "no entity"},
            source="soc",
            source_type=SourceType.SOC,
            provenance=provenance("soc"),
        )


def test_mapping_adapter_supports_dotted_paths_and_defaults() -> None:
    adapter = MappingAdapter(
        FieldMap(
            entity=["asset.hostname"],
            severity=["risk.score"],
            default_category="finding",
            default_entity_type=EntityType.HOST,
        )
    )
    signal = adapter.adapt(
        {"asset": {"hostname": "db-01"}, "risk": {"score": 9.4}},
        source="vuln",
        source_type=SourceType.VULNERABILITY,
        provenance=provenance("vuln"),
    )
    assert signal.entity == "db-01"
    assert signal.severity is Severity.CRITICAL
    assert signal.category == "finding"
    assert signal.entity_type is EntityType.HOST


def test_jsonl_connector_is_confined_to_its_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.jsonl"
    outside.write_text('{"entity": "edge-01"}\n', encoding="utf-8")

    with pytest.raises(ConnectorConfigError):
        JsonlConnector(
            name="obs",
            source_type=SourceType.OBSERVABILITY,
            path=outside,
            root=root,
        )


def test_jsonl_connector_reports_bad_lines_without_stopping(tmp_path: Path) -> None:
    path = tmp_path / "obs.jsonl"
    path.write_text(
        '{"id": "1", "entity": "edge-01", "severity": "high", "title": "ok"}\n'
        "not json\n"
        '{"id": "2", "title": "missing entity"}\n'
        '{"id": "3", "entity": "edge-02", "severity": "low", "title": "ok"}\n',
        encoding="utf-8",
    )
    connector = JsonlConnector(
        name="obs",
        source_type=SourceType.OBSERVABILITY,
        path="obs.jsonl",
        root=tmp_path,
    )
    batch = asyncio.run(connector.fetch())
    assert [s.entity for s in batch.signals] == ["edge-01", "edge-02"]
    assert len(batch.errors) == 2


def test_jsonl_connector_keeps_good_records_when_one_exceeds_schema_limits(tmp_path: Path) -> None:
    """A Pydantic ValidationError on one record must not drop the whole batch."""
    path = tmp_path / "obs.jsonl"
    too_many_tags = json.dumps(
        {"id": "2", "entity": "edge-bad", "severity": "high", "title": "many tags", "tags": [f"t{i}" for i in range(21)]}
    )
    path.write_text(
        '{"id": "1", "entity": "edge-ok", "severity": "low", "title": "fine"}\n'
        + too_many_tags
        + "\n"
        '{"id": "3", "entity": "edge-ok2", "severity": "low", "title": "fine"}\n',
        encoding="utf-8",
    )
    connector = JsonlConnector(
        name="obs",
        source_type=SourceType.OBSERVABILITY,
        path="obs.jsonl",
        root=tmp_path,
    )
    batch = asyncio.run(connector.fetch())
    assert [s.entity for s in batch.signals] == ["edge-ok", "edge-ok2"]
    assert len(batch.errors) == 1


def test_http_connector_refuses_plain_http_off_loopback() -> None:
    with pytest.raises(ConnectorConfigError):
        HttpJsonConnector(
            name="vuln",
            source_type=SourceType.VULNERABILITY,
            url="http://vulnerability.example.com/findings",
            allowed_hosts=["vulnerability.example.com"],
        )


def test_http_connector_requires_allowlist_and_https() -> None:
    with pytest.raises(ConnectorConfigError):
        HttpJsonConnector(
            name="vuln",
            source_type=SourceType.VULNERABILITY,
            url="https://vulnerability.example.com/findings",
            allowed_hosts=[],
        )
    with pytest.raises(ConnectorConfigError):
        HttpJsonConnector(
            name="vuln",
            source_type=SourceType.VULNERABILITY,
            url="https://other.example.com/findings",
            allowed_hosts=["vulnerability.example.com"],
        )
    with pytest.raises(ConnectorConfigError):
        HttpJsonConnector(
            name="vuln",
            source_type=SourceType.VULNERABILITY,
            url="https://user:pass@vulnerability.example.com/findings",
            allowed_hosts=["vulnerability.example.com"],
        )


def test_http_connector_allows_loopback_http() -> None:
    connector = HttpJsonConnector(
        name="local",
        source_type=SourceType.SOC,
        url="http://127.0.0.1:9000/alerts",
        allowed_hosts=["127.0.0.1"],
        allow_http_loopback=True,
    )
    assert connector.host == "127.0.0.1"
    assert connector.describe()["type"] == "HttpJsonConnector"


def test_jira_basic_auth_and_empty_page(monkeypatch) -> None:
    import base64
    from agents import connectors as module

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, size):
            return b'{"issues":[]}'

    class Opener:
        def open(self, request, timeout):
            assert request.get_method() == "GET"
            assert request.get_header("Authorization") == "Basic " + base64.b64encode(
                b"operator@example.com:test-token"
            ).decode()
            return Response()

    monkeypatch.setattr(module, "build_opener", lambda *args: Opener())
    connector = HttpJsonConnector(
        name="jira_cloud",
        source_type=SourceType.WORKFLOW,
        url="https://example.atlassian.net/rest/api/3/search/jql",
        allowed_hosts=["example.atlassian.net"],
        basic_user="operator@example.com",
        token="test-token",
        records_path="issues",
    )
    batch = asyncio.run(connector.fetch())
    assert not batch.errors
    assert not batch.signals
    assert "test-token" not in str(connector.describe())


def test_basic_auth_refuses_http():
    with pytest.raises(ConnectorConfigError):
        HttpJsonConnector(
            name="jira_cloud", source_type=SourceType.WORKFLOW,
            url="http://127.0.0.1:9000/", allowed_hosts=["127.0.0.1"],
            basic_user="user", token="token",
        )


def test_jira_config_loads_with_credentials(monkeypatch):
    monkeypatch.setenv("JIRA_EMAIL", "operator@example.com")
    monkeypatch.setenv("JIRA_API_TOKEN", "test-token")
    connector = load_connectors(ROOT / "connectors.yaml", settings=settings())[0]
    assert connector.host == "lyfe3493.atlassian.net"


def test_ingest_isolates_a_broken_connector(tmp_path: Path) -> None:
    good = tmp_path / "good.jsonl"
    good.write_text('{"id": "1", "entity": "edge-01", "title": "ok"}\n', encoding="utf-8")
    connectors = [
        JsonlConnector(
            name="good",
            source_type=SourceType.OBSERVABILITY,
            path="good.jsonl",
            root=tmp_path,
        ),
        JsonlConnector(
            name="missing",
            source_type=SourceType.SOC,
            path="missing.jsonl",
            root=tmp_path,
        ),
    ]
    result = asyncio.run(ingest_connectors(connectors, timeout_s=5))
    assert len(result.signals) == 1
    assert any("missing" in error for error in result.errors)
    assert result.counts_by_source == {"good": 1}


def test_load_connectors_yaml(tmp_path: Path) -> None:
    (tmp_path / "obs.jsonl").write_text(
        '{"id": "1", "entity": "edge-01", "title": "ok"}\n', encoding="utf-8"
    )
    config = tmp_path / "connectors.yaml"
    config.write_text(
        "connectors:\n"
        "  - name: obs\n"
        "    type: jsonl\n"
        "    source_type: observability\n"
        "    path: obs.jsonl\n"
        "  - name: disabled\n"
        "    type: jsonl\n"
        "    source_type: soc\n"
        "    path: obs.jsonl\n"
        "    enabled: false\n",
        encoding="utf-8",
    )
    connectors = load_connectors(config, settings=settings())
    assert [c.name for c in connectors] == ["obs"]


def test_load_connectors_rejects_duplicates_and_missing_tokens(tmp_path: Path) -> None:
    config = tmp_path / "connectors.yaml"
    config.write_text(
        "connectors:\n"
        "  - name: dup\n"
        "    type: jsonl\n"
        "    source_type: observability\n"
        "    path: obs.jsonl\n"
        "  - name: dup\n"
        "    type: jsonl\n"
        "    source_type: soc\n"
        "    path: obs.jsonl\n",
        encoding="utf-8",
    )
    with pytest.raises(ConnectorConfigError):
        load_connectors(config, settings=settings())

    config.write_text(
        "connectors:\n"
        "  - name: api\n"
        "    type: http_json\n"
        "    source_type: vulnerability\n"
        "    url: https://vulnerability.example.com/findings\n"
        "    token_env: USOC_TEST_UNSET_TOKEN\n"
        "    allowed_hosts: [vulnerability.example.com]\n",
        encoding="utf-8",
    )
    with pytest.raises(ConnectorConfigError):
        load_connectors(config, settings=settings())


def test_fixture_connectors_cover_the_incumbent_categories() -> None:
    connectors = build_fixture_connectors(settings(), FIXTURES)
    result = asyncio.run(ingest_connectors(connectors, timeout_s=5))
    assert not result.errors
    assert len(connectors) == 11
    assert {
        "observability",
        "cloud_cost",
        "vulnerability",
        "soc",
        "identity",
        "network",
        "infrastructure",
        "workflow_ticketing",
        "backup_recovery",
        "incident_response",
        "cyber_training",
    } <= set(result.counts_by_source_type)
    assert len(result.signals) == 15


def test_signal_serializes_round_trip() -> None:
    adapter = MappingAdapter()
    signal = adapter.adapt(
        {"id": "1", "entity": "edge-01", "title": "ok"},
        source="obs",
        source_type=SourceType.OBSERVABILITY,
        provenance=provenance("obs"),
    )
    payload = json.loads(signal.model_dump_json())
    assert payload["fingerprint"] == signal.fingerprint
    assert payload["source_type"] == "observability"
