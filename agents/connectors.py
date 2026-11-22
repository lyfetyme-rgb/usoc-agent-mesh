"""Connectors: turn incumbent tools into normalized, comparable signals.

The fragmentation problem is not solved by replacing every enterprise system.
It is solved by putting one operational-intelligence layer above them. This
module is the ingestion edge of that layer.

A connector is **read-only by contract**. It fetches data from one incumbent
system and maps it to ``Signal`` records. It never executes a change, never
follows a redirect to another host, and never lets one broken source stop the
others.

Security boundaries
-------------------
* JSONL paths are confined to a configured root; absolute paths outside it are
  refused.
* HTTP is GET-only, HTTPS by default, requires a host allowlist, refuses
  redirects, caps response size and enforces a timeout.
* Tokens come from the environment, never from YAML or an evidence record.
* Raw payloads are untrusted data, never instructions. Sensitive keys are
  redacted before a signal is stored or audited.

Adding a source means adding a mapping, not changing the mesh.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import json
import os
import re
from abc import ABC, abstractmethod
from collections import Counter
from datetime import datetime, timezone
from enum import Enum
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Iterable, Literal
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .config import Settings
from .contracts import Classification
from .security import detect_sensitive_data, redact_fields

MAX_ATTRIBUTES_BYTES = 16 * 1024
MAX_DETAIL_CHARS = 8_000
NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")


# ---------------------------------------------------------------------------
# normalized signal contract
# ---------------------------------------------------------------------------
class SourceType(str, Enum):
    """The incumbent system a signal came from.

    These are the eleven categories in the fragmentation problem statement.
    ``OTHER`` exists for a home-grown source that does not fit yet.
    """

    OBSERVABILITY = "observability"
    CLOUD_COST = "cloud_cost"
    VULNERABILITY = "vulnerability"
    SOC = "soc"
    INFRASTRUCTURE = "infrastructure"
    NETWORK = "network"
    IDENTITY = "identity"
    INCIDENT_RESPONSE = "incident_response"
    BACKUP_RECOVERY = "backup_recovery"
    CYBER_TRAINING = "cyber_training"
    WORKFLOW = "workflow_ticketing"
    OTHER = "other"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EntityType(str, Enum):
    HOST = "host"
    SERVICE = "service"
    ACCOUNT = "account"
    USER = "user"
    NETWORK = "network"
    CLOUD_ACCOUNT = "cloud_account"
    WORKLOAD = "workload"
    TICKET = "ticket"
    OTHER = "other"


class ConnectorError(RuntimeError):
    """Base class for connector configuration and data failures."""


class ConnectorConfigError(ConnectorError):
    """The connector cannot be built safely from its configuration."""


class ConnectorDataError(ConnectorError):
    """A record could not be normalized; it is skipped and counted."""


class Provenance(BaseModel):
    """Where a signal came from, without storing the raw payload or credentials."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    connector: str = Field(min_length=1, max_length=64)
    location: str = Field(min_length=1, max_length=1_000)
    fetched_at: datetime
    content_sha256: str | None = Field(default=None, max_length=64)
    raw_hash: str | None = Field(default=None, max_length=64)
    record_index: int | None = Field(default=None, ge=0)

    @field_validator("fetched_at")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return _as_utc(value)


class Signal(BaseModel):
    """One normalized observation from one incumbent system.

    The schema is deliberately narrow. Every field the correlation engine needs
    is explicit; everything source-specific goes in ``attributes`` so the
    engine never has to know a vendor's JSON shape.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(default_factory=lambda: _hash_id("sig"))
    source: str = Field(min_length=1, max_length=64)
    source_type: SourceType
    external_id: str | None = Field(default=None, max_length=200)
    observed_at: datetime
    entity: str = Field(min_length=1, max_length=200)
    entity_type: EntityType = EntityType.OTHER
    aliases: list[str] = Field(default_factory=list, max_length=20)
    category: str = Field(min_length=1, max_length=100)
    severity: Severity = Severity.MEDIUM
    title: str = Field(min_length=1, max_length=500)
    detail: str = Field(default="", max_length=MAX_DETAIL_CHARS)
    attributes: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list, max_length=20)
    classification: Classification = Classification.INTERNAL
    # Clinical pack: PII/PHI detected in this record. A positive label forces
    # taint propagation and restricted classification on every downstream step.
    sensitive_labels: list[str] = Field(default_factory=list, max_length=12)
    tainted: bool = False
    provenance: Provenance
    fingerprint: str = Field(default="", max_length=64)

    @field_validator("source")
    @classmethod
    def _source_name(cls, value: str) -> str:
        if not NAME_PATTERN.match(value):
            raise ValueError("source must match ^[a-z][a-z0-9_.-]{1,63}$")
        return value

    @field_validator("entity")
    @classmethod
    def _entity(cls, value: str) -> str:
        cleaned = canonical_entity(value)
        if not cleaned:
            raise ValueError("entity must not be empty")
        return cleaned

    @field_validator("aliases")
    @classmethod
    def _aliases(cls, value: list[str]) -> list[str]:
        return _dedupe([canonical_entity(v) for v in value if canonical_entity(v)])[:20]

    @field_validator("observed_at")
    @classmethod
    def _observed_utc(cls, value: datetime) -> datetime:
        return _as_utc(value)

    @field_validator("attributes")
    @classmethod
    def _bounded_attributes(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _bounded_attributes(value)

    def model_post_init(self, __context: Any) -> None:
        # ``model_post_init`` keeps the fingerprint deterministic while respecting
        # the frozen model: a validator that returns a copy breaks nested validation.
        if self.fingerprint:
            return
        material = "|".join(
            [
                self.source,
                self.external_id or "",
                self.entity,
                self.category,
                self.title,
                self.observed_at.isoformat(),
            ]
        )
        object.__setattr__(
            self,
            "fingerprint",
            hashlib.sha256(material.encode("utf-8")).hexdigest()[:32],
        )


class ConnectorBatch(BaseModel):
    """The result of polling one connector. A broken source is reported, not fatal."""

    model_config = ConfigDict(extra="forbid")

    connector: str
    source_type: SourceType
    signals: list[Signal] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    fetched_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    truncated: bool = False


class IngestResult(BaseModel):
    """Normalized output of one ingestion wave across every enabled connector."""

    model_config = ConfigDict(extra="forbid")

    signals: list[Signal] = Field(default_factory=list)
    batches: list[ConnectorBatch] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    fetched_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def counts_by_source(self) -> dict[str, int]:
        return dict(sorted(Counter(s.source for s in self.signals).items()))

    @property
    def counts_by_source_type(self) -> dict[str, int]:
        return dict(sorted(Counter(s.source_type.value for s in self.signals).items()))

    @property
    def truncated_sources(self) -> list[str]:
        return [b.connector for b in self.batches if b.truncated]


# ---------------------------------------------------------------------------
# mapping raw vendor JSON to a Signal
# ---------------------------------------------------------------------------
DEFAULT_EXTERNAL_ID = ["id", "external_id", "event_id", "alert_id", "incident_id", "cve", "ticket_id"]
DEFAULT_TIMESTAMP = ["timestamp", "ts", "observed_at", "time", "created_at", "first_seen", "last_seen"]
DEFAULT_ENTITY = [
    "entity",
    "host",
    "hostname",
    "node",
    "resource",
    "resource_id",
    "asset",
    "service",
    "account",
    "user",
    "cmdb_ci",
    "target",
]
DEFAULT_ENTITY_TYPE = ["entity_type", "asset_type", "resource_type"]
DEFAULT_CATEGORY = ["category", "type", "event_type", "signal_type", "kind"]
DEFAULT_SEVERITY = ["severity", "priority", "risk", "level", "urgency"]
DEFAULT_TITLE = ["title", "name", "message", "summary", "description", "alert", "rule_name"]
DEFAULT_DETAIL = ["detail", "details", "description", "message", "body", "notes"]
DEFAULT_ALIASES = ["aliases", "alias", "also_known_as", "fqdn", "instance_id"]
DEFAULT_TAGS = ["tags", "labels", "tag"]


class FieldMap(BaseModel):
    """Vendor field aliases. Dotted paths are supported (``resource.instance_id``)."""

    model_config = ConfigDict(extra="forbid")

    external_id: list[str] = Field(default_factory=lambda: list(DEFAULT_EXTERNAL_ID))
    timestamp: list[str] = Field(default_factory=lambda: list(DEFAULT_TIMESTAMP))
    entity: list[str] = Field(default_factory=lambda: list(DEFAULT_ENTITY))
    entity_type: list[str] = Field(default_factory=lambda: list(DEFAULT_ENTITY_TYPE))
    category: list[str] = Field(default_factory=lambda: list(DEFAULT_CATEGORY))
    severity: list[str] = Field(default_factory=lambda: list(DEFAULT_SEVERITY))
    title: list[str] = Field(default_factory=lambda: list(DEFAULT_TITLE))
    detail: list[str] = Field(default_factory=lambda: list(DEFAULT_DETAIL))
    aliases: list[str] = Field(default_factory=lambda: list(DEFAULT_ALIASES))
    tags: list[str] = Field(default_factory=lambda: list(DEFAULT_TAGS))
    attributes: list[str] = Field(
        default_factory=list,
        description="Extra fields to copy. Empty means copy every unmapped field.",
    )
    default_entity: str | None = Field(default=None, max_length=200)
    default_category: str | None = Field(default=None, max_length=100)
    default_severity: Severity = Severity.MEDIUM
    default_entity_type: EntityType = EntityType.OTHER

    @property
    def mapped_keys(self) -> set[str]:
        keys: set[str] = set()
        for names in (
            self.external_id,
            self.timestamp,
            self.entity,
            self.entity_type,
            self.category,
            self.severity,
            self.title,
            self.detail,
            self.aliases,
            self.tags,
        ):
            keys.update(n.split(".")[-1] for n in names)
        return keys


class MappingAdapter:
    """Deterministic adapter from a vendor record to the normalized schema."""

    def __init__(
        self,
        field_map: FieldMap | None = None,
        *,
        phi_detection_enabled: bool = False,
    ) -> None:
        self.map = field_map or FieldMap()
        self.phi_detection_enabled = bool(phi_detection_enabled)

    def adapt(
        self,
        raw: dict[str, Any],
        *,
        source: str,
        source_type: SourceType,
        provenance: Provenance,
    ) -> Signal:
        if not isinstance(raw, dict):
            raise ConnectorDataError("record is not a JSON object")

        entity_value = _first(raw, self.map.entity) or self.map.default_entity
        if not entity_value:
            raise ConnectorDataError("record has no entity/host/resource field")

        observed_at, explicit_time = _parse_timestamp(
            _first(raw, self.map.timestamp), provenance.fetched_at
        )
        severity = _parse_severity(_first(raw, self.map.severity), self.map.default_severity)
        category = _as_text(_first(raw, self.map.category)) or self.map.default_category or source_type.value
        title = _as_text(_first(raw, self.map.title)) or f"{source_type.value} signal from {source}"
        detail = _as_text(_first(raw, self.map.detail))
        external_id = _as_text(_first(raw, self.map.external_id))
        aliases = _as_list(_first(raw, self.map.aliases))
        tags = _as_list(_first(raw, self.map.tags))

        attributes = self._attributes(raw)
        if not explicit_time:
            attributes["timestamp_inferred"] = True

        entity_type = self.map.default_entity_type
        if entity_type is EntityType.OTHER:
            entity_type = _parse_entity_type(_first(raw, self.map.entity_type))

        classification = _parse_classification(_first(raw, ["classification", "data_classification"]))
        # Clinical pack: every connector is checked, not just a "health" source.
        # A positive PII/PHI label is monotone: it can raise classification and
        # set taint, but a vendor label can never lower either.
        sensitive_labels = detect_sensitive_data(
            raw, enabled=self.phi_detection_enabled
        )
        tainted = bool(sensitive_labels)
        if sensitive_labels:
            classification = Classification.RESTRICTED

        return Signal(
            source=source,
            source_type=source_type,
            external_id=external_id,
            observed_at=observed_at,
            entity=str(entity_value),
            entity_type=entity_type,
            aliases=aliases,
            category=category[:100],
            severity=severity,
            title=title[:500],
            detail=detail[:MAX_DETAIL_CHARS],
            attributes=attributes,
            tags=tags,
            classification=classification,
            sensitive_labels=sensitive_labels,
            tainted=tainted,
            provenance=provenance,
        )

    def _attributes(self, raw: dict[str, Any]) -> dict[str, Any]:
        if self.map.attributes:
            chosen = {key: _get(raw, key) for key in self.map.attributes if _get(raw, key) is not None}
        else:
            reserved = self.map.mapped_keys | {"classification", "data_classification"}
            chosen = {k: v for k, v in raw.items() if k not in reserved}
        # A connector must never turn a token or password into an audited signal.
        return _bounded_attributes(redact_fields(chosen))


# ---------------------------------------------------------------------------
# connectors
# ---------------------------------------------------------------------------
class Connector(ABC):
    """Read-only source adapter."""

    def __init__(
        self,
        *,
        name: str,
        source_type: SourceType,
        adapter: MappingAdapter | None = None,
    ) -> None:
        if not NAME_PATTERN.match(name):
            raise ConnectorConfigError(
                f"connector name {name!r} must match ^[a-z][a-z0-9_.-]{{1,63}}$"
            )
        self.name = name
        self.source_type = source_type
        self.adapter = adapter or MappingAdapter()

    @abstractmethod
    async def fetch(self) -> ConnectorBatch: ...

    async def close(self) -> None:
        return None

    def describe(self) -> dict[str, Any]:
        return {"name": self.name, "source_type": self.source_type.value, "type": type(self).__name__}


class JsonlConnector(Connector):
    """Read newline-delimited JSON from a file inside an approved root.

    This is the onboarding path for exports, log shippers and air-gapped
    environments: any tool that can drop JSONL can feed the correlation layer
    without an API integration.
    """

    def __init__(
        self,
        *,
        name: str,
        source_type: SourceType,
        path: str | Path,
        root: str | Path,
        adapter: MappingAdapter | None = None,
        max_records: int = 5_000,
        max_line_bytes: int = 256 * 1024,
    ) -> None:
        super().__init__(name=name, source_type=source_type, adapter=adapter)
        self.root = Path(root).resolve()
        candidate = Path(path)
        resolved = candidate.resolve() if candidate.is_absolute() else (self.root / candidate).resolve()
        if self.root not in resolved.parents and resolved != self.root:
            raise ConnectorConfigError(f"JSONL path escapes the connector root: {path}")
        self.path = resolved
        self.max_records = max(1, int(max_records))
        self.max_line_bytes = max(1_024, int(max_line_bytes))

    async def fetch(self) -> ConnectorBatch:
        return await asyncio.to_thread(self._fetch_sync)

    def _fetch_sync(self) -> ConnectorBatch:
        fetched_at = datetime.now(timezone.utc)
        signals: list[Signal] = []
        errors: list[str] = []
        truncated = False
        location = self._location()
        if not self.path.is_file():
            return ConnectorBatch(
                connector=self.name,
                source_type=self.source_type,
                errors=[f"file not found: {location}"],
                fetched_at=fetched_at,
            )
        with self.path.open("r", encoding="utf-8", errors="replace") as handle:
            index = 0
            for line_no, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                index += 1
                if len(signals) >= self.max_records:
                    truncated = True
                    break
                encoded = line.encode("utf-8")
                if len(encoded) > self.max_line_bytes:
                    errors.append(f"line {line_no}: exceeds {self.max_line_bytes} bytes")
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError as exc:
                    errors.append(f"line {line_no}: invalid JSON ({exc.msg})")
                    continue
                try:
                    signals.append(
                        self.adapter.adapt(
                            raw,
                            source=self.name,
                            source_type=self.source_type,
                            provenance=Provenance(
                                connector=self.name,
                                location=location,
                                fetched_at=fetched_at,
                                raw_hash=hashlib.sha256(encoded).hexdigest()[:32],
                                record_index=index,
                            ),
                        )
                    )
                except (ConnectorDataError, ValidationError) as exc:
                    # One malformed record must not discard the other good
                    # signals from this source.
                    errors.append(f"line {line_no}: {exc}")
        return ConnectorBatch(
            connector=self.name,
            source_type=self.source_type,
            signals=signals,
            errors=errors[:50],
            fetched_at=fetched_at,
            truncated=truncated,
        )

    def _location(self) -> str:
        try:
            return self.path.relative_to(self.root).as_posix()
        except ValueError:
            return self.path.name


class _NoRedirect(HTTPRedirectHandler):
    """Refuse redirects so an allowlisted host cannot bounce to another host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class HttpJsonConnector(Connector):
    """GET a JSON document from one allowlisted HTTPS endpoint.

    The connector is intentionally narrow: no writes, no arbitrary headers, no
    redirects, no unbounded reads. An incumbent API with a different shape is
    handled by a ``FieldMap``, not by code.
    """

    def __init__(
        self,
        *,
        name: str,
        source_type: SourceType,
        url: str,
        allowed_hosts: Iterable[str],
        adapter: MappingAdapter | None = None,
        token: str | None = None,
        basic_user: str | None = None,
        records_path: str | None = None,
        timeout_s: float = 15.0,
        max_bytes: int = 2_000_000,
        max_records: int = 5_000,
        allow_http_loopback: bool = True,
    ) -> None:
        super().__init__(name=name, source_type=source_type, adapter=adapter)
        self.allowed_hosts = [h.strip() for h in allowed_hosts if h and h.strip()]
        self.url = url
        self.host = _validate_http_url(url, self.allowed_hosts, allow_http_loopback)
        if basic_user and (not token or ":" in basic_user or urlsplit(url).scheme.lower() != "https"):
            raise ConnectorConfigError("Basic authentication requires HTTPS, a valid user and a token")
        self.token = token
        self.basic_user = basic_user
        self.records_path = records_path
        self.timeout_s = max(1.0, float(timeout_s))
        self.max_bytes = max(1_024, int(max_bytes))
        self.max_records = max(1, int(max_records))

    async def fetch(self) -> ConnectorBatch:
        return await asyncio.to_thread(self._fetch_sync)

    def _fetch_sync(self) -> ConnectorBatch:
        fetched_at = datetime.now(timezone.utc)
        location = _safe_url(self.url)
        headers = {"Accept": "application/json", "User-Agent": "usoc-connector/0.1"}
        if self.token:
            if self.basic_user:
                encoded = base64.b64encode(f"{self.basic_user}:{self.token}".encode()).decode()
                headers["Authorization"] = f"Basic {encoded}"
            else:
                headers["Authorization"] = f"Bearer {self.token}"
        request = Request(self.url, headers=headers, method="GET")
        opener = build_opener(_NoRedirect)
        try:
            with opener.open(request, timeout=self.timeout_s) as response:
                status = getattr(response, "status", 200)
                if not 200 <= status < 300:
                    return self._error(location, fetched_at, f"HTTP {status}")
                body = response.read(self.max_bytes + 1)
        except HTTPError as exc:
            return self._error(location, fetched_at, f"HTTP {exc.code}")
        except (URLError, TimeoutError, OSError) as exc:
            return self._error(location, fetched_at, f"request failed: {exc}")
        if len(body) > self.max_bytes:
            return self._error(location, fetched_at, f"response exceeds {self.max_bytes} bytes")
        try:
            payload = json.loads(body.decode("utf-8", "replace"))
        except json.JSONDecodeError as exc:
            return self._error(location, fetched_at, f"invalid JSON ({exc.msg})")
        try:
            records = self._extract_records(payload)
        except ConnectorDataError as exc:
            return self._error(location, fetched_at, str(exc))

        content_hash = hashlib.sha256(body).hexdigest()[:32]
        signals: list[Signal] = []
        errors: list[str] = []
        truncated = len(records) > self.max_records or (
            isinstance(payload, dict) and bool(payload.get("nextPageToken"))
        )
        for index, raw in enumerate(records[: self.max_records]):
            try:
                signals.append(
                    self.adapter.adapt(
                        raw,
                        source=self.name,
                        source_type=self.source_type,
                        provenance=Provenance(
                            connector=self.name,
                            location=location,
                            fetched_at=fetched_at,
                            content_sha256=content_hash,
                            raw_hash=hashlib.sha256(
                                json.dumps(raw, sort_keys=True, default=str).encode("utf-8")
                            ).hexdigest()[:32],
                            record_index=index,
                        ),
                    )
                )
            except (ConnectorDataError, ValidationError) as exc:
                errors.append(f"record {index}: {exc}")
        return ConnectorBatch(
            connector=self.name,
            source_type=self.source_type,
            signals=signals,
            errors=errors[:50],
            fetched_at=fetched_at,
            truncated=truncated,
        )

    def _extract_records(self, payload: Any) -> list[dict[str, Any]]:
        value: Any
        if self.records_path:
            value = _get(payload, self.records_path)
            if value is None:
                raise ConnectorDataError(f"records_path {self.records_path!r} not found")
        elif isinstance(payload, list):
            value = payload
        elif isinstance(payload, dict):
            value = None
            for key in ("items", "results", "data", "records", "alerts", "incidents", "value"):
                candidate = payload.get(key)
                if isinstance(candidate, list):
                    value = candidate
                    break
            if value is None:
                value = [payload]
        else:
            raise ConnectorDataError("response is not a JSON object or array")
        if not isinstance(value, list):
            raise ConnectorDataError("records are not a JSON array")
        records: list[dict[str, Any]] = []
        for item in value:
            if isinstance(item, dict):
                records.append(item)
        if not records and value:
            raise ConnectorDataError("response contained no JSON objects")
        return records

    def _error(self, location: str, fetched_at: datetime, message: str) -> ConnectorBatch:
        return ConnectorBatch(
            connector=self.name,
            source_type=self.source_type,
            errors=[message],
            fetched_at=fetched_at,
        )

    def describe(self) -> dict[str, Any]:
        return {**super().describe(), "host": self.host}


# ---------------------------------------------------------------------------
# YAML configuration
# ---------------------------------------------------------------------------
class ConnectorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    type: Literal["jsonl", "http_json"]
    source_type: SourceType
    enabled: bool = True
    path: str | None = None
    url: str | None = None
    records_path: str | None = None
    token_env: str | None = None
    basic_user_env: str | None = None
    entity_type: EntityType | None = None
    max_records: int | None = Field(default=None, ge=1, le=100_000)
    field_map: FieldMap | None = None
    allowed_hosts: list[str] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        if not NAME_PATTERN.match(value):
            raise ValueError("name must match ^[a-z][a-z0-9_.-]{1,63}$")
        return value

    @model_validator(mode="after")
    def _check_transport(self) -> "ConnectorConfig":
        if self.type == "jsonl":
            if not self.path:
                raise ValueError("jsonl connector requires path")
            if self.url:
                raise ValueError("jsonl connector must not set url")
        else:
            if not self.url:
                raise ValueError("http_json connector requires url")
            if self.path:
                raise ValueError("http_json connector must not set path")
        return self


def load_connectors(
    path: str | Path,
    *,
    settings: Settings,
    root: str | Path | None = None,
) -> list[Connector]:
    """Build connectors from a YAML file. Fail closed on an unsafe definition."""
    config_path = Path(path).resolve()
    if not config_path.is_file():
        raise ConnectorConfigError(f"connectors file not found: {config_path}")
    try:
        raw: dict[str, Any] = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConnectorConfigError(f"invalid YAML in {config_path}: {exc}") from exc

    entries = raw.get("connectors")
    if not isinstance(entries, list) or not entries:
        raise ConnectorConfigError(f"{config_path} must contain a non-empty 'connectors' list")

    base_root = Path(root).resolve() if root else config_path.parent
    global_hosts = [h.strip() for h in settings.connector_allowed_hosts.split(",") if h.strip()]
    connectors: list[Connector] = []
    names: set[str] = set()

    for entry in entries:
        try:
            config = ConnectorConfig.model_validate(entry)
        except ValidationError as exc:
            raise ConnectorConfigError(f"invalid connector definition: {exc}") from exc
        if not config.enabled:
            continue
        if config.name in names:
            raise ConnectorConfigError(f"duplicate connector name: {config.name}")
        names.add(config.name)

        field_map = config.field_map or FieldMap()
        if config.entity_type is not None:
            field_map = field_map.model_copy(update={"default_entity_type": config.entity_type})
        adapter = MappingAdapter(
            field_map,
            phi_detection_enabled=settings.phi_detection_enabled,
        )

        if config.type == "jsonl":
            connectors.append(
                JsonlConnector(
                    name=config.name,
                    source_type=config.source_type,
                    path=config.path or "",
                    root=base_root,
                    adapter=adapter,
                    max_records=config.max_records or settings.connector_max_records,
                    max_line_bytes=min(settings.connector_max_bytes, 256 * 1024),
                )
            )
            continue

        allowed_hosts = config.allowed_hosts or global_hosts
        token = None
        if config.token_env:
            token = os.environ.get(config.token_env)
            if not token:
                raise ConnectorConfigError(
                    f"connector {config.name!r} expects its token in {config.token_env}, which is unset"
                )
        basic_user = None
        if config.basic_user_env:
            basic_user = os.environ.get(config.basic_user_env)
            if not basic_user or not token or ":" in basic_user:
                raise ConnectorConfigError(
                    f"connector {config.name!r} requires a valid user in {config.basic_user_env} and a token"
                )
            if urlsplit(config.url or "").scheme.lower() != "https":
                raise ConnectorConfigError("Basic authentication requires HTTPS")
        connectors.append(
            HttpJsonConnector(
                name=config.name,
                source_type=config.source_type,
                url=config.url or "",
                allowed_hosts=allowed_hosts,
                adapter=adapter,
                token=token,
                basic_user=basic_user,
                records_path=config.records_path,
                timeout_s=settings.connector_timeout_s,
                max_bytes=settings.connector_max_bytes,
                max_records=config.max_records or settings.connector_max_records,
                allow_http_loopback=settings.connector_allow_http_loopback,
            )
        )
    if not connectors:
        raise ConnectorConfigError(f"{config_path} enabled no connectors")
    return connectors


FIXTURE_SOURCES: dict[str, SourceType] = {
    "observability": SourceType.OBSERVABILITY,
    "cloud_cost": SourceType.CLOUD_COST,
    "vulnerability": SourceType.VULNERABILITY,
    "soc": SourceType.SOC,
    "infrastructure": SourceType.INFRASTRUCTURE,
    "network": SourceType.NETWORK,
    "identity": SourceType.IDENTITY,
    "incident_response": SourceType.INCIDENT_RESPONSE,
    "backup": SourceType.BACKUP_RECOVERY,
    "backup_recovery": SourceType.BACKUP_RECOVERY,
    "cyber_training": SourceType.CYBER_TRAINING,
    "ticketing": SourceType.WORKFLOW,
    "workflow_ticketing": SourceType.WORKFLOW,
}


def build_fixture_connectors(settings: Settings, directory: str | Path) -> list[Connector]:
    """Build file connectors for a directory of ``<source_type>.jsonl`` fixtures."""
    base = Path(directory).resolve()
    if not base.is_dir():
        raise ConnectorConfigError(f"fixtures directory not found: {base}")
    connectors: list[Connector] = []
    adapter = MappingAdapter(phi_detection_enabled=settings.phi_detection_enabled)
    for path in sorted(base.glob("*.jsonl")):
        source_type = FIXTURE_SOURCES.get(path.stem, SourceType.OTHER)
        connectors.append(
            JsonlConnector(
                name=path.stem,
                source_type=source_type,
                path=path.name,
                root=base,
                adapter=adapter,
                max_records=settings.connector_max_records,
                max_line_bytes=min(settings.connector_max_bytes, 256 * 1024),
            )
        )
    if not connectors:
        raise ConnectorConfigError(f"no .jsonl fixtures found in {base}")
    return connectors


async def ingest_connectors(
    connectors: Iterable[Connector],
    *,
    timeout_s: float = 15.0,
    max_concurrency: int = 8,
) -> IngestResult:
    """Poll connectors concurrently. One failure is isolated from the rest."""
    items = list(connectors)
    semaphore = asyncio.Semaphore(max(1, max_concurrency))

    async def poll(connector: Connector) -> ConnectorBatch:
        async with semaphore:
            return await asyncio.wait_for(connector.fetch(), timeout=timeout_s)

    results = await asyncio.gather(*(poll(c) for c in items), return_exceptions=True)
    batches: list[ConnectorBatch] = []
    errors: list[str] = []
    for connector, result in zip(items, results):
        if isinstance(result, ConnectorBatch):
            batches.append(result)
            errors.extend(f"{connector.name}: {e}" for e in result.errors)
        elif isinstance(result, asyncio.TimeoutError):
            errors.append(f"{connector.name}: timed out after {timeout_s}s")
        else:
            errors.append(f"{connector.name}: {type(result).__name__}: {result}")

    signals = sorted(
        (s for batch in batches for s in batch.signals),
        key=lambda s: (s.observed_at, s.source, s.id),
    )
    return IngestResult(signals=signals, batches=batches, errors=errors[:100])


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def canonical_entity(value: str) -> str:
    """Normalize an entity key for cross-tool comparison."""
    import unicodedata

    text = unicodedata.normalize("NFKC", str(value)).casefold()
    text = " ".join(text.strip().split())
    return text.rstrip(".")


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _hash_id(prefix: str) -> str:
    import uuid

    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _get(raw: Any, path: str) -> Any:
    current = raw
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _first(raw: dict[str, Any], paths: Iterable[str]) -> Any:
    for path in paths:
        value = _get(raw, path)
        if value is not None and value != "":
            return value
    return None


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, default=str)[:MAX_DETAIL_CHARS]
    return str(value).strip()


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return _dedupe([str(v).strip() for v in value if str(v).strip()])
    if isinstance(value, str):
        return _dedupe([part.strip() for part in re.split(r"[,;|]", value) if part.strip()])
    return [str(value).strip()]


def _parse_timestamp(value: Any, fallback: datetime) -> tuple[datetime, bool]:
    if value is None or value == "":
        return _as_utc(fallback), False
    if isinstance(value, (int, float)):
        seconds = float(value) / 1000.0 if float(value) > 10_000_000_000 else float(value)
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc), True
        except (OverflowError, OSError, ValueError):
            return _as_utc(fallback), False
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
        return _as_utc(parsed), True
    except ValueError:
        try:
            return datetime.fromtimestamp(float(text), tz=timezone.utc), True
        except (OverflowError, OSError, ValueError):
            return _as_utc(fallback), False


_SEVERITY_ALIASES: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "crit": Severity.CRITICAL,
    "sev1": Severity.CRITICAL,
    "p1": Severity.CRITICAL,
    "emergency": Severity.CRITICAL,
    "high": Severity.HIGH,
    "sev2": Severity.HIGH,
    "p2": Severity.HIGH,
    "error": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "med": Severity.MEDIUM,
    "sev3": Severity.MEDIUM,
    "p3": Severity.MEDIUM,
    "warning": Severity.MEDIUM,
    "warn": Severity.MEDIUM,
    "low": Severity.LOW,
    "sev4": Severity.LOW,
    "p4": Severity.LOW,
    "notice": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "sev5": Severity.INFO,
    "p5": Severity.INFO,
    "debug": Severity.INFO,
}


def _parse_severity(value: Any, default: Severity) -> Severity:
    if value is None or value == "":
        return default
    if isinstance(value, Severity):
        return value
    text = str(value).strip().lower()
    if text in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[text]
    if isinstance(value, (int, float)) or re.fullmatch(r"\d+(?:\.\d+)?", text):
        number = float(value if isinstance(value, (int, float)) else text)
        if 0 <= number <= 5:
            return {
                0: Severity.INFO,
                1: Severity.INFO,
                2: Severity.LOW,
                3: Severity.MEDIUM,
                4: Severity.HIGH,
                5: Severity.CRITICAL,
            }.get(int(round(number)), default)
        if 5 < number <= 10:
            if number >= 9:
                return Severity.CRITICAL
            if number >= 7:
                return Severity.HIGH
            if number >= 4:
                return Severity.MEDIUM
            return Severity.LOW
        if number > 10:
            if number >= 80:
                return Severity.CRITICAL
            if number >= 60:
                return Severity.HIGH
            if number >= 30:
                return Severity.MEDIUM
            return Severity.LOW
    return default


def _parse_entity_type(value: Any) -> EntityType:
    if value is None:
        return EntityType.OTHER
    text = str(value).strip().lower()
    try:
        return EntityType(text)
    except ValueError:
        return EntityType.OTHER


def _parse_classification(value: Any) -> Classification:
    if value is None:
        return Classification.INTERNAL
    try:
        return Classification(str(value).strip().lower())
    except ValueError:
        return Classification.INTERNAL


def _prune_depth(value: Any, depth: int = 0, max_depth: int = 4) -> Any:
    if depth >= max_depth:
        return str(value)[:200] if not isinstance(value, (dict, list)) else None
    if isinstance(value, dict):
        return {k: _prune_depth(v, depth + 1, max_depth) for k, v in value.items()}
    if isinstance(value, list):
        return [_prune_depth(v, depth + 1, max_depth) for v in value[:50]]
    return value


def _bounded_attributes(value: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    value = _prune_depth(value)
    blob = json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))
    if len(blob.encode("utf-8")) <= MAX_ATTRIBUTES_BYTES:
        return value
    scalars: dict[str, Any] = {}
    for key, item in value.items():
        if isinstance(item, (str, int, float, bool)) or item is None:
            scalars[key] = item[:500] if isinstance(item, str) else item
    scalars["_truncated"] = True
    blob = json.dumps(scalars, sort_keys=True, default=str, separators=(",", ":"))
    if len(blob.encode("utf-8")) <= MAX_ATTRIBUTES_BYTES:
        return scalars
    return {"_truncated": True, "_keys": list(value)[:20]}


def _is_loopback(host: str) -> bool:
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_http_url(url: str, allowed_hosts: list[str], allow_http_loopback: bool) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        raise ConnectorConfigError("http_json connector requires an http(s) URL")
    if not parsed.hostname:
        raise ConnectorConfigError("http_json connector URL has no host")
    if parsed.username or parsed.password:
        raise ConnectorConfigError("credentials must not be embedded in a connector URL")
    host = parsed.hostname.lower()
    if parsed.scheme == "http" and not (allow_http_loopback and _is_loopback(host)):
        raise ConnectorConfigError(
            "http_json connector requires https:// unless the host is loopback"
        )
    if not allowed_hosts:
        raise ConnectorConfigError(
            "http_json connector requires AGENT_CONNECTOR_ALLOWED_HOSTS or allowed_hosts"
        )
    if not any(fnmatchcase(host, pattern.lower()) for pattern in allowed_hosts):
        raise ConnectorConfigError(f"host {host!r} is not in the connector allowlist")
    return host


def _safe_url(url: str) -> str:
    parsed = urlsplit(url)
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{parsed.hostname or ''}{port}{parsed.path}"
