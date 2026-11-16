from __future__ import annotations

import hashlib
import hmac
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .security import SecurityError, read_secret


class Settings(BaseSettings):
    """All runtime knobs, from env vars or .env. Defaults are local and safe."""

    model_config = SettingsConfigDict(
        env_prefix="AGENT_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # transport
    bus: Literal["memory", "redis"] = "memory"
    redis_url: str = "redis://localhost:6379/0"
    redis_socket_timeout_s: float = 5.0
    consumer_group: str = "mesh"

    # model (empty base_url => deterministic offline model)
    llm_base_url: str | None = None
    llm_api_key: str | None = Field(default=None, repr=False)
    model: str = "gpt-4.1-mini"
    model_fast: str = "gpt-4.1-nano"
    llm_timeout_s: float = 60.0
    temperature: float = 0.0
    # Remote model endpoints must use TLS unless this is explicitly relaxed.
    allow_insecure_llm: bool = False

    # security: message authentication and approval identity
    message_auth: bool = True
    shared_secret: str | None = Field(default=None, repr=False)
    shared_secret_file: Path | None = None
    max_message_age_s: int = 0  # 0 disables freshness checks (at-least-once safe)
    approvers: str = ""  # comma-separated allowlist; empty means any name (dev)
    require_approver_allowlist: bool = False
    approval_ttl_s: int = 86_400  # pending approvals expire after one day

    # configuration integrity: pin the capability-card manifest before startup.
    # SHA-256 covers the exact bytes of subsystems.yaml. The HMAC variant binds
    # the same bytes to AGENT_SHARED_SECRET. Set require_* in production so a
    # missing pin fails closed instead of silently trusting the file on disk.
    subsystems_manifest_hash: str | None = Field(default=None, repr=False)
    subsystems_signature: str | None = Field(default=None, repr=False)
    require_subsystems_integrity: bool = False

    # service: container health/readiness endpoint
    health_host: str = "127.0.0.1"
    health_port: int = 8080
    health_token: str | None = Field(default=None, repr=False)
    health_token_file: Path | None = None
    # Separate administrative credential for /diagnostics. If absent, the
    # diagnostics route is not served at all.
    admin_token: str | None = Field(default=None, repr=False)
    admin_token_file: Path | None = None
    reclaim_interval_s: float = 30.0

    # tools
    allow_workspace_delete: bool = False

    # governance
    mission_id: str | None = None
    allowed_targets: str = "sandbox/*,staging/*"

    # fragmentation: read-only ingestion + cross-source correlation
    connectors_file: Path = Path("connectors.yaml")
    connector_timeout_s: float = 15.0
    connector_max_records: int = 5_000
    connector_max_bytes: int = 2_000_000
    # Comma-separated host allowlist for http_json connectors. Empty means no
    # remote connectors may be built (fail closed).
    connector_allowed_hosts: str = ""
    connector_allow_http_loopback: bool = True
    correlation_window_s: int = 900
    correlation_min_sources: int = 2
    correlation_min_score: float = 40.0

    # limits
    max_concurrency: int = 4
    task_timeout_s: float = 120.0
    max_attempts: int = 3
    max_hops: int = 8
    plan_timeout_s: float = 90.0
    max_tokens_per_step: int = 8_000

    # files
    subsystems_file: Path = Path("subsystems.yaml")
    workspace: Path = Path("workspace")

    # observability
    log_level: str = "INFO"
    log_json: bool = False


def _pinned_digests(path: str | Path) -> tuple[bytes, str]:
    file = Path(path)
    try:
        data = file.read_bytes()
    except OSError as exc:
        raise SecurityError(f"cannot read subsystems file {file}: {exc}") from exc
    return data, hashlib.sha256(data).hexdigest()


def subsystems_integrity(path: str | Path, settings: Settings | None = None) -> tuple[str, str | None]:
    """Return ``(sha256, hmac_signature)`` for a capability-card file.

    Use this to generate the values pinned in ``AGENT_SUBSYSTEMS_MANIFEST_HASH``
    and ``AGENT_SUBSYSTEMS_SIGNATURE``. The signature is HMAC-SHA256 keyed with
    the cluster secret, so it cannot be forged by editing the file alone.
    """
    settings = settings or get_settings()
    data, digest = _pinned_digests(path)
    secret = read_secret(settings.shared_secret, settings.shared_secret_file)
    signature = (
        hmac.new(secret.encode("utf-8"), data, hashlib.sha256).hexdigest()
        if secret
        else None
    )
    return digest, signature


def verify_subsystems_file(path: str | Path, settings: Settings | None = None) -> str:
    """Verify the capability cards before any agent is constructed.

    ``subsystems.yaml`` is the IAM policy store: it decides which tools and
    topics each subsystem may use. A runtime edit would be privilege escalation,
    so startup refuses a file that does not match the pinned SHA-256 or HMAC.
    Missing pins are allowed for local development, but setting
    ``AGENT_REQUIRE_SUBSYSTEMS_INTEGRITY=true`` makes them mandatory.
    """
    settings = settings or get_settings()
    data, digest = _pinned_digests(path)
    expected_hash = (settings.subsystems_manifest_hash or "").strip().lower()
    expected_signature = (settings.subsystems_signature or "").strip().lower()

    if not expected_hash and not expected_signature:
        if settings.require_subsystems_integrity:
            raise SecurityError(
                "AGENT_REQUIRE_SUBSYSTEMS_INTEGRITY is set but neither "
                "AGENT_SUBSYSTEMS_MANIFEST_HASH nor AGENT_SUBSYSTEMS_SIGNATURE is configured"
            )
        return digest

    if expected_hash:
        if len(expected_hash) != 64 or not hmac.compare_digest(digest, expected_hash):
            raise SecurityError(
                "subsystems file SHA-256 does not match AGENT_SUBSYSTEMS_MANIFEST_HASH"
            )

    if expected_signature:
        secret = read_secret(settings.shared_secret, settings.shared_secret_file)
        if not secret:
            raise SecurityError(
                "AGENT_SUBSYSTEMS_SIGNATURE requires AGENT_SHARED_SECRET or AGENT_SHARED_SECRET_FILE"
            )
        actual = hmac.new(secret.encode("utf-8"), data, hashlib.sha256).hexdigest()
        if len(expected_signature) != 64 or not hmac.compare_digest(actual, expected_signature):
            raise SecurityError(
                "subsystems file HMAC does not match AGENT_SUBSYSTEMS_SIGNATURE"
            )
    return digest


@lru_cache
def get_settings() -> Settings:
    return Settings()
