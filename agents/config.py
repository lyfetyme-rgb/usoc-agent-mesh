from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


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

    # service: container health/readiness endpoint
    health_host: str = "127.0.0.1"
    health_port: int = 8080
    health_token: str | None = Field(default=None, repr=False)
    health_token_file: Path | None = None
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


@lru_cache
def get_settings() -> Settings:
    return Settings()
