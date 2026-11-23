from __future__ import annotations

import hashlib
import hmac
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator
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
    # Fail-closed production mode. Requires managed key files, per-coordinator
    # Ed25519 bus keys and a detached-signature-bound approver registry.
    strict_prod: bool = False

    # Per-coordinator bus identities. ``bus_public_keys_file`` is a mounted JSON
    # trust bundle {agent_id: {kid: hex_or_pem_public_key}}; every node gets it,
    # but only the node acting as ``bus_signing_agent`` mounts the private key
    # (or a KMS signing URL). This prevents a low-privilege worker from forging
    # messages as another coordinator. Inline JSON is dev/test only.
    bus_public_keys: dict[str, dict[str, str]] | None = None
    bus_public_keys_file: Path | None = None
    bus_signing_agent: str | None = None
    bus_signing_kid: str = "default"
    bus_signing_key: str | None = Field(default=None, repr=False)
    bus_signing_key_file: Path | None = None
    bus_kms_sign_url: str | None = None
    bus_kms_sign_token: str | None = Field(default=None, repr=False)
    bus_kms_sign_token_file: Path | None = None
    bus_kms_sign_timeout_s: float = 5.0

    # Signed approver registry. It maps approver_id -> {role, public_key,
    # max_tier} and is verified against a detached Ed25519 signature before any
    # entry is trusted. The registry signature key is a separate trust anchor
    # from the bus keyset, so a compromised worker cannot add an approver.
    approver_registry: dict[str, Any] | None = None  # inline JSON, dev/test only
    approver_registry_file: Path | None = None
    approver_registry_signature: str | None = Field(default=None, repr=False)
    approver_registry_signature_file: Path | None = None
    approver_registry_public_key: str | None = None
    approver_registry_public_key_file: Path | None = None
    approver_registry_public_keys: dict[str, str] | None = None
    approver_registry_public_keys_file: Path | None = None

    # Human approval credentials. "detached" verifies an Ed25519 signature over
    # the canonical approval payload with the key in the signed registry;
    # "oidc" verifies an Okta/Entra id_token; "either" accepts both.
    approval_credential_mode: Literal["detached", "oidc", "either"] = "either"
    approval_require_credential: bool = False
    approval_oidc_issuer: str | None = None
    approval_oidc_audience: str | None = None
    approval_oidc_jwks_url: str | None = None
    approval_oidc_sub_claim: str = "sub"
    approval_oidc_role_claim: str | None = None
    # Claim carrying the per-approval binding digest (default: standard OIDC nonce).
    approval_oidc_binding_claim: str = "nonce"
    approval_oidc_leeway_s: int = 60
    approval_oidc_timeout_s: float = 5.0

    # configuration integrity: pin the capability-card manifest before startup.
    # SHA-256 covers the exact bytes of subsystems.yaml. The HMAC variant binds
    # the same bytes to AGENT_SHARED_SECRET. Set require_* in production so a
    # missing pin fails closed instead of silently trusting the file on disk.
    subsystems_manifest_hash: str | None = Field(default=None, repr=False)
    subsystems_signature: str | None = Field(default=None, repr=False)
    subsystems_signature_ed25519: str | None = Field(default=None, repr=False)
    subsystems_signature_file: Path | None = None
    require_subsystems_integrity: bool = False

    # asymmetric signing: Ed25519 private keys belong to CI/CD or a KMS.
    # Runtime nodes should mount only the public verification key.
    signing_mode: Literal["hmac", "ed25519"] = "hmac"
    ed25519_private_key: str | None = Field(default=None, repr=False)
    ed25519_private_key_file: Path | None = None
    ed25519_public_key: str | None = None
    ed25519_public_key_file: Path | None = None
    # Trusted verification keyset: {kid: hex_or_pem_public_key}. Accepts a JSON
    # object in the env var or a mounted JSON file. Multiple kids allow key
    # rotation without breaking in-flight waves or historical evidence checks.
    ed25519_public_keys: dict[str, str] | None = None
    ed25519_public_keys_file: Path | None = None
    ed25519_key_id: str = "default"
    # KMS/sidecar signing endpoint; the private key never enters this process.
    kms_sign_url: str | None = None
    kms_sign_token: str | None = Field(default=None, repr=False)
    kms_sign_token_file: Path | None = None
    kms_sign_timeout_s: float = 5.0

    # Atlassian publishing bridge: opt-in and approval-gated. A decided HITL
    # approval can publish a signed ADR/evidence bundle and a JSM request.
    # Credentials come from env or a mounted file, never from this config.
    atlassian_bridge_enabled: bool = False
    atlassian_base_url: str | None = None
    atlassian_auth_mode: Literal["bearer", "basic"] = "bearer"
    atlassian_api_key: str | None = Field(default=None, repr=False)
    atlassian_api_key_file: Path | None = None
    atlassian_email: str | None = None
    atlassian_confluence_space_key: str | None = None
    atlassian_jira_project_key: str | None = None
    atlassian_jsm_enabled: bool = False
    atlassian_jsm_service_desk_id: str | None = None
    atlassian_jsm_request_type_id: str | None = None
    atlassian_publish_state_file: Path | None = None
    atlassian_timeout_s: float = 10.0

    # worker autoscaling advice (reads Redis backlog; see `agents scale-advice`)
    scale_min_replicas: int = 1
    scale_max_replicas: int = 4
    scale_messages_per_replica: int = 8

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
    # Shadow mode: consume real inputs and run policy/HITL/evidence, but never
    # execute a consequential action or write to an external sink. Isolated
    # workspace, tools, egress and bridge are enforced in code, not by convention.
    shadow_mode: bool = False

    # Industry Starter Profiles. The profile only filters the capability-card
    # role *view*; all nine coordinators always run. Profile control defaults
    # are applied by agents.profiles.settings_for_profile() and never override
    # an explicit AGENT_* environment variable.
    role_profile: str = "full_usoc"
    # FinOps/banking: hard ceiling on a governed transaction. Empty = no limit.
    max_transaction_amount: str | None = None
    transaction_currency: str = "USD"
    # Number of distinct verified human approvers required before HITL clears.
    approval_quorum: int = 1
    # Clinical: detect PII/PHI in every connector and block tainted egress.
    phi_detection_enabled: bool = False
    block_tainted_egress: bool = False
    # OEKP/BENGAL compliance export formats (comma-separated).
    evidence_export_formats: str = "jsonl"

    @field_validator("approval_quorum")
    @classmethod
    def _positive_quorum(cls, value: int) -> int:
        if value < 1:
            raise ValueError("approval_quorum must be at least 1")
        return value

    @field_validator("evidence_export_formats")
    @classmethod
    def _export_formats(cls, value: str) -> str:
        from .evidence import EXPORT_FORMATS

        names = [part.strip() for part in str(value).split(",") if part.strip()]
        if not names:
            raise ValueError("evidence_export_formats must not be empty")
        unknown = [name for name in names if name not in EXPORT_FORMATS]
        if unknown:
            raise ValueError(
                f"unknown evidence export format(s): {', '.join(unknown)}; "
                f"choose from {', '.join(sorted(EXPORT_FORMATS))}"
            )
        return ",".join(names)

    @model_validator(mode="after")
    def _production_backends_are_configured(self) -> "Settings":
        if (
            self.approval_backend == "postgres"
            or self.ledger_backend == "postgres"
            or self.evidence_backend == "postgres"
        ) and not self.postgres_dsn:
            raise ValueError(
                "AGENT_POSTGRES_DSN is required when a postgres backend is selected"
            )
        if self.archive_backend == "s3" and not self.archive_bucket:
            raise ValueError("AGENT_ARCHIVE_BUCKET is required when AGENT_ARCHIVE_BACKEND=s3")
        if self.archive_retention_days < 1:
            raise ValueError("archive_retention_days must be positive")
        return self

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
    # Bounded exponential backoff between requeues of a RetryableError.
    retry_backoff_base_s: float = 0.25
    retry_backoff_max_s: float = 2.0
    max_hops: int = 8
    plan_timeout_s: float = 90.0
    max_tokens_per_step: int = 8_000

    # edge ingress and deterministic idempotency
    ingress_require_tenant: bool = False
    ingress_quarantine_max: int = 256
    idempotency_ttl_s: int = 86_400

    # resilience: fail-fast breakers and jittered retries for external calls
    circuit_failure_threshold: int = 5
    circuit_reset_s: float = 30.0
    retry_jitter: bool = True

    # durable task state: hot Redis tier and signed cold archive
    ledger_backend: Literal["memory", "redis", "postgres"] = "memory"
    ledger_hot_ttl_s: int = 86_400
    ledger_archive_path: Path | None = None

    # production governance storage: transactional, tenant-partitioned Postgres
    # with a Redis hot cache. "file" keeps the legacy single-host behaviour for
    # local dev; only "postgres" supports concurrent control-plane replicas.
    approval_backend: Literal["file", "postgres"] = "file"
    evidence_backend: Literal["file", "postgres"] = "file"
    postgres_dsn: str | None = Field(default=None, repr=False)
    postgres_approval_table: str = "governance_approvals"
    postgres_ledger_table: str = "task_ledger_events"
    approval_cache_ttl_s: float = 2.0
    approval_cache_namespace: str = "usoc"

    # async S3 Object Lock (WORM) evidence archival. "file" keeps the legacy
    # signed JSONL on the shared /data PVC; "s3" makes control-plane pods fully
    # stateless by streaming signed segments to immutable object storage.
    archive_backend: Literal["file", "s3"] = "file"
    # Dedicated WORM chain key. In HMAC clusters the shared cluster key is used
    # when this is unset; asymmetric/KMS clusters must set it explicitly.
    archive_secret: str | None = Field(default=None, repr=False)
    archive_secret_file: Path | None = None
    archive_bucket: str | None = None
    archive_prefix: str = "usoc/task-ledger"
    archive_region: str | None = None
    archive_endpoint_url: str | None = None
    archive_retention_days: int = 2_555  # ~7 years of WORM retention
    archive_lock_mode: Literal["GOVERNANCE", "COMPLIANCE"] = "COMPLIANCE"

    # Fail startup outside local dev when signing rests on an ephemeral,
    # per-process HMAC key. Ed25519/KMS modes use persistent keys and are fine.
    require_persistent_signing_key: bool = False

    # BENGAL BAA threat-mode analysis (IARPA BAA-24-03)
    bengal_eval_cases: Path = Path("fixtures/bengal/cases.jsonl")
    bengal_grounded_min: float = 0.6
    bengal_plausible_min: float = 0.25
    bengal_min_independent_sources: int = 2
    bengal_corroboration_min: float = 0.5
    bengal_k_anonymity: int = 3
    bengal_review_at: float = 0.5
    bengal_block_at: float = 0.8
    bengal_simulate_dialogue: bool = True

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
    so startup refuses a file that does not match a pinned SHA-256, HMAC, or
    Ed25519 signature.

    Ed25519 verification is the offline model: CI signs the file with a private
    key and the runtime mounts only ``AGENT_ED25519_PUBLIC_KEY(_FILE)``. Missing
    pins are allowed for local development, but
    ``AGENT_REQUIRE_SUBSYSTEMS_INTEGRITY=true`` makes at least one mandatory.
    """
    settings = settings or get_settings()
    data, digest = _pinned_digests(path)
    expected_hash = (settings.subsystems_manifest_hash or "").strip().lower()
    expected_signature = (settings.subsystems_signature or "").strip().lower()
    expected_ed25519 = (settings.subsystems_signature_ed25519 or "").strip()
    if not expected_ed25519 and settings.subsystems_signature_file:
        try:
            expected_ed25519 = Path(settings.subsystems_signature_file).read_text(
                encoding="utf-8"
            ).strip()
        except OSError as exc:
            raise SecurityError(
                f"cannot read AGENT_SUBSYSTEMS_SIGNATURE_FILE: {exc}"
            ) from exc

    if not expected_hash and not expected_signature and not expected_ed25519:
        if settings.require_subsystems_integrity:
            raise SecurityError(
                "AGENT_REQUIRE_SUBSYSTEMS_INTEGRITY is set but no manifest hash or "
                "signature (HMAC or Ed25519) is configured"
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

    if expected_ed25519:
        from .asymmetric import configured_key_set, load_private_key

        private_key = None
        if settings.ed25519_private_key or settings.ed25519_private_key_file:
            private_key = load_private_key(
                settings.ed25519_private_key, settings.ed25519_private_key_file
            )
        key_set = configured_key_set(settings, private_key=private_key)
        # A capability card signed by a retired key still verifies while that
        # key remains in the trust bundle.
        ok, _kid = key_set.verify_bytes(data, expected_ed25519)
        if not ok:
            raise SecurityError(
                "subsystems file Ed25519 signature verification failed"
            )
    return digest


@lru_cache
def get_settings() -> Settings:
    return Settings()
