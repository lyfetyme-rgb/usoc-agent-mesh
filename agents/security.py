"""Security primitives shared by the bus, approvals and evidence.

The mesh has one cluster trust root: ``AGENT_SHARED_SECRET``. Keys are derived
from it per purpose and per identity, so a captured message cannot be edited and
a process cannot impersonate another subsystem without the secret.

This module is deliberately small and dependency-free:

* ``Signer``        HMAC-SHA256 over canonical JSON
* ``build_signer``  secure default: memory bus gets an ephemeral secret, Redis
                    requires an explicit secret and fails closed
* ``redact_*``      keep secrets out of logs and diagnostics
* ``exclusive_lock`` cross-process lock for JSON state files
* ``secure_*``      0600/0700 permissions on POSIX (no-op on Windows)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterator

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .contracts import Message

MIN_SECRET_LEN = 32

# Match whole key segments so ``token`` and ``access_token`` are redacted but
# benign counters such as ``tokens`` and ``max_tokens`` are left visible.
SENSITIVE_KEY = re.compile(
    r"(?:^|[_-])(?:secret|token|password|passwd|api[_-]?key|authorization|credential|private[_-]?key)(?:$|[_-])",
    re.IGNORECASE,
)
BEARER = re.compile(r"(Bearer\s+)[A-Za-z0-9._~+/=-]+", re.IGNORECASE)
BASIC = re.compile(r"(Basic\s+)[A-Za-z0-9+/=]+", re.IGNORECASE)
URL_CREDENTIALS = re.compile(
    r"(?P<scheme>[a-z][a-z0-9+.-]*://)(?P<user>[^:/@\s]*):(?P<password>[^@/\s]+)@",
    re.IGNORECASE,
)
QUERY_SECRET = re.compile(
    r"([?&](?:token|key|secret|password|signature|api_key)=)[^&\s]+",
    re.IGNORECASE,
)


class SecurityError(RuntimeError):
    """Configuration or integrity failure that must never be ignored."""


def canonical(body: Any) -> bytes:
    """Stable byte representation used for every signature."""
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


class Signer:
    """HMAC-SHA256 signer for messages, approvals and evidence records."""

    def __init__(self, secret: str, *, max_age_s: int = 0) -> None:
        if not secret or len(secret) < MIN_SECRET_LEN:
            raise SecurityError(
                f"shared secret must be at least {MIN_SECRET_LEN} characters; "
                "generate one with: python -c \"import secrets; print(secrets.token_urlsafe(48))\""
            )
        self._secret = secret.encode("utf-8")
        self.max_age_s = max(0, int(max_age_s))

    def _key(self, scope: str, identity: str = "") -> bytes:
        material = f"{scope}:{identity}".encode("utf-8")
        return hmac.new(self._secret, material, hashlib.sha256).digest()

    # -- generic records ----------------------------------------------------
    def sign_record(self, scope: str, body: dict[str, Any], identity: str = "") -> str:
        return hmac.new(self._key(scope, identity), canonical(body), hashlib.sha256).hexdigest()

    def verify_record(
        self,
        scope: str,
        body: dict[str, Any],
        signature: str | None,
        identity: str = "",
    ) -> tuple[bool, str]:
        if not signature:
            return False, "missing signature"
        expected = self.sign_record(scope, body, identity)
        if not hmac.compare_digest(expected, signature):
            return False, "signature mismatch"
        return True, "ok"

    # -- messages -----------------------------------------------------------
    def sign_message(self, msg: "Message") -> "Message":
        body = msg.model_dump(mode="json", exclude={"signature"})
        signature = self.sign_record("message", body, msg.sender)
        return msg.model_copy(update={"signature": signature})

    def verify_message(self, msg: "Message") -> tuple[bool, str]:
        body = msg.model_dump(mode="json", exclude={"signature"})
        ok, detail = self.verify_record("message", body, msg.signature, msg.sender)
        if not ok:
            return ok, detail
        if self.max_age_s:
            created = msg.created_at
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - created).total_seconds()
            if age > self.max_age_s:
                return False, f"message too old ({int(age)}s > {self.max_age_s}s)"
            if age < -60:
                return False, "message timestamp is in the future"
        return True, "ok"


# -- configuration ----------------------------------------------------------
def configured_approvers(settings: Any) -> set[str]:
    raw = getattr(settings, "approvers", "") or ""
    return {item.strip() for item in raw.split(",") if item.strip()}


def read_secret(value: str | None, file: str | Path | None) -> str | None:
    """Accept a secret from env or from a mounted file (Docker secrets)."""
    if value:
        return value
    if file:
        try:
            return Path(file).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise SecurityError(f"cannot read secret file {file}: {exc}") from exc
    return None


def build_signer(settings: Any) -> Signer | None:
    """Return a signer, or ``None`` only when authentication is explicitly off.

    With the memory bus, an ephemeral secret is generated per process: messages
    are still authenticated inside that process, but nothing survives a restart.
    With the Redis bus an explicit secret is mandatory, so a misconfigured deploy
    fails at startup instead of silently running unauthenticated.
    """
    if not getattr(settings, "message_auth", True):
        return None
    mode = str(getattr(settings, "signing_mode", "hmac") or "hmac").lower()
    if mode == "ed25519":
        # Asymmetric mode: the runtime may hold only a public verification key,
        # or delegate signing to a KMS. No shared HMAC secret is required.
        from .asymmetric import build_ed25519_signer

        return build_ed25519_signer(settings)
    if mode not in ("hmac", "symmetric"):
        raise SecurityError(
            f"unknown AGENT_SIGNING_MODE {mode!r}; expected 'hmac' or 'ed25519'"
        )
    secret = read_secret(
        getattr(settings, "shared_secret", None),
        getattr(settings, "shared_secret_file", None),
    )
    if not secret:
        if getattr(settings, "bus", "memory") == "redis":
            raise SecurityError("AGENT_SHARED_SECRET (or AGENT_SHARED_SECRET_FILE) is required when AGENT_BUS=redis")
        secret = secrets.token_hex(32)
    return Signer(secret, max_age_s=int(getattr(settings, "max_message_age_s", 0) or 0))


def is_ephemeral_secret(settings: Any) -> bool:
    """True when message/approval signing rests on an in-memory random key.

    Health checks use this to fail closed in production: an ephemeral key makes
    approvals written by another process unverifiable, so an operator must never
    mistake a "ready" result for a durable trust root.
    """
    if not getattr(settings, "message_auth", True):
        return True
    mode = str(getattr(settings, "signing_mode", "hmac") or "hmac").lower()
    if mode == "ed25519":
        # No shared secret is used at all, and build_ed25519_signer requires an
        # explicitly configured key set, so this is never an ephemeral value.
        return False
    if getattr(settings, "bus", "memory") == "redis":
        # A missing secret fails closed at startup for Redis instead of being
        # silently replaced with a random value.
        return False
    return not (
        getattr(settings, "shared_secret", None)
        or getattr(settings, "shared_secret_file", None)
    )


def uses_managed_secrets(settings: Any) -> bool:
    """True when key material comes from mounted files/KMS, not inline values.

    ``AGENT_STRICT_PROD`` requires this so secrets injected by a secret manager
    are not accidentally pasted into env files, process listings or logs.
    """
    mode = str(getattr(settings, "signing_mode", "hmac") or "hmac").lower()
    if mode == "ed25519":
        public_inline = bool(
            getattr(settings, "ed25519_public_keys", None)
            or getattr(settings, "ed25519_public_key", None)
        )
        public_file = bool(
            getattr(settings, "ed25519_public_keys_file", None)
            or getattr(settings, "ed25519_public_key_file", None)
        )
        private_inline = bool(getattr(settings, "ed25519_private_key", None))
        private_file = bool(getattr(settings, "ed25519_private_key_file", None))
        kms = bool(getattr(settings, "kms_sign_url", None))
        if public_inline or private_inline or not public_file:
            return False
        return bool(private_file or kms)
    return bool(getattr(settings, "shared_secret_file", None)) and not bool(
        getattr(settings, "shared_secret", None)
    )


# -- redaction --------------------------------------------------------------
def redact_text(value: str) -> str:
    import unicodedata

    value = unicodedata.normalize("NFKC", str(value))
    value = BEARER.sub(r"\1***", value)
    value = BASIC.sub(r"\1***", value)
    value = URL_CREDENTIALS.sub(
        lambda m: f"{m.group('scheme')}{m.group('user')}:***@", value
    )
    return QUERY_SECRET.sub(r"\1***", value)


def redact_url(url: str) -> str:
    return redact_text(url)


def _normalize_key(key: Any) -> str:
    text = re.sub(r"([a-z0-9])([A-Z])", r"\\1_\\2", str(key))
    text = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\\1_\\2", text)
    return text.lower()


def _is_sensitive_key(key: Any) -> bool:
    normalized = _normalize_key(key)
    return bool(
        re.search(
            r"(?:^|[_-])(?:secret|token|password|passwd|api[_-]?key|apikey|authorization|credential|private[_-]?key|auth(?:token)?)(?:$|[_-])",
            normalized,
        )
    )


# Clinical/PII detection. Key matches are conservative word-boundary checks on
# normalized names; value matches catch direct identifiers even when a vendor
# uses a generic key such as ``note``. Detection is opt-in per profile so a
# cyber telemetry feed is not misclassified as patient data.
_PHI_KEY = re.compile(
    r"(?:^|[_-])(?:mrn|medical_record|health_record|patient|diagnos(?:is|e)|"
    r"medication|prescription|lab_result|lab|icd10|icd_10|phi|nhs_number|"
    r"treatment|clinical|discharge|admission)(?:$|[_-])"
)
_PII_KEY = re.compile(
    r"(?:^|[_-])(?:email|e_mail|phone|mobile|address|full_name|first_name|"
    r"last_name|dob|date_of_birth|ssn|social_security|passport|driver_license|"
    r"national_id|tax_id|patient_id|insurance_id)(?:$|[_-])"
)
_PII_VALUE = {
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    "phone": re.compile(r"(?<!\w)(?:\+\d{1,3}[ -]?)?\(?\d{3}\)?[ -]\d{3}[ -]\d{4}(?!\w)"),
    "mrn": re.compile(r"\b(?:mrn|medical[-_ ]?record)[:# ]*\d{4,}\b", re.IGNORECASE),
    "dob": re.compile(r"\b(?:19|20)\d{2}-\d{2}-\d{2}\b"),
}


def detect_sensitive_data(fields: dict[str, Any], *, enabled: bool = False) -> list[str]:
    """Return sorted PII/PHI labels present in a connector record.

    This is a *classification* signal, not a redaction substitute: the values
    still flow through ``redact_fields`` first. A positive result marks the
    connector's signal tainted and restricted, which forces mandatory HITL and
    blocks egress until a signed sign-off is supplied.
    """
    if not enabled:
        return []
    labels: set[str] = set()

    def visit(key: str, value: Any) -> None:
        normalized = _normalize_key(key)
        if _PHI_KEY.search(normalized):
            labels.add("phi")
        if _PII_KEY.search(normalized):
            labels.add("pii")
        if isinstance(value, str):
            for name, pattern in _PII_VALUE.items():
                if pattern.search(value):
                    labels.add(name)
        elif isinstance(value, dict):
            for child_key, child_value in value.items():
                visit(str(child_key), child_value)
        elif isinstance(value, (list, tuple)):
            for child in value:
                if isinstance(child, dict):
                    for child_key, child_value in child.items():
                        visit(str(child_key), child_value)
                elif isinstance(child, str):
                    visit(key, child)

    for key, value in fields.items():
        visit(str(key), value)
    return sorted(labels)


def redact_fields(fields: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in fields.items():
        if _is_sensitive_key(key):
            out[key] = "***"
        elif isinstance(value, str):
            out[key] = redact_text(value)
        elif isinstance(value, dict):
            out[key] = redact_fields(value)
        elif isinstance(value, (list, tuple)):
            out[key] = [
                redact_fields(v)
                if isinstance(v, dict)
                else redact_text(v)
                if isinstance(v, str)
                else v
                for v in value
            ]
        else:
            out[key] = value
    return out


# -- files ------------------------------------------------------------------
def secure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass


def secure_file(path: Path) -> None:
    if os.name != "nt":
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


@contextmanager
def exclusive_lock(path: Path, timeout_s: float = 10.0) -> Iterator[None]:
    """Cross-process lock beside ``path``. Blocks briefly, then fails closed."""
    lock_path = path.with_name(path.name + ".lock")
    secure_dir(lock_path.parent)
    handle = open(lock_path, "a+b")
    secure_file(lock_path)
    deadline = time.monotonic() + timeout_s
    try:
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            while True:
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise SecurityError(f"could not lock {lock_path} within {timeout_s}s")
                    time.sleep(0.05)
        else:
            import fcntl

            while True:
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise SecurityError(f"could not lock {lock_path} within {timeout_s}s")
                    time.sleep(0.05)
        yield
    finally:
        try:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        handle.close()
