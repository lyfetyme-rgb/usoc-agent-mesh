"""Ed25519 signatures for offline and KMS-held signing keys.

The HMAC signer in :mod:`agents.security` is symmetric: every node that can
verify a record can also forge one. This module adds an asymmetric mode where
the private key never has to live on a runtime node.

Custody model
-------------
* CI/CD or a KMS holds the Ed25519 private key and produces signatures.
* Runtime nodes mount only the public verification key.
* ``Ed25519Signer`` is for the offline signer/CI job (it has the private key).
* ``Ed25519Verifier`` is the runtime default when only a public key is present.
  It verifies messages, approvals and evidence but refuses to sign.
* ``Ed25519KMSSigner`` calls an external signing function (a KMS or a local
  signing sidecar) so an active runtime can sign without holding key material.

Signatures are deterministic: Ed25519 over the same canonical envelope always
yields the same hex string, which keeps evidence records reproducible.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from pathlib import Path
from typing import Any, Callable

from .security import SecurityError, Signer, canonical, read_secret

# Domain separation: an Ed25519 signature always covers scope, identity and the
# record body, so a signature from one purpose cannot be replayed into another.
SIGNATURE_DOMAIN = b"usoc-mesh/ed25519/v1\x00"


def _material(value: str | None, file: str | Path | None, label: str) -> str:
    material = read_secret(value, file)
    if not material:
        raise SecurityError(f"{label} is required for Ed25519 signing")
    return material.strip()


def _raw_bytes(text: str, label: str) -> bytes:
    """Decode a hex or base64 key/signature body."""
    compact = "".join(text.split())
    try:
        if len(compact) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in compact):
            return bytes.fromhex(compact)
    except ValueError:
        pass
    try:
        return base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SecurityError(f"{label} must be hex or base64") from exc


def load_private_key(value: str | None, file: str | Path | None) -> Any:
    """Load an Ed25519 private key from PEM, raw seed hex, or base64 seed."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    material = _material(value, file, "Ed25519 private key")
    if "BEGIN" in material:
        try:
            key = serialization.load_pem_private_key(material.encode("utf-8"), password=None)
        except ValueError as exc:
            raise SecurityError(f"invalid Ed25519 private key PEM: {exc}") from exc
    else:
        raw = _raw_bytes(material, "Ed25519 private key")
        try:
            key = Ed25519PrivateKey.from_private_bytes(raw)
        except ValueError as exc:
            raise SecurityError(f"invalid Ed25519 private key material: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise SecurityError("configured private key is not Ed25519")
    return key


def load_public_key(value: str | None, file: str | Path | None) -> Any:
    """Load an Ed25519 public key from PEM, raw hex, or base64."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    material = _material(value, file, "Ed25519 public key")
    if "BEGIN" in material:
        try:
            key = serialization.load_pem_public_key(material.encode("utf-8"))
        except ValueError as exc:
            raise SecurityError(f"invalid Ed25519 public key PEM: {exc}") from exc
    else:
        raw = _raw_bytes(material, "Ed25519 public key")
        try:
            key = Ed25519PublicKey.from_public_bytes(raw)
        except ValueError as exc:
            raise SecurityError(f"invalid Ed25519 public key material: {exc}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise SecurityError("configured public key is not Ed25519")
    return key


def public_key_hex(key: Any) -> str:
    from cryptography.hazmat.primitives import serialization

    return key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def sign_bytes(private_key: Any, data: bytes) -> str:
    return private_key.sign(SIGNATURE_DOMAIN + data).hex()


def verify_bytes(public_key: Any, data: bytes, signature: str) -> bool:
    from cryptography.exceptions import InvalidSignature

    try:
        raw = bytes.fromhex(signature.strip())
    except ValueError:
        return False
    try:
        public_key.verify(raw, SIGNATURE_DOMAIN + data)
        return True
    except InvalidSignature:
        return False


class PublicKeySet:
    """Trusted Ed25519 verification keys, keyed by key id.

    Signatures do not carry a key id, so verification tries every trusted key.
    That is deliberate: a record signed by a retired key stays valid while that
    key remains in the bundle, which is what makes zero-downtime rotation and
    historical evidence checks possible. Remove a key only when no in-flight
    waves or stored records still need it.
    """

    def __init__(self, keys: dict[str, Any], *, active_key_id: str | None = None) -> None:
        if not keys:
            raise SecurityError("Ed25519 key set must contain at least one public key")
        cleaned: dict[str, Any] = {}
        for kid, key in keys.items():
            name = str(kid).strip()
            if not name:
                raise SecurityError("Ed25519 key set contains an empty key id")
            if name in cleaned:
                raise SecurityError(f"duplicate Ed25519 key id {name!r}")
            cleaned[name] = key
        self.keys = cleaned
        self.active_key_id = (
            str(active_key_id).strip() if active_key_id else next(iter(cleaned))
        )
        if self.active_key_id not in self.keys:
            raise SecurityError(
                f"active Ed25519 key id {self.active_key_id!r} is not in the trusted key set"
            )

    @property
    def active_key(self) -> Any:
        return self.keys[self.active_key_id]

    def verify_bytes(self, data: bytes, signature: str) -> tuple[bool, str | None]:
        """Try every trusted key, returning the matching kid when one verifies."""
        for kid, key in self.keys.items():
            if verify_bytes(key, data, signature):
                return True, kid
        return False, None

    def describe(self) -> dict[str, str]:
        """kid -> fingerprint, safe to log or expose on a diagnostics route."""
        return {kid: fingerprint(key) for kid, key in self.keys.items()}


def _envelope(scope: str, identity: str, body: dict[str, Any]) -> bytes:
    return canonical({"scope": scope, "identity": identity, "body": body})


class Ed25519Signer(Signer):
    """Offline/CI signer that holds the private key.

    Never mount the private key on an active runtime node. Use this class in a
    signing job, or use :class:`Ed25519KMSSigner` at runtime.
    """

    algorithm = "ed25519"

    def __init__(
        self,
        private_key: Any,
        *,
        public_key: Any | None = None,
        key_id: str = "default",
        key_set: PublicKeySet | None = None,
    ) -> None:
        self._private = private_key
        derived = private_key.public_key()
        if key_set is None:
            key_set = PublicKeySet({key_id: public_key or derived}, active_key_id=key_id)
        elif public_key_hex(derived) != public_key_hex(key_set.active_key):
            raise SecurityError(
                "active signing key does not match the trusted Ed25519 key set"
            )
        self.key_set = key_set
        self._public = key_set.active_key
        self.key_id = key_set.active_key_id
        self.max_age_s = 0

    @property
    def public_key_hex(self) -> str:
        return public_key_hex(self._public)

    def sign_record(self, scope: str, body: dict[str, Any], identity: str = "") -> str:
        return sign_bytes(self._private, _envelope(scope, identity, body))

    def verify_record(
        self,
        scope: str,
        body: dict[str, Any],
        signature: str | None,
        identity: str = "",
    ) -> tuple[bool, str]:
        if not signature:
            return False, "missing signature"
        ok, _kid = self.key_set.verify_bytes(_envelope(scope, identity, body), signature)
        return (True, "ok") if ok else (False, "ed25519 signature mismatch")


class Ed25519Verifier(Signer):
    """Runtime verifier that holds only the public key.

    It can validate messages, approvals and evidence created by the offline
    signer, but signing fails closed. This is the mode for audit/read-only
    nodes that must never be able to mint records.
    """

    algorithm = "ed25519"

    def __init__(self, public_key: Any | PublicKeySet, *, key_id: str = "default") -> None:
        self.key_set = (
            public_key
            if isinstance(public_key, PublicKeySet)
            else PublicKeySet({key_id: public_key}, active_key_id=key_id)
        )
        self._public = self.key_set.active_key
        self.key_id = self.key_set.active_key_id
        self.max_age_s = 0

    @property
    def public_key_hex(self) -> str:
        return public_key_hex(self._public)

    def sign_record(self, scope: str, body: dict[str, Any], identity: str = "") -> str:
        raise SecurityError(
            "this node holds only the Ed25519 public key; sign with the offline "
            "key or configure AGENT_KMS_SIGN_URL"
        )

    def verify_record(
        self,
        scope: str,
        body: dict[str, Any],
        signature: str | None,
        identity: str = "",
    ) -> tuple[bool, str]:
        if not signature:
            return False, "missing signature"
        ok, _kid = self.key_set.verify_bytes(_envelope(scope, identity, body), signature)
        return (True, "ok") if ok else (False, "ed25519 signature mismatch")


class Ed25519KMSSigner(Ed25519Verifier):
    """Signer that delegates private-key operations to a KMS or sidecar.

    ``sign`` receives the canonical envelope bytes and must return the raw
    64-byte Ed25519 signature. The signing key never enters this process.
    """

    def __init__(
        self,
        public_key: Any | PublicKeySet,
        sign: Callable[[bytes], bytes],
        *,
        key_id: str = "default",
    ) -> None:
        super().__init__(public_key, key_id=key_id)
        self._sign = sign

    def sign_record(self, scope: str, body: dict[str, Any], identity: str = "") -> str:
        # The KMS receives the exact bytes to raw-sign (including domain
        # separation), so the private key never leaves the KMS boundary.
        return self._sign(SIGNATURE_DOMAIN + _envelope(scope, identity, body)).hex()


def kms_http_signer(
    url: str,
    *,
    token: str | None = None,
    timeout_s: float = 5.0,
    allowed_key_ids: set[str] | None = None,
) -> Callable[[bytes], bytes]:
    """Build a KMS signing callable for a small HTTP contract.

    Request:  POST <url> with the exact canonical bytes to raw-sign (Ed25519,
    no hashing or extra prefix; domain separation is already included).
    Response: {"signature": "<hex or base64>", "key_id": "..."}
    """

    def sign(payload: bytes) -> bytes:
        import httpx

        headers = {"Content-Type": "application/octet-stream"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            response = httpx.post(url, content=payload, headers=headers, timeout=timeout_s)
            response.raise_for_status()
            data = response.json()
            raw = str(data.get("signature", ""))
            returned_kid = data.get("key_id")
        except Exception as exc:
            raise SecurityError(f"KMS signing request failed: {exc}") from exc
        if (
            allowed_key_ids is not None
            and returned_kid
            and str(returned_kid) not in allowed_key_ids
        ):
            raise SecurityError(
                f"KMS returned an untrusted key_id {str(returned_kid)!r}; "
                "add it to the public key set first"
            )
        signature = _raw_bytes(raw, "KMS signature")
        if len(signature) != 64:
            raise SecurityError("KMS returned a signature that is not Ed25519 (64 bytes)")
        return signature

    return sign


def build_ed25519_signer(settings: Any) -> Ed25519Verifier | Ed25519Signer:
    """Construct the Ed25519 backend from settings, failing closed.

    * private key present  -> offline/CI signer (development or signing job)
    * KMS URL present      -> runtime signer that delegates private operations
    * public key(s) only   -> verification-only runtime node

    All nodes verify against the full trusted key set, so records signed by a
    retired key remain valid until that key is removed from the bundle.
    """
    private_key = None
    if getattr(settings, "ed25519_private_key", None) or getattr(
        settings, "ed25519_private_key_file", None
    ):
        private_key = load_private_key(
            getattr(settings, "ed25519_private_key", None),
            getattr(settings, "ed25519_private_key_file", None),
        )
    key_set = configured_key_set(settings, private_key=private_key)
    key_id = key_set.active_key_id

    # A signing node must name a key it actually trusts. A verification-only
    # node can fall back to the first key in the bundle.
    configured_kid = str(getattr(settings, "ed25519_key_id", "default") or "default")
    kms_url = getattr(settings, "kms_sign_url", None)
    if (private_key is not None or kms_url) and configured_kid not in key_set.keys:
        raise SecurityError(
            f"active Ed25519 key id {configured_kid!r} is not in the trusted key set"
        )

    if private_key is not None:
        return Ed25519Signer(
            private_key,
            public_key=key_set.active_key,
            key_id=key_id,
            key_set=key_set,
        )

    if kms_url:
        token = read_secret(
            getattr(settings, "kms_sign_token", None),
            getattr(settings, "kms_sign_token_file", None),
        )
        return Ed25519KMSSigner(
            key_set,
            kms_http_signer(
                str(kms_url),
                token=token,
                timeout_s=float(getattr(settings, "kms_sign_timeout_s", 5.0) or 5.0),
                allowed_key_ids=set(key_set.keys),
            ),
            key_id=key_id,
        )
    return Ed25519Verifier(key_set, key_id=key_id)


def configured_key_set(settings: Any, *, private_key: Any | None = None) -> PublicKeySet:
    """Load every trusted public key from settings, failing closed on bad input.

    Sources, in precedence order:

    * ``AGENT_ED25519_PUBLIC_KEYS`` (JSON object ``{kid: hex_or_pem}``) or
      ``AGENT_ED25519_PUBLIC_KEYS_FILE`` (same JSON, mounted by the orchestrator)
    * the legacy ``AGENT_ED25519_PUBLIC_KEY(_FILE)`` single key
    * the public half of a locally configured private key (CI/dev only)

    ``AGENT_ED25519_KEY_ID`` selects the active/signing key. A signing node must
    have that kid in the bundle; a verification-only node falls back to the
    first key if it does not.
    """
    keys: dict[str, Any] = {}
    configured = getattr(settings, "ed25519_public_keys", None)
    keys_file = getattr(settings, "ed25519_public_keys_file", None)
    if configured or keys_file:
        if configured:
            payload = configured
        else:
            try:
                payload = json.loads(Path(keys_file).read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise SecurityError(
                    f"cannot read AGENT_ED25519_PUBLIC_KEYS_FILE: {exc}"
                ) from exc
        if not isinstance(payload, dict) or not payload:
            raise SecurityError("AGENT_ED25519_PUBLIC_KEYS must be a non-empty JSON object")
        for kid, material in payload.items():
            name = str(kid).strip()
            if not name:
                raise SecurityError("Ed25519 key set contains an empty key id")
            key = load_public_key(str(material), None)
            if name in keys and public_key_hex(keys[name]) != public_key_hex(key):
                raise SecurityError(f"conflicting public keys for Ed25519 key id {name!r}")
            keys[name] = key

    active = str(getattr(settings, "ed25519_key_id", "default") or "default")
    legacy = getattr(settings, "ed25519_public_key", None) or getattr(
        settings, "ed25519_public_key_file", None
    )
    if legacy:
        key = load_public_key(
            getattr(settings, "ed25519_public_key", None),
            getattr(settings, "ed25519_public_key_file", None),
        )
        if active in keys and public_key_hex(keys[active]) != public_key_hex(key):
            raise SecurityError(
                f"AGENT_ED25519_PUBLIC_KEY conflicts with key id {active!r} in the key set"
            )
        keys[active] = key

    if private_key is not None:
        derived = private_key.public_key()
        if active in keys and public_key_hex(keys[active]) != public_key_hex(derived):
            raise SecurityError(
                f"private key does not match the trusted public key for {active!r}"
            )
        keys[active] = derived

    if not keys:
        raise SecurityError(
            "AGENT_SIGNING_MODE=ed25519 requires AGENT_ED25519_PUBLIC_KEYS(_FILE) "
            "or AGENT_ED25519_PUBLIC_KEY(_FILE) or a private key"
        )
    return PublicKeySet(keys, active_key_id=active if active in keys else None)


def configured_public_key(settings: Any, *, private_key: Any | None = None) -> Any:
    """Load the active public key (compatibility wrapper around the key set)."""
    return configured_key_set(settings, private_key=private_key).active_key


def sign_file(private_key: Any, path: str | Path, signature_path: str | Path | None = None) -> str:
    """Sign a file's exact bytes (used for capability-card manifests)."""
    data = Path(path).read_bytes()
    signature = sign_bytes(private_key, data)
    if signature_path is not None:
        target = Path(signature_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(signature + "\n", encoding="utf-8")
    return signature


def verify_file(public_key: Any, path: str | Path, signature: str) -> bool:
    return verify_bytes(public_key, Path(path).read_bytes(), signature)


def generate_keypair() -> tuple[Any, Any]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def private_key_pem(private_key: Any) -> str:
    from cryptography.hazmat.primitives import serialization

    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def fingerprint(public_key: Any) -> str:
    """Stable key identifier for logs and rotation records."""
    return hashlib.sha256(bytes.fromhex(public_key_hex(public_key))).hexdigest()[:16]
