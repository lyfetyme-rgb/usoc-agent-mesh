"""OIDC/SSO id_token verification for human approvals.

Okta and Entra ID publish RS256/ES256 signing keys as a JWKS document. This
module verifies a detached ``id_token`` against that document with the
``cryptography`` dependency the mesh already ships — no extra JOSE package, and
no cloud SDK. Runtime nodes only need the issuer, audience and JWKS URL; the
private keys stay with the identity provider.

The verifier checks the JOSE header algorithm, key id, signature, issuer,
audience, expiry and not-before claims. It deliberately returns the full claim
set so the caller can bind ``sub`` (or a configured claim) to an entry in the
signed approver registry *and* bind the token to one exact decision (see
``ApprovalVerifier`` and ``oidc_approval_binding``). An identity-only token is
never sufficient to approve a request. JWKS responses are cached for a short
TTL to avoid a network round trip on every approval.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from .security import SecurityError

_JWKS_CACHE: dict[str, tuple[float, dict[str, dict[str, Any]]]] = {}
_JWKS_TTL_S = 300.0


def clear_jwks_cache() -> None:
    """Drop cached JWKS documents (used by tests and key-rotation tooling)."""
    _JWKS_CACHE.clear()


@dataclass(frozen=True)
class OIDCConfig:
    issuer: str
    audience: str
    jwks_url: str
    sub_claim: str = "sub"
    role_claim: str | None = None
    # Claim that carries the approval binding digest. Defaults to the standard
    # OIDC ``nonce`` so no custom IdP claim is required: the human's login flow
    # passes the value printed by ``agents approval-payload --oidc-binding`` as
    # the authorization request nonce, and the provider echoes it in the token.
    binding_claim: str = "nonce"
    leeway_s: int = 60
    timeout_s: float = 5.0

    def __post_init__(self) -> None:
        if not self.issuer or not self.audience or not self.jwks_url:
            raise SecurityError(
                "OIDC verification requires issuer, audience and JWKS URL"
            )
        parsed = urlparse(self.jwks_url)
        if parsed.scheme != "https" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
            raise SecurityError("AGENT_APPROVAL_OIDC_JWKS_URL must use https")
        if not self.sub_claim:
            raise SecurityError("AGENT_APPROVAL_OIDC_SUB_CLAIM must not be empty")
        if not self.binding_claim:
            raise SecurityError("AGENT_APPROVAL_OIDC_BINDING_CLAIM must not be empty")


def _b64decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _load_jwks(config: OIDCConfig) -> dict[str, dict[str, Any]]:
    cached = _JWKS_CACHE.get(config.jwks_url)
    now = time.time()
    if cached and now - cached[0] < _JWKS_TTL_S:
        return cached[1]
    try:
        import httpx

        response = httpx.get(config.jwks_url, timeout=config.timeout_s)
        response.raise_for_status()
        document = response.json()
    except Exception as exc:  # network, TLS and JSON failures all fail closed
        raise SecurityError(f"cannot load OIDC JWKS document: {exc}") from exc
    keys = document.get("keys") if isinstance(document, dict) else None
    if not isinstance(keys, list) or not keys:
        raise SecurityError("OIDC JWKS document contains no keys")
    by_kid: dict[str, dict[str, Any]] = {}
    for key in keys:
        if isinstance(key, dict) and key.get("kid"):
            by_kid[str(key["kid"])] = key
    if not by_kid:
        raise SecurityError("OIDC JWKS document has no key ids")
    _JWKS_CACHE[config.jwks_url] = (now, by_kid)
    return by_kid


def _public_key(jwk: dict[str, Any]) -> Any:
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    kty = jwk.get("kty")
    try:
        if kty == "RSA":
            return rsa.RSAPublicNumbers(
                int.from_bytes(_b64decode(jwk["e"]), "big"),
                int.from_bytes(_b64decode(jwk["n"]), "big"),
            ).public_key()
        if kty == "EC" and jwk.get("crv") == "P-256":
            return ec.EllipticCurvePublicNumbers(
                int.from_bytes(_b64decode(jwk["x"]), "big"),
                int.from_bytes(_b64decode(jwk["y"]), "big"),
                ec.SECP256R1(),
            ).public_key()
    except (KeyError, ValueError, TypeError) as exc:
        raise SecurityError(f"invalid OIDC JWK: {exc}") from exc
    raise SecurityError(f"unsupported OIDC JWK type {kty!r}")


def verify_id_token(token: str, config: OIDCConfig) -> dict[str, Any]:
    """Verify an id_token and return its claims, or raise ``SecurityError``."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    parts = (token or "").strip().split(".")
    if len(parts) != 3:
        raise SecurityError("OIDC id_token is not a compact JWS")
    try:
        header = json.loads(_b64decode(parts[0]))
        claims = json.loads(_b64decode(parts[1]))
    except (ValueError, UnicodeDecodeError) as exc:
        raise SecurityError(f"malformed OIDC id_token: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise SecurityError("malformed OIDC id_token header or claims")

    alg = header.get("alg")
    kid = str(header.get("kid") or "")
    if alg not in ("RS256", "ES256"):
        raise SecurityError(f"unsupported OIDC id_token algorithm {alg!r}")
    if not kid:
        raise SecurityError("OIDC id_token has no key id")
    jwk = _load_jwks(config).get(kid)
    if jwk is None:
        raise SecurityError(f"OIDC id_token key id {kid!r} is not trusted")
    key = _public_key(jwk)
    signed = f"{parts[0]}.{parts[1]}".encode("ascii")
    signature = _b64decode(parts[2])
    try:
        if alg == "RS256":
            if not isinstance(key, rsa.RSAPublicKey):
                raise SecurityError("OIDC id_token RS256 signature uses a non-RSA key")
            key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
        else:
            if not isinstance(key, ec.EllipticCurvePublicKey):
                raise SecurityError("OIDC id_token ES256 signature uses a non-EC key")
            key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise SecurityError("OIDC id_token signature verification failed") from exc

    now = time.time()
    if claims.get("iss") != config.issuer:
        raise SecurityError("OIDC id_token issuer does not match configuration")
    audience = claims.get("aud")
    audiences = audience if isinstance(audience, list) else [audience]
    if config.audience not in audiences:
        raise SecurityError("OIDC id_token audience does not match configuration")
    if "exp" not in claims or float(claims["exp"]) + config.leeway_s <= now:
        raise SecurityError("OIDC id_token has expired")
    if "nbf" in claims and float(claims["nbf"]) - config.leeway_s > now:
        raise SecurityError("OIDC id_token is not yet valid")
    if not claims.get(config.sub_claim):
        raise SecurityError(f"OIDC id_token has no {config.sub_claim!r} claim")
    return claims
