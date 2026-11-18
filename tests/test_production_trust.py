"""Production trust: per-coordinator bus keys, signed approvers, strict doctor."""

from __future__ import annotations

import base64
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from agents import __main__ as cli
from agents.asymmetric import (
    generate_keypair,
    private_key_pem,
    public_key_hex,
    sign_bytes,
)
from agents.config import Settings
from agents.contracts import ActionClass, Classification, Message, RiskLevel
from agents.evidence import EvidenceChain
from agents.governance import (
    ApprovalCredential,
    ApprovalRequest,
    ApprovalStatus,
    FileApprovalStore,
    InMemoryApprovalStore,
    PolicyConfig,
    PolicyEngine,
    tier_allows,
)
from agents.oidc import OIDCConfig, clear_jwks_cache, verify_id_token
from agents.security import SecurityError, Signer
from agents.trust import (
    ApprovalVerifier,
    CoordinatorKeyring,
    approval_credential_payload,
    build_approval_verifier,
    build_message_authority,
    load_approver_registry,
    validate_strict_prod,
)

ROOT = Path(__file__).resolve().parents[1]


# -- fixtures ----------------------------------------------------------------

def _bus_bundle(tmp_path: Path):
    private_a, public_a = generate_keypair()
    private_b, public_b = generate_keypair()
    bundle = {
        "seraphim": {"seraphim-1": public_key_hex(public_a)},
        "bengal": {"bengal-1": public_key_hex(public_b)},
    }
    path = tmp_path / "bus_keys.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    key_path = tmp_path / "seraphim.pem"
    key_path.write_text(private_key_pem(private_a), encoding="utf-8")
    return path, key_path, private_b


def _registry_files(tmp_path: Path, max_tier: str = "high", name: str = "approvers"):
    registry_private, registry_public = generate_keypair()
    approver_private, approver_public = generate_keypair()
    entries = {
        "alice": {
            "role": "commander",
            "public_key": public_key_hex(approver_public),
            "max_tier": max_tier,
        }
    }
    path = tmp_path / f"{name}.json"
    data = json.dumps(entries, indent=2).encode("utf-8")
    path.write_bytes(data)
    sig_path = tmp_path / f"{name}.json.sig"
    sig_path.write_text(sign_bytes(registry_private, data) + "\n", encoding="utf-8")
    public_path = tmp_path / f"{name}_public.hex"
    public_path.write_text(public_key_hex(registry_public) + "\n", encoding="utf-8")
    return path, sig_path, public_path, approver_private


def _settings(tmp_path: Path, **overrides) -> Settings:
    return Settings(
        subsystems_file=ROOT / "subsystems.yaml",
        workspace=tmp_path / "workspace",
        log_level="CRITICAL",
        **overrides,
    )


def _registry_settings(tmp_path: Path, **overrides) -> Settings:
    path, sig_path, public_path, _ = _registry_files(tmp_path)
    return _settings(
        tmp_path,
        approver_registry_file=path,
        approver_registry_signature_file=sig_path,
        approver_registry_public_key_file=public_path,
        approvers="alice",
        **overrides,
    )


# -- per-coordinator bus signing ---------------------------------------------

def test_keyring_signs_only_as_the_configured_coordinator(tmp_path):
    path, key_path, other_private = _bus_bundle(tmp_path)
    settings = _settings(
        tmp_path,
        bus_public_keys_file=path,
        bus_signing_agent="seraphim",
        bus_signing_kid="seraphim-1",
        max_message_age_s=60,
        bus_signing_key_file=key_path,
    )
    keyring = build_message_authority(settings)
    assert isinstance(keyring, CoordinatorKeyring)

    msg = Message.task(sender="seraphim", recipient="oekp", objective="x")
    signed = keyring.sign_message(msg)
    assert signed.signature_alg == "ed25519"
    assert signed.signing_kid == "seraphim-1"
    assert keyring.verify_message(signed) == (True, "ok")

    # A compromised low-privilege worker holds only its own key: it cannot sign
    # as another coordinator because the keyring has no signer for that sender.
    with pytest.raises(SecurityError, match="no managed signing key"):
        keyring.sign_message(msg.model_copy(update={"sender": "bengal"}))
    # Holding a key for another identity does not grant a signing slot either.
    assert other_private is not None


def test_keyring_rejects_sender_kid_and_algorithm_forgery(tmp_path):
    path, key_path, _ = _bus_bundle(tmp_path)
    settings = _settings(
        tmp_path,
        bus_public_keys_file=path,
        bus_signing_agent="seraphim",
        bus_signing_kid="seraphim-1",
        bus_signing_key_file=key_path,
    )
    keyring = CoordinatorKeyring.load(settings)
    signed = keyring.sign_message(
        Message.event(sender="seraphim", name="event", data={"text": "ok"})
    )

    ok, detail = keyring.verify_message(signed.model_copy(update={"sender": "hitl"}))
    assert not ok and "unknown coordinator" in detail
    ok, detail = keyring.verify_message(signed.model_copy(update={"signing_kid": "bengal-1"}))
    assert not ok and "untrusted key id" in detail
    ok, detail = keyring.verify_message(signed.model_copy(update={"signature_alg": "hmac"}))
    assert not ok and "unexpected message algorithm" in detail
    ok, _ = keyring.verify_message(signed.model_copy(update={"topic": "mesh:evil"}))
    assert not ok


def test_keyring_enforces_message_freshness(tmp_path):
    path, key_path, _ = _bus_bundle(tmp_path)
    settings = _settings(
        tmp_path,
        bus_public_keys_file=path,
        bus_signing_agent="seraphim",
        bus_signing_kid="seraphim-1",
        bus_signing_key_file=key_path,
        max_message_age_s=1,
    )
    keyring = CoordinatorKeyring.load(settings)
    old = Message.event(sender="seraphim", name="event", data={"text": "ok"}).model_copy(
        update={"created_at": datetime.now(timezone.utc) - timedelta(minutes=5)}
    )
    ok, detail = keyring.verify_message(keyring.sign_message(old))
    assert not ok and "too old" in detail


def test_strict_prod_requires_managed_bus_keys(tmp_path):
    settings = _settings(tmp_path, strict_prod=True)
    with pytest.raises(SecurityError, match="BUS_PUBLIC_KEYS"):
        build_message_authority(settings)


def test_strict_prod_rejects_symmetric_cluster_signing(tmp_path):
    settings = _settings(
        tmp_path, strict_prod=True, shared_secret_file=tmp_path / "shared"
    )
    problems = validate_strict_prod(settings)
    assert "AGENT_SIGNING_MODE=ed25519 is required" in problems


# -- signed approver registry and detached credentials -----------------------

def test_signed_registry_loads_and_tampering_fails(tmp_path):
    settings = _registry_settings(tmp_path)
    registry = load_approver_registry(settings)
    assert registry is not None
    assert registry.get("alice").role == "commander"
    assert registry.signature_kid is not None

    raw = settings.approver_registry_file.read_bytes()
    settings.approver_registry_file.write_bytes(raw.replace(b"alice", b"mallory"))
    with pytest.raises(SecurityError, match="signature verification failed"):
        load_approver_registry(settings)


def test_detached_signature_approval_and_tamper(tmp_path):
    settings = _registry_settings(tmp_path)
    registry = load_approver_registry(settings)
    verifier = build_approval_verifier(settings, registry)
    assert verifier is not None and verifier.require_credential is False

    # Recreate the registry so we own the matching approver private key.
    path, sig_path, public_path, approver_private = _registry_files(tmp_path, name="detached")
    settings = _settings(
        tmp_path,
        approver_registry_file=path,
        approver_registry_signature_file=sig_path,
        approver_registry_public_key_file=public_path,
    )
    registry = load_approver_registry(settings)
    verifier = build_approval_verifier(settings, registry)

    req = ApprovalRequest(
        action_class=ActionClass.EXECUTE,
        target="sandbox/node-1",
        risk=RiskLevel.HIGH,
        requested_by="seraphim",
        status=ApprovalStatus.APPROVED,
        decided_by="alice",
    )
    payload = approval_credential_payload(req, approved=True, approver="alice")
    valid = sign_bytes(approver_private, payload)
    req.credential = ApprovalCredential(kind="detached", signature=valid)
    result = verifier("alice", req)
    assert result.verified and result.method == "detached"
    assert result.role == "commander" and result.max_tier is RiskLevel.HIGH

    # Flip the first hex character deterministically: replacing the tail with
    # "00" was a no-op whenever the random signature already ended in "00".
    tampered = ("0" if valid[0] != "0" else "1") + valid[1:]
    req.credential = ApprovalCredential(kind="detached", signature=tampered)
    assert not verifier("alice", req).verified
    assert not verifier("mallory", req).verified


def test_max_tier_blocks_high_risk_actions(tmp_path):
    settings = _registry_settings(tmp_path)
    registry = load_approver_registry(settings)
    verifier = build_approval_verifier(settings, registry)
    store = InMemoryApprovalStore(signer=Signer("x" * 32), approvers={"alice"})
    store.approver_verifier = verifier

    import asyncio

    req = ApprovalRequest(
        action_class=ActionClass.EXECUTE,
        target="sandbox/node-1",
        risk=RiskLevel.CRITICAL,
        requested_by="seraphim",
    )
    saved = asyncio.run(store.request(req))
    assert tier_allows(RiskLevel.HIGH, RiskLevel.HIGH)
    assert not tier_allows(RiskLevel.HIGH, RiskLevel.CRITICAL)

    policy = PolicyEngine(PolicyConfig(), store, registry)
    before = asyncio.run(
        policy.evaluate(
            action=ActionClass.EXECUTE,
            target="sandbox/node-1",
            risk=RiskLevel.CRITICAL,
            mission_id=None,
            classification=Classification.INTERNAL,
            approval_ref=saved.id,
            requested_by="seraphim",
        )
    )
    assert before.approval_ref == saved.id  # pending -> HOLD

    asyncio.run(
        store.decide(saved.id, approved=True, approver="alice")
    )
    decision = asyncio.run(
        policy.evaluate(
            action=ActionClass.EXECUTE,
            target="sandbox/node-1",
            risk=RiskLevel.CRITICAL,
            mission_id=None,
            classification=Classification.INTERNAL,
            approval_ref=saved.id,
            requested_by="seraphim",
        )
    )
    assert not decision.allowed
    assert "may authorize at most" in " ".join(decision.reasons)


# -- OIDC id_token verification ----------------------------------------------

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _fake_jwks(monkeypatch, key, kid: str) -> None:
    numbers = key.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "kid": kid,
        "n": _b64u(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        "e": _b64u(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
    }

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"keys": [jwk]}

    monkeypatch.setattr(httpx, "get", lambda *a, **k: Response())


def _jwt(key, kid: str, claims: dict) -> str:
    header = _b64u(json.dumps({"alg": "RS256", "kid": kid}).encode())
    body = _b64u(json.dumps(claims).encode())
    signing = f"{header}.{body}"
    return f"{signing}.{_b64u(key.sign(signing.encode(), padding.PKCS1v15(), hashes.SHA256()))}"


def test_oidc_id_token_verification(monkeypatch):
    clear_jwks_cache()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _fake_jwks(monkeypatch, key, "okta-1")
    config = OIDCConfig(
        issuer="https://example.okta.com/oauth2/default",
        audience="usoc-mesh",
        jwks_url="https://example.okta.com/oauth2/default/v1/keys",
    )
    token = _jwt(
        key,
        "okta-1",
        {
            "iss": config.issuer,
            "aud": config.audience,
            "exp": time.time() + 600,
            "sub": "alice",
        },
    )
    assert verify_id_token(token, config)["sub"] == "alice"

    token = _jwt(
        key,
        "okta-1",
        {
            "iss": config.issuer,
            "aud": "someone-else",
            "exp": time.time() + 600,
            "sub": "alice",
        },
    )
    with pytest.raises(SecurityError, match="audience"):
        verify_id_token(token, config)


def test_oidc_approval_verifier_binds_subject_to_registry(tmp_path, monkeypatch):
    clear_jwks_cache()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _fake_jwks(monkeypatch, key, "entra-1")
    settings = _registry_settings(
        tmp_path,
        approval_credential_mode="oidc",
        approval_oidc_issuer="https://login.example.com/tenant",
        approval_oidc_audience="usoc-mesh",
        approval_oidc_jwks_url="https://login.example.com/tenant/keys",
    )
    registry = load_approver_registry(settings)
    verifier = build_approval_verifier(settings, registry)
    assert isinstance(verifier, ApprovalVerifier)

    req = ApprovalRequest(
        action_class=ActionClass.EXECUTE,
        target="sandbox/node-1",
        risk=RiskLevel.HIGH,
        requested_by="seraphim",
        status=ApprovalStatus.APPROVED,
        decided_by="alice",
    )
    token = _jwt(
        key,
        "entra-1",
        {
            "iss": settings.approval_oidc_issuer,
            "aud": settings.approval_oidc_audience,
            "exp": time.time() + 600,
            "sub": "alice",
        },
    )
    req.credential = ApprovalCredential(kind="oidc", id_token=token)
    result = verifier("alice", req)
    assert result.verified and result.method == "oidc"
    assert not verifier("bob", req).verified


# -- strict doctor ------------------------------------------------------------

def test_doctor_fails_closed_in_strict_prod(tmp_path, monkeypatch, capsys):
    settings = _settings(tmp_path, strict_prod=True)
    monkeypatch.setattr(cli, "_settings", lambda args: settings)
    args = cli.build_parser().parse_args(["doctor"])
    assert cli.cmd_doctor(args) == 1
    out = capsys.readouterr().out
    assert "strict production" in out
    assert "BUS_PUBLIC_KEYS_FILE" in out
    assert "APPROVER_REGISTRY_FILE" in out


def test_doctor_passes_with_full_production_trust(tmp_path, monkeypatch, capsys):
    bus_path, bus_key, _ = _bus_bundle(tmp_path)
    # Restricted control-plane topics are pinned to both owning coordinators.
    _, hitl_public = generate_keypair()
    bus_bundle = json.loads(bus_path.read_text(encoding="utf-8"))
    bus_bundle["hitl"] = {"hitl-1": public_key_hex(hitl_public)}
    bus_path.write_text(json.dumps(bus_bundle), encoding="utf-8")
    reg_path, sig_path, pub_path, _ = _registry_files(tmp_path)
    mesh_private, mesh_public = generate_keypair()
    mesh_pub_path = tmp_path / "mesh_public.hex"
    mesh_pub_path.write_text(public_key_hex(mesh_public) + "\n", encoding="utf-8")
    mesh_key_path = tmp_path / "mesh_private.pem"
    mesh_key_path.write_text(private_key_pem(mesh_private), encoding="utf-8")
    bundle_path = tmp_path / "mesh_keys.json"
    bundle_path.write_text(json.dumps({"mesh-1": public_key_hex(mesh_public)}), encoding="utf-8")

    settings = _settings(
        tmp_path,
        strict_prod=True,
        signing_mode="ed25519",
        ed25519_public_keys_file=bundle_path,
        ed25519_private_key_file=mesh_key_path,
        ed25519_key_id="mesh-1",
        bus_public_keys_file=bus_path,
        bus_signing_agent="seraphim",
        bus_signing_kid="seraphim-1",
        bus_signing_key_file=bus_key,
        approver_registry_file=reg_path,
        approver_registry_signature_file=sig_path,
        approver_registry_public_key_file=pub_path,
        approvers="alice",
    )
    assert validate_strict_prod(settings) == []
    monkeypatch.setattr(cli, "_settings", lambda args: settings)
    args = cli.build_parser().parse_args(["doctor"])
    assert cli.cmd_doctor(args) == 0
    out = capsys.readouterr().out
    assert "per-coordinator Ed25519" in out
    assert "signed approvers" in out


def test_cli_approval_logs_verification_to_oekp(tmp_path, monkeypatch):
    import asyncio

    settings = _registry_settings(tmp_path, approval_require_credential=True)
    settings.workspace.mkdir(parents=True, exist_ok=True)
    signer = Signer("x" * 32)
    path, sig_path, public_path, approver_private = _registry_files(
        tmp_path, name="cli-approvers"
    )
    settings.approver_registry_file = path
    settings.approver_registry_signature_file = sig_path
    settings.approver_registry_public_key_file = public_path
    verifier = build_approval_verifier(settings, load_approver_registry(settings))

    store = FileApprovalStore(
        settings.workspace / "approvals.json",
        signer=signer,
        approvers={"alice"},
        approver_verifier=verifier,
    )
    req = asyncio.run(
        store.request(
            ApprovalRequest(
                action_class=ActionClass.EXECUTE,
                target="sandbox/node-1",
                risk=RiskLevel.HIGH,
                requested_by="seraphim",
            )
        )
    )
    payload = approval_credential_payload(req, approved=True, approver="alice")
    signature = sign_bytes(approver_private, payload)

    monkeypatch.setattr(cli, "_settings", lambda args: settings)
    monkeypatch.setattr(cli, "_signer", lambda s: signer)
    rc = cli.main(
        [
            "--workspace",
            str(settings.workspace),
            "approve",
            req.id,
            "--by",
            "alice",
            "--signature",
            signature,
        ]
    )
    assert rc == 0
    chain = EvidenceChain(settings.workspace / "evidence" / "chain.jsonl", signer=signer)
    records = chain.records()
    assert any(r.kind == "approval.verification" for r in records)
    verification = next(r for r in records if r.kind == "approval.verification")
    assert verification.data["verified"] is True
    assert verification.data["method"] == "detached"
    assert chain.verify()[0] is True
