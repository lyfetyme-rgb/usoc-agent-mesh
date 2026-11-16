"""Ed25519 signing: offline private keys, public-key-only runtime verification."""

from __future__ import annotations

import asyncio
import argparse
from pathlib import Path

import pytest

from agents.asymmetric import (
    Ed25519KMSSigner,
    Ed25519Signer,
    Ed25519Verifier,
    generate_keypair,
    load_public_key,
    private_key_pem,
    public_key_hex,
    sign_file,
    verify_file,
)
from agents.config import Settings, verify_subsystems_file
from agents.contracts import Message
from agents.evidence import EvidenceChain
from agents.security import SecurityError, build_signer


def keypair():
    private, public = generate_keypair()
    return private, public


def test_sign_and_verify_a_record_with_only_the_public_key():
    private, public = keypair()
    signer = Ed25519Signer(private)
    verifier = Ed25519Verifier(public)

    signature = signer.sign_record("evidence", {"kind": "test", "ok": True}, "oekp")
    assert len(signature) == 128
    assert verifier.verify_record("evidence", {"kind": "test", "ok": True}, signature, "oekp") == (True, "ok")


def test_tampering_identity_scope_or_body_fails_verification():
    private, public = keypair()
    signer = Ed25519Signer(private)
    verifier = Ed25519Verifier(public)
    body = {"kind": "test", "ok": True}
    signature = signer.sign_record("evidence", body, "oekp")

    assert verifier.verify_record("approval", body, signature, "oekp")[0] is False
    assert verifier.verify_record("evidence", body, signature, "bengal")[0] is False
    assert verifier.verify_record("evidence", {"kind": "test", "ok": False}, signature, "oekp")[0] is False


def test_a_different_public_key_cannot_verify():
    private, _ = keypair()
    _, other_public = keypair()
    signature = Ed25519Signer(private).sign_record("evidence", {"a": 1})
    assert Ed25519Verifier(other_public).verify_record("evidence", {"a": 1}, signature)[0] is False


def test_verification_only_nodes_refuse_to_sign():
    _, public = keypair()
    verifier = Ed25519Verifier(public)
    with pytest.raises(SecurityError, match="public key"):
        verifier.sign_record("evidence", {"a": 1})


def test_message_signatures_round_trip_and_reject_edits():
    private, public = keypair()
    signer = Ed25519Signer(private)
    verifier = Ed25519Verifier(public)
    message = Message.task(sender="client", recipient="worker", objective="do the work")

    signed = signer.sign_message(message)
    assert verifier.verify_message(signed) == (True, "ok")

    tampered = signed.model_copy(
        update={"payload": signed.payload.model_copy(update={"objective": "do something else"})}
    )
    assert verifier.verify_message(tampered)[0] is False


def test_build_signer_prefers_a_local_private_key_for_signing():
    private, public = keypair()
    settings = Settings(
        signing_mode="ed25519",
        ed25519_private_key=private_key_pem(private),
        ed25519_public_key=public_key_hex(public),
        ed25519_key_id="ci-2026-11",
    )
    signer = build_signer(settings)
    assert isinstance(signer, Ed25519Signer)
    assert signer.key_id == "ci-2026-11"
    signature = signer.sign_record("evidence", {"a": 1})
    assert Ed25519Verifier(public).verify_record("evidence", {"a": 1}, signature)[0]


def test_build_signer_returns_a_verifier_when_only_the_public_key_is_present():
    _, public = keypair()
    settings = Settings(signing_mode="ed25519", ed25519_public_key=public_key_hex(public))
    verifier = build_signer(settings)
    assert isinstance(verifier, Ed25519Verifier)
    with pytest.raises(SecurityError):
        verifier.sign_record("message", {"a": 1})


def test_kms_signer_never_holds_the_private_key():
    private, public = keypair()

    def kms_sign(payload: bytes) -> bytes:
        # A real KMS would do this inside its HSM boundary; the test stands in
        # for it without ever exposing the key to Ed25519KMSSigner.
        return private.sign(payload)

    signer = Ed25519KMSSigner(public, kms_sign, key_id="kms-2026")
    signature = signer.sign_record("approval", {"id": "apr-1"}, "alice")
    assert Ed25519Verifier(public).verify_record("approval", {"id": "apr-1"}, signature, "alice")[0]


def test_detached_ed25519_signature_pins_the_capability_cards(tmp_path: Path):
    private, public = keypair()
    cards = tmp_path / "subsystems.yaml"
    cards.write_text("subsystems: []\n", encoding="utf-8")
    signature_path = tmp_path / "subsystems.yaml.sig"
    sign_file(private, cards, signature_path)

    settings = Settings(
        signing_mode="ed25519",
        ed25519_public_key=public_key_hex(public),
        subsystems_signature_file=signature_path,
        require_subsystems_integrity=True,
    )
    assert verify_subsystems_file(cards, settings)

    cards.write_text("subsystems: [evil]\n", encoding="utf-8")
    with pytest.raises(SecurityError, match="Ed25519"):
        verify_subsystems_file(cards, settings)


def test_evidence_chain_verifies_with_the_public_key_only(tmp_path: Path):
    private, public = keypair()
    path = tmp_path / "chain.jsonl"

    async def run():
        chain = EvidenceChain(path, signer=Ed25519Signer(private))
        await chain.append(kind="test", actor="oekp", subsystem="oekp", data={"a": 1})
        return EvidenceChain(path, signer=Ed25519Verifier(public)).verify()

    ok, detail = asyncio.run(run())
    assert ok, detail


def test_keygen_and_sign_config_cli_workflow(tmp_path: Path):
    from agents.__main__ import cmd_keygen, cmd_sign_config

    cards = tmp_path / "subsystems.yaml"
    cards.write_text("subsystems: []\n", encoding="utf-8")
    private_path = tmp_path / "keys" / "ed25519_private.pem"
    public_path = tmp_path / "keys" / "ed25519_public.hex"
    signature_path = tmp_path / "subsystems.yaml.sig"

    assert (
        cmd_keygen(
            argparse.Namespace(
                private_key_file=str(private_path), public_key_file=str(public_path)
            )
        )
        == 0
    )
    assert private_path.is_file() and public_path.is_file()

    assert (
        cmd_sign_config(
            argparse.Namespace(
                registry=str(cards),
                workspace=None,
                json_logs=False,
                key_file=str(private_path),
                out=str(signature_path),
            )
        )
        == 0
    )
    public_key = load_public_key(public_path.read_text(encoding="utf-8").strip(), None)
    assert verify_file(
        public_key, cards, signature_path.read_text(encoding="utf-8").strip()
    )
