"""Ed25519 signing: offline private keys, public-key-only runtime verification."""

from __future__ import annotations

import asyncio
import argparse
import json
from pathlib import Path

import pytest

from agents.asymmetric import (
    Ed25519KMSSigner,
    Ed25519Signer,
    Ed25519Verifier,
    PublicKeySet,
    generate_keypair,
    kms_http_signer,
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


def test_keyset_verifies_records_from_retired_and_active_keys():
    old_private, old_public = keypair()
    new_private, new_public = keypair()
    keys = {"2025": old_public, "2026": new_public}
    verifier = Ed25519Verifier(PublicKeySet(keys, active_key_id="2026"))

    old_sig = Ed25519Signer(old_private, key_id="2025").sign_record(
        "evidence", {"a": 1}, "oekp"
    )
    new_sig = Ed25519Signer(new_private, key_id="2026").sign_record(
        "evidence", {"a": 2}, "oekp"
    )
    assert verifier.verify_record("evidence", {"a": 1}, old_sig, "oekp") == (True, "ok")
    assert verifier.verify_record("evidence", {"a": 2}, new_sig, "oekp") == (True, "ok")

    new_only = Ed25519Verifier(PublicKeySet({"2026": new_public}))
    assert new_only.verify_record("evidence", {"a": 1}, old_sig, "oekp")[0] is False
    assert verifier.key_set.describe().keys() == {"2025", "2026"}


def test_keyset_loads_from_settings_json_and_mounted_file(tmp_path: Path):
    old_private, old_public = keypair()
    _, new_public = keypair()
    signature = Ed25519Signer(old_private, key_id="2025").sign_record(
        "evidence", {"a": 1}
    )
    payload = {
        "2025": public_key_hex(old_public),
        "2026": public_key_hex(new_public),
    }

    inline = build_signer(
        Settings(
            signing_mode="ed25519",
            ed25519_public_keys=payload,
            ed25519_key_id="2026",
        )
    )
    assert inline.key_set.active_key_id == "2026"
    assert inline.verify_record("evidence", {"a": 1}, signature) == (True, "ok")
    with pytest.raises(SecurityError):
        inline.sign_record("evidence", {"a": 2})

    path = tmp_path / "trusted_keys.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    from_file = build_signer(
        Settings(
            signing_mode="ed25519",
            ed25519_public_keys_file=path,
            ed25519_key_id="2025",
        )
    )
    assert from_file.key_set.active_key_id == "2025"
    assert from_file.verify_record("evidence", {"a": 1}, signature)[0] is True

    with pytest.raises(SecurityError):
        PublicKeySet({})


def test_signing_nodes_fail_closed_when_active_kid_is_not_trusted():
    private, _public = keypair()
    _, other_public = keypair()

    mismatched = Settings(
        signing_mode="ed25519",
        ed25519_private_key=private_key_pem(private),
        ed25519_public_keys={"2026": public_key_hex(other_public)},
        ed25519_key_id="2026",
    )
    with pytest.raises(SecurityError, match="does not match the trusted public key"):
        build_signer(mismatched)

    with pytest.raises(SecurityError, match="not in the trusted key set"):
        build_signer(
            Settings(
                signing_mode="ed25519",
                ed25519_public_keys={"2025": public_key_hex(other_public)},
                ed25519_key_id="2026",
                kms_sign_url="https://kms.invalid/sign",
            )
        )


def test_kms_rejects_a_key_id_that_is_not_in_the_trust_bundle(monkeypatch):
    import httpx

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"signature": "ab" * 64, "key_id": "rogue"}

    monkeypatch.setattr(httpx, "post", lambda *args, **kwargs: FakeResponse())
    sign = kms_http_signer("https://kms.invalid/sign", allowed_key_ids={"2026"})
    with pytest.raises(SecurityError, match="untrusted key_id"):
        sign(b"payload")


def test_capability_card_signed_by_retired_key_still_verifies(tmp_path: Path):
    old_private, old_public = keypair()
    _, new_public = keypair()
    cards = tmp_path / "subsystems.yaml"
    cards.write_text("subsystems: []\n", encoding="utf-8")
    signature = sign_file(old_private, cards)

    settings = Settings(
        signing_mode="ed25519",
        ed25519_public_keys={
            "2025": public_key_hex(old_public),
            "2026": public_key_hex(new_public),
        },
        ed25519_key_id="2026",
        subsystems_signature_ed25519=signature,
        require_subsystems_integrity=True,
    )
    assert verify_subsystems_file(cards, settings)

    new_only = Settings(
        signing_mode="ed25519",
        ed25519_public_keys={"2026": public_key_hex(new_public)},
        ed25519_key_id="2026",
        subsystems_signature_ed25519=signature,
    )
    with pytest.raises(SecurityError, match="Ed25519 signature verification failed"):
        verify_subsystems_file(cards, new_only)


def test_evidence_chain_from_two_signing_keys_verifies_with_the_keyset(tmp_path: Path):
    old_private, old_public = keypair()
    new_private, new_public = keypair()
    path = tmp_path / "chain.jsonl"

    async def run():
        first = EvidenceChain(path, signer=Ed25519Signer(old_private, key_id="2025"))
        await first.append(kind="test", actor="oekp", subsystem="oekp", data={"era": "old"})
        keyset = PublicKeySet(
            {"2025": old_public, "2026": new_public}, active_key_id="2026"
        )
        # The writer needs the same trust bundle to verify the existing chain
        # on load, while signing new records with the active key.
        second = EvidenceChain(
            path, signer=Ed25519Signer(new_private, key_id="2026", key_set=keyset)
        )
        await second.append(kind="test", actor="oekp", subsystem="oekp", data={"era": "new"})
        return EvidenceChain(path, signer=Ed25519Verifier(keyset)).verify()

    ok, detail = asyncio.run(run())
    assert ok, detail


def test_keygen_can_write_a_keyset_bundle(tmp_path: Path):
    from agents.__main__ import cmd_keygen

    private_path = tmp_path / "keys" / "private.pem"
    public_path = tmp_path / "keys" / "public.hex"
    keyset_path = tmp_path / "trust" / "keys.json"
    assert (
        cmd_keygen(
            argparse.Namespace(
                private_key_file=str(private_path),
                public_key_file=str(public_path),
                key_id="2026",
                keyset_file=str(keyset_path),
            )
        )
        == 0
    )
    assert json.loads(keyset_path.read_text(encoding="utf-8")).keys() == {"2026"}

