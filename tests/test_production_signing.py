"""Production must never sign evidence with an ephemeral per-process key."""

from __future__ import annotations

import pytest

from agents.config import Settings
from agents.security import SecurityError, build_signer, is_ephemeral_secret, is_local_dev


def _opts(**kwargs):
    return Settings(_env_file=None, **kwargs)


def test_local_dev_may_use_an_ephemeral_key():
    settings = _opts(shared_secret=None, shared_secret_file=None)
    assert is_local_dev(settings) is True
    assert is_ephemeral_secret(settings) is True
    signer = build_signer(settings)
    assert signer is not None  # authenticated in-process, but not durable


def test_redis_bus_requires_a_persistent_key():
    settings = _opts(bus="redis", shared_secret=None, shared_secret_file=None)
    assert is_local_dev(settings) is False
    with pytest.raises(SecurityError, match="AGENT_SHARED_SECRET"):
        build_signer(settings)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"strict_prod": True},
        {"postgres_dsn": "postgresql://localhost/usoc"},
        {"archive_bucket": "usoc-evidence"},
        {"require_persistent_signing_key": True},
    ],
)
def test_multi_pod_configurations_require_a_persistent_key(kwargs):
    settings = _opts(shared_secret=None, shared_secret_file=None, **kwargs)
    assert is_local_dev(settings) is False
    with pytest.raises(SecurityError, match="ephemeral per-process key"):
        build_signer(settings)
    assert is_ephemeral_secret(settings) is False


def test_persistent_key_from_env_is_accepted():
    settings = _opts(
        strict_prod=True,
        shared_secret="a-persistent-cluster-key-with-at-least-32-chars",
    )
    signer = build_signer(settings)
    assert signer is not None
    assert is_ephemeral_secret(settings) is False


def test_ed25519_mode_is_exempt_from_shared_hmac_key():
    from agents.asymmetric import generate_keypair, private_key_pem, public_key_hex

    private, public = generate_keypair()
    settings = _opts(
        signing_mode="ed25519",
        strict_prod=True,
        shared_secret=None,
        shared_secret_file=None,
        ed25519_private_key=private_key_pem(private),
        ed25519_public_key=public_key_hex(public),
    )
    assert is_ephemeral_secret(settings) is False
    assert build_signer(settings) is not None


def test_backend_settings_fail_closed_when_incomplete():
    with pytest.raises(ValueError, match="AGENT_POSTGRES_DSN"):
        _opts(approval_backend="postgres", postgres_dsn=None)
    with pytest.raises(ValueError, match="AGENT_ARCHIVE_BUCKET"):
        _opts(archive_backend="s3", archive_bucket=None)


def test_agent_env_production_requires_a_persistent_key():
    settings = _opts(env="production", shared_secret=None, shared_secret_file=None)
    assert settings.env == "production"
    assert is_local_dev(settings) is False
    with pytest.raises(SecurityError, match="AGENT_SHARED_SECRET"):
        build_signer(settings)


def test_agent_env_is_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("AGENT_ENV", "PRODUCTION")
    monkeypatch.delenv("AGENT_SHARED_SECRET", raising=False)
    monkeypatch.delenv("AGENT_SHARED_SECRET_FILE", raising=False)
    settings = Settings(_env_file=None)
    assert settings.env == "production"
    assert is_local_dev(settings) is False


async def test_serve_refuses_to_listen_without_a_persistent_key(monkeypatch):
    from argparse import Namespace

    from agents.__main__ import _run_serve

    settings = _opts(env="production", shared_secret=None, shared_secret_file=None)
    monkeypatch.setattr("agents.__main__._settings", lambda _args: settings)
    with pytest.raises(SecurityError, match="AGENT_SHARED_SECRET"):
        await _run_serve(Namespace())
