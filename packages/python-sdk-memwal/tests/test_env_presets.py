"""Tests for the relayer environment presets (prod/dev/staging/local).

Pure config resolution — no network. Any explicit ``server_url`` wins,
including the hosted default. ``env`` applies only when ``server_url`` is ``None``.
"""

import pytest

from memwal import ENV_PRESETS, MemWal, MemWalConfig, MemWalSync
from memwal.types import DEFAULT_SERVER_URL

# A throwaway but structurally valid 32-byte Ed25519 seed (64 hex chars).
KEY = "11" * 32
ACCOUNT = "0x" + "ab" * 32


@pytest.mark.parametrize(
    "env,expected",
    [
        ("prod", "https://relayer.memory.walrus.xyz"),
        ("dev", "https://relayer.dev.memwal.ai"),
        ("staging", "https://relayer-staging.memory.walrus.xyz"),
        ("local", "http://127.0.0.1:8000"),
    ],
)
def test_env_preset_resolves(env, expected):
    cfg = MemWalConfig(key=KEY, account_id=ACCOUNT, env=env)
    assert cfg.server_url == expected
    assert ENV_PRESETS[env] == expected


def test_explicit_server_url_overrides_env():
    cfg = MemWalConfig(
        key=KEY,
        account_id=ACCOUNT,
        server_url="https://my.custom.relayer",
        env="prod",
    )
    assert cfg.server_url == "https://my.custom.relayer"


def test_no_env_keeps_default():
    cfg = MemWalConfig(key=KEY, account_id=ACCOUNT)
    assert cfg.server_url == "https://relayer.memory.walrus.xyz"
    assert cfg.server_url == DEFAULT_SERVER_URL


def test_unknown_env_raises():
    with pytest.raises(ValueError, match="Unknown env preset"):
        MemWalConfig(key=KEY, account_id=ACCOUNT, env="prdo")


def test_create_threads_env_through_to_client():
    client = MemWal.create(key=KEY, account_id=ACCOUNT, env="staging")
    assert client._server_url == "https://relayer-staging.memory.walrus.xyz"


def test_sync_create_threads_env_through():
    client = MemWalSync.create(key=KEY, account_id=ACCOUNT, env="prod")
    assert client._inner._server_url == "https://relayer.memory.walrus.xyz"


def test_explicit_hosted_url_wins_over_env():
    cfg = MemWalConfig(
        key=KEY,
        account_id=ACCOUNT,
        server_url=DEFAULT_SERVER_URL,
        env="local",
    )
    assert cfg.server_url == "https://relayer.memory.walrus.xyz"
