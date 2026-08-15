import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from loginshield import Config, Guard, Store  # noqa: E402


class FakeClock:
    """Steuerbare Uhr - damit Tests keine echten Wartezeiten brauchen."""

    def __init__(self, start: float = 1_700_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> float:
        self.now += seconds
        return self.now


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def config(tmp_path):
    cfg = Config()
    cfg.db_path = str(tmp_path / "test.db")
    cfg.allowlist = []
    cfg.identity_hmac_key = "test-key"
    return cfg


@pytest.fixture
def store(config):
    store = Store(
        config.db_path,
        identity_mode=config.identity_mode,
        identity_hmac_key=config.identity_hmac_key,
    )
    yield store
    store.close()


@pytest.fixture
def guard(config, clock, store):
    guard = Guard(config, store, clock=clock)
    yield guard
    guard.close()
