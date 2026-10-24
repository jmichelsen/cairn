import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "phase1"))


@pytest.fixture(autouse=True)
def _fresh_zfs_allow_cache():
    """collector caches `zfs allow` output for a few minutes; tests reuse dataset names."""
    import collector
    collector._ZALLOW.clear()
    yield
    collector._ZALLOW.clear()


@pytest.fixture(autouse=True)
def _scratch_state_dir(tmp_path, monkeypatch):
    """Agent state (removable last-backup memory etc.) goes to a per-test dir, never ~/.local/state."""
    monkeypatch.setenv("CAIRN_STATE_DIR", str(tmp_path / "state"))
