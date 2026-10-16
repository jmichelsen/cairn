"""Env bootstrap tokens: changing a value in the env must revoke the old secret (label is UNIQUE,
so a plain INSERT OR IGNORE used to keep the old row and ignore the new value)."""
import os
import sys
import tempfile

os.environ.setdefault("CAIRN_DB", os.path.join(tempfile.mkdtemp(), "cairn-test.db"))
os.environ.setdefault("CAIRN_ADMIN_TOKEN", "test-admin-token")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "phase1"))
import api  # noqa: E402


def _seed(monkeypatch, admin, agents):
    monkeypatch.setenv("CAIRN_ADMIN_TOKEN", admin)
    monkeypatch.setenv("CAIRN_AGENT_TOKENS", agents)
    api._seed_tokens()


def test_rotating_env_tokens_revokes_the_old_ones(monkeypatch):
    _seed(monkeypatch, "admin-old", "agent-old")
    assert api._lookup_role("admin-old") == "admin"
    assert api._lookup_role("agent-old") == "agent"
    _seed(monkeypatch, "admin-new", "agent-new")
    assert api._lookup_role("admin-new") == "admin"
    assert api._lookup_role("agent-new") == "agent"
    assert api._lookup_role("admin-old") is None
    assert api._lookup_role("agent-old") is None


def test_unchanged_env_keeps_an_admin_revocation(monkeypatch):
    _seed(monkeypatch, "admin-keep", "agent-a,agent-b")
    with api.db() as c:
        c.execute("UPDATE auth_tokens SET active=0 WHERE label='env-agent-1'")
        c.commit()
    _seed(monkeypatch, "admin-keep", "agent-a,agent-b")
    assert api._lookup_role("agent-a") == "agent"
    assert api._lookup_role("agent-b") is None


def test_agent_token_dropped_from_env_is_deactivated(monkeypatch):
    _seed(monkeypatch, "admin-x", "agent-1,agent-2")
    assert api._lookup_role("agent-2") == "agent"
    _seed(monkeypatch, "admin-x", "agent-1")
    assert api._lookup_role("agent-1") == "agent"
    assert api._lookup_role("agent-2") is None
