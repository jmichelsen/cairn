"""Unit tests for agent-side logic that isn't just a passthrough - currently the off-peak walk window,
whose wrap-around case is easy to get wrong. Importing agent.py pulls in collector + reads env, which is
harmless (no network until a loop runs)."""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import agent  # noqa: E402


def _window(hour, spec, monkeypatch):
    monkeypatch.setattr(agent, "RECOVER_WALK_HOURS", spec)
    monkeypatch.setattr(agent.time, "localtime",
                        lambda *a: time.struct_time((2026, 9, 13, hour, 0, 0, 0, 0, -1)))
    return agent._in_walk_window()


def test_walk_window_simple(monkeypatch):
    assert _window(3, "1-6", monkeypatch) is True
    assert _window(1, "1-6", monkeypatch) is True    # start inclusive
    assert _window(6, "1-6", monkeypatch) is False   # end exclusive
    assert _window(0, "1-6", monkeypatch) is False


def test_walk_window_wraps_past_midnight(monkeypatch):
    assert _window(23, "22-6", monkeypatch) is True
    assert _window(3, "22-6", monkeypatch) is True
    assert _window(12, "22-6", monkeypatch) is False


def test_walk_window_empty_is_anytime(monkeypatch):
    assert _window(12, "", monkeypatch) is True
    assert _window(3, "  ", monkeypatch) is True


def test_walk_window_bad_spec_does_not_block_forever(monkeypatch):
    assert _window(12, "garbage", monkeypatch) is True
