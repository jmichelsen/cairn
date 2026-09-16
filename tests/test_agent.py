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


def _capture(monkeypatch, tmp_path):
    """Point the detached-job registry + state dir at tmp and record every api_call POST."""
    posts = []
    monkeypatch.setattr(agent.C, "_cairn_state_dir", lambda: str(tmp_path))
    monkeypatch.setattr(agent, "api_call", lambda m, p, b=None: posts.append((m, p, b)) or {})
    monkeypatch.setattr(agent, "NAME", "local")
    return posts


def test_jobs_registry_roundtrip(monkeypatch, tmp_path):
    _capture(monkeypatch, tmp_path)
    agent._jobs_add(7, {"removable": "seagate", "out": "/x.out"})
    assert agent._jobs_load()["7"]["removable"] == "seagate"
    agent._jobs_del(7)
    assert agent._jobs_load() == {}


def test_reap_reports_and_stamps_when_done(monkeypatch, tmp_path):
    posts = _capture(monkeypatch, tmp_path)
    out = tmp_path / "job-9.out"; out.write_text("=== mcz/Pics ===\nsent 10 bytes\n")
    done = tmp_path / "job-9.done"; done.write_text("0\n")
    stamp = tmp_path / "s"; stamp.write_text("1700000000")
    agent._jobs_add(9, {"removable": "seagate", "out": str(out), "done": str(done),
                        "datasets": [{"name": "mcz/Pics", "stamp": str(stamp)}], "started": 1})
    agent._reap_detached()
    stamps = [b for m, p, b in posts if p.endswith("/removable-links")]
    results = [b for m, p, b in posts if p.endswith("/result")]
    assert stamps and stamps[0]["dataset"] == "mcz/Pics" and stamps[0]["ts"] == 1700000000
    assert results and results[0]["ok"] is True and "mcz/Pics" in results[0]["output"]
    assert agent._jobs_load() == {}                 # registry cleared
    assert not out.exists() and not done.exists()   # files cleaned up


def test_reap_reports_failure_on_nonzero_rc(monkeypatch, tmp_path):
    posts = _capture(monkeypatch, tmp_path)
    out = tmp_path / "job-3.out"; out.write_text("rsync: error\n")
    done = tmp_path / "job-3.done"; done.write_text("23\n")
    agent._jobs_add(3, {"removable": "seagate", "out": str(out), "done": str(done), "datasets": [], "started": 1})
    agent._reap_detached()
    results = [b for m, p, b in posts if p.endswith("/result")]
    assert results and results[0]["ok"] is False
    assert agent._jobs_load() == {}


def test_reap_leaves_unfinished_job_untouched(monkeypatch, tmp_path):
    posts = _capture(monkeypatch, tmp_path)
    agent._jobs_add(5, {"removable": "seagate", "out": str(tmp_path / "job-5.out"),
                        "done": str(tmp_path / "job-5.done"), "datasets": [], "started": int(time.time())})
    agent._reap_detached()
    # no result posted (job not done); still tracked. A progress post is fine but must not be a /result.
    assert all(not p.endswith("/result") for m, p, b in posts)
    assert "5" in agent._jobs_load()


def test_reap_posts_progress_for_running_job(monkeypatch, tmp_path):
    posts = _capture(monkeypatch, tmp_path)
    out = tmp_path / "job-8.out"
    out.write_text("=== mcz/Pics ===\r     1.23G  45%   12.34MB/s    0:12:34\r")
    cur = tmp_path / "job-8.cur"; cur.write_text("mcz/Pics\n")
    agent._jobs_add(8, {"removable": "seagate", "out": str(out), "done": str(tmp_path / "job-8.done"),
                        "cur": str(cur), "nlinks": 2, "datasets": [], "started": int(time.time())})
    agent._reap_detached()
    prog = [b for m, p, b in posts if p.endswith("/progress")]
    assert prog, "expected a progress post for the running job"
    assert prog[0]["pct"] == 45 and prog[0]["eta"] == "0:12:34"
    assert prog[0]["label"] == "mcz/Pics" and prog[0]["total"] == 2
    assert "8" in agent._jobs_load()      # still running, still tracked
