"""Unit tests for the dashboard's server-side rendering that has repeatedly regressed: capability-
aware action buttons, viewer read-only gating, and the scrub progress bar. Uses an isolated temp DB
so importing the app (which runs _init_db at import time) never touches a real database."""
import json
import os
import sys
import tempfile

os.environ.setdefault("CAIRN_DB", os.path.join(tempfile.mkdtemp(), "cairn-test.db"))
os.environ.setdefault("CAIRN_ADMIN_TOKEN", "test-admin-token")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "phase1"))
import api  # noqa: E402


def _row(source, caps=None, scrub=None, typ="zfs-local", sev="OK"):
    detail = {"reasons": []}
    if caps is not None:
        detail["caps"] = caps
    if scrub is not None:
        detail["scrub"] = scrub
    return {"name": "t", "type": typ, "source": source, "severity": sev,
            "agent": "a", "detail_json": json.dumps(detail)}


# ---- capability-aware buttons ----------------------------------------------------------------
def test_no_snapshot_button_without_cap():
    h = api._acts(_row("rpool", caps={"snapshot": False, "scrub": True}), can_act=True, viewer=False)
    assert ">Snapshot<" not in h and ">Scrub<" in h


def test_child_dataset_has_no_scrub_button():
    h = api._acts(_row("mcz/mclife/wyze", caps={"snapshot": True, "scrub": False}), True, False)
    assert ">Snapshot<" in h and ">Scrub<" not in h


def test_pool_root_with_both_caps():
    h = api._acts(_row("mcz", caps={"snapshot": True, "scrub": True}), True, False)
    assert ">Snapshot<" in h and ">Scrub<" in h


def test_missing_caps_defaults_to_showing():
    # a pre-caps agent reports no caps map at all -> keep the old behaviour (buttons shown)
    h = api._acts(_row("mcz"), True, False)
    assert ">Snapshot<" in h and ">Scrub<" in h


# ---- read-only viewer gating -----------------------------------------------------------------
def test_viewer_gets_no_controls():
    assert api._acts(_row("mcz", caps={"snapshot": True, "scrub": True}), False, True) == ""


# ---- scrub progress bar ----------------------------------------------------------------------
def test_card_shows_scrub_bar_and_disables_button_while_running():
    row = _row("iwolf", caps={"snapshot": True, "scrub": True},
               scrub={"state": "in_progress", "pct": 42.5, "eta": "01:00:00"})
    h = api._card(row, can_act=True, viewer=False)
    assert "data-scrubprog" in h and "42.5%" in h
    assert "data-scrub disabled" in h  # the button can't be re-triggered mid-run


def test_card_scrub_button_active_when_idle():
    row = _row("iwolf", caps={"snapshot": True, "scrub": True}, scrub={"state": "finished"})
    h = api._card(row, can_act=True, viewer=False)
    assert "data-scrub disabled" not in h and ">Scrub<" in h


# ---- hide / unhide ---------------------------------------------------------------------------
def test_card_has_hide_button_for_admin_not_viewer():
    row = dict(_row("mcz", caps={"snapshot": True, "scrub": True}))
    row["target_id"] = 123
    assert ">Hide<" in api._card(dict(row), can_act=True, viewer=False)
    assert ">Hide<" not in api._card(dict(row), can_act=False, viewer=True)


def _seed_target(name="junkpool", agent="local"):
    with api.db() as conn:
        tid = conn.execute(
            "INSERT INTO targets(name,type,source,agent,enabled) VALUES(?,?,?,?,1) RETURNING id",
            (name, "zfs-local", name, agent)).fetchone()[0]
        conn.commit()
    return tid


def test_hide_then_unhide_roundtrip():
    tid = _seed_target("hidepool")
    api.hide_target(tid)
    with api.db() as conn:
        assert conn.execute("SELECT enabled FROM targets WHERE id=?", (tid,)).fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM target_retired WHERE name=?", ("hidepool",)).fetchone()[0] == 1
    api.unhide_target(tid)
    with api.db() as conn:
        assert conn.execute("SELECT enabled FROM targets WHERE id=?", (tid,)).fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM target_retired WHERE name=?", ("hidepool",)).fetchone()[0] == 0


# ---- versions manifest merge ------------------------------------------------------------------
def test_versions_manifest_merge_by_subtree():
    import gzip as _gz
    tid = _seed_target("vmerge")
    with api.db() as conn:
        api._merge_versions_manifest(conn, tid, "", {"a/x": [1], "a/y": [1], "b/z": [1]}, False, 1)
        api._merge_versions_manifest(conn, tid, "a", {"x": [1], "new": [1]}, False, 2)  # replace a/* only
        conn.commit()
        gz = conn.execute("SELECT gz FROM recovery_manifests WHERE target_id=? AND kind='versions'",
                          (tid,)).fetchone()[0]
    files = json.loads(_gz.decompress(gz).decode())["files"]
    assert set(files) == {"a/x", "a/new", "b/z"}   # a/y dropped, a/new added, b/z untouched
