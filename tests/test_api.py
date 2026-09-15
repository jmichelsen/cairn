"""Unit tests for the dashboard's server-side rendering that has repeatedly regressed: capability-
aware action buttons, viewer read-only gating, and the scrub progress bar. Uses an isolated temp DB
so importing the app (which runs _init_db at import time) never touches a real database."""
import json
import os
import sys
import tempfile
import time

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


# ---- recovery buttons gated on a usable mountpoint --------------------------------------------
def test_unmounted_dataset_hides_deleted_versions_keeps_snapshots():
    h = api._acts(_row("iwolf", caps={"snapshot": False, "scrub": True, "recoverable": False}), True, False)
    assert ">Snapshots<" in h                     # listing snapshots needs no mount
    assert ">Deleted<" not in h and ">Versions<" not in h


def test_recoverable_dataset_shows_all_recovery():
    h = api._acts(_row("mcz/x", caps={"snapshot": True, "scrub": False, "recoverable": True}), True, False)
    assert ">Snapshots<" in h and ">Deleted<" in h and ">Versions<" in h


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


# ---- CI status broker + public badge ----------------------------------------------------------
def test_badge_color_mapping():
    assert api._badge_color("passed") == "#4c1"
    assert api._badge_color("SUCCESS") == "#4c1"      # case-insensitive
    assert api._badge_color("failed") == "#e05d44"
    assert api._badge_color("running") == "#007ec6"
    assert api._badge_color("whatever") == api._BADGE_DEFAULT_COLOR
    assert api._badge_color(None) == api._BADGE_DEFAULT_COLOR


def test_badge_svg_is_well_formed_and_reflects_status():
    import xml.dom.minidom as _x
    svg = api._badge_svg("tests", "passed", api._badge_color("passed"))
    _x.parseString(svg)                     # raises on malformed XML
    assert "tests" in svg and "passed" in svg and "#4c1" in svg


def test_public_badge_only_serves_allowlisted_names():
    # 'tests' is public (default allowlist); 'deploy' is internal-only and must 404 publicly.
    ok = api.ci_badge("tests")
    assert ok.status_code == 200 and ok.media_type == "image/svg+xml"
    assert api.ci_badge("deploy").status_code == 404
    assert api.ci_badge("nope").status_code == 404


def test_ci_status_roundtrip_and_badge_render():
    now = 12345
    with api.db() as conn:
        conn.execute("INSERT INTO ci_status(name,status,ref,url,updated_ts) VALUES(?,?,?,?,?) "
                     "ON CONFLICT(name) DO UPDATE SET status=excluded.status,updated_ts=excluded.updated_ts",
                     ("tests", "passed", "main", "https://gl/x/-/pipelines/1", now))
        conn.commit()
    body = api.ci_badge("tests").body.decode()
    assert "passed" in body and "#4c1" in body
    # the store round-trips through the list endpoint
    names = {r["name"]: r["status"] for r in api.ci_status_list()["status"]}
    assert names.get("tests") == "passed"


def test_deploy_status_stored_but_never_public():
    # cairn-deploy status is stored (available via the authed /api/v1/ci/status) but must never be
    # served over the public badge route, even after it has a value.
    with api.db() as conn:
        conn.execute("INSERT INTO ci_status(name,status,url,updated_ts) VALUES('deploy','failed','',7) "
                     "ON CONFLICT(name) DO UPDATE SET status='failed',updated_ts=7")
        conn.commit()
    assert api.ci_badge("deploy").status_code == 404
    names = {r["name"]: r["status"] for r in api.ci_status_list()["status"]}
    assert names.get("deploy") == "failed"


# ---- removable 2nd-leg action button ---------------------------------------------------------
def _removable_row(backupable):
    return {"name": "ext", "type": "removable", "source": "/tank/photos", "severity": "OK",
            "agent": "local", "detail_json": json.dumps({"caps": {"backupable": backupable},
                                                          "reasons": ["attached"]})}


def test_backup_now_is_an_allowed_action():
    assert "backup-now" in api.ALLOWED_ACTIONS


def test_backup_now_button_shows_only_when_backupable():
    on = api._acts(_removable_row(True), can_act=True, viewer=False)
    assert "backup-now" in on and "Back up now" in on
    assert "mirrorRemovable" in on and "Mirror" in on     # destructive variant is offered too
    off = api._acts(_removable_row(False), can_act=True, viewer=False)
    assert "backup-now" not in off and "Mirror" not in off  # detached / read-only -> no buttons
    assert api._acts(_removable_row(True), can_act=True, viewer=True) == ""  # viewer: no controls


# ---- removable links + scorecard credit ------------------------------------------------------
def _seed_repl(name, source, dest, tier="A", location="offsite", agent="local"):
    with api.db() as conn:
        tid = conn.execute(
            "INSERT INTO targets(name,type,source,dest,tier,location,agent,enabled) "
            "VALUES(?,?,?,?,?,?,?,1) RETURNING id",
            (name, "zfs-repl", source, dest, tier, location, agent)).fetchone()[0]
        conn.execute("INSERT INTO status(ts,target_id,severity) VALUES(1,?, 'OK')", (tid,))
        conn.commit()
    return tid


def test_link_suggest_then_confirm_roundtrip():
    with api.db() as conn:
        api._link_suggest(conn, "local", "extd", [{"dataset": "Pics", "subpath": "bk/Pics", "score": 0.8}], 1000)
        links = api._links_for(conn, removable="extd")
        assert len(links) == 1 and links[0]["confirmed"] == 0 and links[0]["dataset"] == "Pics"
        api._link_confirm(conn, "local", "extd", "Pics", "bk/Pics", 1001)
        c = api._links_for(conn, removable="extd", confirmed_only=True)
        assert len(c) == 1 and c[0]["confirmed"] == 1


def test_link_suggest_preserves_confirmed_and_drops_stale_suggestions():
    with api.db() as conn:
        api._link_confirm(conn, "local", "d2", "Pics", "bk/Pics", 2000)
        api._link_suggest(conn, "local", "d2", [{"dataset": "karly", "subpath": "k", "score": 0.9}], 2000)
        got = {L["dataset"]: L["confirmed"] for L in api._links_for(conn, removable="d2")}
        assert got == {"Pics": 1, "karly": 0}       # confirmed Pics survived a scan that didn't mention it
        api._link_suggest(conn, "local", "d2", [], 2000)   # a scan mentioning neither
        got = {L["dataset"] for L in api._links_for(conn, removable="d2")}
        assert got == {"Pics"}                        # unconfirmed karly dropped, confirmed Pics kept


def test_scorecard_credits_fresh_removable_copy():
    now = int(time.time())
    _seed_repl("PicsA", "mcz/mclife/PicsA", "vault/PicsA")     # 2 copies (mcz+vault), off-site, fails 3-2-1
    base = {c["name"]: c for c in api.scorecard()["cards"]}["PicsA"]
    assert base["copies"] == 2 and base["pass_321"] is False
    with api.db() as conn:
        api._link_confirm(conn, "local", "extA", "PicsA", "PicsA", now)
        conn.execute("UPDATE removable_links SET last_backup_ts=? WHERE removable='extA'", (now,))
        conn.commit()
    card = {c["name"]: c for c in api.scorecard()["cards"]}["PicsA"]
    assert card["copies"] == 3 and card["media"] == 3 and card["removable"] is True
    assert card["pass_321"] is True


def test_scorecard_ignores_stale_removable_copy():
    now = int(time.time())
    _seed_repl("PicsB", "mcz/mclife/PicsB", "vault/PicsB")
    with api.db() as conn:
        api._link_confirm(conn, "local", "extB", "PicsB", "PicsB", now)
        conn.execute("UPDATE removable_links SET last_backup_ts=? WHERE removable='extB'",
                     (now - (api.REMOVABLE_STALE_D + 5) * api.DAY,))
        conn.commit()
    card = {c["name"]: c for c in api.scorecard()["cards"]}["PicsB"]
    assert card["copies"] == 2 and card["removable"] is False and "STALE" in card["note"]


# ---- removable phase (a): subpath policy + verify-freshness ----------------------------------
def test_subpath_conflict_rejects_root_and_nesting():
    with api.db() as conn:
        api._link_confirm(conn, "local", "drv", "A", "cairn/A", 1)
        assert api._subpath_conflict(conn, "local", "drv", "B", "") is not None          # root
        assert api._subpath_conflict(conn, "local", "drv", "B", "cairn/A") is not None    # exact overlap
        assert api._subpath_conflict(conn, "local", "drv", "B", "cairn/A/sub") is not None  # nested under
        assert api._subpath_conflict(conn, "local", "drv", "B", "cairn") is not None      # parent of A
        assert api._subpath_conflict(conn, "local", "drv", "B", "cairn/B") is None        # distinct - ok
        assert api._subpath_conflict(conn, "local", "drv", "A", "cairn/A") is None        # same dataset - ok


def test_scorecard_credits_verify_freshness_without_a_sync():
    now = int(time.time())
    _seed_repl("PicsV", "mcz/mclife/PicsV", "vault/PicsV")
    with api.db() as conn:
        api._link_confirm(conn, "local", "extV", "PicsV", "cairn/PicsV", now)
        conn.execute("UPDATE removable_links SET verify_ts=? WHERE removable='extV'", (now,))  # no sync, just a verify
        conn.commit()
    card = {c["name"]: c for c in api.scorecard()["cards"]}["PicsV"]
    assert card["removable"] is True and card["copies"] == 3
