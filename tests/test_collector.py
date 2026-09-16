"""Unit tests for the pure collector logic - command building, zpool/zfs output parsing, and the
per-target capability probes. No ZFS host required: the `run` helper is monkeypatched with canned
command output, so these run anywhere (CI included)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "phase1"))
import collector  # noqa: E402


# ---- build_command ---------------------------------------------------------------------------
def test_scrub_goes_through_the_sudo_wrapper(monkeypatch):
    monkeypatch.delenv("CAIRN_ZPOOL_WRAPPER", raising=False)
    cmd, err = collector.build_command("scrub", {"name": "iwolf", "type": "zfs-local",
                                                 "source": "iwolf"}, {})
    assert err is None
    assert cmd == ["sudo", "-n", "/opt/cairn/phase1/zpool-scrub.sh", "iwolf"]


def test_scrub_honours_wrapper_env(monkeypatch):
    monkeypatch.setenv("CAIRN_ZPOOL_WRAPPER", "/custom/wrap.sh")
    cmd, err = collector.build_command("scrub", {"name": "p", "type": "zfs-local",
                                                 "source": "p/child"}, {})
    assert err is None and cmd == ["sudo", "-n", "/custom/wrap.sh", "p"]  # pool root taken from source


def test_scrub_rejected_on_non_local():
    cmd, err = collector.build_command("scrub", {"name": "x", "type": "zfs-repl",
                                                 "source": "a/b", "dest": "c/d"}, {})
    assert cmd is None and "not allowed" in err


def test_snapshot_is_bare_zfs_snapshot():
    cmd, err = collector.build_command("snapshot", {"name": "mcz", "type": "zfs-local",
                                                    "source": "mcz"}, {})
    assert err is None and cmd[:2] == ["zfs", "snapshot"] and cmd[2].startswith("mcz@cairn-manual-")


def test_recover_points_is_readonly_snapshot_list():
    cmd, err = collector.build_command("recover-points", {"name": "p", "type": "zfs-local",
                                                          "source": "pool/ds"}, {})
    assert err is None and cmd[:3] == ["zfs", "list", "-Hp"] and cmd[-1] == "pool/ds"


def test_restore_is_verbose_copy_only(monkeypatch):
    # restore must copy (never move/overwrite) and be verbose so stdout reveals the dest path.
    monkeypatch.setattr(collector, "run", _canned("/mnt/pool\n"))   # _mountpoint lookup
    cmd, err = collector.build_command(
        "restore", {"name": "p", "type": "zfs-local", "source": "pool"},
        {"version": "/mnt/pool/.zfs/snapshot/s1/file.txt"})
    assert err is None
    assert cmd[:4] == ["cp", "-av", "--no-clobber", "--"] and cmd[-2].endswith("file.txt")
    assert "/.cairn-restores/" in cmd[-1] and ".restored-" in cmd[-1]


# ---- zpool_scrub_progress --------------------------------------------------------------------
_INPROG = """  pool: iwolf
 state: ONLINE
  scan: scrub in progress since Sun Sep 13 09:00:00 2026
\t2.50T scanned at 1.00G/s, 2.00T issued at 800M/s, 5.00T total
\t0B repaired, 40.00% done, 01:05:00 to go
config:
errors: No known data errors
"""
_DONE = """  scan: scrub repaired 0B in 04:30:12 with 0 errors on Sun Sep 13 13:30:00 2026
errors: No known data errors
"""
_NEVER = "  scan: none requested\nerrors: No known data errors\n"
_BAD = """  scan: scrub repaired 1.5M in 04:30:12 with 3 errors on Sun Sep 13 2026
errors: Permanent errors have been detected in the following files:
"""


def _canned(out):
    return lambda *a, **k: (0, out, "")


def test_scrub_progress_in_progress(monkeypatch):
    monkeypatch.setattr(collector, "run", _canned(_INPROG))
    d = collector.zpool_scrub_progress("iwolf")
    assert d["state"] == "in_progress" and d["pct"] == 40.0 and d["eta"] == "01:05:00"


def test_scrub_progress_finished_clean(monkeypatch):
    monkeypatch.setattr(collector, "run", _canned(_DONE))
    d = collector.zpool_scrub_progress("iwolf")
    assert d["state"] == "finished" and d["scrub_errors"] == 0 and "No known" in d["errors"]


def test_scrub_progress_never(monkeypatch):
    monkeypatch.setattr(collector, "run", _canned(_NEVER))
    assert collector.zpool_scrub_progress("rpool")["state"] == "never"


def test_scrub_progress_errors_surface(monkeypatch):
    monkeypatch.setattr(collector, "run", _canned(_BAD))
    d = collector.zpool_scrub_progress("iwolf")
    assert d["scrub_errors"] == 3 and "Permanent errors" in d["errors"]


def test_scrub_progress_unreadable(monkeypatch):
    monkeypatch.setattr(collector, "run", lambda *a, **k: (1, "", "no such pool"))
    assert collector.zpool_scrub_progress("nope") == {}


# ---- zfs_delegated ---------------------------------------------------------------------------
_ALLOW = """---- Permissions on mcz/mclife/wyze_backups ----
Local+Descendent permissions:
\tuser jmichelsen create,destroy,mount,snapshot,hold
\tgroup staff snapshot
\teveryone send
"""


def test_delegated_user(monkeypatch):
    monkeypatch.setattr(collector, "run", _canned(_ALLOW))
    assert collector.zfs_delegated("ds", "snapshot", "jmichelsen") is True
    assert collector.zfs_delegated("ds", "destroy", "jmichelsen") is True


def test_delegated_missing_perm(monkeypatch):
    monkeypatch.setattr(collector, "run", _canned(_ALLOW))
    assert collector.zfs_delegated("ds", "rollback", "jmichelsen") is False


def test_delegated_via_group(monkeypatch):
    monkeypatch.setattr(collector, "run", _canned(_ALLOW))
    assert collector.zfs_delegated("ds", "snapshot", "someoneelse", groups=["staff"]) is True
    assert collector.zfs_delegated("ds", "snapshot", "someoneelse", groups=["adm"]) is False


def test_delegated_everyone(monkeypatch):
    monkeypatch.setattr(collector, "run", _canned(_ALLOW))
    assert collector.zfs_delegated("ds", "send", "nobody") is True


def test_delegated_unreadable_is_false(monkeypatch):
    monkeypatch.setattr(collector, "run", lambda *a, **k: (1, "", "permission denied"))
    assert collector.zfs_delegated("ds", "snapshot", "jmichelsen") is False


# ---- recovery walk / manifest reduction --------------------------------------------------------
def test_recovery_walk_is_bounded_readonly(monkeypatch):
    monkeypatch.setattr(collector, "run", _canned("/mnt/pool\n"))   # _mountpoint lookup
    cmd, err = collector.build_recovery_walk("deleted", {"name": "p", "type": "zfs-local",
                                                         "source": "pool/ds"})
    assert err is None
    # a nice/ionice politeness prefix may lead the argv, so assert membership, not position
    assert "httm" in cmd and cmd[-1] == "/mnt/pool"
    for flag in ("--deleted=only", "--recursive", "--one-filesystem", "--no-live", "--json"):
        assert flag in cmd


def test_recovery_walk_rejects_unknown_kind():
    cmd, err = collector.build_recovery_walk("points", {"name": "p", "source": "pool"})
    assert cmd is None and "unknown recovery-walk kind" in err


_DELJSON = """{
  "/mnt/pool/a.txt": [
    {"path":"/mnt/pool/.zfs/snapshot/s1/a.txt","metadata":{"size":"10 bytes","modify_time":"Mon Sep 07 01:00:00 2026"}},
    {"path":"/mnt/pool/.zfs/snapshot/s3/a.txt","metadata":{"size":"30 bytes","modify_time":"Wed Sep 09 01:00:00 2026"}},
    {"path":"/mnt/pool/.zfs/snapshot/s2/a.txt","metadata":{"size":"20 bytes","modify_time":"Tue Sep 08 01:00:00 2026"}}
  ],
  "/mnt/pool/b.txt": [
    {"path":"/mnt/pool/.zfs/snapshot/s1/b.txt","metadata":{"size":"5 bytes","modify_time":"Mon Sep 07 01:00:00 2026"}}
  ]
}"""


def test_reduce_keeps_newest_version_per_file():
    js, count = collector.reduce_deleted_manifest(_DELJSON)
    import json as _j
    out = _j.loads(js)
    assert count == 2
    # a.txt: newest is s3 (Sep 09) regardless of list order
    assert out["/mnt/pool/a.txt"]["path"].endswith("/s3/a.txt")
    assert out["/mnt/pool/a.txt"]["versions"] == 3
    assert out["/mnt/pool/b.txt"]["path"].endswith("/s1/b.txt")


def test_reduce_handles_empty_and_garbage():
    assert collector.reduce_deleted_manifest("") == ("{}", 0)
    assert collector.reduce_deleted_manifest("not json") == ("{}", 0)
    assert collector.reduce_deleted_manifest("{}") == ("{}", 0)


def test_reduce_parses_concatenated_objects_and_caps():
    # httm's recursive json is a STREAM of pretty-printed objects joined by "}\n{", not one object.
    import json as _j

    def _obj(i):
        day = (i % 9) + 1
        return _j.dumps({f"/mnt/pool/f{i}.txt": [
            {"path": f"/mnt/pool/.zfs/snapshot/s1/f{i}.txt",
             "metadata": {"size": "1 bytes", "modify_time": f"Mon Sep 0{day} 01:00:00 2026"}}]}, indent=2)

    stream = "\n".join(_obj(i) for i in range(10))
    js, total = collector.reduce_deleted_manifest(stream, cap=3)
    out = _j.loads(js)
    assert total == 10 and len(out) == 3          # all 10 parsed from the stream, capped to 3
    # newest-first: the top entry must carry the max day present (day 9, from i=8)
    first = next(iter(out.values()))
    assert first["modify_time"].split()[2] == "09"


def test_reduce_versions_keeps_history_drops_live_only():
    merged = {
        "/mnt/pool/a.txt": [
            {"path": "/mnt/pool/a.txt", "metadata": {"size": "3", "modify_time": "Wed Sep 09 01:00:00 2026"}},
            {"path": "/mnt/pool/.zfs/snapshot/s1/a.txt",
             "metadata": {"size": "2", "modify_time": "Mon Sep 07 01:00:00 2026"}},
        ],
        "/mnt/pool/b.txt": [   # only a live version -> nothing to restore -> dropped
            {"path": "/mnt/pool/b.txt", "metadata": {"size": "1", "modify_time": "Mon Sep 07 01:00:00 2026"}},
        ],
    }
    files, total = collector._reduce_versions(merged, "/mnt/pool", 100, 10)
    assert total == 1 and set(files) == {"a.txt"}          # relative to mountpoint, b.txt dropped
    vs = files["a.txt"]
    assert vs[0]["live"] is True and vs[0]["modify_time"].startswith("Wed")   # newest-first
    assert any(not v["live"] for v in vs)                  # a restorable snapshot version is present


def test_reduce_versions_caps_files_and_versions():
    merged = {}
    for i in range(10):
        merged[f"/mnt/pool/f{i}.txt"] = [
            {"path": f"/mnt/pool/f{i}.txt", "metadata": {"size": "1", "modify_time": "Wed Sep 09 01:00:00 2026"}},
            {"path": f"/mnt/pool/.zfs/snapshot/s1/f{i}.txt",
             "metadata": {"size": "1", "modify_time": "Mon Sep 07 01:00:00 2026"}},
        ]
    files, total = collector._reduce_versions(merged, "/mnt/pool", 3, 1)
    assert total == 10 and len(files) == 3                 # file show-cap
    assert all(len(v) == 1 for v in files.values())        # per-file version cap


def test_scan_files_enumerates_and_skips(tmp_path):
    (tmp_path / "a.txt").write_text("x")
    sub = tmp_path / "sub"; sub.mkdir(); (sub / "b.txt").write_text("y")
    zfs = tmp_path / ".zfs"; zfs.mkdir(); (zfs / "hidden.txt").write_text("z")
    bm = tmp_path / ".cairn-restores"; bm.mkdir(); (bm / "r.txt").write_text("w")
    files, trunc, scanned = collector._scan_files(str(tmp_path), 100)
    assert sorted(os.path.basename(f) for f in files) == ["a.txt", "b.txt"]   # .zfs + .cairn-restores skipped
    assert trunc is False


def test_scan_files_respects_cap(tmp_path):
    for i in range(5):
        (tmp_path / f"f{i}").write_text("x")
    files, trunc, scanned = collector._scan_files(str(tmp_path), 2)
    assert len(files) == 2 and trunc is True


def test_build_dirtree_folders_only(monkeypatch, tmp_path):
    (tmp_path / "docs").mkdir(); (tmp_path / "docs" / "2020").mkdir()
    (tmp_path / "pics").mkdir()
    (tmp_path / "a.txt").write_text("x")     # a file: not in the tree
    (tmp_path / ".zfs").mkdir()              # skipped
    monkeypatch.setattr(collector, "run", lambda *a, **k: (0, str(tmp_path) + "\n", ""))
    res, err = collector.build_dirtree({"source": "p"}, cap=1000)
    assert err is None
    assert set(res["tree"]) == {"docs", "pics"}          # files + .zfs excluded
    assert set(res["tree"]["docs"]) == {"2020"} and res["tree"]["pics"] == {}
    assert res["truncated"] is False and res["count"] == 3


def test_reduce_accepts_future_array_form():
    # the recursive framing is undocumented; be robust if a future httm emits a top-level ARRAY of the
    # per-directory objects instead of concatenating them.
    import json as _j
    arr = _j.dumps([
        {"/mnt/pool/a.txt": [{"path": "/s/a.txt",
                              "metadata": {"size": "1 bytes", "modify_time": "Mon Sep 08 01:00:00 2026"}}]},
        {"/mnt/pool/b.txt": [{"path": "/s/b.txt",
                              "metadata": {"size": "2 bytes", "modify_time": "Mon Sep 09 01:00:00 2026"}}]},
    ])
    js, total = collector.reduce_deleted_manifest(arr)
    out = _j.loads(js)
    assert total == 2 and set(out) == {"/mnt/pool/a.txt", "/mnt/pool/b.txt"}


# ---- removable 2nd-leg -----------------------------------------------------------------------
_REMOVABLE_T = {"name": "ext", "type": "removable", "tool": "rsync",
                "uuid": "1234-abcd", "mount": "/mnt/ext", "source": "/tank/photos",
                "dest_subpath": "photos", "tier": "B", "location": "removable"}


def test_backup_now_builds_incremental_rsync():
    cmd, err = collector.build_command("backup-now", _REMOVABLE_T)
    assert err is None
    assert cmd[:3] == ["rsync", "-aHXh", "--stats"]  # -X user.b3sig; -H hardlinks; -h human-readable stats
    assert cmd[-3:] == ["--", "/tank/photos/", "/mnt/ext/photos/"]   # contents-of via trailing slash
    assert "--delete" not in cmd            # additive by default: never auto-clobbers


def test_backup_now_logs_to_a_persistent_file_on_real_runs():
    cmd, _ = collector.build_command("backup-now", _REMOVABLE_T)
    assert "--log-file" in cmd
    log = cmd[cmd.index("--log-file") + 1]
    assert log.endswith("removable-ext.rsync.log")
    # a dry run does NOT write the persistent log (its output would pollute the real record)
    dcmd, _ = collector.build_command("backup-now", _REMOVABLE_T, {"dryrun": True})
    assert "--log-file" not in dcmd and "-n" in dcmd


def test_backup_now_emits_progress_on_real_runs_only():
    # real runs get --info=progress2 so the detached reaper can post % / ETA to the dashboard
    assert "--info=progress2" in collector.build_command("backup-now", _REMOVABLE_T)[0]
    # a dry run stays quiet (it is quick and its output is the intent result, not parsed for progress)
    assert "--info=progress2" not in collector.build_command("backup-now", _REMOVABLE_T, {"dryrun": True})[0]


def test_removable_last_backup_uses_freshest_per_link_stamp(tmp_path):
    # link-driven drive: no target-level dest_subpath; each dataset writes its own stamp under cairn/
    mount = tmp_path
    d1 = mount / "cairn" / "mclife" / "mcz_mclife_Pics"; d1.mkdir(parents=True)
    d2 = mount / "cairn" / "mclife" / "mcz_mclife_karly"; d2.mkdir(parents=True)
    (d1 / ".cairn-lastbackup").write_text("1700000000")
    (d2 / ".cairn-lastbackup").write_text("1700009999")   # the freshest -> should win
    t = {"name": "seagate", "type": "removable", "mount": str(mount)}
    pr = {"mounted": True, "mount": str(mount)}
    assert collector._removable_last_backup(t, pr) == 1700009999
    # nothing on the drive -> falls back (no stamps) to host-side state (None here)
    empty = tmp_path / "empty"; empty.mkdir()
    assert collector._removable_last_backup(t, {"mounted": True, "mount": str(empty)}) is None


def test_parse_rsync_progress():
    # human-formatted (-h) progress2 line
    p = collector.parse_rsync_progress("stuff\r        1.23G  45%   12.34MB/s    0:12:34\r")
    assert p == {"bytes": "1.23G", "pct": 45, "rate": "12.34MB/s", "eta": "0:12:34"}
    # last (freshest) sample wins when several are present
    assert collector.parse_rsync_progress(
        "  10M   1%  1MB/s 0:10:00\r  900M  90%  5MB/s 0:00:20")["pct"] == 90
    # raw-byte form (no -h) still parses
    assert collector.parse_rsync_progress("1,234,567  12%  3.00kB/s 1:02:03")["pct"] == 12
    assert collector.parse_rsync_progress("no progress here") is None
    assert collector.parse_rsync_progress("") is None


def test_backup_now_mirror_and_excludes_and_dryrun():
    t = dict(_REMOVABLE_T, mirror=True, exclude=["*.tmp", "cache"])
    cmd, _ = collector.build_command("backup-now", t, {"dryrun": True})
    assert "--delete" in cmd and "-n" in cmd
    assert cmd.count("--exclude") == 2 and "*.tmp" in cmd and "cache" in cmd
    assert "--delete-excluded" not in cmd      # prune is OPT-IN, not implied by mirror+excludes


def test_delete_excluded_is_opt_in():
    t = dict(_REMOVABLE_T, mirror=True, exclude=["x"])
    # mirror + excludes but no prune_excluded -> --delete but NOT --delete-excluded
    cmd, _ = collector.build_command("backup-now", t)
    assert "--delete" in cmd and "--delete-excluded" not in cmd
    # opt in -> --delete-excluded
    cmd, _ = collector.build_command("backup-now", t, {"prune_excluded": True})
    assert "--delete-excluded" in cmd
    # prune opt without excludes is a no-op
    cmd, _ = collector.build_command("backup-now", dict(_REMOVABLE_T, mirror=True), {"prune_excluded": True})
    assert "--delete-excluded" not in cmd


def test_backup_now_mirror_opt_overrides_config():
    # per-click opts.mirror wins over the target default (both directions)
    on, _ = collector.build_command("backup-now", _REMOVABLE_T, {"mirror": True})
    assert "--delete" in on                                   # opt turns it on
    off, _ = collector.build_command("backup-now", dict(_REMOVABLE_T, mirror=True), {"mirror": False})
    assert "--delete" not in off                              # opt turns a config default back off


def test_backup_now_rejected_on_non_removable():
    cmd, err = collector.build_command("backup-now", {"type": "zfs-local", "source": "tank"})
    assert cmd is None and "not allowed" in err


def test_backup_now_needs_source_and_mount():
    cmd, err = collector.build_command("backup-now", {"type": "removable", "tool": "rsync",
                                                      "mount": "/mnt/ext"})
    assert cmd is None and "source" in err


def _probe(monkeypatch, **kw):
    base = {"attached": True, "mounted": True, "ro": False, "mount": "/mnt/ext", "dev": "/dev/sdz1"}
    monkeypatch.setattr(collector, "removable_probe", lambda t: dict(base, **kw))


def test_removable_detached_is_neutral_not_crit(monkeypatch):
    _probe(monkeypatch, attached=False, mounted=False)
    monkeypatch.setattr(collector, "_removable_last_backup", lambda t, pr: None)
    st = collector.adapter_removable(_REMOVABLE_T, collector.DEFAULT_THRESHOLDS, 1_000_000)[0]
    assert st["severity"] == "OK"
    import json
    d = json.loads(st["detail_json"])
    assert d["caps"]["backupable"] is False and "detached" in d["reasons"][0]


def test_removable_detached_long_grace_warns(monkeypatch):
    _probe(monkeypatch, attached=False, mounted=False)
    now = 100 * 86400
    monkeypatch.setattr(collector, "_removable_last_backup", lambda t, pr: now - 60 * 86400)
    st = collector.adapter_removable(dict(_REMOVABLE_T, detach_warn_d=45),
                                     collector.DEFAULT_THRESHOLDS, now)[0]
    assert st["severity"] == "WARN"        # 60d detached, past the 45d grace


def test_removable_readonly_warns_and_blocks_backup(monkeypatch):
    _probe(monkeypatch, ro=True)
    monkeypatch.setattr(collector, "_removable_last_backup", lambda t, pr: None)
    st = collector.adapter_removable(_REMOVABLE_T, collector.DEFAULT_THRESHOLDS, 1_000_000)[0]
    import json
    d = json.loads(st["detail_json"])
    assert st["severity"] == "WARN" and d["caps"]["backupable"] is False
    assert any("READ-ONLY" in r for r in d["reasons"])


def test_removable_attached_rw_fresh_is_ok_and_backupable(monkeypatch):
    _probe(monkeypatch)                    # attached, mounted, rw
    now = 1_000_000
    monkeypatch.setattr(collector, "_removable_last_backup", lambda t, pr: now - 3600)  # 1h old
    st = collector.adapter_removable(_REMOVABLE_T, collector.DEFAULT_THRESHOLDS, now)[0]
    import json
    d = json.loads(st["detail_json"])
    assert st["severity"] == "OK" and d["caps"]["backupable"] is True
    assert st["last_run_ts"] == now - 3600


# ---- removable discovery (structural tree matching) ------------------------------------------
def test_discover_matches_dataset_by_directory_structure(tmp_path):
    import os
    # dataset root has 5 children; the drive holds 4 of them under bk/Pics (drift) => score 0.8
    ds = tmp_path / "live" / "Pics"
    for n in ["a", "b", "c", "d", "e"]:
        os.makedirs(ds / n)
    drive = tmp_path / "drive"
    for n in ["a", "b", "c", "d"]:
        os.makedirs(drive / "bk" / "Pics" / n)
    # an unrelated dataset that is NOT on the drive
    karly = tmp_path / "live" / "karly"
    for n in ["k1", "k2", "k3"]:
        os.makedirs(karly / n)
    res = collector.discover_removable_links(
        str(drive), [{"name": "Pics", "path": str(ds)}, {"name": "karly", "path": str(karly)}])
    assert len(res) == 1
    m = res[0]
    assert m["dataset"] == "Pics" and m["subpath"] == "bk/Pics"
    assert 0.79 <= m["score"] <= 0.81 and m["matched"] == 4 and m["total"] == 5
    assert m["added"] == ["e"]                      # the drift = exactly what a sync would add


def test_discover_ignores_weak_matches(tmp_path):
    import os
    ds = tmp_path / "Pics"
    for n in ["a", "b", "c", "d", "e"]:
        os.makedirs(ds / n)
    drive = tmp_path / "drive"
    for n in ["a", "zzz"]:                          # only 1 of 5 overlaps -> below min_score
        os.makedirs(drive / "x" / n)
    assert collector.discover_removable_links(str(drive), [{"name": "Pics", "path": str(ds)}]) == []


# ---- removable phase (a): cairn subpath, relocate, rsync census ------------------------------
def test_cairn_subpath_slugs_source():
    assert collector.cairn_subpath("mcz/mclife/Pics") == "cairn/mcz_mclife_Pics"    # no host
    assert collector.cairn_subpath("/tank/photos/") == "cairn/tank_photos"
    assert collector.cairn_subpath("") == "cairn/dataset"
    assert collector.cairn_subpath("mcz/mclife/Pics", "mclife") == "cairn/mclife/mcz_mclife_Pics"
    assert collector.cairn_subpath("evo500", "mclife") == "cairn/mclife/evo500"


def test_removable_relocate_moves_within_drive(tmp_path):
    import os
    mount = tmp_path / "mnt"; os.makedirs(mount / "old" / "Pics")
    (mount / "old" / "Pics" / "a.jpg").write_text("x")
    ok, msg = collector.removable_relocate(str(mount), "old/Pics", "cairn/mcz_Pics")
    assert ok, msg
    assert (mount / "cairn" / "mcz_Pics" / "a.jpg").exists()
    assert not (mount / "old" / "Pics").exists()
    assert not (mount / "old").exists()          # now-empty parent pruned
    assert (mount).exists()                       # but never the mount itself


def test_removable_relocate_refuses_existing_dest_and_escape(tmp_path):
    import os
    mount = tmp_path / "mnt"; os.makedirs(mount / "a"); os.makedirs(mount / "cairn" / "x")
    ok, _ = collector.removable_relocate(str(mount), "a", "cairn/x"); assert not ok
    ok, _ = collector.removable_relocate(str(mount), "a", "../escape"); assert not ok


def test_rsync_census_parses_counts(monkeypatch):
    canned = (">f+++++++++ new1.jpg\n>f..t...... changed1.jpg\n*deleting old/gone.jpg\n\n"
              "Number of files: 1,000 (reg: 950, dir: 50)\n"
              "Number of created files: 10 (reg: 8, dir: 2)\n"
              "Number of regular files transferred: 12\n"
              "Total transferred file size: 4,200,000 bytes\n")
    monkeypatch.setattr(collector, "run", lambda *a, **k: (0, canned, ""))
    cen, err = collector.rsync_census("/src", "/dst")
    assert err is None
    assert cen["reg_total"] == 950 and cen["transfer"] == 12
    assert cen["add"] == 8 and cen["update"] == 4 and cen["delete"] == 1
    assert cen["bytes_add"] == 4200000 and abs(cen["pct"] - 938/950) < 0.001


# ---- removable phase (b): xattr tier-2 content verify -----------------------------------------
def test_xattr_verify_flags_mismatch_and_missing(tmp_path):
    import os
    import pytest
    src = tmp_path / "src"; dst = tmp_path / "dst"; os.makedirs(src); os.makedirs(dst)
    for n in ("a", "b", "c"):
        (src / n).write_text(n)
    (dst / "a").write_text("a"); (dst / "b").write_text("b")   # c missing on dst
    try:
        os.setxattr(str(src / "a"), "user.b3sig", b"Faaa")
        os.setxattr(str(src / "b"), "user.b3sig", b"Fbbb")
        os.setxattr(str(src / "c"), "user.b3sig", b"Fccc")
        os.setxattr(str(dst / "a"), "user.b3sig", b"Faaa")     # match
        os.setxattr(str(dst / "b"), "user.b3sig", b"Fzzz")     # mismatch
    except OSError:
        pytest.skip("filesystem does not support user xattrs")
    # content coverage is PATH-INDEPENDENT: a=aaa is on the drive (present); b=bbb and c=ccc are not.
    res, err = collector.xattr_verify(str(src), str(dst))
    assert err is None
    assert res["present"] == 1 and res["missing"] == 2 and res["clean"] is False


def test_xattr_verify_content_present_ignores_path(tmp_path):
    import os
    import pytest
    # same content on both sides but at DIFFERENT paths -> still counts as present (path-independent)
    src = tmp_path / "s"; dst = tmp_path / "d"; os.makedirs(src); os.makedirs(dst / "elsewhere")
    (src / "x").write_text("x"); (dst / "elsewhere" / "renamed").write_text("x")
    try:
        os.setxattr(str(src / "x"), "user.b3sig", b"Fxxx")
        os.setxattr(str(dst / "elsewhere" / "renamed"), "user.b3sig", b"Fxxx")
    except OSError:
        pytest.skip("filesystem does not support user xattrs")
    res, _ = collector.xattr_verify(str(src), str(dst))
    assert res["clean"] is True and res["pct"] == 1.0 and res["present"] == 1 and res["missing"] == 0


# ---- removable phase (c): full-hash ledger tier-3 ---------------------------------------------
def test_hash_ledger_verify_compares_to_source_sig(tmp_path, monkeypatch):
    import os
    import pytest
    src = tmp_path / "src"; dst = tmp_path / "dst"; os.makedirs(src); os.makedirs(dst)
    for n in ("a", "b", "c"):
        (src / n).write_text(n); (dst / n).write_text(n)
    ha, hb, hc = "a" * 64, "b" * 64, "c" * 64
    try:
        os.setxattr(str(src / "a"), "user.b3sig", ("F" + ha).encode())   # will match
        os.setxattr(str(src / "b"), "user.b3sig", ("F" + ("9" * 64)).encode())  # will mismatch
        os.setxattr(str(src / "c"), "user.b3sig", b"Q123:deadbeef")      # edge-sig -> unverifiable
    except OSError:
        pytest.skip("filesystem does not support user xattrs")
    monkeypatch.setattr(collector, "_have", lambda c: True)
    hashes = {os.path.join(str(dst), "a"): ha, os.path.join(str(dst), "b"): hb,
              os.path.join(str(dst), "c"): hc}
    def fake_run(cmd, timeout=None, env=None):        # canned b3sum: "<hash>  <path>" per file
        paths = cmd[cmd.index("--") + 1:]
        return 0, "".join(f"{hashes[p]}  {p}\n" for p in paths), ""
    monkeypatch.setattr(collector, "run", fake_run)
    monkeypatch.setattr(collector, "NICE", [])
    led = tmp_path / "l.tsv"
    # drive set (from b3sum) = {ha,hb,hc}. source coverage: a(ha) present, b(wrong) missing, c(Q) unverifiable
    res, err = collector.hash_ledger_verify(str(src), str(dst), ledger_path=str(led))
    assert err is None
    assert res["present"] == 1 and res["missing"] == 1 and res["no_src_sig"] == 1
    assert res["clean"] is False and res["hashed"] == 3
    assert led.exists() and "\tb" in led.read_text()


def test_drive_tagged_fraction(tmp_path):
    import os
    import pytest
    d = tmp_path / "d"; os.makedirs(d)
    for n in ("a", "b", "c", "e"):
        (d / n).write_text(n)
    try:
        os.setxattr(str(d / "a"), "user.b3sig", b"Fa")
        os.setxattr(str(d / "b"), "user.b3sig", b"Fb")
        os.setxattr(str(d / "c"), "user.b3sig", b"Fc")   # 3 of 4 tagged
    except OSError:
        pytest.skip("filesystem does not support user xattrs")
    assert abs(collector.drive_tagged_fraction(str(d)) - 0.75) < 0.01


def test_human_bytes():
    assert collector.human_bytes(210261472793) == "210.3 GB"
    assert collector.human_bytes(1500000000000) == "1.5 TB"
    assert collector.human_bytes(4200000) == "4 MB"
    assert collector.human_bytes(0) == "0 B"


def test_spawn_detached_runs_and_writes_markers(tmp_path):
    import time as _t
    out = str(tmp_path / "j.out"); done = str(tmp_path / "j.done")
    pid = collector.spawn_detached('echo hello; exit 0', out, done)
    assert pid
    for _ in range(50):                       # setsid child finishes async; poll briefly
        if os.path.exists(done):
            break
        _t.sleep(0.1)
    assert open(done).read().strip() == "0"   # exit code captured
    assert "hello" in open(out).read()        # stdout captured
    assert os.path.exists(out + ".sh")        # script written 0700


def test_spawn_detached_propagates_failure_rc(tmp_path):
    import time as _t
    out = str(tmp_path / "f.out"); done = str(tmp_path / "f.done")
    collector.spawn_detached('exit 7', out, done)
    for _ in range(50):
        if os.path.exists(done):
            break
        _t.sleep(0.1)
    assert open(done).read().strip() == "7"
