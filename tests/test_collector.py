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
    assert "/.bm-restores/" in cmd[-1] and ".restored-" in cmd[-1]


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
