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
