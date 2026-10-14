"""ZFS delegation needs (collector.zfs_perm_needs), the zfs-perms.py plan, and the per-cycle check."""
import importlib.util
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "phase1"))
import collector  # noqa: E402

_p = os.path.join(os.path.dirname(__file__), "..", "phase1", "zfs-perms.py")
_spec = importlib.util.spec_from_file_location("zfs_perms", _p)
zp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(zp)


def _rows(targets, pools):
    return {(ds, req): (ess, extra) for ds, ess, extra, _, req in zp.plan(targets, set(pools))}


def test_vault_pulled_source_needs_only_send():
    r = _rows([{"name": "g", "type": "zfs-repl", "source": "rpool/apps/wiki", "dest": "tank/apps/wiki",
                "dest_agent": "vault"}], ["rpool"])
    assert r == {("rpool/apps/wiki", True): (("send",), ("snapshot", "hold"))}


def test_local_repl_needs_send_side_and_receive_on_dest_pool():
    r = _rows([{"name": "p", "type": "zfs-repl", "source": "tank/photos", "dest": "backup/photos"}],
              ["tank", "backup"])
    assert r[("tank/photos", True)] == (("snapshot", "send"), ("hold",))
    assert r[("backup", True)] == (("create", "mount", "receive"), ("mountpoint",))


def test_vault_replica_gets_receive_and_no_snapshot():
    r = _rows([{"name": "g", "type": "zfs-local", "source": "tank/apps/wiki", "source_agent": "home"}],
              ["tank"])
    assert r == {("tank", True): (("create", "mount", "receive"), ("mountpoint",))}


def test_snapshot_button_grant_is_optional_and_separate():
    r = _rows([{"name": "m", "type": "zfs-local", "source": "mediaz"},
               {"name": "c", "type": "zfs-repl", "source": "tank/a", "dest": "mediaz/a"}],
              ["tank", "mediaz"])
    assert r[("mediaz", False)] == (("snapshot",), ())
    assert r[("mediaz", True)][0] == ("create", "mount", "receive")


def test_extra_promoted_when_another_target_needs_it():
    # a vault pull makes snapshot an extra, a local Replicate of the same source makes it essential
    r = _rows([{"name": "a", "type": "zfs-repl", "source": "tank/a", "dest": "v/a", "dest_agent": "vault"},
               {"name": "b", "type": "zfs-repl", "source": "tank/a", "dest": "tank2/a"}], ["tank", "tank2"])
    ess, extra = r[("tank/a", True)]
    assert "snapshot" in ess and "snapshot" not in extra


def test_datasets_on_other_hosts_are_skipped():
    assert zp.plan([{"name": "g", "type": "zfs-repl", "source": "rpool/a", "dest": "tank/a"}], {"rpool"}) \
        == [("rpool/a", ("snapshot", "send"), ("hold",), ["g: Replicate (send side)"], True)]


_ALLOW = """---- Permissions on tank ---------------------------------------------
Local+Descendent permissions:
\tuser alice hold,send
\tgroup backup snapshot
"""


def test_zfs_allowed_reads_user_group_and_everyone(monkeypatch):
    collector._ZALLOW.clear()
    monkeypatch.setattr(collector, "run", lambda *a, **k: (0, _ALLOW + "\teveryone diff\n", ""))
    assert collector.zfs_allowed("tank/x", "alice", ["backup"]) == {"hold", "send", "snapshot", "diff"}
    collector._ZALLOW.clear()


def test_per_cycle_check_warns_with_the_fix(monkeypatch):
    collector._ZALLOW.clear()
    monkeypatch.setattr(collector, "run", lambda *a, **k: (0, _ALLOW, ""))
    monkeypatch.setattr(collector, "_whoami", lambda: ("alice", []))
    monkeypatch.setattr(collector.os, "geteuid", lambda: 1000)
    st = {"severity": "OK", "detail_json": json.dumps({"reasons": []})}
    t = {"name": "p", "type": "zfs-repl", "source": "tank/photos", "dest": "backup/photos"}
    collector._annotate_perm_gaps(st, t, {"tank": {}, "backup": {}})
    d = json.loads(st["detail_json"])
    assert st["severity"] == "WARN"
    assert {x["dataset"] for x in d["perm_missing"]} == {"tank/photos", "backup"}
    assert any("snapshot" in r and "zfs-perms.py --apply" in r for r in d["reasons"])
    collector._ZALLOW.clear()


def test_per_cycle_check_quiet_when_essentials_held(monkeypatch):
    collector._ZALLOW.clear()
    monkeypatch.setattr(collector, "run", lambda *a, **k: (0, _ALLOW, ""))
    monkeypatch.setattr(collector, "_whoami", lambda: ("alice", []))
    monkeypatch.setattr(collector.os, "geteuid", lambda: 1000)
    st = {"severity": "OK", "detail_json": "{}"}
    collector._annotate_perm_gaps(st, {"name": "g", "type": "zfs-repl", "source": "tank/g", "dest": "v/g",
                                       "dest_agent": "vault"}, {"tank": {}})
    assert st["severity"] == "OK" and "perm_missing" not in st["detail_json"]
    collector._ZALLOW.clear()
