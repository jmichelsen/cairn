"""zfs-perms: which delegations each host needs, derived from its targets.yaml."""
import importlib.util
import os

_p = os.path.join(os.path.dirname(__file__), "..", "phase1", "zfs-perms.py")
_spec = importlib.util.spec_from_file_location("zfs_perms", _p)
zp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(zp)


def _rows(targets, pools):
    return {(ds, req): perms for ds, perms, _, req in zp.plan(targets, set(pools))}


def test_vault_pulled_source_needs_send_side_only():
    r = _rows([{"name": "g", "type": "zfs-repl", "source": "rpool/apps/wiki", "dest": "tank/apps/wiki",
                "dest_agent": "vault"}], ["rpool"])
    assert r == {("rpool/apps/wiki", True): ("snapshot", "send", "hold")}


def test_local_repl_needs_send_on_source_and_receive_on_dest_pool():
    r = _rows([{"name": "p", "type": "zfs-repl", "source": "tank/photos", "dest": "backup/photos"}],
              ["tank", "backup"])
    assert r[("tank/photos", True)] == ("snapshot", "send", "hold")
    assert r[("backup", True)] == ("create", "mount", "receive", "mountpoint")


def test_vault_replica_gets_receive_and_no_snapshot():
    r = _rows([{"name": "g", "type": "zfs-local", "source": "tank/apps/wiki", "source_agent": "home"}],
              ["tank"])
    assert r == {("tank", True): ("create", "mount", "receive", "mountpoint")}


def test_snapshot_button_grant_is_optional_and_separate():
    r = _rows([{"name": "d", "type": "backup", "source": "x"},
               {"name": "m", "type": "zfs-local", "source": "mediaz"},
               {"name": "c", "type": "zfs-repl", "source": "tank/a", "dest": "mediaz/a"}],
              ["tank", "mediaz"])
    assert r[("mediaz", False)] == ("snapshot",)
    assert r[("mediaz", True)] == ("create", "mount", "receive", "mountpoint")


def test_datasets_on_other_hosts_are_skipped():
    assert zp.plan([{"name": "g", "type": "zfs-repl", "source": "rpool/a", "dest": "tank/a"}], {"rpool"}) \
        == [("rpool/a", ("snapshot", "send", "hold"), ["g: Replicate (send side)"], True)]
