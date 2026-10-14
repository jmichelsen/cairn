"""cairn doctor: the host-side config checks (phase1/doctor.py) and the control plane's cross-agent
fleet check (api.fleet_doctor). The API shares one temp DB across the suite, so every seed here uses
names no other test uses and assertions filter to them."""
import json
import os
import sys
import tempfile
import time

os.environ.setdefault("CAIRN_DB", os.path.join(tempfile.mkdtemp(), "cairn-test.db"))
os.environ.setdefault("CAIRN_ADMIN_TOKEN", "test-admin-token")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "phase1"))
import api  # noqa: E402
import doctor  # noqa: E402


# ---- host side: targets.yaml structure ----------------------------------------------------------
def _check(cfg):
    r = doctor.Report(quiet=True)
    doctor.check_targets_cfg(r, cfg, "targets.yaml")
    return r


def _msgs(r, level):
    return [m for lvl, m, _ in r.items if lvl == level]


def test_typo_key_gets_a_suggestion():
    r = _check({"targets": [{"name": "g", "type": "zfs-repl", "source": "rpool/g", "dest": "tank/g",
                             "dest-agent": "vault"}]})
    assert any("'dest-agent'" in m and "did you mean 'dest_agent'" in m for m in _msgs(r, "WARN"))


def test_missing_type_unknown_type_and_duplicates_fail():
    r = _check({"targets": [{"name": "a"}, {"name": "b", "type": "zfs-locl", "source": "x"},
                            {"name": "c", "type": "smart"}, {"name": "c", "type": "smart"}]})
    fails = " | ".join(_msgs(r, "FAIL"))
    assert "'a' has no type" in fails
    assert "unknown type 'zfs-locl'" in fails and "did you mean 'zfs-local'" in fails
    assert "'c' is defined twice" in fails


def test_repl_dest_must_be_a_dataset_not_a_path_or_host():
    for bad in ("/tank/g", "user@vault:tank/g"):
        r = _check({"targets": [{"name": "g", "type": "zfs-repl", "source": "rpool/g", "dest": bad}]})
        assert any("must be a dataset name" in m for m in _msgs(r, "FAIL")), bad


def test_partial_scrub_cadence_fails():
    r = _check({"scrub_cadence": {"tank": {"warn_d": 10}},
                "targets": [{"name": "t", "type": "zfs-local", "source": "tank"}]})
    assert any("scrub_cadence: 'tank'" in m for m in _msgs(r, "FAIL"))


def test_clean_config_passes():
    r = _check({"targets": [{"name": "g", "type": "zfs-repl", "source": "rpool/g", "dest": "tank/g",
                             "dest_agent": "vault", "tier": "A"},
                            {"name": "disk", "type": "smart"}]})
    assert not _msgs(r, "FAIL") and not _msgs(r, "WARN")


def test_unit_env_parses_quoted_pairs():
    env = doctor.unit_env('PYTHONUNBUFFERED=1 "CAIRN_API_URL=https://x y" CAIRN_CAN_EXECUTE=1')
    assert env == {"PYTHONUNBUFFERED": "1", "CAIRN_API_URL": "https://x y", "CAIRN_CAN_EXECUTE": "1"}


# ---- host side: the vault's pull config vs its targets ------------------------------------------
CONF = """HOME_SSH  alice@homebox
PORT      2222
KEY       /home/alice/.ssh/cairn-pull
SET  wiki_offsite  rpool/apps/wiki  tank/homebox/apps/wiki
"""


def test_parse_pull_conf():
    c = doctor.parse_pull_conf(CONF)
    assert c["HOME_SSH"] == "alice@homebox" and c["PORT"] == "2222"
    assert c["SETS"] == [("wiki_offsite", "rpool/apps/wiki", "tank/homebox/apps/wiki", "")]


def test_set_name_mismatch_is_named_with_the_rename():
    # A reported case: the vault watched the copy as 'wiki', the SET (= home's zfs-repl) is 'wiki_offsite'
    tg = [{"name": "wiki", "type": "zfs-local", "source": "tank/homebox/apps/wiki"}]
    f = doctor.pull_set_findings(doctor.parse_pull_conf(CONF), tg, {"tank"})
    assert f[0][0] == "FAIL" and "named 'wiki'" in f[0][1] and "rename the target 'wiki' to 'wiki_offsite'" in f[0][2]


def test_matching_set_without_source_agent_warns():
    tg = [{"name": "wiki_offsite", "type": "zfs-local", "source": "tank/homebox/apps/wiki"}]
    f = doctor.pull_set_findings(doctor.parse_pull_conf(CONF), tg, {"tank"})
    assert [x[0] for x in f] == ["WARN"] and "no source_agent" in f[0][1]


def test_matching_set_is_clean_and_orphan_receiver_warns():
    tg = [{"name": "wiki_offsite", "type": "zfs-local", "source": "tank/homebox/apps/wiki", "source_agent": "local"},
          {"name": "photos", "type": "zfs-local", "source": "tank/photos", "source_agent": "local"}]
    f = doctor.pull_set_findings(doctor.parse_pull_conf(CONF), tg, {"tank"})
    assert len(f) == 1 and "'photos'" in f[0][1] and "no SET" in f[0][1]


def test_set_into_a_missing_pool_fails():
    f = doctor.pull_set_findings(doctor.parse_pull_conf(CONF), [], {"vault"})
    assert any(x[0] == "FAIL" and "isn't on this vault" in x[1] for x in f)


# ---- host side: agent process scan ---------------------------------------------------------------
def test_agent_processes_finds_python_agents_only(tmp_path):
    (tmp_path / "stat").write_text("cpu 1 2 3\nbtime 1000\n")
    def proc(pid, argv, cg):
        d = tmp_path / str(pid); d.mkdir()
        (d / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")
        (d / "stat").write_text(f"{pid} (python3) S " + " ".join(["0"] * 18) + " 500 0 0\n")
        (d / "cgroup").write_text(f"0::{cg}\n")
    proc(10, ["/usr/bin/python3", "/home/s/cairn/agent.py"], "/user.slice/cairn-agent.service")
    proc(11, ["python3", "/app/agent.py"], "/user.slice/libpod-abc.scope")
    proc(12, ["/usr/bin/sg", "backup", "-c", "exec python3 agent.py"], "/user.slice/cairn-agent.service")
    proc(13, ["python3", "phase1/doctor.py"], "/user.slice/session.scope")
    got = doctor.agent_processes(str(tmp_path))
    assert [p for p, _, _ in got] == [10, 11]
    assert got[1][2].endswith("libpod-abc.scope")


# ---- control plane: cross-agent fleet check -----------------------------------------------------
def _agent(name, version=None, ts=None, host=None):
    with api.db() as conn:
        conn.execute("INSERT OR REPLACE INTO agents(name,can_execute,last_report_ts,report_interval,agent_version,hostname) "
                     "VALUES(?,1,?,120,?,?)", (name, ts or int(time.time()), version or api.CAIRN_VERSION, host))
        conn.commit()


def _target(agent, name, typ, source, dest=None, **detail):
    with api.db() as conn:
        tid = conn.execute("INSERT INTO targets(name,type,source,dest,agent,enabled) VALUES(?,?,?,?,?,1) RETURNING id",
                           (name, typ, source, dest, agent)).fetchone()[0]
        conn.execute("INSERT INTO status(ts,target_id,severity,detail_json) VALUES(?,?,'OK',?)",
                     (int(time.time()), tid, json.dumps(detail)))
        conn.commit()


def _fleet(*agents):
    with api.db() as conn:
        return [f for f in api.fleet_doctor(conn) if f["agent"] in agents]


def test_fleet_unknown_dest_agent():
    _agent("dr-home1")
    _target("dr-home1", "g1", "zfs-repl", "rpool/g1", "tank/g1", dest_agent="dr-vaultX")
    f = _fleet("dr-home1")
    assert any(x["severity"] == "CRIT" and "'dr-vaultX', which isn't an agent" in x["problem"] for x in f)


def test_fleet_unjoined_pair_points_at_the_wrong_dataset():
    _agent("dr-home2"); _agent("dr-vault2")
    _target("dr-home2", "g2", "zfs-repl", "rpool/vol/g2", "tank/g2", dest_agent="dr-vault2")
    _target("dr-vault2", "g2", "zfs-local", "tank/home2/vol/g2", source_agent="dr-home2")
    f = _fleet("dr-home2")
    assert any("doesn't join" in x["problem"] and "watches tank/home2/vol/g2" in x["problem"] for x in f)


def test_fleet_pair_name_mismatch_and_missing_source_agent():
    _agent("dr-home3"); _agent("dr-vault3")
    _target("dr-home3", "g3_offsite", "zfs-repl", "rpool/g3", "tank/g3", dest_agent="dr-vault3")
    _target("dr-vault3", "g3", "zfs-local", "tank/g3")
    probs = " | ".join(x["problem"] for x in _fleet("dr-vault3"))
    assert "calls the copy of 'g3_offsite' 'g3'" in probs and "no source_agent" in probs


def test_fleet_clean_pair_has_no_findings():
    _agent("dr-home4"); _agent("dr-vault4")
    _target("dr-home4", "g4", "zfs-repl", "rpool/g4", "tank/g4", dest_agent="dr-vault4")
    _target("dr-vault4", "g4", "zfs-local", "tank/g4", source_agent="dr-home4")
    assert _fleet("dr-home4", "dr-vault4") == []


def test_fleet_receiver_nothing_sends_to():
    _agent("dr-home5"); _agent("dr-vault5")
    _target("dr-vault5", "g5", "zfs-local", "tank/g5", source_agent="dr-home5")
    assert any("has no zfs-repl with dest tank/g5" in x["problem"] for x in _fleet("dr-vault5"))


def test_fleet_outdated_and_silent_agents():
    _agent("dr-old", version="0.1.0", ts=int(time.time()) - 86400)
    probs = " | ".join(x["problem"] for x in _fleet("dr-old"))
    assert "runs 0.1.0" in probs and "hasn't reported" in probs


def test_duplicate_agent_hostname_flip_is_flagged():
    now = int(time.time())
    _agent("dr-dup", ts=now - 30, host="homebox")
    with api.db() as conn:
        api._note_host_conflict(conn, "dr-dup", "3f2a9c1d", now)       # a container's hostname
        conn.commit()
    f = _fleet("dr-dup")
    assert f and f[0]["severity"] == "CRIT" and "homebox and 3f2a9c1d" in f[0]["problem"]


def test_moving_an_agent_to_a_new_box_is_not_a_duplicate():
    now = int(time.time())
    _agent("dr-moved", ts=now - 7 * 86400, host="oldbox")
    with api.db() as conn:
        api._note_host_conflict(conn, "dr-moved", "newbox", now)
        conn.commit()
    assert not any("two agents" in x["problem"] for x in _fleet("dr-moved"))


def test_agent_doctor_filters_to_one_agent():
    _agent("dr-home6")
    _target("dr-home6", "g6", "zfs-repl", "rpool/g6", "tank/g6", dest_agent="nobody6")
    j = api.agent_doctor("dr-home6")
    assert j["known"] and j["findings"] and all(x["agent"] == "dr-home6" for x in j["findings"])


# ---- main box: checking the vault over ssh -------------------------------------------------------
def test_split_hostport():
    assert doctor.split_hostport("alice@vault:2222") == ("alice@vault", "2222")
    assert doctor.split_hostport("vault") == ("vault", "")


def _vault(targets, pull=CONF, name="offsite-vault", pools=("tank",)):
    out = "@@NAME\n%s\n@@VERSION\n0.38.0\n@@POOLS\n%s\n@@TARGETS\n%s\n@@PULL\n%s@@END\n" % (
        name, "\n".join(pools), json.dumps({"targets": targets}), pull)
    v, err = doctor.parse_remote(out)
    assert err is None
    return v


HOME = [{"name": "wiki_offsite", "type": "zfs-repl", "source": "rpool/apps/wiki",
         "dest": "tank/homebox/apps/wiki", "dest_agent": "offsite-vault"}]


def test_vault_compare_clean():
    v = _vault([{"name": "wiki_offsite", "type": "zfs-local", "source": "tank/homebox/apps/wiki",
                 "source_agent": "local"}])
    f = doctor.compare_vault(HOME, "local", v)
    assert [x[0] for x in f] == ["OK"]


def test_vault_compare_reported_mismatch():
    # vault target named 'wiki', and the home dest missed the vault's dataset path
    home = [dict(HOME[0], dest="tank/apps/wiki")]
    v = _vault([{"name": "wiki", "type": "zfs-local", "source": "tank/homebox/apps/wiki"}],
               pull="HOME_SSH s@e\nKEY /k\nSET wiki_offsite rpool/apps/wiki tank/homebox/apps/wiki\n")
    msgs = " | ".join(m for lvl, m, _ in doctor.compare_vault(home, "local", v) if lvl == "FAIL")
    assert "no zfs-local on 'offsite-vault' watches tank/apps/wiki" in msgs and "'wiki' there watches tank/homebox/apps/wiki" in msgs
    assert "no SET in the vault's replication.conf pulls into tank/apps/wiki" in msgs


def test_vault_compare_wrong_dest_agent_name_and_no_pull_conf():
    home = [dict(HOME[0], dest_agent="offsite")]
    v = _vault([{"name": "wiki_offsite", "type": "zfs-local", "source": "tank/homebox/apps/wiki",
                 "source_agent": "local"}], pull="")
    v["pull"] = None
    msgs = " | ".join(m for lvl, m, _ in doctor.compare_vault(home, "local", v) if lvl == "FAIL")
    assert "dest_agent is 'offsite' but the vault's agent is named 'offsite-vault'" in msgs
    assert "no replication.conf" in msgs


def test_vault_compare_undeclared_pull_and_raw_mismatch():
    home = [dict(HOME[0], encrypted=True)]
    v = _vault([{"name": "wiki_offsite", "type": "zfs-local", "source": "tank/homebox/apps/wiki",
                 "source_agent": "local"}],
               pull=CONF + "SET photos rpool/photos tank/homebox/photos\n")
    f = doctor.compare_vault(home, "local", v)
    assert any("is not raw" in m for _, m, _ in f)
    assert any("SET 'photos'" in m and "no zfs-repl here declares it" in m for _, m, _ in f)


def test_parse_remote_reports_missing_checkout():
    assert doctor.parse_remote("@@ERR no ~/cairn on this host\n") == (None, "no ~/cairn on this host")
