"""phase1/cairn-agent-rename.py: renaming an agent across the API database keeps its history."""
import importlib.util
import os
import sqlite3
import subprocess
import sys
import time

TOOL = os.path.join(os.path.dirname(__file__), "..", "phase1", "cairn-agent-rename.py")
SCHEMA = os.path.join(os.path.dirname(__file__), "..", "phase1", "schema.sql")
_spec = importlib.util.spec_from_file_location("agent_rename", TOOL)
R = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(R)


def _db(tmp_path, last=None):
    p = str(tmp_path / "c.db")
    c = sqlite3.connect(p)
    c.executescript(open(SCHEMA).read())
    for col in ("hostname TEXT",):
        try: c.execute(f"ALTER TABLE agents ADD COLUMN {col}")
        except sqlite3.OperationalError: pass
    c.execute("CREATE TABLE removable_links (id INTEGER PRIMARY KEY, agent TEXT NOT NULL, removable TEXT, dataset TEXT)")
    c.execute("INSERT INTO agents(name,last_report_ts,report_interval) VALUES('local',?,120)", (last or 1,))
    c.execute("INSERT INTO agents(name,last_report_ts,report_interval) VALUES('vault',1,300)")
    c.execute("INSERT INTO targets(name,type,agent) VALUES('Pics','zfs-repl','local')")
    c.execute("INSERT INTO targets(name,type,agent) VALUES('Pics','zfs-local','vault')")
    tid = c.execute("SELECT id FROM targets WHERE agent='local'").fetchone()[0]
    c.execute("INSERT INTO status(ts,target_id,severity) VALUES(1,?,'OK')", (tid,))
    c.execute("INSERT INTO intents(target_id,action,state,created_ts,claimed_by) VALUES(?,'sync','done',1,'local')", (tid,))
    c.execute("INSERT INTO target_retired(agent,name,ts) VALUES('local','old',1)")
    c.execute("INSERT INTO removable_links(agent,removable,dataset) VALUES('local','ext','Pics')")
    c.execute("INSERT INTO reconcile_dismissed(pair,ts) VALUES('local:Pics|vault:Pics',1)")
    c.commit(); c.close()
    return p


def _run(p, *args):
    return subprocess.run([sys.executable, TOOL, "--db", p, *args], capture_output=True, text=True)


def test_rename_moves_every_reference_and_keeps_history(tmp_path):
    p = _db(tmp_path)
    r = _run(p, "local", "mclife")
    assert r.returncode == 0, r.stderr
    assert list(tmp_path.glob("c.db.bak-rename-*"))
    c = sqlite3.connect(p)
    assert [x[0] for x in c.execute("SELECT name FROM agents ORDER BY name")] == ["mclife", "vault"]
    assert c.execute("SELECT COUNT(*) FROM targets WHERE agent='local'").fetchone()[0] == 0
    tid = c.execute("SELECT id FROM targets WHERE agent='mclife' AND name='Pics'").fetchone()[0]
    assert c.execute("SELECT COUNT(*) FROM status WHERE target_id=?", (tid,)).fetchone()[0] == 1   # history kept
    assert c.execute("SELECT claimed_by FROM intents").fetchone()[0] == "mclife"
    assert c.execute("SELECT agent FROM target_retired").fetchone()[0] == "mclife"
    assert c.execute("SELECT agent FROM removable_links").fetchone()[0] == "mclife"
    assert c.execute("SELECT pair FROM reconcile_dismissed").fetchone()[0] == "mclife:Pics|vault:Pics"
    assert c.execute("SELECT agent FROM targets WHERE type='zfs-local'").fetchone()[0] == "vault"   # others untouched


def test_dry_run_changes_nothing(tmp_path):
    p = _db(tmp_path)
    r = _run(p, "local", "mclife", "--dry-run")
    assert r.returncode == 0 and "targets.agent: 1 row(s)" in r.stdout
    assert sqlite3.connect(p).execute("SELECT name FROM agents WHERE name='local'").fetchone()
    assert not list(tmp_path.glob("c.db.bak-rename-*"))


def test_refuses_taken_name_unknown_agent_and_bad_name(tmp_path):
    p = _db(tmp_path)
    assert "already exists" in _run(p, "local", "vault").stderr
    assert "no agent named 'nope'" in _run(p, "nope", "x").stderr
    assert "isn't a valid agent name" in _run(p, "local", "has space").stderr


def test_refuses_while_the_old_agent_is_still_reporting(tmp_path):
    p = _db(tmp_path, last=int(time.time()) - 30)
    r = _run(p, "local", "mclife", "--no-backup")
    assert r.returncode != 0 and "Stop it first" in r.stderr
    assert sqlite3.connect(p).execute("SELECT 1 FROM agents WHERE name='local'").fetchone()
    assert _run(p, "local", "mclife", "--no-backup", "--force").returncode == 0
