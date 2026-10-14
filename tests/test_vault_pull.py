"""replication/vault-pull.sh: config parsing and the ssh/syncoid it runs (stubbed)."""
import os
import subprocess

RUNNER = os.path.join(os.path.dirname(__file__), "..", "replication", "vault-pull.sh")


def _run(tmp_path, conf_lines, *args):
    bin_ = tmp_path / "bin"; bin_.mkdir()
    log = tmp_path / "calls.log"
    for tool in ("ssh", "syncoid"):
        f = bin_ / tool
        f.write_text(f'#!/bin/sh\necho "{tool} $*" >> "{log}"\nexit 0\n')
        f.chmod(0o755)
    conf = tmp_path / "replication.conf"
    conf.write_text("\n".join(conf_lines) + "\n")
    env = dict(os.environ, PATH=f"{bin_}:{os.environ['PATH']}", PULL_PROBE_TRIES="1", PULL_PROBE_WAIT="0")
    r = subprocess.run(["bash", RUNNER, "--conf", str(conf), *args], capture_output=True, text=True, env=env)
    return r, (log.read_text() if log.exists() else "")


BASE = ["HOME_SSH  alice@home", "KEY  /k", "SET  wiki  rpool/wiki  tank/wiki"]


def test_custom_port_reaches_probe_and_syncoid(tmp_path):
    r, calls = _run(tmp_path, BASE + ["PORT  2222"])
    assert r.returncode == 0, r.stderr
    assert "ssh -o BatchMode=yes -o ConnectTimeout=10 -p 2222" in calls
    assert "--sshport 2222" in calls and "alice@home:rpool/wiki tank/wiki" in calls


def test_default_port_adds_nothing(tmp_path):
    r, calls = _run(tmp_path, BASE)
    assert r.returncode == 0 and "-p " not in calls and "--sshport" not in calls


def test_bad_port_is_rejected(tmp_path):
    r, _ = _run(tmp_path, BASE + ["PORT  ssh"])
    assert r.returncode == 2 and "PORT must be a number" in r.stderr
