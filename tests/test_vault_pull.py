"""replication/vault-pull.sh: config parsing and the ssh/syncoid it runs (stubbed)."""
import os
import subprocess

RUNNER = os.path.join(os.path.dirname(__file__), "..", "replication", "vault-pull.sh")


def _run(tmp_path, conf_lines, *args, ssh_fail=None, tries="1"):
    bin_ = tmp_path / "bin"; bin_.mkdir()
    log = tmp_path / "calls.log"
    for tool in ("ssh", "syncoid"):
        f = bin_ / tool
        body = (f'echo "{ssh_fail}" >&2\nexit 255' if tool == "ssh" and ssh_fail else "exit 0")
        f.write_text(f'#!/bin/sh\necho "{tool} $*" >> "{log}"\n{body}\n')
        f.chmod(0o755)
    conf = tmp_path / "replication.conf"
    conf.write_text("\n".join(conf_lines) + "\n")
    env = dict(os.environ, PATH=f"{bin_}:{os.environ['PATH']}", PULL_PROBE_TRIES=tries, PULL_PROBE_WAIT="0")
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


def test_unknown_host_key_fails_fast_with_the_reason(tmp_path):
    r, calls = _run(tmp_path, BASE, ssh_fail="Host key verification failed.", tries="4")
    assert r.returncode == 4 and calls.count("ssh ") == 1          # no pointless retries
    assert "Host key verification failed" in r.stderr and "not a network problem" in r.stderr
    assert "syncoid" not in calls


def test_network_failure_retries_and_shows_ssh_error(tmp_path):
    r, calls = _run(tmp_path, BASE + ["PORT  2222"],
                    ssh_fail="ssh: connect to host home port 2222: Connection timed out", tries="2")
    assert r.returncode == 3 and calls.count("ssh ") == 2
    assert "port 2222 (attempt 1/2): ssh: connect to host home port 2222: Connection timed out" in r.stderr
