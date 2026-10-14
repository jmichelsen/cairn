"""replication/vault-pull.sh: config parsing and the ssh/syncoid it runs (stubbed)."""
import os
import subprocess

RUNNER = os.path.join(os.path.dirname(__file__), "..", "replication", "vault-pull.sh")


def _run(tmp_path, conf_lines, *args, ssh_fail=None, tries="1", zfs=None):
    bin_ = tmp_path / "bin"; bin_.mkdir()
    log = tmp_path / "calls.log"
    for tool in ("ssh", "syncoid"):
        f = bin_ / tool
        body = (f'echo "{ssh_fail}" >&2\nexit 255' if tool == "ssh" and ssh_fail else "exit 0")
        f.write_text(f'#!/bin/sh\necho "{tool} $*" >> "{log}"\n{body}\n')
        f.chmod(0o755)
    if zfs is not None:                       # a stub zfs answering from a script body
        f = bin_ / "zfs"; f.write_text("#!/bin/sh\n" + zfs); f.chmod(0o755)
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


# zfs stub: tank/wiki exists, 192K used, with or without snapshots / a resume token
def _zfs(snaps="", token="-"):
    return (f'case "$*" in\n'
            f'  *"-t snapshot"*) printf "%s" "{snaps}" ;;\n'
            f'  *receive_resume_token*) echo "{token}" ;;\n'
            f'  *"-o used"*) echo 192K ;;\n'
            f'  *) echo tank/wiki ;;\n'
            f'esac\n')


def test_existing_empty_dest_is_explained_not_sent(tmp_path):
    r, calls = _run(tmp_path, BASE, zfs=_zfs())
    assert r.returncode == 1 and "syncoid" not in calls
    assert "tank/wiki already exists on this vault (using 192K) but has no snapshots" in r.stdout
    assert "sudo zfs destroy tank/wiki" in r.stdout


def test_dest_with_snapshots_or_resume_token_still_pulls(tmp_path):
    for z in (_zfs(snaps="tank/wiki@a\\n"), _zfs(token="1-abc")):
        d = tmp_path / str(abs(hash(z))); d.mkdir()
        r, calls = _run(d, BASE, zfs=z)
        assert r.returncode == 0 and "syncoid" in calls, r.stdout
