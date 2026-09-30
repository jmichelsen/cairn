"""Tests for notify.sh per-severity EMAIL routing (immediate | digest | off) and the --flush-digest
daily summary. The SMTP transport is stubbed by shimming a fake `msmtp` onto PATH that records every
delivered message, so these run offline and assert exactly what would (and would NOT) be emailed."""
import os
import subprocess
import sys

HERE = os.path.dirname(__file__)
NOTIFY = os.path.abspath(os.path.join(HERE, "..", "phase0", "notify.sh"))


def _env(tmp_path):
    """A clean env: fake-msmtp shim on PATH, an isolated STATE_DIR + log, real-looking recipient."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    captured = tmp_path / "sent"          # one delivered message appended per email
    msmtp = bindir / "msmtp"
    # Record the stdin (the full RFC822 message) framed by a separator, ignore all args, succeed.
    msmtp.write_text('#!/usr/bin/env bash\n{ echo "=== MSG ==="; cat; } >> "%s"\nexit 0\n' % captured)
    msmtp.chmod(0o755)
    state = tmp_path / "state"
    state.mkdir()
    e = dict(os.environ)
    e["PATH"] = f"{bindir}:{e['PATH']}"
    e["CAIRN_ENV"] = str(tmp_path / "nonexistent.env")   # don't source the host's real config
    e["MAIL_MODE"] = "smtp"
    e["NOTIFY_EMAIL"] = "ops@homelab.lan"
    e["STATE_DIR"] = str(state)
    e["NOTIFY_LOG"] = str(tmp_path / "cairn.log")
    # neutralize any inherited routing/force flags so each test starts from documented defaults
    for k in ("EMAIL_CRIT", "EMAIL_WARN", "EMAIL_INFO", "NOTIFY_INFO_EMAIL",
              "NOTIFY_GOTIFY_WARN", "NOTIFY_FORCE_GOTIFY", "GOTIFY_URL", "GOTIFY_TOKEN"):
        e.pop(k, None)
    return e, captured, state


def _run(env, *args):
    return subprocess.run(["bash", NOTIFY, *args], env=env, capture_output=True, text=True, timeout=30)


def _sent(captured):
    return captured.read_text() if captured.exists() else ""


def _spool(state):
    f = state / "digest-spool"
    return f.read_text() if f.exists() else ""


# ---- back-compat defaults (no EMAIL_* set) ----

def test_warn_defaults_to_immediate_email(tmp_path):
    env, captured, state = _env(tmp_path)
    _run(env, "WARN", "pool degraded", "cap 90%", "k1")
    assert "[cairn:WARN] pool degraded" in _sent(captured)
    assert _spool(state) == ""             # nothing held for digest


def test_info_defaults_to_no_email(tmp_path):
    env, captured, state = _env(tmp_path)
    _run(env, "INFO", "just fyi", "body", "k2")
    assert _sent(captured) == ""
    assert _spool(state) == ""


def test_info_email_flag_still_forces_immediate(tmp_path):
    env, captured, _ = _env(tmp_path)
    env["NOTIFY_INFO_EMAIL"] = "1"         # the historic force-email flag (refresh confirmations)
    _run(env, "INFO", "2nd copy refreshed", "attached + synced", "k3")
    assert "[cairn:INFO] 2nd copy refreshed" in _sent(captured)


# ---- digest routing ----

def test_warn_digest_spools_instead_of_emailing(tmp_path):
    env, captured, state = _env(tmp_path)
    env["EMAIL_WARN"] = "digest"
    _run(env, "WARN", "scrub 41d old", "last scrub long ago", "k4")
    assert _sent(captured) == ""           # NOT emailed immediately
    line = _spool(state).strip().split("\t")
    assert line[1] == "WARN" and line[2] == "scrub 41d old" and line[3] == "last scrub long ago"


def test_email_off_suppresses_entirely(tmp_path):
    env, captured, state = _env(tmp_path)
    env["EMAIL_WARN"] = "off"
    _run(env, "WARN", "noisy warn", "body", "k5")
    assert _sent(captured) == ""
    assert _spool(state) == ""


def test_explicit_policy_overrides_info_email_flag(tmp_path):
    # user chose to batch INFO -> even a force-email INFO goes to the digest, not immediate mail
    env, captured, state = _env(tmp_path)
    env["EMAIL_INFO"] = "digest"
    env["NOTIFY_INFO_EMAIL"] = "1"
    _run(env, "INFO", "action done", "restic prune ok", "k6")
    assert _sent(captured) == ""
    assert "action done" in _spool(state)


# ---- flush ----

def test_flush_sends_one_grouped_email_and_clears_spool(tmp_path):
    env, captured, state = _env(tmp_path)
    env["EMAIL_WARN"] = "digest"
    env["EMAIL_CRIT"] = "digest"
    _run(env, "CRIT", "pool FAULTED", "vdev bad", "c1")
    _run(env, "WARN", "scrub overdue", "42d", "w1")
    _run(env, "WARN", "drive aging", "84k hrs", "w2")
    assert _sent(captured) == ""                       # all held
    r = _run(env, "--flush-digest")
    assert r.returncode == 0
    body = _sent(captured)
    assert body.count("=== MSG ===") == 1              # exactly ONE email
    assert "[cairn:digest] 3 notices" in body
    assert "CRITICAL" in body and "pool FAULTED" in body
    assert "WARNING" in body and "scrub overdue" in body and "drive aging" in body
    assert _spool(state) == ""                          # spool cleared after a successful send


def test_flush_empty_spool_is_a_noop(tmp_path):
    env, captured, _ = _env(tmp_path)
    r = _run(env, "--flush-digest")
    assert r.returncode == 0
    assert _sent(captured) == ""


def test_flush_restores_spool_when_send_fails(tmp_path):
    env, captured, state = _env(tmp_path)
    env["EMAIL_WARN"] = "digest"
    _run(env, "WARN", "will be held", "body", "w9")
    # make msmtp fail so the send errors out
    (tmp_path / "bin" / "msmtp").write_text("#!/usr/bin/env bash\nexit 1\n")
    (tmp_path / "bin" / "msmtp").chmod(0o755)
    r = _run(env, "--flush-digest")
    assert r.returncode == 1
    assert "will be held" in _spool(state)              # nothing lost


if __name__ == "__main__":
    sys.exit(subprocess.call(["pytest", "-q", __file__]))
