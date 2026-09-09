#!/usr/bin/env python3
"""backup-monitor Phase 3 action runner (the privileged executor).

Triggered by backup-action.path when a *.intent file lands in INTENT_DIR. Runs as ROOT
(syncoid/scrub need it). The web/API tier stays unprivileged and only *writes* intents.

SECURITY MODEL (read before editing):
  * The intent file carries ONLY {id, target, action} - never a command.
  * The command is built HERE from targets.yaml (root-owned, trusted) by target NAME, via a
    fixed action allowlist. Arbitrary strings from the intent are never executed.
  * Actions allowed: sync (zfs-repl only) -> syncoid;  scrub (zfs-local only) -> zpool scrub.
  * BM_DRYRUN=1 logs the command instead of running it (safe end-to-end test).

Usage: backup-action-runner.py --once      # process all pending *.intent then exit
Env (or /etc/backup-monitor/backup-monitor.env): BM_DB, BM_TARGETS, INTENT_DIR, NOTIFY_SH,
     ACTION_LOG, BM_DRYRUN, ACTION_TIMEOUT
"""
import argparse, json, os, sqlite3, subprocess, sys, time
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required")

def load_env(path="/etc/backup-monitor/backup-monitor.env"):
    p = Path(os.environ.get("BACKUP_MONITOR_ENV", path))
    if p.is_file():
        for line in p.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

load_env()
INTENT_DIR = Path(os.environ.get("INTENT_DIR", "/run/backup-intents"))
DB = os.environ.get("BM_DB", "/var/lib/backup-monitor/backup-monitor.db")
TARGETS = os.environ.get("BM_TARGETS", "/opt/backup-monitor/targets.yaml")
NOTIFY = os.environ.get("NOTIFY_SH", "/opt/backup-monitor/phase0/notify.sh")
LOG = os.environ.get("ACTION_LOG", "/var/log/backup-monitor-actions.log")
DRYRUN = os.environ.get("BM_DRYRUN", "0") == "1"
TIMEOUT = int(os.environ.get("ACTION_TIMEOUT", "7200"))

def log(msg):
    line = f"{time.strftime('%F %T')} {msg}\n"
    try:
        with open(LOG, "a") as f:
            f.write(line)
    except OSError:
        pass
    print(line, end="")

def db():
    c = sqlite3.connect(DB, timeout=30)
    return c

def set_state(iid, state, result=None):
    with db() as c:
        if result is None:
            c.execute("UPDATE intents SET state=?,claimed_ts=strftime('%s','now'),claimed_by='runner' WHERE id=?",
                      (state, iid))
        else:
            c.execute("UPDATE intents SET state=?,result=?,result_ts=strftime('%s','now') WHERE id=?",
                      (state, result[:4000], iid))
        c.commit()

def targets():
    return {t["name"]: t for t in yaml.safe_load(Path(TARGETS).read_text()).get("targets", [])}

def notify(sev, title, body, key, info_email=False):
    if not os.path.exists(NOTIFY):
        return
    env = dict(os.environ)
    if info_email:
        env["NOTIFY_INFO_EMAIL"] = "1"
    try:
        subprocess.run(["bash", NOTIFY, sev, title, body, key], env=env, timeout=30)
    except subprocess.SubprocessError:
        pass

# --- the fixed action allowlist: (action, target-type) -> argv built from trusted fields ---
def build_command(action, t, opts):
    typ = t.get("type")
    src = t.get("source")
    if action == "snapshot":
        # take a manual snapshot of the source dataset (works for any dataset with a source).
        if not src:
            return None, "target has no source dataset"
        snap = f"{src}@bm-manual-{time.strftime('%Y%m%dT%H%M%S')}"
        return ["zfs", "snapshot", snap], None
    if action == "sync":
        if typ != "zfs-repl":
            return None, f"'sync' not allowed for type '{typ}'"
        dst = t.get("dest")
        if not src or not dst:
            return None, "target missing source/dest"
        # --no-stream = single incremental (the essential syncoid gotcha).
        cmd = ["syncoid", "--no-privilege-elevation", "--no-stream"]
        # create_snapshot=True (default): syncoid takes a fresh sync-snapshot and sends it
        # (captures current state on demand). False: replicate only EXISTING snapshots.
        if not opts.get("create_snapshot", True):
            cmd.append("--no-sync-snap")
        cmd += [src, dst]
        return cmd, None
    if action == "scrub":
        if typ != "zfs-local":
            return None, f"'scrub' not allowed for type '{typ}'"
        pool = (src or "").split("/")[0]
        if not pool:
            return None, "no pool for scrub"
        return ["zpool", "scrub", pool], None
    return None, f"unknown action '{action}'"

def process(path):
    try:
        intent = json.loads(Path(path).read_text())
    except (ValueError, OSError) as e:
        log(f"bad intent {path}: {e}"); Path(path).unlink(missing_ok=True); return
    iid, target, action = intent.get("id"), intent.get("target"), intent.get("action")
    if not (iid and target and action):
        log(f"incomplete intent {path}"); Path(path).unlink(missing_ok=True); return
    log(f"intent {iid}: target={target} action={action}")
    set_state(iid, "running")
    tmap = targets()
    t = tmap.get(target)
    if not t:
        set_state(iid, "failed", f"unknown target '{target}'")
        notify("CRIT", f"action FAILED: {target} {action}", f"unknown target '{target}'", f"action-{iid}")
        Path(path).unlink(missing_ok=True); return
    opts = {"create_snapshot": intent.get("create_snapshot", True)}
    cmd, err = build_command(action, t, opts)
    if err:
        set_state(iid, "failed", err)
        notify("CRIT", f"action FAILED: {target} {action}", err, f"action-{iid}")
        Path(path).unlink(missing_ok=True); return
    log(f"run: {' '.join(cmd)}  (dryrun={DRYRUN})")
    if DRYRUN:
        out, rc = f"[DRYRUN] would run: {' '.join(cmd)}", 0
    else:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)
            out, rc = (p.stdout + p.stderr), p.returncode
        except subprocess.TimeoutExpired:
            out, rc = f"TIMEOUT after {TIMEOUT}s", 124
    tail = out.strip()[-1500:]
    if rc == 0:
        set_state(iid, "done", tail)
        log(f"intent {iid} DONE")
        notify("INFO", f"action done: {target} {action}", tail or "ok", f"action-{iid}", info_email=True)
    else:
        set_state(iid, "failed", tail)
        log(f"intent {iid} FAILED rc={rc}")
        notify("CRIT", f"action FAILED: {target} {action}", f"rc={rc}\n{tail}", f"action-{iid}")
    Path(path).unlink(missing_ok=True)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true", help="process pending intents then exit")
    ap.parse_args()
    INTENT_DIR.mkdir(parents=True, exist_ok=True)
    # simple lock so overlapping path-triggers don't double-run an intent
    lock = INTENT_DIR / ".runner.lock"
    try:
        fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        # stale lock older than 3h -> steal it
        try:
            if time.time() - lock.stat().st_mtime > 3 * 3600:
                lock.unlink(missing_ok=True)
                fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            else:
                log("another runner holds the lock; exiting"); return 0
        except OSError:
            log("lock contention; exiting"); return 0
    try:
        pending = sorted(INTENT_DIR.glob("*.intent"))
        if not pending:
            log("no pending intents")
        for f in pending:
            process(f)
    finally:
        os.close(fd)
        lock.unlink(missing_ok=True)
    return 0

if __name__ == "__main__":
    sys.exit(main())
