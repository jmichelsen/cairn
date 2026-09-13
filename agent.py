#!/usr/bin/env python3
"""cairn agent - one uniform agent for ANY host (local main host or remote vault).

Talks ONLY to the API over HTTP - localhost or a public URL + token. Same code regardless of
distance; the only difference is CAIRN_API_URL + CAIRN_API_TOKEN + CAIRN_AGENT_NAME. Two capabilities:

  report  (always)  - collect THIS host's backup status and POST it to the API.
  execute (opt-in)  - poll the API for intents assigned to this agent, run them, POST results.
                      Commands are built from THIS agent's TRUSTED local config (targets.yaml),
                      never from the wire. Needs root / zfs-delegation on this host.

Report-only agents need no privilege beyond reads. There is no file-based path - every host,
near or far, uses this one HTTP agent.

Env: CAIRN_API_URL, CAIRN_API_TOKEN, CAIRN_AGENT_NAME, CAIRN_TARGETS, CAIRN_CAN_EXECUTE(0/1),
     CAIRN_INTERVAL, CAIRN_DRYRUN(0/1), CAIRN_ACTION_TIMEOUT
Run: agent.py [--once]
"""
import base64, gzip, json, os, sys, time, urllib.request, urllib.error
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "phase1"))
import collector as C            # adapter library: collect_all, build_command, run, STATUS_COLS
try:
    import yaml
except ImportError:
    sys.exit("PyYAML required")

C.load_env()                     # pull /config/cairn.env if present
def _e(k, d=None): return os.environ.get(k, d)
API      = _e("CAIRN_API_URL", "http://localhost:8929").rstrip("/")
# Two ways to authenticate:
#  - CAIRN_ENROLL_SECRET (preferred): the long-lived per-agent secret; the agent trades it for a
#    short-lived access token via /enroll and auto-re-enrolls on 401 (so forced rotation self-heals).
#  - CAIRN_API_TOKEN (simple/legacy): a static access token, no rotation.
ENROLL_SECRET = _e("CAIRN_ENROLL_SECRET", "")
_access = {"token": _e("CAIRN_API_TOKEN", "")}
NAME     = _e("CAIRN_AGENT_NAME", "local")
TARGETS  = _e("CAIRN_TARGETS", str(HERE / "targets.yaml"))
CAN_EXEC = _e("CAIRN_CAN_EXECUTE", "0") == "1"
INTERVAL = int(_e("CAIRN_INTERVAL", "900"))
DRYRUN   = _e("CAIRN_DRYRUN", "0") == "1"
TIMEOUT  = int(_e("CAIRN_ACTION_TIMEOUT", "7200"))
# Nightly recovery-manifest walk. The walk is disk-heavy (it crosses every snapshot), and ionice does
# NOT throttle ZFS, so the real protection is OFF-PEAK scheduling + doing one dataset at a time:
#   RECOVER_WALK_HOURS  local-hour window the walk may run in, end-exclusive ("1-6" = 01:00-05:59; wraps,
#                       e.g. "22-6" = 22:00-05:59; "" = anytime). Keeps the walk off the disks by day.
#   RECOVER_WALK_MAX    datasets per loop (default 1, so load is spread across loops, not packed).
#   RECOVER_WALK_TIMEOUT per-dataset cap so one huge dataset can't run away.
RECOVER_WALK_HOURS   = _e("CAIRN_RECOVER_WALK_HOURS", "1-6")
RECOVER_WALK_MAX     = int(_e("CAIRN_RECOVER_WALK_MAX", "1"))
RECOVER_WALK_TIMEOUT = int(_e("CAIRN_RECOVER_WALK_TIMEOUT", "900"))

def _in_walk_window():
    """True if now (agent-local time) is inside RECOVER_WALK_HOURS. Supports a wrapping window (22-6)."""
    spec = (RECOVER_WALK_HOURS or "").strip()
    if not spec:
        return True
    try:
        a, b = (int(x) for x in spec.split("-", 1))
    except ValueError:
        return True     # misconfigured window -> don't silently block walks forever
    h = time.localtime().tm_hour
    return (a <= h < b) if a <= b else (h >= a or h < b)
# Identify with a real User-Agent. urllib's default ("Python-urllib/X.Y") is a known-bot signature
# that CDNs/WAFs in front of the API (e.g. Cloudflare) reject with 403, so always send our own.
UA       = _e("CAIRN_USER_AGENT", "cairn-agent/1.0")
def _version():
    try:
        return _e("CAIRN_VERSION") or (HERE / "VERSION").read_text().strip() or "0.0.0"
    except Exception:
        return "0.0.0"
VERSION  = _version()

META_KEYS = ["type", "source", "dest", "tier", "location", "encrypted", "cadence"]

def enroll():
    """Trade the enrollment secret for a fresh short-lived access token."""
    if not ENROLL_SECRET:
        raise RuntimeError("got 401 and no CAIRN_ENROLL_SECRET to re-enroll with")
    req = urllib.request.Request(f"{API}/api/v1/backup/enroll", data=b"{}", method="POST",
          headers={"Content-Type": "application/json", "X-Backup-Enroll": ENROLL_SECRET, "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        j = json.loads(r.read())
    _access["token"] = j["access_token"]
    print(f"enrolled: fresh access token (expires_in {j.get('expires_in')}s)")

def api_call(method, path, body=None, _retry=True):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{API}{path}", data=data, method=method,
          headers={"Content-Type": "application/json", "X-Backup-Token": _access["token"], "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read() or "null")
    except urllib.error.HTTPError as e:
        # 401 with an enrollment secret => our access token was rotated/expired; re-enroll + retry once.
        if e.code == 401 and ENROLL_SECRET and _retry:
            enroll()
            return api_call(method, path, body, _retry=False)
        raise

def do_report(cfg):
    items = []
    for tgt, st in C.collect_all(cfg):
        item = {"name": tgt["name"], "severity": st.get("severity", "UNKNOWN")}
        for k in META_KEYS:
            if tgt.get(k) is not None:
                item[k] = tgt[k]
        for k in C.STATUS_COLS:
            if st.get(k) is not None:
                item[k] = st[k]
        items.append(item)
    resp = api_call("POST", "/api/v1/backup/report",
                    {"agent": NAME, "ts": int(time.time()), "can_execute": CAN_EXEC,
                     "interval": INTERVAL, "version": VERSION, "statuses": items}) or {}
    return len(items), bool(resp.get("update"))

def self_update():
    """The control plane asked this agent to update. Run install.sh --update in a DETACHED cgroup
    (systemd-run --user) so the agent restart it performs doesn't kill the updater mid-flight."""
    import subprocess
    script = str(HERE / "install.sh")
    print("update requested by control plane -> launching detached updater (install.sh --update)")
    try:
        subprocess.Popen(["systemd-run", "--user", "--collect", "--quiet",
                          f"--unit=cairn-self-update-{int(time.time())}", "bash", script, "--update"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:   # no systemd-run: best-effort detached (may not survive the restart)
        subprocess.Popen(["bash", script, "--update"], start_new_session=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def do_execute(cfg):
    tmap = {t["name"]: t for t in cfg.get("targets", [])}
    res = api_call("GET", f"/api/v1/backup/intents?agent={NAME}") or {}
    intents = res.get("intents", [])
    for it in intents:
        iid, target, action = it["id"], it.get("target"), it.get("action")
        opts = it.get("opts") or {"create_snapshot": it.get("create_snapshot", True)}
        t = tmap.get(target)
        if not t:
            api_call("POST", f"/api/v1/backup/intents/{iid}/result",
                     {"ok": False, "output": f"agent '{NAME}' does not manage target '{target}'"})
            continue
        cmd, err = C.build_command(action, t, opts)
        if err:
            api_call("POST", f"/api/v1/backup/intents/{iid}/result", {"ok": False, "output": err})
            continue
        # dry-run is per-action (opts.dryrun from the UI) OR agent-wide (CAIRN_DRYRUN). A dry-run runs
        # a native `-n`/read-only PROBE and returns its REAL output - never the mutating command.
        dry = DRYRUN or bool(opts.get("dryrun"))
        if dry:
            dcmd, note = C.build_dryrun(action, t, opts)
            header = f"[DRY-RUN] would run: {' '.join(cmd)}"
            if dcmd is None:
                rc, out = 0, f"{header}\n\n{note}"
            else:
                rc, so, se = C.run(dcmd, timeout=min(TIMEOUT, 900))
                out = f"{header}\n\nprobe: {' '.join(dcmd)}\n\n{(so + se).strip()}"
            body = {"ok": rc == 0, "output": out.strip()[-1800:], "cmd": " ".join(cmd), "dryrun": True}
        else:
            rc, so, se = C.run(cmd, timeout=TIMEOUT)
            full = (so + se).strip()
            # Recovery LISTINGS are JSON / tab-separated tables that the dashboard parses, so they must
            # arrive whole and from the START (tail-truncated JSON is unparseable). Keep the head with a
            # generous cap for those; every other action keeps the compact last-1500 for the activity log.
            if action in ("recover-points", "recover-search", "recover-deleted"):
                out = full[:200000]
            else:
                out = full[-1500:]
            body = {"ok": rc == 0, "output": out, "cmd": " ".join(cmd)}
        api_call("POST", f"/api/v1/backup/intents/{iid}/result", body)
        print(f"  intent {iid} {target} {action}{' [dry]' if dry else ''} -> {'ok' if rc == 0 else 'FAIL'}")
    return len(intents)

def do_recovery_walk(cfg):
    """Nightly-cadence 'deleted files' manifest builder. The API returns only the datasets whose manifest
    is missing or stale (walk interval), so this is a no-op most loops. For each, walk with httm (bounded
    to this dataset via --one-filesystem), reduce to the newest version per file, gzip, and push. Walking
    is read-only; the manifest turns the otherwise-slow on-demand deleted scan into an instant lookup."""
    if not _in_walk_window():
        return 0                       # off-peak only: stay off the disks during the day
    tmap = {t["name"]: t for t in cfg.get("targets", [])}
    due = (api_call("GET", f"/api/v1/backup/agent/recovery-due?agent={NAME}") or {}).get("targets", [])
    walked = 0
    for d in due[:RECOVER_WALK_MAX]:
        t = tmap.get(d.get("name"))
        if not t:
            continue
        cmd, err = C.build_recovery_walk("deleted", t)
        if err or not cmd:
            api_call("POST", "/api/v1/backup/agent/recovery-manifest",
                     {"target": d.get("name"), "kind": "deleted", "ok": False, "error": err or "no command"})
            continue
        rc, so, se = C.run(cmd, timeout=RECOVER_WALK_TIMEOUT)
        if rc != 0:
            api_call("POST", "/api/v1/backup/agent/recovery-manifest",
                     {"target": t["name"], "kind": "deleted", "ok": False, "error": (se or so).strip()[-500:]})
            continue
        manifest, count = C.reduce_deleted_manifest(so)
        raw = manifest.encode()
        api_call("POST", "/api/v1/backup/agent/recovery-manifest",
                 {"target": t["name"], "kind": "deleted", "ok": True,
                  "gz_b64": base64.b64encode(gzip.compress(raw)).decode(),
                  "entry_count": count, "raw_bytes": len(raw), "walked_ts": int(time.time())})
        walked += 1
        print(f"  recovery walk {t['name']} -> {count} deleted file(s), {len(raw)}B raw")
    return walked

def main():
    once = "--once" in sys.argv
    cfg = yaml.safe_load(Path(TARGETS).read_text())
    auth = "enroll" if ENROLL_SECRET else "static-token"
    print(f"agent '{NAME}' v{VERSION} -> {API}  (auth={auth}, execute={CAN_EXEC}, dryrun={DRYRUN}, interval={INTERVAL}s)")
    if ENROLL_SECRET:
        try:
            enroll()
        except Exception as e:
            print(f"initial enroll failed (will retry on first 401): {e}")
    while True:
        try:
            n, want_update = do_report(cfg); print(f"reported {n} statuses")
            if want_update:
                self_update();
                if not once: time.sleep(INTERVAL); continue   # let the detached updater restart us
        except Exception as e:
            print(f"report failed: {e}")
        if CAN_EXEC:
            try:
                do_execute(cfg)
            except urllib.error.HTTPError as e:
                print(f"poll failed: HTTP {e.code}")
            except Exception as e:
                print(f"execute failed: {e}")
            try:
                w = do_recovery_walk(cfg)
                if w:
                    print(f"recovery: refreshed {w} manifest(s)")
            except Exception as e:
                print(f"recovery walk failed: {e}")
        if once:
            break
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
