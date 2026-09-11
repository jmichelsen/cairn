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
import json, os, sys, time, urllib.request, urllib.error
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

META_KEYS = ["type", "source", "dest", "tier", "location", "encrypted", "cadence"]

def enroll():
    """Trade the enrollment secret for a fresh short-lived access token."""
    if not ENROLL_SECRET:
        raise RuntimeError("got 401 and no CAIRN_ENROLL_SECRET to re-enroll with")
    req = urllib.request.Request(f"{API}/api/v1/backup/enroll", data=b"{}", method="POST",
          headers={"Content-Type": "application/json", "X-Backup-Enroll": ENROLL_SECRET})
    with urllib.request.urlopen(req, timeout=30) as r:
        j = json.loads(r.read())
    _access["token"] = j["access_token"]
    print(f"enrolled: fresh access token (expires_in {j.get('expires_in')}s)")

def api_call(method, path, body=None, _retry=True):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{API}{path}", data=data, method=method,
          headers={"Content-Type": "application/json", "X-Backup-Token": _access["token"]})
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
    api_call("POST", "/api/v1/backup/report",
             {"agent": NAME, "ts": int(time.time()), "can_execute": CAN_EXEC,
              "interval": INTERVAL, "statuses": items})
    return len(items)

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
            body = {"ok": rc == 0, "output": (so + se).strip()[-1500:], "cmd": " ".join(cmd)}
        api_call("POST", f"/api/v1/backup/intents/{iid}/result", body)
        print(f"  intent {iid} {target} {action}{' [dry]' if dry else ''} -> {'ok' if rc == 0 else 'FAIL'}")
    return len(intents)

def main():
    once = "--once" in sys.argv
    cfg = yaml.safe_load(Path(TARGETS).read_text())
    auth = "enroll" if ENROLL_SECRET else "static-token"
    print(f"agent '{NAME}' -> {API}  (auth={auth}, execute={CAN_EXEC}, dryrun={DRYRUN}, interval={INTERVAL}s)")
    if ENROLL_SECRET:
        try:
            enroll()
        except Exception as e:
            print(f"initial enroll failed (will retry on first 401): {e}")
    while True:
        try:
            n = do_report(cfg); print(f"reported {n} statuses")
        except Exception as e:
            print(f"report failed: {e}")
        if CAN_EXEC:
            try:
                do_execute(cfg)
            except urllib.error.HTTPError as e:
                print(f"poll failed: HTTP {e.code}")
            except Exception as e:
                print(f"execute failed: {e}")
        if once:
            break
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
