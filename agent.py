#!/usr/bin/env python3
"""backup-monitor agent - one uniform agent for ANY host (local main host or remote vault).

Talks ONLY to the API over HTTP - localhost or a public URL + token. Same code regardless of
distance; the only difference is BM_API_URL + BM_API_TOKEN + BM_AGENT_NAME. Two capabilities:

  report  (always)  - collect THIS host's backup status and POST it to the API.
  execute (opt-in)  - poll the API for intents assigned to this agent, run them, POST results.
                      Commands are built from THIS agent's TRUSTED local config (targets.yaml),
                      never from the wire. Needs root / zfs-delegation on this host.

Report-only agents need no privilege beyond reads. There is no file-based path - every host,
near or far, uses this one HTTP agent.

Env: BM_API_URL, BM_API_TOKEN, BM_AGENT_NAME, BM_TARGETS, BM_CAN_EXECUTE(0/1),
     BM_INTERVAL, BM_DRYRUN(0/1), BM_ACTION_TIMEOUT
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

C.load_env()                     # pull /config/backup-monitor.env if present
def _e(k, d=None): return os.environ.get(k, d)
API      = _e("BM_API_URL", "http://localhost:8929").rstrip("/")
TOKEN    = _e("BM_API_TOKEN", "")
NAME     = _e("BM_AGENT_NAME", "local")
TARGETS  = _e("BM_TARGETS", str(HERE / "targets.yaml"))
CAN_EXEC = _e("BM_CAN_EXECUTE", "0") == "1"
INTERVAL = int(_e("BM_INTERVAL", "900"))
DRYRUN   = _e("BM_DRYRUN", "0") == "1"
TIMEOUT  = int(_e("BM_ACTION_TIMEOUT", "7200"))

META_KEYS = ["type", "source", "dest", "tier", "location", "encrypted", "cadence"]

def api_call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{API}{path}", data=data, method=method,
          headers={"Content-Type": "application/json", "X-Backup-Token": TOKEN})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read() or "null")

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
             {"agent": NAME, "ts": int(time.time()), "statuses": items})
    return len(items)

def do_execute(cfg):
    tmap = {t["name"]: t for t in cfg.get("targets", [])}
    res = api_call("GET", f"/api/v1/backup/intents?agent={NAME}") or {}
    intents = res.get("intents", [])
    for it in intents:
        iid, target, action = it["id"], it.get("target"), it.get("action")
        opts = {"create_snapshot": it.get("create_snapshot", True)}
        t = tmap.get(target)
        if not t:
            api_call("POST", f"/api/v1/backup/intents/{iid}/result",
                     {"ok": False, "output": f"agent '{NAME}' does not manage target '{target}'"})
            continue
        cmd, err = C.build_command(action, t, opts)
        if err:
            api_call("POST", f"/api/v1/backup/intents/{iid}/result", {"ok": False, "output": err})
            continue
        if DRYRUN:
            out, rc = f"[DRYRUN] would run: {' '.join(cmd)}", 0
        else:
            rc, so, se = C.run(cmd, timeout=TIMEOUT); out = (so + se)
        api_call("POST", f"/api/v1/backup/intents/{iid}/result",
                 {"ok": rc == 0, "output": out.strip()[-1500:], "cmd": " ".join(cmd)})
        print(f"  intent {iid} {target} {action} -> {'ok' if rc == 0 else 'FAIL'}")
    return len(intents)

def main():
    once = "--once" in sys.argv
    cfg = yaml.safe_load(Path(TARGETS).read_text())
    print(f"agent '{NAME}' -> {API}  (execute={CAN_EXEC}, dryrun={DRYRUN}, interval={INTERVAL}s)")
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
