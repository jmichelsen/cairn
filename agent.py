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
import base64, gzip, json, os, socket, sys, time, urllib.request, urllib.error
from pathlib import Path

HOSTNAME = socket.gethostname().split(".")[0]   # source-server namespace for cairn/<host>/<dataset>

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
# Nightly the agent seeds a CHEAP directory tree (folders only, no httm) so Versions opens into real
# folders to browse; version history is scanned per-folder ON DEMAND. VERS_* bound those on-demand scans.
DIRTREE_CAP          = int(_e("CAIRN_DIRTREE_CAP", "20000"))
VERS_SCAN_CAP        = int(_e("CAIRN_VERS_SCAN_CAP", "6000"))
VERS_SHOW_CAP        = int(_e("CAIRN_VERS_SHOW_CAP", "1200"))
VERS_BUDGET          = int(_e("CAIRN_VERS_BUDGET", "300"))

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
                     "interval": INTERVAL, "version": VERSION, "hostname": HOSTNAME, "statuses": items}) or {}
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

def _dataset_paths(cfg):
    """Monitored dataset-backed targets as [{name, path, source}]: path = the live root (zfs
    mountpoint resolved) rsync reads from; source = the dataset identity (e.g. mcz/mclife/Pics) used
    to slug its cairn/ subfolder. Feeds removable discovery, census, and link-driven backups."""
    out = []
    for t in cfg.get("targets", []):
        typ = t.get("type"); src = t.get("source")
        if not src or typ == "removable":
            continue
        if typ in ("zfs-local", "zfs-repl"):
            mp, err = C._mountpoint(src)
            if not err and mp:
                out.append({"name": t["name"], "path": mp, "source": src})
        elif os.path.isdir(src):
            out.append({"name": t["name"], "path": src, "source": src})
    return out

def _exlist(link):
    """Per-link rsync exclude patterns (JSON list on the link row), safe-parsed."""
    try:
        return json.loads((link or {}).get("excludes") or "[]")
    except (ValueError, TypeError):
        return []

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
        if action == "recover-versions":
            # folder-wide version history: enumerate files ourselves + batch through httm (httm --recursive
            # panics for versions outside interactive mode). Result goes back as the intent output JSON.
            rel = opts.get("path") or ""
            result, err = C.scan_versions(t, rel, scan_cap=VERS_SCAN_CAP, show_cap=VERS_SHOW_CAP,
                                          timeout=RECOVER_WALK_TIMEOUT, budget=VERS_BUDGET)
            if err:
                api_call("POST", f"/api/v1/backup/intents/{iid}/result", {"ok": False, "output": err})
            else:
                _push_versions_manifest(t, rel, result)   # store/merge the tree; the UI reads it back
                # return only a small summary (the full tree can exceed the intent-result cap; it lives
                # in the manifest now, which the dashboard re-fetches once this completes).
                api_call("POST", f"/api/v1/backup/intents/{iid}/result",
                         {"ok": True, "output": json.dumps({"path": rel, "total": result.get("total") or 0,
                                                             "truncated": bool(result.get("truncated"))})})
            print(f"  intent {iid} {target} recover-versions -> {'FAIL' if err else str(result.get('total'))+' file(s)'}")
            continue
        if action == "recover-dirtree":
            # build the cheap folder tree NOW (first Versions open before any nightly walk). Stores the
            # dirtree manifest; the intent result is a small summary the UI ignores (it reads the manifest).
            dok, dcount, derr = _dirtree_and_push(t)
            api_call("POST", f"/api/v1/backup/intents/{iid}/result",
                     {"ok": dok, "output": (f"folders: {dcount}" if dok else (derr or "dirtree failed"))})
            print(f"  intent {iid} {target} recover-dirtree -> {'ok' if dok else 'FAIL'} ({dcount})")
            continue
        if action == "recover-walk":
            # explicit UI refresh: walk this dataset now (bypassing the off-peak window) and STORE the
            # manifest, so the scan is kept, not discarded. The intent result is just a small summary.
            ok, count, err = _walk_and_push(t)
            api_call("POST", f"/api/v1/backup/intents/{iid}/result",
                     {"ok": ok, "output": (f"manifest refreshed: {count} deleted file(s)" if ok
                                           else (err or "walk failed"))})
            print(f"  intent {iid} {target} recover-walk -> {'ok' if ok else 'FAIL'} ({count})")
            continue
        if action == "removable-scan":
            # Discover which monitored datasets this drive already holds: structural match to LOCATE a
            # candidate subtree, then a dry-run rsync CENSUS on each hit for real file-level confidence
            # (size+mtime match %, add/update/delete, bytes-to-add). READ-ONLY. Push as suggestions.
            pr = C.removable_probe(t)
            if not pr["attached"] or not pr["mounted"]:
                api_call("POST", f"/api/v1/backup/intents/{iid}/result",
                         {"ok": False, "output": f"drive not attached/mounted at {pr['mount']}"}); continue
            dsp = _dataset_paths(cfg); pmap = {d["name"]: d["path"] for d in dsp}
            sugg = C.discover_removable_links(pr["mount"], dsp)
            for s in sugg:
                srcp = pmap.get(s["dataset"]); dest = os.path.join(pr["mount"], s["subpath"])
                if srcp:
                    cen, err = C.rsync_census(srcp, dest, timeout=RECOVER_WALK_TIMEOUT * 4)
                    if cen:
                        s["census"] = cen
            api_call("POST", "/api/v1/backup/agent/removable-links",
                     {"agent": NAME, "removable": target, "suggestions": sugg})
            msg = ("; ".join(f"{s['dataset']}->{s['subpath']} struct {s['score']}"
                             + (f" census {s['census']['pct']:.0%}" if s.get("census") else "") for s in sugg)
                   or "no dataset trees recognized on this drive")
            api_call("POST", f"/api/v1/backup/intents/{iid}/result",
                     {"ok": True, "output": f"{len(sugg)} match(es): {msg}"})
            print(f"  intent {iid} {target} removable-scan -> {len(sugg)} match(es)"); continue
        if action == "removable-verify":
            # Verify one dataset link. tier=census (default): size+mtime diff/fit. tier=xattr: compare
            # cached user.b3sig on both sides (free content check; a clean pass marks freshness).
            # tier=hash (phase c): full BLAKE3. All READ-ONLY of the drive.
            pr = C.removable_probe(t)
            if not pr["attached"] or not pr["mounted"]:
                api_call("POST", f"/api/v1/backup/intents/{iid}/result",
                         {"ok": False, "output": f"drive not attached/mounted at {pr['mount']}"}); continue
            ds = opts.get("dataset") or ""; tier = opts.get("tier") or "census"
            lr = api_call("GET", f"/api/v1/backup/agent/removable-links?agent={NAME}&removable={target}") or {}
            link = next((L for L in (lr.get("links") or []) if L["dataset"] == ds), None)
            sub = (link or {}).get("dest_subpath") or opts.get("dest_subpath") or ""
            srcp = {d["name"]: d["path"] for d in _dataset_paths(cfg)}.get(ds)
            if not srcp or not sub:
                api_call("POST", f"/api/v1/backup/intents/{iid}/result",
                         {"ok": False, "output": f"no source/subpath for dataset '{ds}'"}); continue
            dest = os.path.join(pr["mount"], sub)
            if tier in ("content", "auto"):     # one "Verify content": xattrs if tagged, else full hash
                tier = "xattr" if C.drive_tagged_fraction(dest) >= 0.8 else "hash"
            if tier in ("xattr", "hash"):
                if tier == "xattr":
                    res, err = C.xattr_verify(srcp, dest)
                    detail = (f"{res['present']} present, {res['missing']} missing content "
                              f"({res['missing_bytes']/1e9:.1f} GB), {res['dest_untagged']} drive files untagged"
                              if res else "")
                else:
                    res, err = C.hash_ledger_verify(srcp, dest, ledger_path=C._ledger_path(target, ds),
                                                    timeout=RECOVER_WALK_TIMEOUT * 8)
                    detail = (f"{res['present']} present, {res['missing']} missing content "
                              f"({res['missing_bytes']/1e9:.1f} GB); ledger {res['ledger']}" if res else "")
                if err:
                    api_call("POST", f"/api/v1/backup/intents/{iid}/result", {"ok": False, "output": err}); continue
                api_call("POST", "/api/v1/backup/agent/removable-links",
                         {"agent": NAME, "removable": target, "op": "verify", "dataset": ds,
                          "method": tier, "result": res, "verified": res["clean"]})
                note = "" if res["clean"] else " — NOT counted fresh"
                api_call("POST", f"/api/v1/backup/intents/{iid}/result",
                         {"ok": True, "output": f"{tier}-verify {ds}: {res['pct']:.0%} content-matched "
                                                f"({detail}){note}"})
                print(f"  intent {iid} {target} removable-verify[{tier}] {ds} -> {res['pct']:.0%} clean={res['clean']}")
                continue
            cen, err = C.rsync_census(srcp, dest, excludes=_exlist(link), timeout=RECOVER_WALK_TIMEOUT * 4)
            if err:
                api_call("POST", f"/api/v1/backup/intents/{iid}/result", {"ok": False, "output": err}); continue
            api_call("POST", "/api/v1/backup/agent/removable-links",
                     {"agent": NAME, "removable": target, "op": "census", "dataset": ds, "census": cen})
            api_call("POST", f"/api/v1/backup/intents/{iid}/result",
                     {"ok": True, "output": f"{ds}: {cen['pct']:.0%} match, +{cen['add']} new / {cen['update']} "
                                            f"changed / {cen['delete']} extra, {cen['bytes_add']} bytes to add"})
            print(f"  intent {iid} {target} removable-verify {ds} -> {cen['pct']:.0%}"); continue
        if action == "removable-relocate":
            # Move a top-level tree on the drive into cairn/<slug> - an intra-drive rename (instant, no
            # copy) - so cairn-managed data is namespaced and multiple datasets can share the drive.
            pr = C.removable_probe(t)
            if not pr["attached"] or not pr["mounted"] or pr["ro"]:
                api_call("POST", f"/api/v1/backup/intents/{iid}/result",
                         {"ok": False, "output": f"drive not attached/mounted rw at {pr['mount']}"}); continue
            ds = opts.get("dataset") or ""
            dmap = {d["name"]: d for d in _dataset_paths(cfg)}
            lr = api_call("GET", f"/api/v1/backup/agent/removable-links?agent={NAME}&removable={target}") or {}
            link = next((L for L in (lr.get("links") or []) if L["dataset"] == ds), None)
            if not link or ds not in dmap:
                api_call("POST", f"/api/v1/backup/intents/{iid}/result",
                         {"ok": False, "output": f"no confirmed link for dataset '{ds}'"}); continue
            newsub = C.cairn_subpath(dmap[ds]["source"], HOSTNAME)   # cairn/<host>/<dataset-slug>
            ok2, msg = C.removable_relocate(pr["mount"], link["dest_subpath"], newsub)
            if ok2:
                api_call("POST", "/api/v1/backup/agent/removable-links",
                         {"agent": NAME, "removable": target, "op": "relocate", "dataset": ds, "dest_subpath": newsub})
            api_call("POST", f"/api/v1/backup/intents/{iid}/result",
                     {"ok": ok2, "output": msg})
            print(f"  intent {iid} {target} removable-relocate {ds} -> {'ok' if ok2 else 'FAIL'}"); continue
        if action == "backup-now":
            # Removable 2nd-leg incremental backup. Guard presence/rw HERE (a clear message beats an
            # opaque rsync failure). If the drive has CONFIRMED dataset links, back up each of them
            # (per-dataset stamp so the scorecard credits each copy); otherwise fall back to the
            # target's own single source/dest_subpath.
            dry = DRYRUN or bool(opts.get("dryrun"))
            pr = C.removable_probe(t)
            if not pr["attached"]:
                api_call("POST", f"/api/v1/backup/intents/{iid}/result",
                         {"ok": False, "output": "drive not attached - plug in the 2nd-leg drive and retry"})
                print(f"  intent {iid} {target} backup-now -> SKIP (detached)"); continue
            if not pr["mounted"]:
                api_call("POST", f"/api/v1/backup/intents/{iid}/result",
                         {"ok": False, "output": f"drive attached but not mounted at {pr['mount']}"})
                print(f"  intent {iid} {target} backup-now -> SKIP (unmounted)"); continue
            if pr["ro"] and not dry:
                api_call("POST", f"/api/v1/backup/intents/{iid}/result",
                         {"ok": False, "output": f"{pr['mount']} is mounted READ-ONLY - remount rw to back up"})
                print(f"  intent {iid} {target} backup-now -> SKIP (read-only)"); continue
            lr = api_call("GET", f"/api/v1/backup/agent/removable-links?agent={NAME}&removable={target}") or {}
            links = lr.get("links") or []
            # per-dataset link jobs, or a single fallback job from the target's own source/dest_subpath
            dsmap = {d["name"]: d["path"] for d in _dataset_paths(cfg)}
            if links:
                jobs = []
                for L in links:
                    srcp = dsmap.get(L["dataset"])
                    jobs.append((L["dataset"], dict(t, source=srcp, dest_subpath=L["dest_subpath"],
                                                    exclude=_exlist(L)), srcp is not None))
            else:
                jobs = [(None, t, bool(t.get("source")))]
            head = ("[DRY-RUN] " if dry else "") + (f"log: {C._removable_log_path(t)}\n" if not dry else "")
            oks, lines = [], []
            for ds, jt, have_src in jobs:
                label = ds or "source"
                if not have_src:
                    oks.append(False); lines.append(f"{label}: FAIL (dataset source not on this agent)"); continue
                cmd, err = C.build_command("backup-now", jt, opts)
                if err:
                    oks.append(False); lines.append(f"{label}: FAIL ({err})"); continue
                rc, so, se = C.run(cmd, timeout=TIMEOUT)
                oks.append(rc == 0)
                if rc == 0 and not dry:
                    ts = int(time.time()); dest = C._removable_dest(jt)
                    try:
                        if dest:
                            with open(os.path.join(dest, ".cairn-lastbackup"), "w") as f:
                                f.write(str(ts))
                    except OSError:
                        pass
                    C.removable_write_state(t, last_backup_ts=ts)
                    if ds:   # record per-dataset freshness so the scorecard can credit this copy
                        api_call("POST", "/api/v1/backup/agent/removable-links",
                                 {"agent": NAME, "removable": target, "op": "stamp", "dataset": ds, "ts": ts})
                tail = (so + se).strip()[-500:]
                lines.append(f"{label}: {'ok' if rc == 0 else 'FAIL'}\n{tail}")
            ok = all(oks) and bool(oks)
            api_call("POST", f"/api/v1/backup/intents/{iid}/result",
                     {"ok": ok, "output": (head + "\n".join(lines))[-1800:], "dryrun": dry})
            print(f"  intent {iid} {target} backup-now{' [dry]' if dry else ''} -> "
                  f"{'ok' if ok else 'FAIL'} ({sum(oks)}/{len(oks)} datasets)"); continue
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

def _push_versions_manifest(t, rel, result):
    """Store/refresh the browsable VERSIONS manifest for this dataset. The API merges by path: a
    whole-dataset scan (rel='') replaces it; a subpath scan replaces just that subtree - so a manual
    'Scan here' is kept, not thrown away, and reopening Versions shows a live tree, never an empty box."""
    api_call("POST", "/api/v1/backup/agent/recovery-manifest",
             {"target": t["name"], "kind": "versions", "ok": True, "path": rel or "",
              "files": result.get("files") or {}, "truncated": bool(result.get("truncated")),
              "total": result.get("total") or 0})

def _dirtree_and_push(t):
    """Nightly: build the CHEAP directory tree (folders only, no httm) and store it as the 'dirtree'
    manifest, so Versions opens into real folders to browse. Version history is scanned per-folder later."""
    result, err = C.build_dirtree(t, cap=DIRTREE_CAP)
    if err or not result:
        api_call("POST", "/api/v1/backup/agent/recovery-manifest",
                 {"target": t["name"], "kind": "dirtree", "ok": False, "error": err or "no result"})
        return False, 0, (err or "no result")
    raw = json.dumps(result).encode()
    api_call("POST", "/api/v1/backup/agent/recovery-manifest",
             {"target": t["name"], "kind": "dirtree", "ok": True,
              "gz_b64": base64.b64encode(gzip.compress(raw)).decode(),
              "entry_count": result.get("count") or 0, "raw_bytes": len(raw), "walked_ts": int(time.time())})
    return True, result.get("count") or 0, None

def _walk_and_push(t):
    """Walk ONE dataset's deleted files (httm, bounded to this dataset via --one-filesystem), reduce to
    the newest version per file, gzip, and push it as the stored manifest. Read-only. Returns (ok, count,
    err). Used by both the nightly walk and the on-demand 'recover-walk' intent, so a manual refresh fills
    the manifest instead of throwing the scan away."""
    cmd, err = C.build_recovery_walk("deleted", t)
    if err or not cmd:
        api_call("POST", "/api/v1/backup/agent/recovery-manifest",
                 {"target": t["name"], "kind": "deleted", "ok": False, "error": err or "no command"})
        return False, 0, (err or "no command")
    rc, so, se = C.run(cmd, timeout=RECOVER_WALK_TIMEOUT)
    if rc != 0:
        e = (se or so).strip()[-500:]
        api_call("POST", "/api/v1/backup/agent/recovery-manifest",
                 {"target": t["name"], "kind": "deleted", "ok": False, "error": e})
        return False, 0, e
    manifest, count = C.reduce_deleted_manifest(so)
    raw = manifest.encode()
    api_call("POST", "/api/v1/backup/agent/recovery-manifest",
             {"target": t["name"], "kind": "deleted", "ok": True,
              "gz_b64": base64.b64encode(gzip.compress(raw)).decode(),
              "entry_count": count, "raw_bytes": len(raw), "walked_ts": int(time.time())})
    return True, count, None

def do_recovery_walk(cfg):
    """Nightly-cadence 'deleted files' manifest builder. The API returns only the datasets whose manifest
    is missing or stale (walk interval), so this is a no-op most loops. Off-peak-gated (the disk-heavy
    walk stays off the pool during the day); an explicit UI 'recover-walk' bypasses this and runs now."""
    if not _in_walk_window():
        return 0                       # off-peak only: stay off the disks during the day
    tmap = {t["name"]: t for t in cfg.get("targets", [])}
    due = (api_call("GET", f"/api/v1/backup/agent/recovery-due?agent={NAME}") or {}).get("targets", [])
    walked = 0
    for d in due[:RECOVER_WALK_MAX]:
        t = tmap.get(d.get("name"))
        if not t:
            continue
        ok, count, _ = _walk_and_push(t)
        if ok:
            print(f"  recovery walk {t['name']} -> {count} deleted file(s)")
        dok, dcount, _ = _dirtree_and_push(t)              # cheap folder tree for the Versions browser
        if dok:
            print(f"  dirtree walk {t['name']} -> {dcount} folder(s)")
        if ok or dok:
            walked += 1
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
