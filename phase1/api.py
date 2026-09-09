#!/usr/bin/env python3
"""backup-monitor Phase 1 API (read-only status + derived views) with Phase-3 stubs.

Serves the aggregated status the collector writes, the Tier-1 derived views
(single health badge, 3-2-1 scorecard, coverage-gap, timeline), a minimal HTML
dashboard, and the token-authed vault endpoints (report + intent poll/result).

Run:  uvicorn api:app --host 127.0.0.1 --port 8929
Env:  BM_DB, BM_API_TOKEN (vault/agent bearer token; hash-at-rest is a deploy hardening)
"""
import hashlib, hmac, json, os, sqlite3, time
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

HERE = Path(__file__).resolve().parent
DB = os.environ.get("BM_DB", "/var/lib/backup-monitor/backup-monitor.db")
API_TOKEN = os.environ.get("BM_API_TOKEN", "")
DAY = 86400
app = FastAPI(title="backup-monitor", version="1.0")

SEV_ORDER = {"CRIT": 0, "WARN": 1, "UNKNOWN": 2, "OK": 3}

def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def _init_db():
    """Ensure the DB + schema exist so the API can start before the collector's first run
    (e.g. as a standalone container service)."""
    Path(DB).parent.mkdir(parents=True, exist_ok=True)
    schema = HERE / "schema.sql"
    if schema.is_file():
        with sqlite3.connect(DB) as c:
            c.executescript(schema.read_text())
_init_db()

def latest_status(conn):
    """Latest status row per target, joined to target meta."""
    q = """
    SELECT t.name,t.type,t.tier,t.source,t.dest,t.location,t.encrypted,s.*
    FROM targets t
    JOIN status s ON s.target_id=t.id
    JOIN (SELECT target_id, MAX(ts) mx FROM status GROUP BY target_id) l
      ON l.target_id=s.target_id AND l.mx=s.ts
    WHERE t.enabled=1
    ORDER BY t.name
    """
    return [dict(r) for r in conn.execute(q).fetchall()]

def require_token(tok):
    if not API_TOKEN:
        raise HTTPException(503, "API token not configured")
    if not tok or not hmac.compare_digest(tok, API_TOKEN):
        raise HTTPException(401, "invalid token")

# ---------------- read-only views ----------------
@app.get("/api/v1/backup/health")
def health():
    with db() as conn:
        rows = latest_status(conn)
    counts = {"CRIT": 0, "WARN": 0, "UNKNOWN": 0, "OK": 0}
    worst = "OK"
    for r in rows:
        sev = r["severity"]
        counts[sev] = counts.get(sev, 0) + 1
        if SEV_ORDER.get(sev, 9) < SEV_ORDER.get(worst, 9):
            worst = sev
    return {"severity": worst, "counts": counts, "targets": len(rows), "ts": int(time.time())}

@app.get("/api/v1/backup/status")
def status():
    with db() as conn:
        rows = latest_status(conn)
    for r in rows:
        r["detail"] = json.loads(r.get("detail_json") or "{}")
    rows.sort(key=lambda r: SEV_ORDER.get(r["severity"], 9))
    return {"targets": rows}

@app.get("/api/v1/backup/scorecard")
def scorecard():
    """3-2-1 per Tier-A dataset: copies / distinct media (pools) / off-site copies."""
    with db() as conn:
        rows = latest_status(conn)
    tiera = [r for r in rows if r["type"] == "zfs-repl" and (r["tier"] == "A")]
    cards = []
    for r in tiera:
        src_pool = (r["source"] or "").split("/")[0]
        dst_pool = (r["dest"] or "").split("/")[0]
        pools = {p for p in (src_pool, dst_pool) if p}
        # location of dest: backup today = onsite-secondary; a real vault would be 'offsite'
        offsite = 1 if (r.get("location") == "offsite") else 0
        onsite = len(pools) - offsite
        copies = len(pools)
        card = dict(name=r["name"], copies=copies, media=len(pools), onsite=onsite,
                    offsite=offsite,
                    pass_321=(copies >= 3 and len(pools) >= 2 and offsite >= 1),
                    note="")
        if offsite == 0:
            card["note"] = "NO off-site copy - vault not yet a target for this dataset"
        cards.append(card)
    overall = all(c["pass_321"] for c in cards) if cards else False
    return {"pass": overall, "cards": cards,
            "explain": "3-2-1 = >=3 copies, >=2 media, >=1 off-site. backup is same-site today; "
                       "off-site column stays 0 until the vault is added as a dataset target."}

@app.get("/api/v1/backup/coverage-gap")
def coverage_gap():
    """Things backed up by nothing / not snapshotted / no off-site."""
    with db() as conn:
        rows = latest_status(conn)
    gaps = []
    for r in rows:
        d = json.loads(r.get("detail_json") or "{}")
        reasons = d.get("reasons", [])
        if "no snapshots" in reasons:
            gaps.append(dict(name=r["name"], gap="not snapshotted", severity=r["severity"]))
        if r["type"] == "zfs-repl" and r.get("location") != "offsite":
            gaps.append(dict(name=r["name"], gap="no off-site copy", severity=r["severity"]))
        if r["severity"] == "CRIT" and r["type"] == "zfs-repl":
            gaps.append(dict(name=r["name"], gap="replication stale/broken", severity="CRIT"))
    return {"gaps": gaps}

@app.get("/api/v1/backup/timeline")
def timeline(days: int = 14):
    since = int(time.time()) - days * DAY
    with db() as conn:
        q = """SELECT t.name, s.ts, s.severity FROM status s JOIN targets t ON t.id=s.target_id
               WHERE s.ts>=? ORDER BY t.name, s.ts"""
        grid = {}
        for r in conn.execute(q, (since,)):
            day = time.strftime("%Y-%m-%d", time.localtime(r["ts"]))
            cell = grid.setdefault(r["name"], {}).setdefault(day, "OK")
            if SEV_ORDER.get(r["severity"], 9) < SEV_ORDER.get(cell, 9):
                grid[r["name"]][day] = r["severity"]  # worst wins per day
    return {"days": days, "grid": grid}

# ---------------- vault call-home (token-authed) ----------------
@app.post("/api/v1/backup/report")
async def vault_report(request: Request, x_backup_token: str = Header(default="")):
    require_token(x_backup_token)
    payload = await request.json()
    agent = payload.get("agent", "vault")
    with db() as conn:
        conn.execute("INSERT INTO vault_reports(ts,agent,payload_json) VALUES(?,?,?)",
                     (int(time.time()), agent, json.dumps(payload)))
        conn.commit()
    return {"ok": True}

@app.get("/api/v1/backup/intents")
def poll_intents(agent: str = "vault", x_backup_token: str = Header(default="")):
    require_token(x_backup_token)
    now = int(time.time())
    with db() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM intents WHERE state='pending' ORDER BY created_ts").fetchall()]
        for r in rows:  # claim
            conn.execute("UPDATE intents SET state='claimed',claimed_ts=?,claimed_by=? WHERE id=?",
                         (now, agent, r["id"]))
        conn.commit()
    return {"intents": rows}

@app.post("/api/v1/backup/intents/{iid}/result")
async def intent_result(iid: int, request: Request, x_backup_token: str = Header(default="")):
    require_token(x_backup_token)
    body = await request.json()
    state = "done" if body.get("ok") else "failed"
    with db() as conn:
        conn.execute("UPDATE intents SET state=?,result=?,result_ts=? WHERE id=?",
                     (state, json.dumps(body), int(time.time()), iid))
        conn.commit()
    # NOTE: Phase 3 fires the action-outcome notification here (email; failed->+Gotify).
    return {"ok": True, "state": state}

# ---------------- actions (Phase 3): create/list local intents ----------------
# The API only QUEUES intents (unprivileged): it inserts a row + drops a run-file in
# INTENT_DIR. The root backup-action.path unit picks it up and executes via the runner.
# Keep this surface PRIVATE (behind a reverse proxy / VPN) - never on the public token path.
INTENT_DIR = Path(os.environ.get("INTENT_DIR", "/run/backup-intents"))
ALLOWED_ACTIONS = {"snapshot", "sync", "scrub"}

@app.post("/api/v1/backup/actions")
async def create_action(request: Request):
    body = await request.json()
    target = body.get("target"); action = body.get("action")
    create_snapshot = bool(body.get("create_snapshot", True))
    requested_by = body.get("requested_by", "ui")
    if action not in ALLOWED_ACTIONS:
        raise HTTPException(400, f"action must be one of {sorted(ALLOWED_ACTIONS)}")
    with db() as conn:
        r = conn.execute("SELECT id,type,source,dest,enabled FROM targets WHERE name=?",
                         (target,)).fetchone()
        if not r or not r["enabled"]:
            raise HTTPException(404, f"unknown/disabled target '{target}'")
        if action == "sync" and r["type"] != "zfs-repl":
            raise HTTPException(400, "sync only valid for zfs-repl targets")
        if action == "scrub" and r["type"] != "zfs-local":
            raise HTTPException(400, "scrub only valid for zfs-local targets")
        if action == "snapshot" and not r["source"]:
            raise HTTPException(400, "target has no source dataset")
        cur = conn.execute(
            "INSERT INTO intents(target_id,action,state,requested_by,created_ts) "
            "VALUES(?,?,'pending',?,strftime('%s','now'))", (r["id"], action, requested_by))
        iid = cur.lastrowid
        conn.commit()
    try:
        INTENT_DIR.mkdir(parents=True, exist_ok=True)
        payload = dict(id=iid, target=target, action=action,
                       create_snapshot=create_snapshot, requested_by=requested_by)
        tmp = INTENT_DIR / f".{iid}.tmp"
        tmp.write_text(json.dumps(payload))
        tmp.rename(INTENT_DIR / f"{iid}.intent")   # atomic: runner never sees a partial file
    except OSError as e:
        with db() as conn:
            conn.execute("UPDATE intents SET state='failed',result=? WHERE id=?",
                         (f"could not queue run-file: {e}", iid)); conn.commit()
        raise HTTPException(500, f"queued in DB but run-file write failed: {e}")
    return {"id": iid, "state": "pending", "target": target, "action": action,
            "create_snapshot": create_snapshot}

@app.get("/api/v1/backup/actions")
def list_actions(limit: int = 20):
    with db() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT i.*, t.name AS target FROM intents i LEFT JOIN targets t ON t.id=i.target_id "
            "ORDER BY i.created_ts DESC LIMIT ?", (limit,)).fetchall()]
    return {"actions": rows}

@app.get("/api/v1/backup/actions/{iid}")
def get_action(iid: int):
    with db() as conn:
        r = conn.execute("SELECT i.*, t.name AS target FROM intents i "
                         "LEFT JOIN targets t ON t.id=i.target_id WHERE i.id=?", (iid,)).fetchone()
    if not r:
        raise HTTPException(404, "no such action")
    return dict(r)

# ---------------- HTML dashboard + on-demand action buttons ----------------
BADGE = {"CRIT": "#c0392b", "WARN": "#e67e22", "UNKNOWN": "#7f8c8d", "OK": "#27ae60"}

PAGE_STYLE = """<style>body{font:14px/1.5 system-ui,sans-serif;margin:2rem;max-width:1150px}
h1{font-size:1.3rem} .badge{display:inline-block;padding:.3rem .8rem;border-radius:6px;color:#fff;font-weight:700}
table{border-collapse:collapse;width:100%;margin-top:1rem} td,th{padding:.35rem .6rem;border-bottom:1px solid #ddd;text-align:left;vertical-align:top}
.w{color:#555;font-size:.9em} .counts span{margin-right:1rem}
button{font-size:.78em;margin:1px;cursor:pointer;border:1px solid #bbb;border-radius:4px;background:#fafafa;padding:2px 6px}
button:hover{background:#eee} #actlog{margin-top:1rem;padding:.6rem;background:#f4f4f4;border-radius:6px;font:12px/1.45 monospace;white-space:pre-wrap;min-height:1.3em}</style>"""

# plain string (NOT an f-string) so JS ${...} and \n survive untouched
PAGE_SCRIPT = """<script>
async function act(target, action, createSnap){
  const label = action==='sync' ? ('replicate '+target+' (new snapshot: '+createSnap+')') : (action+' '+target);
  if(!confirm('Run '+label+'?')) return;
  const el=document.getElementById('actlog'); el.textContent='submitting: '+label+' …';
  let r,j;
  try{ r=await fetch('/api/v1/backup/actions',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({target:target,action:action,create_snapshot:createSnap,requested_by:'ui'})});
       j=await r.json(); }
  catch(e){ el.textContent='network error: '+e; return; }
  if(!r.ok){ el.textContent='error: '+(j.detail||r.status); return; }
  poll(j.id);
}
async function poll(id){
  const el=document.getElementById('actlog');
  for(let i=0;i<180;i++){
    let j; try{ j=await (await fetch('/api/v1/backup/actions/'+id)).json(); }catch(e){ break; }
    el.textContent='#'+id+' '+j.target+' '+j.action+' -> '+j.state+(j.result?('\\n'+j.result):'');
    if(['done','failed','stalled'].includes(j.state)) break;
    await new Promise(s=>setTimeout(s,2000));
  }
}
</script>"""

@app.get("/", response_class=HTMLResponse)
def index():
    with db() as conn:
        rows = latest_status(conn)
        h = health()
    trows = ""
    for r in sorted(rows, key=lambda r: SEV_ORDER.get(r["severity"], 9)):
        d = json.loads(r.get("detail_json") or "{}")
        why = ", ".join(d.get("reasons", [])) or (r.get("last_error") or "")
        extra = []
        if r.get("repl_lag_s") is not None: extra.append(f"lag {r['repl_lag_s']//3600}h")
        if r.get("pool_cap_pct") is not None: extra.append(f"{r['pool_cap_pct']}%")
        if r.get("archive_count") is not None: extra.append(f"{r['archive_count']} arch")
        n = r["name"]
        if r["type"] == "zfs-repl":
            acts = (f"<button onclick=\"act('{n}','snapshot',true)\">Snapshot</button>"
                    f"<button onclick=\"act('{n}','sync',true)\">Replicate&nbsp;+snap</button>"
                    f"<button onclick=\"act('{n}','sync',false)\">Replicate&nbsp;existing</button>")
        elif r["type"] == "zfs-local":
            acts = f"<button onclick=\"act('{n}','scrub',true)\">Scrub</button>"
        else:
            acts = ""
        c = BADGE.get(r["severity"], "#555")
        trows += (f"<tr><td><b style='color:{c}'>{r['severity']}</b></td><td>{n}</td>"
                  f"<td>{r['type']}</td><td>{' · '.join(extra)}</td><td>{acts}</td>"
                  f"<td class=w>{why}</td></tr>")
    bc = BADGE.get(h["severity"], "#555")
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(h["ts"]))
    counts = " ".join(f"<span>{k}: {v}</span>" for k, v in h["counts"].items())
    return (f"""<!doctype html><meta charset=utf-8><title>backup-monitor</title>
{PAGE_STYLE}
<h1>backup-monitor <span class=badge style='background:{bc}'>{h['severity']}</span></h1>
<div class=counts>{counts} &nbsp;·&nbsp; {h['targets']} targets &nbsp;·&nbsp; as of {ts}</div>
<table><tr><th>sev</th><th>target</th><th>type</th><th>metric</th><th>actions</th><th>why</th></tr>{trows}</table>
<div id=actlog>idle - click an action; status streams here.</div>
<p class=w>Read-only aggregate + on-demand actions (snapshot / replicate / scrub).
Views: /api/v1/backup/(health, status, scorecard, coverage-gap, timeline, actions)</p>"""
            + PAGE_SCRIPT)
