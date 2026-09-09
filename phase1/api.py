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
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

HERE = Path(__file__).resolve().parent
DB = os.environ.get("BM_DB", "/var/lib/backup-monitor/backup-monitor.db")
DAY = 86400
app = FastAPI(title="backup-monitor", version="1.0")

SEV_ORDER = {"CRIT": 0, "WARN": 1, "UNKNOWN": 2, "OK": 3}

# ---------------- zero-trust auth: every request needs a token; HASH-AT-REST ----------------
# Only sha256(token) is ever stored (auth_tokens table). Two roles: admin (dashboard/views/
# actions) and agent (report/poll/result only). Per-agent tokens are individual rows, so one can
# be revoked without touching the others. Bootstrap: BM_ADMIN_TOKEN (plaintext env) is hashed
# into the store at startup; mint per-agent tokens via POST /tokens or the bmtoken CLI.
import hashlib as _hashlib, secrets as _secrets
AGENT_PATHS = ("/api/v1/backup/report", "/api/v1/backup/intents")  # + /intents/{id}/result
ACCESS_TTL = int(os.environ.get("BM_ACCESS_TTL", str(24 * 3600)))  # access-token lifetime (s)

def _hash(token):
    return _hashlib.sha256(token.encode()).hexdigest()

def _seed_tokens():
    """Seed the store from env (hash-at-rest). Idempotent. Plaintext env is only a bootstrap
    secret - it is hashed, never stored raw."""
    now = int(time.time())
    seeds = []
    adm = os.environ.get("BM_ADMIN_TOKEN") or os.environ.get("BM_API_TOKEN")
    if adm:
        seeds.append((_hash(adm), "admin", "bootstrap-admin"))
    for i, t in enumerate(x.strip() for x in os.environ.get("BM_AGENT_TOKENS", "").split(",") if x.strip()):
        seeds.append((_hash(t), "agent", f"env-agent-{i}"))
    with db() as c:
        for h, role, label in seeds:
            kind = "admin" if role == "admin" else "access"   # env agent tokens are static access
            c.execute("INSERT OR IGNORE INTO auth_tokens(hash,role,kind,label,created_ts,active) "
                      "VALUES(?,?,?,?,?,1)", (h, role, kind, label, now))
        c.commit()
        return c.execute("SELECT COUNT(*) FROM auth_tokens WHERE role='admin' AND active=1").fetchone()[0]

def _extract_token(request):
    t = request.headers.get("x-backup-token")
    if t:
        return t
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return request.cookies.get("bm_token", "")

def _lookup_role(token):
    """Return the role for a presented token, or None. Only admin+access kinds authenticate
    requests (enroll secrets are used only at /enroll); access tokens must be unexpired."""
    if not token:
        return None
    now = int(time.time())
    h = _hash(token)
    with db() as c:
        r = c.execute("SELECT role,kind,expires_ts FROM auth_tokens WHERE hash=? AND active=1",
                      (h,)).fetchone()
        if not r or r["kind"] not in ("admin", "access"):
            return None
        if r["kind"] == "access" and r["expires_ts"] and r["expires_ts"] < now:
            return None
        c.execute("UPDATE auth_tokens SET last_used_ts=? WHERE hash=?", (now, h))
        c.commit()
    return r["role"]

def _valid(token, need):
    role = _lookup_role(token)
    if role is None:
        return False
    return role == "admin" if need == "admin" else role in ("admin", "agent")

@app.middleware("http")
async def auth_gate(request: Request, call_next):
    p = request.url.path
    if p in ("/login", "/favicon.ico", "/api/v1/backup/enroll"):
        return await call_next(request)   # /enroll authenticates via the enrollment secret itself
    if not HAS_ADMIN:
        return JSONResponse({"detail": "no admin token configured - set BM_ADMIN_TOKEN and restart"},
                            status_code=503)
    role = "agent" if p.startswith(AGENT_PATHS) else "admin"
    if _valid(_extract_token(request), role):
        return await call_next(request)
    wants_html = "text/html" in request.headers.get("accept", "")
    if role == "admin" and wants_html and request.method == "GET":
        return RedirectResponse("/login", status_code=302)
    return JSONResponse({"detail": "unauthorized"}, status_code=401)

LOGIN_HTML = """<!doctype html><meta charset=utf-8><title>backup-monitor login</title>
<style>body{font:15px system-ui,sans-serif;display:grid;place-items:center;height:90vh}
form{display:grid;gap:.6rem;width:280px} input,button{padding:.5rem;font-size:1rem}</style>
<form method=post action=/login><h2>backup-monitor</h2>
<input type=password name=token placeholder="admin token" autofocus>
<button>Sign in</button>{err}</form>"""

@app.get("/login", response_class=HTMLResponse)
def login_form(bad: int = 0):
    return LOGIN_HTML.replace("{err}", "<p style='color:#c0392b'>invalid token</p>" if bad else "")

@app.post("/login")
async def login_submit(request: Request):
    from urllib.parse import parse_qs
    raw = (await request.body()).decode("utf-8", "replace")
    token = parse_qs(raw).get("token", [""])[0].strip()
    if _valid(token, "admin"):
        r = RedirectResponse("/", status_code=302)
        r.set_cookie("bm_token", token, httponly=True, samesite="strict",
                     secure=request.url.scheme == "https", max_age=30 * DAY)
        return r
    return RedirectResponse("/login?bad=1", status_code=302)

@app.post("/logout")
def logout():
    r = RedirectResponse("/login", status_code=302)
    r.delete_cookie("bm_token")
    return r

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
            # idempotent migrations for DBs created before these columns existed
            for tbl, col, typ in [("targets", "agent", "TEXT"), ("intents", "opts", "TEXT"),
                                  ("auth_tokens", "kind", "TEXT DEFAULT 'access'"),
                                  ("auth_tokens", "parent", "TEXT"),
                                  ("auth_tokens", "expires_ts", "INTEGER")]:
                try:
                    c.execute(f"ALTER TABLE {tbl} ADD COLUMN {col} {typ}")
                except sqlite3.OperationalError:
                    pass  # already exists
_init_db()
HAS_ADMIN = _seed_tokens() > 0   # false => middleware returns 503 until BM_ADMIN_TOKEN is set

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

# ---------------- control plane: agents report status + poll intents (token-authed) ----------------
# The API never touches ZFS/borg/disks. Agents (local + remote) do all host work and talk HTTP.
import subprocess
NOTIFY_SH = os.environ.get("NOTIFY_SH", str(HERE.parent / "phase0" / "notify.sh"))
ALLOWED_ACTIONS = {"snapshot", "sync", "scrub",
                   "recover-points", "recover-search", "recover-deleted", "restore"}
STATUS_INGEST_COLS = ["snap_age_src_s","snap_age_dst_s","repl_lag_s","pool_health","pool_cap_pct",
    "last_scrub_ts","usedbysnapshots","compressratio","key_status","archive_count","dedup_ratio",
    "logical_size","physical_size","last_check_ts","last_check_result","lock_state","handler_type",
    "handler_result","last_run_ts","detail_json","last_error"]

async def _json(request):
    try:
        return await request.json()
    except Exception:
        raise HTTPException(400, "invalid JSON body")

def dispatch_alert(sev, title, body, key, info_email=False):
    """Central alerting - the API is the only place email/Gotify go out (agents carry no creds)."""
    if not os.path.exists(NOTIFY_SH):
        return
    if sev == "INFO" and not info_email:
        return
    env = dict(os.environ)
    if info_email:
        env["NOTIFY_INFO_EMAIL"] = "1"
    try:
        subprocess.run(["bash", NOTIFY_SH, sev, title, body or sev, key], env=env, timeout=30)
    except Exception:
        pass

@app.post("/api/v1/backup/report")
async def report(request: Request):
    """An agent reports its host's status. Upserts targets (ownership = reporting agent) +
    inserts status rows, then dispatches WARN/CRIT alerts centrally. (auth: middleware)"""
    payload = await _json(request)
    agent = payload.get("agent", "unknown")
    now = int(payload.get("ts") or time.time())
    statuses = payload.get("statuses", [])
    alerts = []
    with db() as conn:
        for s in statuses:
            name = s.get("name")
            if not name:
                continue
            tid = conn.execute("""INSERT INTO targets(name,type,source,dest,tier,location,encrypted,agent,enabled)
                VALUES(?,?,?,?,?,?,?,?,1)
                ON CONFLICT(name) DO UPDATE SET type=excluded.type,source=excluded.source,dest=excluded.dest,
                  tier=excluded.tier,location=excluded.location,encrypted=excluded.encrypted,agent=excluded.agent
                RETURNING id""",
                (name, s.get("type"), s.get("source"), s.get("dest"), s.get("tier"),
                 s.get("location"), 1 if s.get("encrypted") else 0, agent)).fetchone()[0]
            cols = ["ts", "target_id", "severity"] + STATUS_INGEST_COLS
            vals = [now, tid, s.get("severity", "UNKNOWN")] + [s.get(c) for c in STATUS_INGEST_COLS]
            conn.execute(f"INSERT INTO status({','.join(cols)}) VALUES({','.join('?'*len(cols))})", vals)
            if s.get("severity") in ("WARN", "CRIT"):
                d = {}
                try:
                    d = json.loads(s.get("detail_json") or "{}")
                except (ValueError, TypeError):
                    pass
                why = ", ".join(d.get("reasons", [])) or (s.get("last_error") or "")
                alerts.append((s["severity"], f"{name}: {s['severity']}", f"[{agent}] {why}".strip(), f"bm-{name}"))
        conn.execute("DELETE FROM status WHERE ts < ?", (now - 90 * DAY,))
        conn.commit()
    for a in alerts:
        dispatch_alert(*a)
    return {"ok": True, "ingested": len(statuses)}

@app.get("/api/v1/backup/intents")
def poll_intents(agent: str):
    """An agent claims the pending intents for the targets IT owns (routed by targets.agent).
    (auth: middleware - agent role)"""
    now = int(time.time())
    with db() as conn:
        rows = [dict(r) for r in conn.execute("""
            SELECT i.id, i.action, i.opts, t.name AS target
            FROM intents i JOIN targets t ON t.id=i.target_id
            WHERE i.state='pending' AND t.agent=? ORDER BY i.created_ts""", (agent,)).fetchall()]
        for r in rows:
            conn.execute("UPDATE intents SET state='claimed',claimed_ts=?,claimed_by=? WHERE id=?",
                         (now, agent, r["id"]))
            try:
                opts = json.loads(r.pop("opts") or "{}")
            except (ValueError, TypeError):
                r.pop("opts", None); opts = {}
            r["opts"] = opts
            r["create_snapshot"] = opts.get("create_snapshot", True)  # convenience/back-compat
        conn.commit()
    return {"intents": rows}

@app.post("/api/v1/backup/intents/{iid}/result")
async def intent_result(iid: int, request: Request):
    """An agent reports an action's outcome. The API fires the action-outcome notification.
    (auth: middleware - agent role)"""
    body = await _json(request)
    ok = bool(body.get("ok"))
    state = "done" if ok else "failed"
    with db() as conn:
        r = conn.execute("SELECT i.action, t.name AS target FROM intents i "
                         "LEFT JOIN targets t ON t.id=i.target_id WHERE i.id=?", (iid,)).fetchone()
        conn.execute("UPDATE intents SET state=?,result=?,result_ts=? WHERE id=?",
                     (state, json.dumps(body)[:4000], int(time.time()), iid))
        conn.commit()
    tgt = r["target"] if r else "?"; act = r["action"] if r else "?"
    out = (body.get("output") or "")[:1500]
    if ok:
        dispatch_alert("INFO", f"action done: {tgt} {act}", out, f"act-{iid}", info_email=True)
    else:
        dispatch_alert("CRIT", f"action FAILED: {tgt} {act}", out, f"act-{iid}")
    return {"ok": True, "state": state}

# ---------------- actions: the dashboard queues an intent (routed to the owning agent) ----------------
# No files, no host executor. The intent waits in the DB until the target's agent polls for it.
# Keep this POST surface PRIVATE (reverse proxy / VPN) - never on the public token path.
RECOVER_ACTIONS = {"recover-points", "recover-search", "recover-deleted", "restore"}

@app.post("/api/v1/backup/actions")
async def create_action(request: Request):
    body = await _json(request)
    target = body.get("target"); action = body.get("action")
    requested_by = body.get("requested_by", "ui")
    if action not in ALLOWED_ACTIONS:
        raise HTTPException(400, f"action must be one of {sorted(ALLOWED_ACTIONS)}")
    # options carried to the agent (it builds the command from its trusted config + these).
    opts = {"create_snapshot": bool(body.get("create_snapshot", True))}
    for k in ("path", "dest", "version"):
        if body.get(k) is not None:
            opts[k] = str(body[k])
    with db() as conn:
        r = conn.execute("SELECT id,type,source,dest,enabled,agent FROM targets WHERE name=?",
                         (target,)).fetchone()
        if not r or not r["enabled"]:
            raise HTTPException(404, f"unknown/disabled target '{target}'")
        if action == "sync" and r["type"] != "zfs-repl":
            raise HTTPException(400, "sync only valid for zfs-repl targets")
        if action == "scrub" and r["type"] != "zfs-local":
            raise HTTPException(400, "scrub only valid for zfs-local targets")
        if (action == "snapshot" or action in RECOVER_ACTIONS) and not r["source"]:
            raise HTTPException(400, "action requires a dataset-backed target")
        if action == "restore" and not opts.get("version"):
            raise HTTPException(400, "restore requires a 'version' (snapshot file path from a search)")
        if not r["agent"]:
            raise HTTPException(409, f"no agent has reported target '{target}' yet - can't route it")
        cur = conn.execute(
            "INSERT INTO intents(target_id,action,opts,state,requested_by,created_ts) "
            "VALUES(?,?,?,'pending',?,strftime('%s','now'))",
            (r["id"], action, json.dumps(opts), requested_by))
        iid = cur.lastrowid
        conn.commit()
    return {"id": iid, "state": "pending", "target": target, "action": action,
            "agent": r["agent"], "opts": opts}

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

# ---------------- enrollment (two-tier): agent trades its enroll secret for an access token ----
# Authenticated by the enrollment SECRET itself (not admin/agent role) - see middleware bypass.
@app.post("/api/v1/backup/enroll")
async def enroll(request: Request):
    secret = _extract_token(request) or request.headers.get("x-backup-enroll", "")
    now = int(time.time())
    with db() as c:
        r = c.execute("SELECT role,label FROM auth_tokens WHERE hash=? AND kind='enroll' AND active=1",
                      (_hash(secret),)).fetchone()
        if not r:
            raise HTTPException(401, "invalid or revoked enrollment secret")
        access = _secrets.token_hex(32)
        # one active access token per agent: drop any prior (also kills a leaked one on refresh).
        # DELETE (not deactivate) so the timestamped label is free to reuse immediately.
        c.execute("DELETE FROM auth_tokens WHERE parent=? AND kind='access'", (r["label"],))
        alabel = f"{r['label']}-access-{now}-{_secrets.token_hex(3)}"
        c.execute("INSERT INTO auth_tokens(hash,role,kind,label,parent,expires_ts,created_ts,active) "
                  "VALUES(?,?, 'access', ?, ?, ?, ?, 1)",
                  (_hash(access), r["role"], alabel, r["label"], now + ACCESS_TTL, now))
        c.commit()
    return {"access_token": access, "expires_in": ACCESS_TTL, "agent": r["label"]}

# ---------------- token management (admin role; hash-at-rest) ----------------
@app.post("/api/v1/backup/tokens")
async def mint_token(request: Request):
    body = await _json(request)
    role = body.get("role"); label = body.get("label")
    kind = body.get("kind") or ("admin" if role == "admin" else "enroll")  # agents get enroll secrets
    if role not in ("admin", "agent"):
        raise HTTPException(400, "role must be 'admin' or 'agent'")
    if kind not in ("admin", "enroll", "access"):
        raise HTTPException(400, "kind must be admin | enroll | access")
    if not label:
        raise HTTPException(400, "label required (e.g. the agent/host name)")
    token = _secrets.token_hex(32)
    try:
        with db() as c:
            c.execute("INSERT INTO auth_tokens(hash,role,kind,label,created_ts,active) VALUES(?,?,?,?,?,1)",
                      (_hash(token), role, kind, label, int(time.time())))
            c.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(409, f"label '{label}' already exists")
    global HAS_ADMIN
    if role == "admin":
        HAS_ADMIN = True
    hint = ("enrollment secret - put on the agent as BM_ENROLL_SECRET; it mints short-lived "
            "access tokens") if kind == "enroll" else "SAVE NOW - only its hash is stored"
    return {"token": token, "label": label, "role": role, "kind": kind, "note": hint}

@app.get("/api/v1/backup/tokens")
def list_tokens():
    with db() as c:
        rows = [dict(r) for r in c.execute(
            "SELECT label,role,kind,parent,expires_ts,created_ts,last_used_ts,active "
            "FROM auth_tokens ORDER BY role,kind,label")]
    return {"tokens": rows}   # never returns the token or its hash

@app.post("/api/v1/backup/tokens/{label}/rotate")
def force_rotate(label: str):
    """Forced rotation for a LEAKED token on a TRUSTED box: kill the agent's current access
    token(s) now; the box re-enrolls with its (non-leaked) enrollment secret and gets a fresh one.
    An attacker holding the leaked access token is locked out (they lack the enrollment secret)."""
    with db() as c:
        r = c.execute("SELECT role FROM auth_tokens WHERE label=? AND kind='enroll' AND active=1",
                      (label,)).fetchone()
        if not r:
            raise HTTPException(404, f"no active enrollment secret labelled '{label}' to rotate")
        n = c.execute("UPDATE auth_tokens SET active=0 WHERE parent=? AND kind='access' AND active=1",
                      (label,)).rowcount
        c.commit()
    return {"ok": True, "rotated": label, "access_tokens_invalidated": n,
            "note": "agent re-enrolls on its next call and resumes; leaked access token is dead"}

@app.delete("/api/v1/backup/tokens/{label}")
def revoke_token(label: str):
    """Terminal revoke (compromised box): kill the enrollment secret AND its access tokens.
    The box cannot self-heal - provision a new credential out-of-band."""
    with db() as c:
        row = c.execute("SELECT role,active FROM auth_tokens WHERE label=?", (label,)).fetchone()
        if not row:
            raise HTTPException(404, f"no token labelled '{label}'")
        if row["role"] == "admin" and row["active"]:
            n = c.execute("SELECT COUNT(*) FROM auth_tokens WHERE role='admin' AND active=1").fetchone()[0]
            if n <= 1:
                raise HTTPException(409, "refusing to revoke the last active admin token (lockout guard)")
        # kill the credential itself + any access tokens it issued
        c.execute("UPDATE auth_tokens SET active=0 WHERE label=? OR parent=?", (label, label))
        c.commit()
    return {"ok": True, "revoked": label}

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
async function post(body){
  const el=document.getElementById('actlog'); el.textContent='submitting: '+body.action+' '+body.target+' …';
  let r,j;
  try{ r=await fetch('/api/v1/backup/actions',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify(body)}); j=await r.json(); }
  catch(e){ el.textContent='network error: '+e; return; }
  if(!r.ok){ el.textContent='error: '+(j.detail||r.status); return; }
  poll(j.id);
}
async function act(target, action, createSnap){
  const label = action+' '+target+(action==='sync'?(' (new snap: '+createSnap+')'):'');
  if(!confirm('Run '+label+'?')) return;
  const b={target:target, action:action, requested_by:'ui'};
  if(action==='sync') b.create_snapshot=createSnap;
  post(b);
}
async function actPrompt(target, action, field, msg){
  const v=prompt(msg); if(v===null) return;
  if(!confirm('Run '+action+' '+target+' ['+(v||'(all)')+'] ?')) return;
  const b={target:target, action:action, requested_by:'ui'}; b[field]=v; post(b);
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
        # recovery buttons for any dataset-backed target (httm/zfs recovery-point catalog)
        rec = ""
        if r["type"] in ("zfs-repl", "zfs-local") and r.get("source"):
            rec = (f"<button onclick=\"act('{n}','recover-points')\">Points</button>"
                   f"<button onclick=\"actPrompt('{n}','recover-deleted','path','deleted files under (blank = whole dataset):')\">Deleted</button>"
                   f"<button onclick=\"actPrompt('{n}','recover-search','path','list versions of (path relative to dataset root):')\">Versions</button>")
        if r["type"] == "zfs-repl":
            acts = (f"<button onclick=\"act('{n}','snapshot',true)\">Snapshot</button>"
                    f"<button onclick=\"act('{n}','sync',true)\">Replicate&nbsp;+snap</button>"
                    f"<button onclick=\"act('{n}','sync',false)\">Replicate&nbsp;existing</button>" + rec)
        elif r["type"] == "zfs-local":
            acts = f"<button onclick=\"act('{n}','scrub',true)\">Scrub</button>" + rec
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
