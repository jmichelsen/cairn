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
import sys as _sys
_sys.path.insert(0, str(HERE))
import collector as _cmd   # PURE build_command, for action PREVIEWS only; the API never executes it
DAY = 86400
app = FastAPI(title="backup-monitor", version="1.0")

SEV_ORDER = {"CRIT": 0, "WARN": 1, "UNKNOWN": 2, "OK": 3}
SEVCLS = {"CRIT": "crit", "WARN": "warn", "UNKNOWN": "unk", "OK": "ok"}  # severity -> css class

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
    SELECT t.name,t.type,t.tier,t.source,t.dest,t.location,t.encrypted,t.agent,s.*
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
    can_exec = 1 if payload.get("can_execute") else 0
    statuses = payload.get("statuses", [])
    alerts = []
    with db() as conn:
        conn.execute("""INSERT INTO agents(name,can_execute,last_report_ts) VALUES(?,?,?)
            ON CONFLICT(name) DO UPDATE SET can_execute=excluded.can_execute,
            last_report_ts=excluded.last_report_ts""", (agent, can_exec, now))
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
    if body.get("dryrun"):
        dispatch_alert("INFO", f"dry-run: {tgt} {act}", out, f"act-{iid}")  # UI-only feedback, no email/push
    elif ok:
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
    if body.get("dryrun"):
        opts["dryrun"] = True   # per-action dry-run: the agent runs a native -n / read-only probe
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
        cap = conn.execute("SELECT can_execute FROM agents WHERE name=?", (r["agent"],)).fetchone()
        if not cap or not cap["can_execute"]:
            raise HTTPException(409, f"target '{target}' is owned by report-only agent "
                                     f"'{r['agent']}' (BM_CAN_EXECUTE=0) - no executor to run this")
        cur = conn.execute(
            "INSERT INTO intents(target_id,action,opts,state,requested_by,created_ts) "
            "VALUES(?,?,?,'pending',?,strftime('%s','now'))",
            (r["id"], action, json.dumps(opts), requested_by))
        iid = cur.lastrowid
        conn.commit()
    return {"id": iid, "state": "pending", "target": target, "action": action,
            "agent": r["agent"], "opts": opts}

@app.get("/api/v1/backup/actions")
def list_actions(limit: int = 20, target: str = None):
    """Recent intents, newest first. Pass ?target=<name> for one card's action history."""
    with db() as conn:
        if target:
            rows = [dict(r) for r in conn.execute(
                "SELECT i.*, t.name AS target FROM intents i LEFT JOIN targets t ON t.id=i.target_id "
                "WHERE t.name=? ORDER BY i.created_ts DESC LIMIT ?", (target, limit)).fetchall()]
        else:
            rows = [dict(r) for r in conn.execute(
                "SELECT i.*, t.name AS target FROM intents i LEFT JOIN targets t ON t.id=i.target_id "
                "ORDER BY i.created_ts DESC LIMIT ?", (limit,)).fetchall()]
    return {"actions": rows}

PREVIEWABLE = {"snapshot", "sync", "scrub", "recover-points"}  # build_command touches no ZFS for these

@app.get("/api/v1/backup/actions/preview")
def preview_action(target: str, action: str, create_snapshot: bool = True, path: str = None):
    """Return the exact argv a click WILL run, rebuilt from the stored target row - so the confirm
    dialog can show it. Read-only: only actions whose build_command has no side effects are previewed;
    others resolve on the agent at run time (path→mountpoint needs a live ZFS read)."""
    with db() as conn:
        r = conn.execute("SELECT name,type,source,dest FROM targets WHERE name=?", (target,)).fetchone()
    if not r:
        raise HTTPException(404, f"unknown target '{target}'")
    if action not in PREVIEWABLE:
        return {"cmd": None, "note": "built on the agent at run time"}
    t = {"name": r["name"], "type": r["type"], "source": r["source"], "dest": r["dest"]}
    opts = {"create_snapshot": create_snapshot}
    if path is not None:
        opts["path"] = path
    cmd, err = _cmd.build_command(action, t, opts)
    return {"cmd": " ".join(cmd)} if not err else {"cmd": None, "error": err}

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
# The dashboard is the "Panel" design direction: a 14-day fleet heatmap, a capacity gauge +
# coverage gaps in the rail, targets as grouped cards, and a metric legend. Theme-aware (the
# viewer's light/dark preference drives the token set); server-rendered from live status.
GROUPS = {"zfs-local": (0, "Pools"),
          "zfs-repl": (2, "Replication (ZFS)"),
          "borg-repo": (3, "Archive repos (borg)"),
          "backupninja-handler": (4, "Scheduled jobs"),
          "smart": (5, "Disk health (SMART)"),
          "kernel-errors": (6, "Hardware watch")}

def _group(r):
    if r["type"] == "zfs-repl" and r.get("location") == "offsite":
        return (1, "Off-site replication")
    return GROUPS.get(r["type"], (9, r["type"] or "other"))

def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")) if s else ""

# The metric legend the dashboard footer renders - plain-language key for every column/badge.
LEGEND = [
    ("OK / WARN / CRIT", "Worst-of rollup for a target. Green = healthy, amber = needs attention, "
                         "red = act now. UNKNOWN = the agent couldn't read it (permissions/offline)."),
    ("lag", "Replication lag - hours between the newest source snapshot and the one the destination "
            "has actually received. WARN ~28h (a nightly run missed), CRIT ~50h (two missed)."),
    ("capacity", "Pool capacity used. WARN at ≥ 85%, CRIT at ≥ 92% - ZFS slows sharply when nearly full."),
    ("archives", "borg archive count - how many restore points the repository currently holds."),
    ("dedup", "borg deduplication + compression ratio (original size ÷ stored size)."),
    ("resilver", "ZFS is rebuilding a replaced or errored disk back onto its mirror/raidz. Recent "
                 "resilver = a disk dropped or went flaky, even once the pool reports healthy."),
    ("CRC / CKSUM", "Checksum or link errors from the kernel - usually a bad cable, HBA lane, or a "
                    "failing disk. Caught even when ZFS silently self-heals them."),
    ("off-site", "The target has ≥ 1 copy on the remote vault - the '1' in the 3-2-1 rule."),
    ("enc", "Dataset is encrypted; an off-site copy is held raw and cannot be read there."),
]

FONTS = ('<link rel="preconnect" href="https://fonts.googleapis.com">'
         '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
         '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?'
         'family=Red+Hat+Display:wght@500;700;900&family=Red+Hat+Text:wght@400;500;600&'
         'family=Roboto+Mono:wght@400;500&display=swap">')

PAGE_STYLE = """<style>
:root{
  --bg:#eef2f6; --surf:#ffffff; --ink:#1a2733; --mut:#5f7085; --line:#e0e6ec;
  --acc:#1c5fa8; --acc2:#0f3f74; --accsoft:#e7f0f9; --rail:#f5f8fb; --heatbg:#e4e9ee;
  --ok:#1c8a63; --warn:#c07d21; --crit:#c1443a; --unk:#8090a0;
}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){
  --bg:#0d1621; --surf:#111e2c; --ink:#dbe6f2; --mut:#8496a8; --line:#213347;
  --acc:#4d9fff; --acc2:#9cc6f5; --accsoft:#16304b; --rail:#0e1a27; --heatbg:#1a2b3c;
  --ok:#34c98a; --warn:#e0a53a; --crit:#ff5b51; --unk:#7d90a4;
}}
:root[data-theme=dark]{
  --bg:#0d1621; --surf:#111e2c; --ink:#dbe6f2; --mut:#8496a8; --line:#213347;
  --acc:#4d9fff; --acc2:#9cc6f5; --accsoft:#16304b; --rail:#0e1a27; --heatbg:#1a2b3c;
  --ok:#34c98a; --warn:#e0a53a; --crit:#ff5b51; --unk:#7d90a4;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.5 "Red Hat Text",system-ui,sans-serif;-webkit-font-smoothing:antialiased}
.panel{max-width:1200px;margin:0 auto}
.panel h2,.panel h3{font-family:"Red Hat Display",sans-serif;margin:0}
.mono{font-family:"Roboto Mono",monospace;font-variant-numeric:tabular-nums}
button:focus-visible,a:focus-visible{outline:2px solid var(--acc);outline-offset:2px}
/* hero + heatmap */
.hero{padding:22px 26px 18px;background:linear-gradient(180deg,var(--rail),var(--surf));border-bottom:1px solid var(--line)}
.hero-top{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.hero-top h2{font-weight:900;font-size:20px;letter-spacing:-.01em}
.verd{font-weight:700;font-size:12.5px;padding:4px 12px;border-radius:20px;border:1px solid currentColor;letter-spacing:.02em}
.verd.ok{color:var(--ok)} .verd.warn{color:var(--warn)} .verd.crit{color:var(--crit)} .verd.unk{color:var(--unk)}
.tag{font-size:12.5px;color:var(--mut);margin-left:auto;text-align:right}
.tag a{color:var(--acc);text-decoration:none}
.heat{margin-top:14px;overflow-x:auto}
.heatspan{font-size:11.5px;color:var(--mut);font-family:"Roboto Mono";margin-bottom:8px}
.heat table{border-collapse:collapse;min-width:520px}
.heat td{padding:2px}
.heat .hname{font-size:11.5px;color:var(--mut);text-align:right;padding-right:10px;white-space:nowrap;font-family:"Roboto Mono"}
.heat .c{width:16px;height:16px;border-radius:3px;background:var(--heatbg)}
.heat .c.ok{background:var(--ok)} .heat .c.warn{background:var(--warn)}
.heat .c.crit{background:var(--crit)} .heat .c.unk{background:var(--unk);opacity:.55}
/* split */
.split{display:grid;grid-template-columns:270px 1fr;gap:0}
.rail{padding:22px;border-right:1px solid var(--line);background:var(--rail);display:flex;flex-direction:column;gap:22px}
.gauge-wrap{text-align:center}
.gauge-wrap canvas{width:150px;height:150px}
.gauge-cap{font-family:"Red Hat Display";font-weight:700;font-size:13px;margin-top:2px}
.gauge-cap span{display:block;color:var(--mut);font-weight:400;font-size:11.5px;margin-top:2px}
.railsec h3{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--mut);font-weight:700;margin:0 0 11px}
.gap{display:flex;gap:10px;align-items:flex-start;margin-bottom:12px}
.gap .d{width:8px;height:8px;border-radius:50%;margin-top:5px;flex:none}
.gap b{font-size:13px;font-weight:600}
.gap small{display:block;color:var(--mut);font-size:11.5px;line-height:1.4}
/* cards */
.main{padding:20px 24px 26px}
.gtitle{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--mut);font-weight:700;margin:6px 0 12px}
.gtitle:not(:first-child){margin-top:22px}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(236px,1fr));gap:14px}
.card{background:var(--surf);border:1px solid var(--line);border-radius:13px;padding:15px 16px;
  border-top:3px solid var(--unk);box-shadow:0 1px 2px rgba(20,40,60,.05)}
.card.ok{border-top-color:var(--ok)} .card.warn{border-top-color:var(--warn)} .card.crit{border-top-color:var(--crit)}
.card .ch{display:flex;align-items:center;justify-content:space-between;gap:8px}
.card .cn{font-family:"Red Hat Display";font-weight:700;font-size:15px;word-break:break-word}
.card .cs{font-size:10.5px;font-weight:700;letter-spacing:.05em;flex:none}
.card.ok .cs{color:var(--ok)} .card.warn .cs{color:var(--warn)} .card.crit .cs{color:var(--crit)} .card.unk .cs{color:var(--unk)}
.card .src{font-family:"Roboto Mono";font-size:11.5px;color:var(--mut);margin-top:3px;word-break:break-all}
.card .row{display:flex;gap:16px;margin-top:12px;flex-wrap:wrap}
.card .mv{font-family:"Roboto Mono";font-weight:500;font-size:16px}
.card .ml{font-size:10px;letter-spacing:.06em;text-transform:uppercase;color:var(--mut)}
.card .why{color:var(--mut);font-size:12px;margin-top:11px;line-height:1.4}
.cact{display:flex;gap:6px;margin-top:13px;flex-wrap:wrap}
.cact button{appearance:none;font:600 11.5px/1 "Red Hat Text";border:1px solid var(--line);
  background:var(--surf);color:var(--acc2);border-radius:7px;padding:7px 10px;cursor:pointer}
.cact button.pri{background:var(--acc);color:#fff;border-color:var(--acc)}
.cact button:hover{filter:brightness(1.05)}
.cact .ro{color:var(--unk);font-size:11.5px;font-style:italic;align-self:center}
.crec{display:flex;gap:10px;margin-top:9px}
.crec button{appearance:none;font:500 11px/1 "Red Hat Text";border:0;background:transparent;
  color:var(--acc);cursor:pointer;padding:2px 0;border-bottom:1px dotted var(--acc)}
/* per-card action history */
.chistrow{margin-top:11px;border-top:1px dashed var(--line);padding-top:9px}
.histbtn{appearance:none;font:600 11px/1 "Red Hat Text",sans-serif;border:0;background:transparent;
  color:var(--mut);cursor:pointer;padding:2px 0;display:inline-flex;gap:6px;align-items:center}
.histbtn:hover{color:var(--ink)}
.histbtn::before{content:"▸";font-size:10px;display:inline-block;transition:transform .15s}
.histbtn.open::before{transform:rotate(90deg)}
.chist{margin-top:9px;display:flex;flex-direction:column;gap:8px}
.chist .hrow{display:grid;grid-template-columns:auto 1fr auto;gap:8px;align-items:center}
.chist .hd{width:7px;height:7px;border-radius:50%;flex:none}
.chist .hd.ok{background:var(--ok)} .chist .hd.warn{background:var(--warn)}
.chist .hd.crit{background:var(--crit)} .chist .hd.unk{background:var(--unk)}
.chist .ha{font-size:11.5px;font-weight:600}
.chist .hdry{font-size:9px;letter-spacing:.05em;text-transform:uppercase;color:var(--mut);
  border:1px solid var(--line);border-radius:4px;padding:1px 4px;margin-left:5px;font-weight:700}
.chist .ht{color:var(--mut);font-family:"Roboto Mono";font-size:10.5px;white-space:nowrap}
.chist .hcmd{grid-column:1/-1;color:var(--mut);font-family:"Roboto Mono";font-size:10.5px;
  background:var(--rail);border:1px solid var(--line);border-radius:6px;padding:5px 7px;
  white-space:pre-wrap;word-break:break-all}
.chist .hempty{color:var(--mut);font-size:11.5px;font-style:italic}
#actlog{margin-top:20px;padding:.6rem;background:var(--rail);border:1px solid var(--line);
  border-radius:9px;display:flex;flex-direction:column;gap:7px;min-height:1.4em}
#actlog .amsg{color:var(--mut);font:12px/1.5 "Roboto Mono",monospace;padding:2px 4px}
.actrow{display:grid;grid-template-columns:auto 1fr auto;gap:10px;align-items:center;
  font:12px/1.4 "Roboto Mono",monospace;padding:7px 9px;background:var(--surf);
  border:1px solid var(--line);border-radius:8px}
.actrow .ad{width:8px;height:8px;border-radius:50%;flex:none}
.actrow .ad.ok{background:var(--ok)} .actrow .ad.crit{background:var(--crit)}
.actrow .ad.warn{background:var(--warn)} .actrow .ad.unk{background:var(--unk)}
.actrow.spin .ad{animation:apulse 1.1s ease-in-out infinite}
@keyframes apulse{0%,100%{opacity:.3}50%{opacity:1}}
.actrow .at{color:var(--ink);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.actrow .as{color:var(--mut);white-space:nowrap;font-size:10.5px;text-transform:uppercase;letter-spacing:.05em}
.actrow .aout{grid-column:1/-1;color:var(--mut);font-size:10.5px;white-space:pre-wrap;word-break:break-all;
  background:var(--rail);border:1px solid var(--line);border-radius:6px;padding:5px 7px}
/* legend */
.legend{grid-column:1/-1;background:var(--rail);border-top:1px solid var(--line);padding:20px 24px 26px}
.legend h3{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--mut);font-weight:700;margin:0 0 14px}
.lg{display:grid;grid-template-columns:repeat(3,1fr);gap:13px 28px}
.lg dt{font-family:"Roboto Mono";font-weight:500;font-size:13px;color:var(--acc2);display:flex;gap:8px;align-items:center}
.lg dd{margin:3px 0 0;color:var(--mut);font-size:12px;line-height:1.45}
.lg .sw{width:11px;height:11px;border-radius:3px;flex:none}
/* top bar + hero toggle */
.topbar2{display:flex;align-items:center;gap:16px;flex-wrap:wrap;padding:14px 26px 2px}
.applogo{font-family:"Red Hat Display";font-weight:900;font-size:19px;letter-spacing:-.01em}
.seg{display:inline-flex;background:var(--surf);border:1px solid var(--line);border-radius:10px;padding:3px;gap:2px}
.topbar2 .seg{margin-left:auto}
.seg button{appearance:none;border:0;background:transparent;color:var(--mut);
  font:600 12.5px/1 "Red Hat Text",sans-serif;padding:8px 14px;border-radius:7px;cursor:pointer}
.seg button:hover{color:var(--ink)}
.signout{color:var(--acc);text-decoration:none;font-size:12.5px;white-space:nowrap}
.drysw{display:inline-flex;align-items:center;gap:8px;cursor:pointer;font-size:12.5px;color:var(--mut);
  border:1px solid var(--line);background:var(--surf);border-radius:9px;padding:6px 11px;user-select:none}
.drysw input{appearance:none;-webkit-appearance:none;width:30px;height:17px;border-radius:10px;
  background:var(--line);position:relative;cursor:pointer;transition:background .15s;flex:none;margin:0}
.drysw input::after{content:"";position:absolute;top:2px;left:2px;width:13px;height:13px;border-radius:50%;
  background:#fff;transition:transform .15s;box-shadow:0 1px 2px rgba(0,0,0,.3)}
.drysw input:checked{background:var(--acc)}
.drysw input:checked::after{transform:translateX(13px)}
.drysw input:focus-visible{outline:2px solid var(--acc);outline-offset:2px}
.panel.drymode .drysw{color:var(--acc);border-color:var(--acc);font-weight:600}
.actrow.dryrow{border-style:dashed}
.panel[data-hero=steel] .seg [data-h=steel],
.panel[data-hero=heat] .seg [data-h=heat],
.panel:not([data-hero]) .seg [data-h=steel]{background:var(--acc);color:#fff}
.herox{display:none}
.panel[data-hero=steel] #hero-steel,
.panel:not([data-hero]) #hero-steel,
.panel[data-hero=heat] #hero-heat{display:block}
/* steel-style summary hero */
.sumband{display:flex;flex-wrap:wrap;align-items:center;gap:18px 30px;padding:20px 26px;
  background:linear-gradient(180deg,var(--rail),var(--surf));border-bottom:1px solid var(--line)}
.sumverd{display:flex;align-items:center;gap:15px}
.sumverd svg{width:44px;height:50px;flex:none}
.sumverd .vt{font-family:"Red Hat Display";font-weight:900;font-size:25px;letter-spacing:-.02em;line-height:1;color:currentColor}
.sumverd .vs{color:var(--mut);font-size:12.5px;margin-top:6px}
.sumverd.ok{color:var(--ok)} .sumverd.warn{color:var(--warn)} .sumverd.crit{color:var(--crit)} .sumverd.unk{color:var(--unk)}
.sumchips{display:flex;gap:9px;flex-wrap:wrap}
.sumchip{display:flex;align-items:center;gap:7px;background:var(--surf);border:1px solid var(--line);
  border-radius:9px;padding:7px 12px;font-size:12px;color:var(--mut)}
.sumchip b{font-family:"Roboto Mono";font-size:15px;color:var(--ink)}
.sumchip i{width:9px;height:9px;border-radius:2px;flex:none}
.sumasof{margin-left:auto;color:var(--mut);font-size:12px;text-align:right;line-height:1.7}
.sumasof b{color:var(--ink);font-family:"Roboto Mono";font-weight:500}
.sumtiles{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;padding:20px 26px 4px}
.stile{background:var(--surf);border:1px solid var(--line);border-radius:12px;padding:16px 18px}
.stile .lbl{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--mut);font-weight:700}
.stile .big{font-family:"Red Hat Display";font-weight:900;font-size:26px;margin-top:8px;letter-spacing:-.02em}
.stile .sub{color:var(--mut);font-size:12.5px;margin-top:4px}
.smeter{height:8px;border-radius:5px;background:var(--heatbg);margin-top:12px;overflow:hidden}
.smeter i{display:block;height:100%;border-radius:5px}
.pill321{display:inline-flex;gap:4px;margin-top:11px;flex-wrap:wrap}
.pill321 s{width:24px;height:6px;border-radius:3px;background:var(--ok)}
.pill321 s.off{background:var(--crit)} .pill321 s.warn{background:var(--warn)}
@media (max-width:760px){
  .split{grid-template-columns:1fr} .rail{border-right:0;border-bottom:1px solid var(--line)}
  .lg{grid-template-columns:1fr} .tag{margin-left:0;text-align:left}
  .sumtiles{grid-template-columns:1fr} .sumasof{margin-left:0;text-align:left}
}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
</style>"""

# plain string (NOT an f-string) so JS ${...} and \n survive untouched
PAGE_SCRIPT = """<script>
var _seq=0;
function setRow(key, o){
  var el=document.getElementById('actlog'); var idle=el.querySelector('.amsg'); if(idle) idle.remove();
  var row=document.getElementById('actrow-'+key);
  if(!row){
    row=document.createElement('div'); row.className='actrow'; row.id='actrow-'+key;
    row.innerHTML='<span class="ad"></span><span class="at"></span><span class="as"></span><div class="aout" hidden></div>';
    el.insertBefore(row, el.firstChild);            // newest on top
    while(el.children.length>12) el.removeChild(el.lastChild);   // cap the queue
  }
  if(o.dry===true) row.classList.add('dryrow');
  if(o.title!=null) row.querySelector('.at').textContent=o.title;
  if(o.state!=null) row.querySelector('.as').textContent=o.state;
  if(o.cls!=null) row.querySelector('.ad').className='ad '+o.cls;
  if(o.spin===true) row.classList.add('spin'); else if(o.spin===false) row.classList.remove('spin');
  if(o.out!=null){ var out=row.querySelector('.aout'); out.hidden=false; out.textContent=o.out; }
}
async function post(body){
  var key='q'+(++_seq); var dry=!!body.dryrun; var tag=dry?'[dry] ':'';
  setRow(key,{title:tag+body.action+' '+body.target, state:'submitting', cls:'warn', spin:true, dry:dry});
  var r,j;
  try{ r=await fetch('/api/v1/backup/actions',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify(body)}); j=await r.json(); }
  catch(e){ setRow(key,{state:'network error', cls:'crit', spin:false, out:String(e)}); return; }
  if(!r.ok){ setRow(key,{state:'rejected', cls:'crit', spin:false, out:(j.detail||('HTTP '+r.status))}); return; }
  setRow(key,{title:tag+'#'+j.id+' '+body.action+' '+body.target, state:'pending', cls:'warn', spin:true});
  poll(j.id, key, dry);
}
async function previewCmd(b){
  var q='/api/v1/backup/actions/preview?target='+encodeURIComponent(b.target)+'&action='+encodeURIComponent(b.action);
  if(b.create_snapshot!=null) q+='&create_snapshot='+b.create_snapshot;
  if(b.path!=null) q+='&path='+encodeURIComponent(b.path);
  try{ var j=await (await fetch(q)).json(); return j.cmd||j.note||j.error||''; }catch(e){ return ''; }
}
async function confirmRun(b, label){
  var cmd=await previewCmd(b);
  var head = b.dryrun ? ('DRY-RUN - preview '+label+'?\\n(runs a safe probe / native -n, changes nothing)')
                      : ('Run '+label+'?');
  return confirm(head+(cmd?('\\n\\nwill run:\\n'+cmd):''));
}
async function act(target, action, createSnap){
  var label=action+' '+target+(action==='sync'?(' (new snap: '+createSnap+')'):'');
  var b={target:target, action:action, requested_by:'ui', dryrun:!!window.BM_DRY};
  if(action==='sync') b.create_snapshot=createSnap;
  if(!(await confirmRun(b,label))) return;
  post(b);
}
async function actPrompt(target, action, field, msg){
  var v=prompt(msg); if(v===null) return;
  var b={target:target, action:action, requested_by:'ui', dryrun:!!window.BM_DRY}; b[field]=v;
  if(!(await confirmRun(b, action+' '+target+' ['+(v||'(all)')+']'))) return;
  post(b);
}
async function poll(id, key, dry){
  var tag=dry?'[dry] ':'';
  for(var i=0;i<180;i++){
    var j; try{ j=await (await fetch('/api/v1/backup/actions/'+id)).json(); }catch(e){ break; }
    var st=j.state||'?';
    var done=['done','failed','stalled'].includes(st);
    var cls = st==='done'?'ok' : (st==='failed'||st==='stalled')?'crit' : 'warn';
    var res={}; try{res=JSON.parse(j.result||'{}')}catch(e){}
    setRow(key,{title:tag+'#'+id+' '+(j.target||'')+' '+(j.action||''), state:st+(dry?' · dry':''),
                cls:cls, spin:!done, out: done?(res.output||''):undefined});
    if(done) break;
    await new Promise(s=>setTimeout(s,2000));
  }
}
function drawGauge(){
  var c=document.getElementById('gauge'); if(!c||!window.GP) return;
  var cs=getComputedStyle(document.querySelector('.panel'));
  function v(k,f){var x=cs.getPropertyValue(k).trim();return x||f;}
  var track=v('--heatbg','#e4e9ee'), acc=v('--acc','#1c5fa8'),
      warn=v('--warn','#c07d21'), ink=v('--ink','#1a2733'), mut=v('--mut','#5f7085');
  var x=c.getContext('2d'), cx=150, cy=150, r=112, lw=26,
      start=Math.PI*0.75, end=Math.PI*2.25, pct=Math.max(0,Math.min(100,GP.pct))/100;
  x.clearRect(0,0,300,300); x.lineCap='round';
  x.beginPath(); x.arc(cx,cy,r,start,end); x.strokeStyle=track; x.lineWidth=lw; x.stroke();
  var g=x.createLinearGradient(0,0,300,300); g.addColorStop(0,acc); g.addColorStop(1, GP.pct>=85?warn:acc);
  x.beginPath(); x.arc(cx,cy,r,start,start+(end-start)*pct); x.strokeStyle=g; x.lineWidth=lw; x.stroke();
  x.fillStyle=ink; x.textAlign='center'; x.textBaseline='middle';
  x.font='700 46px "Red Hat Display",sans-serif'; x.fillText(GP.pct+'%',cx,cy-6);
  x.fillStyle=mut; x.font='500 13px "Roboto Mono",monospace'; x.fillText('used',cx,cy+26);
}
window.addEventListener('load',drawGauge);
if(document.fonts&&document.fonts.ready) document.fonts.ready.then(drawGauge);
if(window.matchMedia) matchMedia('(prefers-color-scheme:dark)').addEventListener('change',drawGauge);
function esc(s){return (s==null?'':String(s)).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function relTime(ts){ if(!ts) return ''; var s=Math.max(0, Date.now()/1000 - ts);
  if(s<90) return Math.round(s)+'s ago'; if(s<5400) return Math.round(s/60)+'m ago';
  if(s<172800) return Math.round(s/3600)+'h ago'; return Math.round(s/86400)+'d ago';}
function renderHist(x){
  var st=x.state||'?';
  var cls = st==='done'?'ok' : st==='failed'?'crit' : (st==='pending'||st==='claimed')?'warn':'unk';
  var res={}; try{res=JSON.parse(x.result||'{}')}catch(e){}
  var out=(res.output||res.cmd||'').toString();
  var dry = out.indexOf('[DRYRUN]')===0 ? '<span class=hdry>dry</span>' : '';
  var when = relTime(x.result_ts||x.claimed_ts||x.created_ts);
  return '<div class=hrow><span class="hd '+cls+'"></span>'+
    '<span class=ha>'+esc(x.action)+' · '+esc(st)+dry+'</span>'+
    '<span class=ht>'+when+'</span>'+
    (out?'<div class=hcmd>'+esc(out)+'</div>':'')+'</div>';
}
async function toggleHist(btn, target){
  var box=btn.nextElementSibling; var open=btn.classList.toggle('open');
  if(!open){ box.hidden=true; return; }
  box.hidden=false; box.innerHTML='<div class=hempty>loading…</div>';
  try{
    var j=await (await fetch('/api/v1/backup/actions?limit=8&target='+encodeURIComponent(target))).json();
    var a=(j.actions||[]);
    box.innerHTML = a.length ? a.map(renderHist).join('') : '<div class=hempty>no actions yet</div>';
  }catch(e){ box.innerHTML='<div class=hempty>error loading history</div>'; }
}
function setHero(h){var p=document.querySelector('.panel'); if(!p) return;
  p.dataset.hero=h; try{localStorage.setItem('bm_hero',h)}catch(e){}}
(function(){try{var s=localStorage.getItem('bm_hero');
  if(s) document.querySelector('.panel').dataset.hero=s;}catch(e){}})();
function setDry(v){window.BM_DRY=!!v; var p=document.querySelector('.panel');
  if(p) p.classList.toggle('drymode',!!v); try{localStorage.setItem('bm_dry', v?'1':'')}catch(e){}}
(function(){try{ if(localStorage.getItem('bm_dry')){ window.BM_DRY=true;
  var c=document.getElementById('drychk'); if(c) c.checked=true;
  var p=document.querySelector('.panel'); if(p) p.classList.add('drymode'); } }catch(e){}})();
</script>"""

def _acts(r, can_act):
    """Card action buttons - only when an EXECUTE-capable agent owns the target (else the intent
    would hang pending). Recovery (Points/Deleted/Versions) sits on a compact sub-row."""
    n = r["name"]; t = r["type"]
    if not can_act:
        return ('<div class="cact"><span class="ro">report-only</span></div>'
                if t in ("zfs-repl", "zfs-local") else "")
    rec = ""
    if t in ("zfs-repl", "zfs-local") and r.get("source"):
        rec = (f'<div class="crec">'
               f"<button onclick=\"act('{n}','recover-points')\">Points</button>"
               f"<button onclick=\"actPrompt('{n}','recover-deleted','path','deleted files under (blank = whole dataset):')\">Deleted</button>"
               f"<button onclick=\"actPrompt('{n}','recover-search','path','list versions of (path relative to dataset root):')\">Versions</button>"
               f"</div>")
    if t == "zfs-repl":
        main = (f"<button class=pri onclick=\"act('{n}','sync',true)\">Replicate</button>"
                f"<button onclick=\"act('{n}','snapshot',true)\">Snapshot</button>"
                f"<button onclick=\"act('{n}','sync',false)\">no-snap</button>")
    elif t == "zfs-local":
        main = f"<button class=pri onclick=\"act('{n}','scrub',true)\">Scrub</button>"
    else:
        return ""
    return f'<div class="cact">{main}</div>{rec}'

def _card(r, can_act):
    nm = r["name"]; n = _esc(nm); sev = SEVCLS.get(r["severity"], "unk")
    src = r.get("source") or ""
    src_line = f"{src} → {r['dest']}" if r.get("dest") else src
    meta = []
    if r.get("tier"): meta.append(f"tier {r['tier']}")
    if r.get("encrypted"): meta.append("enc")
    if r.get("location") == "offsite": meta.append("off-site")
    if meta: src_line = (src_line + " · " if src_line else "") + " · ".join(meta)
    mr = ""
    if r.get("pool_cap_pct") is not None:
        mr += f'<div><div class="mv">{r["pool_cap_pct"]}%</div><div class="ml">capacity</div></div>'
    if r.get("repl_lag_s") is not None:
        mr += f'<div><div class="mv">{r["repl_lag_s"]//3600}h</div><div class="ml">repl lag</div></div>'
    if r.get("archive_count") is not None:
        mr += f'<div><div class="mv">{r["archive_count"]}</div><div class="ml">archives</div></div>'
    if r.get("dedup_ratio") is not None:
        mr += f'<div><div class="mv">{r["dedup_ratio"]}×</div><div class="ml">dedup</div></div>'
    d = json.loads(r.get("detail_json") or "{}")
    why = _esc(", ".join(d.get("reasons", [])) or (r.get("last_error") or ""))
    src_html = f'<div class="src">{_esc(src_line)}</div>' if src_line else ""
    mr_html = f'<div class="row">{mr}</div>' if mr else ""
    why_html = f'<div class="why">{why}</div>' if why else ""
    hist_html = ""
    if r["type"] in ("zfs-repl", "zfs-local"):   # the target types that receive action intents
        hist_html = (f'<div class=chistrow><button class=histbtn onclick="toggleHist(this,\'{nm}\')">'
                     f'History</button><div class=chist hidden></div></div>')
    return (f'<div class="card {sev}"><div class="ch"><span class="cn">{n}</span>'
            f'<span class="cs">{r["severity"]}</span></div>{src_html}{mr_html}{why_html}'
            f'{_acts(r, can_act)}{hist_html}</div>')

def _heatmap(order_names):
    """14-day worst-severity-per-day grid, aligned to the card order."""
    grid = timeline(14)["grid"]
    days = [time.strftime("%Y-%m-%d", time.localtime(time.time() - i * DAY)) for i in range(13, -1, -1)]
    out = ""
    for name in order_names:
        g = grid.get(name, {})
        cells = ""
        for dstr in days:
            sev = g.get(dstr)
            cls = SEVCLS.get(sev, "") if sev else ""
            cells += f'<td><div class="c {cls}" title="{dstr}: {sev or "no data"}"></div></td>'
        out += f'<tr><td class="hname">{_esc(name)}</td>{cells}</tr>'
    return out, f"{days[0]} → {days[-1]}"

def _hero_steel(rows, h, gpct, glabel):
    """Steel-style summary header: verdict + 3-2-1 badge / capacity / restore-points tiles.
    An alternative to the 14-day heatmap hero (toggled client-side)."""
    sc = scorecard(); cards = sc["cards"]
    npass = sum(1 for c in cards if c["pass_321"]); ntot = len(cards)
    if ntot:
        pills = "".join(("<s></s>" if c["pass_321"] else "<s class=off></s>") for c in cards)
        s_big, s_cls = f"{npass} / {ntot}", ("ok" if npass == ntot else "crit" if npass == 0 else "warn")
        s_sub = "Tier-A datasets with ≥3 copies · 2 media · 1 off-site"
    else:
        pills, s_big, s_cls, s_sub = "", "-", "unk", "no Tier-A datasets defined"
    arch = [r for r in rows if r["type"] == "borg-repo" and r.get("archive_count") is not None]
    tot_arch = sum(r["archive_count"] for r in arch)
    rp_sub = f"{tot_arch} borg archives across {len(arch)} repos" if arch else "no borg repos"
    cap_cls = "crit" if gpct >= 92 else "warn" if gpct >= 85 else "ok"
    c = h["counts"]
    chips = "".join(f'<div class=sumchip><i style="background:var(--{SEVCLS[k]})"></i>'
                    f'<b>{c.get(k,0)}</b> {k}</div>' for k in ("OK", "WARN", "CRIT", "UNKNOWN"))
    vcls = SEVCLS.get(h["severity"], "unk")
    verdict = {"OK": "All healthy", "WARN": "Attention", "CRIT": "Critical",
               "UNKNOWN": "Unknown"}.get(h["severity"], h["severity"])
    vsub = f'{c.get("WARN",0)} warning(s) · {c.get("CRIT",0)} critical · {h["targets"]} targets'
    ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(h["ts"]))
    glyph = ('<path d="M18 29l6 6 12-13" stroke="currentColor" stroke-width="3.4" stroke-linecap="round" stroke-linejoin="round"/>'
             if h["severity"] == "OK" else
             '<path d="M26 16v18" stroke="currentColor" stroke-width="3.6" stroke-linecap="round"/>'
             '<circle cx="26" cy="43" r="2.3" fill="currentColor"/>')
    shield = ('<svg viewBox="0 0 52 58" fill="none"><path d="M26 2 48 10v20c0 15-10 24-22 26'
              'C14 54 4 45 4 30V10L26 2Z" fill="none" stroke="currentColor" stroke-width="2" '
              'opacity=".85"/>' + glyph + '</svg>')
    meter = (f'<div class=smeter><i style="width:{min(gpct,100)}%;'
             f'background:linear-gradient(90deg,var(--acc),var(--warn))"></i></div>')
    return f"""
    <div class=sumband>
      <div class="sumverd {vcls}">{shield}<div><div class=vt>{verdict}</div><div class=vs>{vsub}</div></div></div>
      <div class=sumchips>{chips}</div>
      <div class=sumasof>as of<br><b>{ts}</b></div>
    </div>
    <div class=sumtiles>
      <div class=stile><div class=lbl>3-2-1 coverage</div>
        <div class=big style="color:var(--{s_cls})">{s_big}</div><div class=sub>{s_sub}</div>
        <div class=pill321>{pills}</div></div>
      <div class=stile><div class=lbl>Capacity · busiest pool</div>
        <div class=big style="color:var(--{cap_cls})">{gpct}%</div><div class=sub>{_esc(glabel)}</div>{meter}</div>
      <div class=stile><div class=lbl>Restore points</div>
        <div class=big>{tot_arch}</div><div class=sub>{rp_sub}</div></div>
    </div>"""

def _shell(inner):
    return (f"<!doctype html><html lang=en><head><meta charset=utf-8>"
            f"<meta name=viewport content=\"width=device-width,initial-scale=1\">"
            f"<title>backup-monitor</title>{FONTS}{PAGE_STYLE}</head><body>"
            f"<div class=panel>{inner}"
            f"<form id=lo method=post action=/logout hidden></form></div>{PAGE_SCRIPT}</body></html>")

@app.get("/", response_class=HTMLResponse)
def index():
    with db() as conn:
        rows = latest_status(conn)
        capable = {x["name"] for x in conn.execute(
            "SELECT name FROM agents WHERE can_execute=1").fetchall()}
    h = health()
    if not rows:
        return _shell(
            '<div class=hero><div class=hero-top><h2>backup-monitor</h2>'
            '<span class="verd unk">No data yet</span></div>'
            '<p class=why style="margin-top:14px;max-width:60ch">No agent has reported yet. Start an '
            'agent (see AGENT.md) - it enrolls, reads this host\'s ZFS / borg / backupninja, and '
            'populates the dashboard within one poll interval.</p></div>')

    rows.sort(key=lambda r: (_group(r)[0], r["name"]))
    order_names = [r["name"] for r in rows]

    pools = [r for r in rows if r["type"] == "zfs-local" and r.get("pool_cap_pct") is not None]
    if pools:
        bp = max(pools, key=lambda r: r["pool_cap_pct"])
        gpct, glabel = int(bp["pool_cap_pct"]), _esc(bp["name"])
    else:
        gpct, glabel = 0, "-"

    gaps = coverage_gap()["gaps"][:6]
    if gaps:
        gaps_html = "".join(
            f'<div class=gap><span class=d style="background:var(--{SEVCLS.get(x["severity"],"unk")})"></span>'
            f'<div><b>{_esc(x["name"])}</b><small>{_esc(x["gap"])}</small></div></div>' for x in gaps)
    else:
        gaps_html = ('<div class=gap><span class=d style="background:var(--ok)"></span>'
                     '<div><b>No gaps</b><small>everything snapshotted &amp; replicating</small></div></div>')

    heat_rows, heat_span = _heatmap(order_names)

    cards, cur = "", None
    for r in rows:
        g = _group(r)[1]
        if g != cur:
            if cur is not None:
                cards += "</div>"
            cards += f'<div class=gtitle>{_esc(g)}</div><div class=cards>'
            cur = g
        cards += _card(r, r.get("agent") in capable)
    if cur is not None:
        cards += "</div>"

    leg = ""
    for term, desc in LEGEND:
        sw = ('<span class=sw style="background:linear-gradient(90deg,var(--ok),var(--warn),var(--crit))"></span>'
              if term.startswith("OK") else "")
        leg += f"<div><dt>{sw}{term}</dt><dd>{desc}</dd></div>"

    c = h["counts"]; ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(h["ts"]))
    verdict = {"OK": "All healthy", "WARN": "Attention", "CRIT": "Critical",
               "UNKNOWN": "Unknown"}.get(h["severity"], h["severity"])
    vcls = SEVCLS.get(h["severity"], "unk")
    steel_hero = _hero_steel(rows, h, gpct, glabel)
    return _shell(f"""
  <div class=topbar2><h2 class=applogo>backup-monitor</h2>
    <div class=seg role=tablist>
      <button data-h=steel onclick="setHero('steel')">Summary</button>
      <button data-h=heat onclick="setHero('heat')">14-day fleet</button></div>
    <label class=drysw title="When on, every action runs a safe dry-run probe (native -n / read-only) instead of executing">
      <input type=checkbox id=drychk onchange="setDry(this.checked)"><span>Dry-run</span></label>
    <a class=signout href=# onclick="lo.submit();return false">sign out</a></div>
  <div id=hero-steel class=herox>{steel_hero}</div>
  <div id=hero-heat class=herox><div class=hero>
    <div class=hero-top><span class="verd {vcls}">{verdict}</span>
      <span class=tag>{h['targets']} targets · {c.get('OK',0)} ok · {c.get('WARN',0)} warn · {c.get('CRIT',0)} crit · as of {ts}</span></div>
    <div class=heat><div class=heatspan>Last 14 days &nbsp;·&nbsp; {heat_span}</div>
      <table>{heat_rows}</table></div></div></div>
  <div class=split>
    <div class=rail>
      <div class=gauge-wrap><canvas id=gauge width=300 height=300></canvas>
        <div class=gauge-cap>Busiest pool<span>{glabel} · {gpct}% used</span></div></div>
      <div class=railsec><h3>Coverage gaps</h3>{gaps_html}</div>
    </div>
    <div class=main>{cards}<div id=actlog><span class=amsg>idle - actions stream here.</span></div></div>
    <div class=legend><h3>Metric key</h3><dl class=lg>{leg}</dl></div>
  </div>
  <script>var GP={{pct:{gpct},label:"{glabel}"}};</script>""")
