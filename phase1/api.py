#!/usr/bin/env python3
"""cairn Phase 1 API (read-only status + derived views) with Phase-3 stubs.

Serves the aggregated status the collector writes, the Tier-1 derived views
(single health badge, 3-2-1 scorecard, coverage-gap, timeline), a minimal HTML
dashboard, and the token-authed vault endpoints (report + intent poll/result).

Run:  uvicorn api:app --host 127.0.0.1 --port 8929
Env:  CAIRN_DB, CAIRN_API_TOKEN (vault/agent bearer token; hash-at-rest is a deploy hardening)
"""
import gzip, hashlib, hmac, json, os, re, sqlite3, time
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

HERE = Path(__file__).resolve().parent
DB = os.environ.get("CAIRN_DB", "/var/lib/cairn/cairn.db")

def _read_version():
    """Release version, from the repo-root VERSION file (shared by API + agent) or CAIRN_VERSION."""
    try:
        return os.environ.get("CAIRN_VERSION") or (HERE.parent / "VERSION").read_text().strip() or "0.0.0"
    except Exception:
        return "0.0.0"
CAIRN_VERSION = _read_version()
import sys as _sys
_sys.path.insert(0, str(HERE))
import collector as _cmd   # PURE build_command, for action PREVIEWS only; the API never executes it
DAY = 86400
app = FastAPI(title="Cairn", version="1.0")

SEV_ORDER = {"CRIT": 0, "WARN": 1, "UNKNOWN": 2, "OK": 3}
SEVCLS = {"CRIT": "crit", "WARN": "warn", "UNKNOWN": "unk", "OK": "ok"}  # severity -> css class

# ---------------- zero-trust auth: every request needs a token; HASH-AT-REST ----------------
# Only sha256(token) is ever stored (auth_tokens table). Two roles: admin (dashboard/views/
# actions) and agent (report/poll/result only). Per-agent tokens are individual rows, so one can
# be revoked without touching the others. Bootstrap: CAIRN_ADMIN_TOKEN (plaintext env) is hashed
# into the store at startup; mint per-agent tokens via POST /tokens or the cairn-token CLI.
import hashlib as _hashlib, secrets as _secrets
AGENT_PATHS = ("/api/v1/backup/report", "/api/v1/backup/intents",
               "/api/v1/backup/agent/")  # agent-only: report, intents/{id}/result, recovery walk push/due
ADMIN_ONLY_PATHS = ("/api/v1/backup/tokens",)  # sensitive even on GET - never for a viewer
ACCESS_TTL = int(os.environ.get("CAIRN_ACCESS_TTL", str(24 * 3600)))  # access-token lifetime (s)
SESSION_TTL = int(os.environ.get("CAIRN_SESSION_TTL", str(7 * 24 * 3600)))  # password-login session (s)

def _hash(token):
    return _hashlib.sha256(token.encode()).hexdigest()

# Password hashing for named accounts (users table). Stdlib PBKDF2-SHA256, hash-at-rest like tokens.
def _pw_hash(pw, salt=None, iters=200_000):
    salt = salt or _secrets.token_bytes(16)
    dk = _hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iters)
    return f"pbkdf2_sha256${iters}${salt.hex()}${dk.hex()}"

def _pw_verify(pw, stored):
    try:
        _algo, iters, salt_hex, hash_hex = stored.split("$")
        dk = _hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt_hex), int(iters))
        return _secrets.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False

def _verify_user(username, password):
    """Return the account's role if username+password check out (and the account is active), else None."""
    if not username or not password:
        return None
    with db() as c:
        r = c.execute("SELECT pass_hash,role FROM users WHERE username=? AND active=1",
                      (username,)).fetchone()
    return r["role"] if (r and _pw_verify(password, r["pass_hash"])) else None

def _mint_session(role, username):
    """Issue a short-lived session token for a password login (its role copied from the account),
    so the cookie carries a real token and nobody pastes a raw admin secret. Prunes expired sessions."""
    tok = _secrets.token_hex(32); now = int(time.time())
    with db() as c:
        c.execute("DELETE FROM auth_tokens WHERE kind='session' AND expires_ts < ?", (now,))
        # parent = the owning username, so cairn-user can revoke this account's sessions on change.
        c.execute("INSERT INTO auth_tokens(hash,role,kind,label,parent,created_ts,expires_ts,active) "
                  "VALUES(?,?,?,?,?,?,?,1)",
                  (_hash(tok), role, "session", f"session:{username}:{tok[:8]}", username, now, now + SESSION_TTL))
        c.commit()
    return tok

def _seed_tokens():
    """Seed the store from env (hash-at-rest). Idempotent. Plaintext env is only a bootstrap
    secret - it is hashed, never stored raw."""
    now = int(time.time())
    seeds = []
    adm = os.environ.get("CAIRN_ADMIN_TOKEN") or os.environ.get("CAIRN_API_TOKEN")
    if adm:
        seeds.append((_hash(adm), "admin", "bootstrap-admin"))
    for i, t in enumerate(x.strip() for x in os.environ.get("CAIRN_AGENT_TOKENS", "").split(",") if x.strip()):
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
    """Return the role (admin|viewer|agent) for a presented token, or None. Every kind except
    'enroll' authenticates a request (enroll secrets are used only at /enroll); any token with an
    expires_ts (access/session) must be unexpired."""
    if not token:
        return None
    now = int(time.time())
    h = _hash(token)
    with db() as c:
        r = c.execute("SELECT role,kind,expires_ts FROM auth_tokens WHERE hash=? AND active=1",
                      (h,)).fetchone()
        if not r or r["kind"] == "enroll":
            return None
        if r["expires_ts"] and r["expires_ts"] < now:
            return None
        c.execute("UPDATE auth_tokens SET last_used_ts=? WHERE hash=?", (now, h))
        c.commit()
    return r["role"]

@app.middleware("http")
async def auth_gate(request: Request, call_next):
    """Three-axis gate. Agent paths: admin or agent. Token-admin paths (sensitive even on GET):
    admin only. Any other GET: admin or viewer (read-only humans). Any other mutating method:
    admin only. The resolved role is stashed on request.state.role for the dashboard to render
    read-only. 401 = not signed in (HTML GET redirects to /login); 403 = signed in but read-only."""
    p = request.url.path
    if p in ("/login", "/logout", "/favicon.ico", "/api/v1/backup/enroll"):
        return await call_next(request)   # /enroll authenticates via the enrollment secret itself
    if not HAS_ADMIN:
        return JSONResponse({"detail": "no admin token configured - set CAIRN_ADMIN_TOKEN and restart"},
                            status_code=503)
    role = _lookup_role(_extract_token(request))
    request.state.role = role
    if p.startswith(AGENT_PATHS):
        ok = role in ("admin", "agent")
    elif p.startswith(ADMIN_ONLY_PATHS):
        ok = role == "admin"
    elif request.method in ("GET", "HEAD"):
        ok = role in ("admin", "viewer")
    else:
        ok = role == "admin"
    if ok:
        return await call_next(request)
    wants_html = "text/html" in request.headers.get("accept", "")
    if role is None and request.method == "GET" and wants_html and not p.startswith(AGENT_PATHS):
        return RedirectResponse("/login", status_code=302)
    return JSONResponse({"detail": "unauthorized" if role is None else "forbidden (read-only account)"},
                        status_code=401 if role is None else 403)

LOGIN_HTML = """<!doctype html><meta charset=utf-8><title>Cairn login</title>
<style>body{font:15px system-ui,sans-serif;display:grid;place-items:center;height:90vh;margin:0}
form{display:grid;gap:.6rem;width:280px} input,button{padding:.5rem;font-size:1rem}
h2{margin:0 0 .2rem} details{font-size:.9rem;color:#555} details input{margin-top:.5rem;width:100%;box-sizing:border-box}
button{cursor:pointer}</style>
<form method=post action=/login><h2>Cairn</h2>
<input name=username placeholder=username autocomplete=username autofocus>
<input type=password name=password placeholder=password autocomplete=current-password>
<button>Sign in</button>{err}
<details><summary>Sign in with a token</summary>
<input type=password name=token placeholder="access / read-only share token"></details></form>"""

def _login_page(bad):
    return HTMLResponse(LOGIN_HTML.replace(
        "{err}", "<p style='color:#c0392b;margin:.2rem 0'>invalid credentials</p>" if bad else ""))

def _sign_in_cookie(cookie_tok, max_age, scheme):
    r = RedirectResponse("/", status_code=302)
    r.set_cookie("bm_token", cookie_tok, httponly=True, samesite="strict",
                 secure=scheme == "https", max_age=max_age)
    return r

# A blank (1x1 transparent) favicon. Browsers auto-request /favicon.ico; without this the app
# 404s every page load. Whitelisted in the auth middleware above so it serves pre-login too.
import base64 as _b64
_FAVICON = _b64.b64decode(
    "AAABAAEAAQEAAAEAIAAwAAAAFgAAACgAAAABAAAAAgAAAAEAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==")

@app.get("/favicon.ico")
def favicon():
    return Response(content=_FAVICON, media_type="image/x-icon",
                    headers={"Cache-Control": "public, max-age=604800"})

@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request, bad: int = 0, token: str = ""):
    # `?token=...` is the shareable read-only link: validate, drop it into the cookie, strip the URL.
    if token:
        if _lookup_role(token):
            return _sign_in_cookie(token, 30 * DAY, request.url.scheme)
        bad = 1
    return _login_page(bad)

@app.post("/login")
async def login_submit(request: Request):
    from urllib.parse import parse_qs
    form = parse_qs((await request.body()).decode("utf-8", "replace"))
    username = form.get("username", [""])[0].strip()
    password = form.get("password", [""])[0]
    token = form.get("token", [""])[0].strip()
    if username:  # named account -> mint a session token carrying the account's role
        role = _verify_user(username, password)
        if role:
            return _sign_in_cookie(_mint_session(role, username), SESSION_TTL, request.url.scheme)
    elif token and _lookup_role(token):  # direct token (admin bootstrap, or a shared RO token)
        return _sign_in_cookie(token, 30 * DAY, request.url.scheme)
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

def _migrate_targets_identity(c):
    """Re-key the targets table from a global UNIQUE(name) to UNIQUE(agent, name), so two agents (e.g.
    home + an off-site vault) may report a same-named target without clobbering each other's row.
    Idempotent and id-preserving (status.target_id / intents.target_id reference targets.id): runs once
    on a pre-existing DB, and is a no-op once migrated or on a fresh DB created from the new schema."""
    row = c.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='targets'").fetchone()
    if not row or not row[0]:
        return
    if "unique(agent,name)" in re.sub(r"\s+", "", row[0]).lower():
        return  # already (agent,name)-keyed
    # Old rows had a globally-unique name, so no (agent,name) pair can collide - a straight copy is safe.
    c.execute("PRAGMA foreign_keys=OFF")
    c.execute("ALTER TABLE targets RENAME TO _targets_pre_agentkey")
    c.execute("""CREATE TABLE targets (
        id INTEGER PRIMARY KEY, name TEXT NOT NULL, type TEXT NOT NULL, source TEXT, dest TEXT,
        tier TEXT, transport TEXT, location TEXT, cadence TEXT, encrypted INTEGER DEFAULT 0,
        agent TEXT, meta_json TEXT, enabled INTEGER DEFAULT 1, UNIQUE(agent, name))""")
    c.execute("""INSERT INTO targets
        (id,name,type,source,dest,tier,transport,location,cadence,encrypted,agent,meta_json,enabled)
        SELECT id,name,type,source,dest,tier,transport,location,cadence,encrypted,agent,meta_json,enabled
        FROM _targets_pre_agentkey""")
    c.execute("DROP TABLE _targets_pre_agentkey")
    c.commit()

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
                                  ("auth_tokens", "expires_ts", "INTEGER"),
                                  ("agents", "report_interval", "INTEGER"),
                                  ("agents", "agent_version", "TEXT"),
                                  ("agents", "update_requested", "INTEGER DEFAULT 0")]:
                try:
                    c.execute(f"ALTER TABLE {tbl} ADD COLUMN {col} {typ}")
                except sqlite3.OperationalError:
                    pass  # already exists
            _migrate_targets_identity(c)   # re-key targets: UNIQUE(name) -> UNIQUE(agent,name)
            # Nightly recovery manifests (agent-walked "deleted files" per dataset). gz is a gzipped
            # JSON blob and may be NULL (a failed walk records only walked_ts so it isn't retried until
            # the next interval, keeping any prior good manifest).
            c.execute("""CREATE TABLE IF NOT EXISTS recovery_manifests (
                target_id   INTEGER NOT NULL,
                kind        TEXT NOT NULL,
                gz          BLOB,
                entry_count INTEGER,
                raw_bytes   INTEGER,
                walked_ts   INTEGER NOT NULL,
                PRIMARY KEY (target_id, kind))""")
_init_db()
HAS_ADMIN = _seed_tokens() > 0   # false => middleware returns 503 until CAIRN_ADMIN_TOKEN is set

ACK_TTL = int(os.environ.get("CAIRN_ACK_TTL", str(14 * DAY)))  # an acknowledgement lapses after this

def _reason(r):
    """Human reason for a status row: detail reasons, else last_error."""
    d = json.loads(r.get("detail_json") or "{}")
    return ", ".join(d.get("reasons", [])) or (r.get("last_error") or "")

def _sig(sev, reason):
    """Ack fingerprint: severity + reason with digits masked, so tick-by-tick number changes
    (25h -> 26h) still match but a different condition or a worse severity does not."""
    return f"{sev}|" + re.sub(r"\d+", "#", reason or "")

def latest_status(conn):
    """Latest status row per target, joined to target meta, annotated with an `acked` flag."""
    q = """
    SELECT t.name,t.type,t.tier,t.source,t.dest,t.location,t.encrypted,t.agent,s.*
    FROM targets t
    JOIN status s ON s.target_id=t.id
    JOIN (SELECT target_id, MAX(ts) mx FROM status GROUP BY target_id) l
      ON l.target_id=s.target_id AND l.mx=s.ts
    WHERE t.enabled=1
    ORDER BY t.name
    """
    rows = [dict(r) for r in conn.execute(q).fetchall()]
    now = int(time.time())
    acks = {a["target"]: a for a in conn.execute("SELECT target,sig,ts FROM acks").fetchall()}
    for r in rows:
        a = acks.get(r["name"])
        r["acked"] = bool(a and (now - a["ts"]) < ACK_TTL and _sig(r["severity"], _reason(r)) == a["sig"])
    return rows


# ---------------- read-only views ----------------
@app.get("/api/v1/backup/health")
def health():
    with db() as conn:
        rows = latest_status(conn)
        pair_views, paired_keys = pairing(conn, rows)
    counts = {"CRIT": 0, "WARN": 0, "UNKNOWN": 0, "OK": 0}
    worst = "OK"; acked = 0
    for r in rows:
        if (r["agent"], r["name"]) in paired_keys:   # a paired half is counted once, via its pair below
            continue
        if r.get("acked"):                 # acknowledged -> excluded from the alarm rollup
            acked += 1; counts["OK"] += 1; continue
        sev = r["severity"]
        counts[sev] = counts.get(sev, 0) + 1
        if SEV_ORDER.get(sev, 9) < SEV_ORDER.get(worst, 9):
            worst = sev
    for v in pair_views:                   # each guaranteed replication pair counts once, at its worst half
        sev = v["severity"]
        counts[sev] = counts.get(sev, 0) + 1
        if SEV_ORDER.get(sev, 9) < SEV_ORDER.get(worst, 9):
            worst = sev
    now = int(time.time())
    with db() as conn:
        astates = agent_states(conn, now)
    stale_agents = 0
    for a in astates:                      # a silent agent is a real alarm (e.g. vault went dark)
        if a["severity"] != "OK":
            counts[a["severity"]] = counts.get(a["severity"], 0) + 1
            stale_agents += 1
            if SEV_ORDER.get(a["severity"], 9) < SEV_ORDER.get(worst, 9):
                worst = a["severity"]
    return {"severity": worst, "counts": counts, "acked": acked,
            "targets": sum(1 for r in rows if (r["agent"], r["name"]) not in paired_keys) + len(pair_views),
            "agents": len(astates), "stale_agents": stale_agents, "ts": now, "version": CAIRN_VERSION}

@app.get("/api/v1/backup/agents")
def agents_view():
    """Liveness of every enrolled agent (for the dashboard's Agents card + monitoring)."""
    with db() as conn:
        return {"agents": agent_states(conn)}

@app.post("/api/v1/backup/agents/{name}/update")
def request_agent_update(name: str):
    """Queue a self-update for one agent (the dashboard's per-agent Update button). Delivered once on
    the agent's next check-in (in the report response); the agent then runs `install.sh --update`,
    which refreshes its code and restarts it, keeping every existing setting. (auth: middleware/admin)"""
    with db() as conn:
        if not conn.execute("SELECT 1 FROM agents WHERE name=?", (name,)).fetchone():
            raise HTTPException(404, f"no agent '{name}'")
        conn.execute("UPDATE agents SET update_requested=1 WHERE name=?", (name,))
        conn.commit()
    return {"ok": True, "agent": name, "queued": True}

@app.post("/api/v1/backup/acks")
async def ack_target(request: Request):
    """Acknowledge a target's current WARN/CRIT - silence it until the condition changes or ACK_TTL
    lapses. Records a fingerprint of the current severity+reason so a *different* problem re-alerts."""
    body = await _json(request)
    target = body.get("target")
    with db() as conn:
        r = {x["name"]: x for x in latest_status(conn)}.get(target)
        if not r:
            raise HTTPException(404, f"unknown target '{target}'")
        if r["severity"] not in ("WARN", "CRIT"):
            raise HTTPException(400, f"nothing to acknowledge - {target} is {r['severity']}")
        conn.execute("INSERT INTO acks(target,sig,ts,note) VALUES(?,?,?,?) "
                     "ON CONFLICT(target) DO UPDATE SET sig=excluded.sig,ts=excluded.ts,note=excluded.note",
                     (target, _sig(r["severity"], _reason(r)), int(time.time()), body.get("note")))
        conn.commit()
    return {"ok": True, "target": target, "acked": True}

@app.delete("/api/v1/backup/acks/{target}")
def unack_target(target: str):
    with db() as conn:
        n = conn.execute("DELETE FROM acks WHERE target=?", (target,)).rowcount
        conn.commit()
    return {"ok": True, "target": target, "removed": n}

# ---------------- replication pairing + reconciliation of cross-agent overlaps ----------------
def _worst(*sevs):
    return min(sevs, key=lambda s: SEV_ORDER.get(s, 9))   # SEV_ORDER: lower = worse

def _pair_rows(conn):
    """GUARANTEED replication pairs: a zfs-repl whose dest is EXACTLY another agent's zfs-local source.
    Provably the two halves of one set (home sends source -> dest; the other agent monitors dest), so
    they auto-merge into a single card rather than needing the user to reconcile."""
    q = """
      SELECT r.id r_id, r.name r_name, IFNULL(r.agent,'') r_agent, r.source r_src, r.dest ds,
             l.id l_id, l.name l_name, IFNULL(l.agent,'') l_agent
      FROM targets r JOIN targets l ON r.dest = l.source
      WHERE r.type='zfs-repl' AND l.type='zfs-local' AND IFNULL(r.agent,'')<>IFNULL(l.agent,'')
        AND r.enabled=1 AND l.enabled=1 AND r.dest IS NOT NULL AND r.dest<>''
    """
    return [dict(x) for x in conn.execute(q).fetchall()]

def pairing(conn, rows):
    """Match guaranteed pairs to their two latest-status rows. Returns (views, paired_keys): a view is
    {'r':R_row,'l':L_row,'dataset':ds,'severity':worst}; paired_keys is the (agent,name) set in a pair."""
    by = {(r["agent"], r["name"]): r for r in rows}
    views = []; keys = set()
    for p in _pair_rows(conn):
        R = by.get((p["r_agent"], p["r_name"])); L = by.get((p["l_agent"], p["l_name"]))
        if R and L:
            # The repl half (home) can't compute repl-lag once the dest lives on the other agent, so it
            # reports UNKNOWN structurally - defer the pair's severity to the off-site copy (L), which is
            # the meaningful end-to-end 3-2-1 signal (it goes stale if the source stops snapshotting OR
            # the pull stalls). Only when the home half has a REAL severity do we take the worse of the two.
            sev = L["severity"] if R["severity"] == "UNKNOWN" else _worst(R["severity"], L["severity"])
            views.append({"r": R, "l": L, "dataset": p["ds"], "severity": sev})
            keys.add((p["r_agent"], p["r_name"])); keys.add((p["l_agent"], p["l_name"]))
    return views, keys

def find_overlaps(conn):
    """AMBIGUOUS overlaps for the reconcile modal: the same target NAME reported by two different agents
    that are NOT a guaranteed pair (guaranteed pairs auto-merge, so they are excluded here). Excludes
    pairs the user chose to keep."""
    paired = set()
    for p in _pair_rows(conn):
        paired.add((p["r_agent"], p["r_name"])); paired.add((p["l_agent"], p["l_name"]))
    dismissed = {r[0] for r in conn.execute("SELECT pair FROM reconcile_dismissed")}
    # ONLY dataset-replication targets can be two views of one replicated dataset. Per-host monitors
    # (smart, kernel-errors, zfs-events, borg, schedules, backupninja) legitimately share a NAME across
    # hosts - e.g. smart:sda on home and on the vault are two DIFFERENT physical disks - so they must
    # never be offered to reconcile (retiring one would drop a real, unrelated target).
    byname = {}
    for r in conn.execute("SELECT id,name,IFNULL(agent,'') agent,type,source,dest FROM targets "
                          "WHERE enabled=1 AND type IN ('zfs-repl','zfs-local')"):
        byname.setdefault(r["name"], []).append(dict(r))
    def _paths(t):   # the dataset path(s) a target references
        return {p for p in (t.get("source"), t.get("dest")) if p}
    out = []
    for name, ts in byname.items():
        if len({t["agent"] for t in ts}) < 2:
            continue
        if all((t["agent"], t["name"]) in paired for t in ts):   # fully handled by auto-pairing
            continue
        a = ts[0]; b = next((t for t in ts if t["agent"] != a["agent"]), None)
        if not b:
            continue
        # Require the two to actually reference the SAME dataset - otherwise two hosts that happen to
        # name a pool the same (e.g. both 'tank') would be matched as if one replicated the other.
        if not (_paths(a) & _paths(b)):
            continue
        pair = f"{a['agent']}:{a['name']}|{b['agent']}:{b['name']}"
        if pair in dismissed:
            continue
        out.append({"pair": pair, "dataset": a.get("source") or a.get("dest") or name,
                    "replication": {"id": a["id"], "name": a["name"], "agent": a["agent"]},
                    "monitor": {"id": b["id"], "name": b["name"], "agent": b["agent"]}})
    return out

@app.get("/api/v1/backup/reconcile")
def reconcile_list():
    with db() as conn:
        return {"overlaps": find_overlaps(conn)}

@app.post("/api/v1/backup/reconcile")
async def reconcile_act(request: Request):
    b = await request.json()
    action = b.get("action")
    with db() as conn:
        if action == "retire":                       # persistently drop one side (survives re-ingest)
            tid = int(b.get("target_id", 0))
            row = conn.execute("SELECT agent,name FROM targets WHERE id=?", (tid,)).fetchone()
            if not row:
                raise HTTPException(404, "unknown target")
            conn.execute("INSERT OR IGNORE INTO target_retired(agent,name,ts) VALUES(?,?,?)",
                         (row["agent"], row["name"], int(time.time())))
            conn.execute("UPDATE targets SET enabled=0 WHERE id=?", (tid,))
            conn.commit()
            return {"ok": True, "retired": {"agent": row["agent"], "name": row["name"]}}
        if action == "dismiss":                      # "keep both": stop warning about this pair
            pair = b.get("pair", "")
            if not pair:
                raise HTTPException(400, "dismiss needs a pair")
            conn.execute("INSERT OR IGNORE INTO reconcile_dismissed(pair,ts) VALUES(?,?)",
                         (pair, int(time.time())))
            conn.commit()
            return {"ok": True, "dismissed": pair}
    raise HTTPException(400, "action must be 'retire' or 'dismiss'")


def _retired_rows(conn):
    """Currently-hidden targets, joined back to their target row for id/type - for the Hidden pane."""
    return [dict(r) for r in conn.execute(
        "SELECT t.id, t.agent, t.name, t.type FROM target_retired r "
        "JOIN targets t ON t.agent=r.agent AND t.name=r.name ORDER BY t.agent, t.name").fetchall()]


@app.post("/api/v1/backup/targets/{tid}/retire")
def hide_target(tid: int):
    """Stop monitoring one target (the per-card Hide button). Persistent: a `target_retired` row keeps
    it disabled even while its agent keeps reporting it, so it stays hidden until explicitly unhidden."""
    with db() as conn:
        row = conn.execute("SELECT agent,name FROM targets WHERE id=?", (tid,)).fetchone()
        if not row:
            raise HTTPException(404, "unknown target")
        conn.execute("INSERT OR IGNORE INTO target_retired(agent,name,ts) VALUES(?,?,?)",
                     (row["agent"], row["name"], int(time.time())))
        conn.execute("UPDATE targets SET enabled=0 WHERE id=?", (tid,))
        conn.commit()
    return {"ok": True, "hidden": {"agent": row["agent"], "name": row["name"]}}


@app.post("/api/v1/backup/targets/{tid}/unretire")
def unhide_target(tid: int):
    """Restore a hidden target (the Hidden pane's Unhide button). Re-enables it; the agent's next
    report confirms it and it reappears on the board."""
    with db() as conn:
        row = conn.execute("SELECT agent,name FROM targets WHERE id=?", (tid,)).fetchone()
        if not row:
            raise HTTPException(404, "unknown target")
        conn.execute("DELETE FROM target_retired WHERE agent=? AND name=?", (row["agent"], row["name"]))
        conn.execute("UPDATE targets SET enabled=1 WHERE id=?", (tid,))
        conn.commit()
    return {"ok": True, "shown": {"agent": row["agent"], "name": row["name"]}}

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
        # A dataset's replica is OFF-SITE when its dest lives on a DIFFERENT agent (a remote vault).
        # That's exactly a guaranteed pair (home zfs-repl -> vault zfs-local), so reuse that detection
        # instead of relying on a `location` flag nobody sets. Keyed by the home (sending) half.
        offsite_keys = {(p["r_agent"], p["r_name"]) for p in _pair_rows(conn)}
    tiera = [r for r in rows if r["type"] == "zfs-repl" and (r["tier"] == "A")]
    cards = []
    for r in tiera:
        src_pool = (r["source"] or "").split("/")[0]
        dst_pool = (r["dest"] or "").split("/")[0]
        pools = {p for p in (src_pool, dst_pool) if p}
        # off-site if the dest is monitored by another agent (the vault) OR flagged location=offsite.
        offsite = 1 if (r.get("location") == "offsite"
                        or ((r.get("agent") or "", r["name"]) in offsite_keys)) else 0
        onsite = len(pools) - offsite
        copies = len(pools)
        card = dict(name=r["name"], copies=copies, media=len(pools), onsite=onsite,
                    offsite=offsite,
                    pass_321=(copies >= 3 and len(pools) >= 2 and offsite >= 1),
                    note="")
        if offsite == 0:
            card["note"] = "NO off-site copy - no remote vault holds this dataset yet"
        elif copies < 3:
            card["note"] = "off-site copy present; needs a 3rd copy for full 3-2-1"
        cards.append(card)
    overall = all(c["pass_321"] for c in cards) if cards else False
    return {"pass": overall, "cards": cards,
            "explain": "3-2-1 = >=3 copies, >=2 media, >=1 off-site. A dataset counts as off-site once "
                       "a remote vault holds its replica (a different agent reports the destination)."}

@app.get("/api/v1/backup/coverage-gap")
def coverage_gap():
    """Things backed up by nothing / not snapshotted / no off-site."""
    with db() as conn:
        rows = latest_status(conn)
        offsite_keys = {(p["r_agent"], p["r_name"]) for p in _pair_rows(conn)}  # dest held by a vault
    gaps = []
    for r in rows:
        d = json.loads(r.get("detail_json") or "{}")
        reasons = d.get("reasons", [])
        # "no snapshots" on a zfs-repl really means its REMOTE dest couldn't be read (e.g. iwolf moved
        # to the vault); the source snapshot age proves the data IS snapshotted. Only flag a genuine
        # absence of SOURCE snapshots, so a replicated dataset isn't mislabeled "not snapshotted".
        if "no snapshots" in reasons and r.get("snap_age_src_s") is None:
            gaps.append(dict(name=r["name"], gap="not snapshotted", severity=r["severity"]))
        has_offsite = (r.get("location") == "offsite"
                       or ((r.get("agent") or "", r["name"]) in offsite_keys))
        if r["type"] == "zfs-repl" and not has_offsite:
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
ALLOWED_ACTIONS = {"snapshot", "sync", "scrub", "pull",
                   "recover-points", "recover-search", "recover-deleted", "restore",
                   "recover-walk"}  # on-demand deleted-files walk that FILLS the stored manifest
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

# ---- agent liveness (dead-man's-switch for remote agents e.g. the off-site vault) ----
AGENT_STALE_FACTOR = int(os.environ.get("CAIRN_AGENT_STALE_FACTOR", "3"))     # missed N cycles -> WARN
AGENT_MISS_FACTOR = int(os.environ.get("CAIRN_AGENT_MISS_FACTOR", "8"))       # missed N cycles -> CRIT
AGENT_STALE_FLOOR = int(os.environ.get("CAIRN_AGENT_STALE_FLOOR", "600"))     # min WARN threshold (s)

def _ago_s(s):
    s = int(s)
    if s < 90:     return f"{s}s"
    if s < 5400:   return f"{s//60}m"
    if s < 172800: return f"{s//3600}h"
    return f"{s//86400}d"

def agent_states(conn, now=None):
    """Per-agent liveness: OK / WARN (missed a few report cycles) / CRIT (long silent).
    Threshold scales off each agent's own reported interval so a slow vault and a 120s
    local agent are both judged fairly."""
    now = now or int(time.time())
    out = []
    for a in conn.execute(
            "SELECT name,can_execute,last_report_ts,report_interval,agent_version FROM agents ORDER BY name").fetchall():
        due = a["report_interval"] or 120
        stale_after = max(due * AGENT_STALE_FACTOR, AGENT_STALE_FLOOR)
        miss_after = max(due * AGENT_MISS_FACTOR, AGENT_STALE_FLOOR * 2)
        last = a["last_report_ts"] or 0
        age = now - last
        sev = "CRIT" if age >= miss_after else "WARN" if age >= stale_after else "OK"
        ver = a["agent_version"]
        out.append(dict(name=a["name"], can_execute=bool(a["can_execute"]), last_report_ts=last,
                        report_interval=due, age_s=age, severity=sev, stale_after=stale_after,
                        version=ver, outdated=bool(ver and ver != CAIRN_VERSION),
                        server_version=CAIRN_VERSION))
    return out

def _reap_agents(conn, now):
    """Alert on any agent that has gone silent past its threshold. Runs on every report (the live
    local agent's cadence drives it); dispatch_alert's per-key cooldown prevents repeat spam."""
    for a in agent_states(conn, now):
        if a["severity"] in ("WARN", "CRIT"):
            dispatch_alert(a["severity"], f"agent '{a['name']}' not reporting",
                           f"last check-in {_ago_s(a['age_s'])} ago "
                           f"(expects every {_ago_s(a['report_interval'])})",
                           f"agent-stale-{a['name']}")

@app.post("/api/v1/backup/report")
async def report(request: Request):
    """An agent reports its host's status. Upserts targets (ownership = reporting agent) +
    inserts status rows, then dispatches WARN/CRIT alerts centrally. (auth: middleware)"""
    payload = await _json(request)
    agent = payload.get("agent", "unknown")
    now = int(payload.get("ts") or time.time())
    can_exec = 1 if payload.get("can_execute") else 0
    interval = int(payload.get("interval") or 0) or None   # agent's own poll cadence (for staleness)
    version = (payload.get("version") or "").strip() or None   # agent's running cairn version
    statuses = payload.get("statuses", [])
    alerts = []
    with db() as conn:
        conn.execute("""INSERT INTO agents(name,can_execute,last_report_ts,report_interval,agent_version)
            VALUES(?,?,?,?,?)
            ON CONFLICT(name) DO UPDATE SET can_execute=excluded.can_execute,
            last_report_ts=excluded.last_report_ts,
            report_interval=COALESCE(excluded.report_interval, agents.report_interval),
            agent_version=COALESCE(excluded.agent_version, agents.agent_version)""",
            (agent, can_exec, now, interval, version))
        for s in statuses:
            name = s.get("name")
            if not name:
                continue
            tid = conn.execute("""INSERT INTO targets(name,type,source,dest,tier,location,encrypted,agent,enabled)
                VALUES(?,?,?,?,?,?,?,?,1)
                ON CONFLICT(agent,name) DO UPDATE SET type=excluded.type,source=excluded.source,dest=excluded.dest,
                  tier=excluded.tier,location=excluded.location,encrypted=excluded.encrypted,agent=excluded.agent,
                  enabled=1
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
                alerts.append((s["severity"], f"{name}: {s['severity']}", f"[{agent}] {why}".strip(), f"cairn-{name}"))
        # Authoritative report: retire (disable) targets THIS agent used to own but no longer reports,
        # so removing a target from targets.yaml - or reassigning it to another agent - doesn't leave a
        # ghost row on the board. A re-reported target is re-enabled above. Guard: only when the agent
        # actually reported something; an empty report is a collection hiccup, not "all targets gone".
        reported = [s.get("name") for s in statuses if s.get("name")]
        if reported:
            ph = ",".join("?" * len(reported))
            conn.execute(f"UPDATE targets SET enabled=0 WHERE agent=? AND enabled=1 AND name NOT IN ({ph})",
                         [agent, *reported])
        # user-retired targets (reconciled away on the dashboard) stay disabled even though their agent
        # still reports them - otherwise the upsert above would re-enable them every cycle.
        conn.execute("UPDATE targets SET enabled=0 WHERE id IN "
                     "(SELECT t.id FROM targets t JOIN target_retired r ON t.agent=r.agent AND t.name=r.name)")
        conn.execute("DELETE FROM status WHERE ts < ?", (now - 90 * DAY,))
        # One-shot self-update signal: if an operator pressed Update for this agent, tell it once (in
        # this response) and clear the flag so it doesn't loop.
        row = conn.execute("SELECT update_requested FROM agents WHERE name=?", (agent,)).fetchone()
        do_update = bool(row and row["update_requested"])
        if do_update:
            conn.execute("UPDATE agents SET update_requested=0 WHERE name=?", (agent,))
        conn.commit()
        _reap_agents(conn, now)   # dead-man's-switch: alert on any OTHER agent gone silent
    for a in alerts:
        dispatch_alert(*a)
    return {"ok": True, "ingested": len(statuses), "update": do_update}

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

# Recovery actions (httm/zfs listing + copy-only restore). Defined here so intent_result can size the
# stored result: a listing must be kept whole to stay parseable, everything else stays compact.
RECOVER_ACTIONS = {"recover-points", "recover-search", "recover-deleted", "restore"}
# How long a recovery LISTING is reused before a click re-runs the scan. Snapshot history changes only
# when snapshots are created/pruned, so a few minutes is safe and spares the slow httm walk. Override
# with CAIRN_RECOVER_CACHE_TTL (seconds); 0 disables reuse.
RECOVER_CACHE_TTL = int(os.environ.get("CAIRN_RECOVER_CACHE_TTL", "600"))
# How stale a per-dataset "deleted files" manifest may get before the agent re-walks it. The agent polls
# for due datasets each loop but only walks those older than this, so a nightly cadence is the default.
RECOVER_WALK_INTERVAL = int(os.environ.get("CAIRN_RECOVER_WALK_INTERVAL", "86400"))

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
        # Recovery listings can be large (many snapshots / a recursive deleted scan); store them intact
        # so the browser can parse them. Other actions keep the small cap that bounds DB growth.
        cap = 262144 if (r and r["action"] in RECOVER_ACTIONS) else 4000
        conn.execute("UPDATE intents SET state=?,result=?,result_ts=? WHERE id=?",
                     (state, json.dumps(body)[:cap], int(time.time()), iid))
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
# RECOVER_ACTIONS is defined above intent_result (it sizes the stored result).

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
    agent_sel = body.get("agent")   # disambiguate a name shared by two agents (e.g. a replication pair)
    with db() as conn:
        # Targets are identified per (agent, name). A by-name lookup is enough for a unique name; pass
        # `agent` to scope it when two agents report the same name (a replication pair: home's zfs-repl
        # and the vault's zfs-local both named e.g. "Pics"). "pull" MUST be scoped to the vault half.
        if agent_sel:
            r = conn.execute("SELECT id,type,source,dest,enabled,agent FROM targets WHERE name=? AND agent=?",
                             (target, agent_sel)).fetchone()
        else:
            r = conn.execute("SELECT id,type,source,dest,enabled,agent FROM targets WHERE name=? "
                             "ORDER BY (agent IS NULL), id LIMIT 1", (target,)).fetchone()
        if not r or not r["enabled"]:
            raise HTTPException(404, f"unknown/disabled target '{target}'"
                                     + (f" for agent '{agent_sel}'" if agent_sel else ""))
        if action == "sync" and r["type"] != "zfs-repl":
            raise HTTPException(400, "sync only valid for zfs-repl targets")
        if action == "scrub" and r["type"] != "zfs-local":
            raise HTTPException(400, "scrub only valid for zfs-local targets")
        if action == "recover-walk" and r["type"] != "zfs-local":
            raise HTTPException(400, "recover-walk only valid for zfs-local targets")
        if action == "pull" and r["type"] != "zfs-local":
            raise HTTPException(400, "pull only valid for a zfs-local replica (the off-site copy)")
        if (action == "snapshot" or action in RECOVER_ACTIONS or action == "recover-walk") and not r["source"]:
            raise HTTPException(400, "action requires a dataset-backed target")
        if action == "restore" and not opts.get("version"):
            raise HTTPException(400, "restore requires a 'version' (snapshot file path from a search)")
        if not r["agent"]:
            raise HTTPException(409, f"no agent has reported target '{target}' yet - can't route it")
        cap = conn.execute("SELECT can_execute FROM agents WHERE name=?", (r["agent"],)).fetchone()
        if not cap or not cap["can_execute"]:
            raise HTTPException(409, f"target '{target}' is owned by report-only agent "
                                     f"'{r['agent']}' (CAIRN_CAN_EXECUTE=0) - no executor to run this")
        # Recovery LISTINGS look back at slowly-changing snapshot history and the httm scan is the slow
        # part, so reuse a recent completed result for the same target+action+path instead of re-running
        # it (skips the agent round-trip entirely; shared across viewers). ?refresh forces a fresh scan.
        # Restore is never cached - it copies files - and dry-runs aren't reused.
        if (action in RECOVER_ACTIONS and action != "restore"
                and not opts.get("dryrun") and not body.get("refresh")):
            cutoff = int(time.time()) - RECOVER_CACHE_TTL
            want_path = opts.get("path") or ""
            for c in conn.execute(
                    "SELECT id, opts, result_ts FROM intents WHERE target_id=? AND action=? "
                    "AND state='done' AND result_ts>=? ORDER BY result_ts DESC LIMIT 25",
                    (r["id"], action, cutoff)).fetchall():
                try:
                    same = (json.loads(c["opts"] or "{}").get("path") or "") == want_path
                except (ValueError, TypeError):
                    same = False
                if same:
                    return {"id": c["id"], "state": "done", "target": target, "action": action,
                            "agent": r["agent"], "opts": opts, "cached": True,
                            "cached_ts": c["result_ts"]}
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

# ---------------- recovery manifests: agent-walked "deleted files" cache per dataset --------------
@app.get("/api/v1/backup/agent/recovery-due")
def recovery_due(agent: str):
    """Datasets this agent should (re)walk: enabled zfs-local targets whose deleted-manifest is missing
    or older than RECOVER_WALK_INTERVAL. Missing ones first, then the stalest."""
    cutoff = int(time.time()) - RECOVER_WALK_INTERVAL
    with db() as conn:
        rows = conn.execute(
            "SELECT t.name, t.source FROM targets t "
            "LEFT JOIN recovery_manifests m ON m.target_id=t.id AND m.kind='deleted' "
            "WHERE t.agent=? AND t.enabled=1 AND t.type='zfs-local' AND t.source IS NOT NULL "
            "AND (m.walked_ts IS NULL OR m.walked_ts < ?) "
            "ORDER BY (m.walked_ts IS NULL) DESC, m.walked_ts ASC", (agent, cutoff)).fetchall()
    return {"targets": [dict(r) for r in rows]}

@app.post("/api/v1/backup/agent/recovery-manifest")
async def recovery_manifest_push(request: Request):
    """An agent pushes a freshly-walked manifest (gzipped JSON, base64). A failed walk (ok=false) records
    only walked_ts so it isn't retried until the next interval, preserving any prior good manifest."""
    body = await _json(request)
    target = body.get("target"); kind = body.get("kind") or "deleted"
    now = int(time.time())
    with db() as conn:
        r = conn.execute("SELECT id FROM targets WHERE name=? ORDER BY (agent IS NULL), id LIMIT 1",
                         (target,)).fetchone()
        if not r:
            raise HTTPException(404, f"unknown target '{target}'")
        if not body.get("ok"):
            conn.execute(
                "INSERT INTO recovery_manifests(target_id,kind,gz,entry_count,raw_bytes,walked_ts) "
                "VALUES(?,?,NULL,NULL,NULL,?) ON CONFLICT(target_id,kind) DO UPDATE SET walked_ts=excluded.walked_ts",
                (r["id"], kind, now))
            conn.commit()
            return {"ok": True, "stored": False}
        gz = _b64.b64decode(body.get("gz_b64") or "")
        conn.execute(
            "INSERT INTO recovery_manifests(target_id,kind,gz,entry_count,raw_bytes,walked_ts) "
            "VALUES(?,?,?,?,?,?) ON CONFLICT(target_id,kind) DO UPDATE SET "
            "gz=excluded.gz, entry_count=excluded.entry_count, raw_bytes=excluded.raw_bytes, "
            "walked_ts=excluded.walked_ts",
            (r["id"], kind, gz, int(body.get("entry_count") or 0), int(body.get("raw_bytes") or 0),
             int(body.get("walked_ts") or now)))
        conn.commit()
    return {"ok": True, "stored": True}

@app.get("/api/v1/backup/recovery-manifest")
def recovery_manifest_get(target: str, kind: str = "deleted"):
    """The dashboard reads a stored manifest (decompressed) to render the recovery browser instantly."""
    with db() as conn:
        r = conn.execute("SELECT id FROM targets WHERE name=? ORDER BY (agent IS NULL), id LIMIT 1",
                         (target,)).fetchone()
        if not r:
            raise HTTPException(404, f"unknown target '{target}'")
        m = conn.execute("SELECT gz, entry_count, raw_bytes, walked_ts FROM recovery_manifests "
                         "WHERE target_id=? AND kind=?", (r["id"], kind)).fetchone()
    if not m or m["gz"] is None:
        return {"present": False}
    try:
        manifest = json.loads(gzip.decompress(m["gz"]).decode() or "{}")
    except Exception:
        manifest = {}
    return {"present": True, "walked_ts": m["walked_ts"], "entry_count": m["entry_count"],
            "raw_bytes": m["raw_bytes"], "manifest": manifest}

PREVIEWABLE = {"snapshot", "sync", "scrub", "recover-points"}  # build_command touches no ZFS for these

@app.get("/api/v1/backup/actions/preview")
def preview_action(target: str, action: str, create_snapshot: bool = True, path: str = None):
    """Return the exact argv a click WILL run, rebuilt from the stored target row - so the confirm
    dialog can show it. Read-only: only actions whose build_command has no side effects are previewed;
    others resolve on the agent at run time (path→mountpoint needs a live ZFS read)."""
    with db() as conn:
        r = conn.execute("SELECT name,type,source,dest,encrypted FROM targets WHERE name=?", (target,)).fetchone()
    if not r:
        raise HTTPException(404, f"unknown target '{target}'")
    if action not in PREVIEWABLE:
        return {"cmd": None, "note": "built on the agent at run time"}
    t = {"name": r["name"], "type": r["type"], "source": r["source"], "dest": r["dest"],
         "encrypted": bool(r["encrypted"])}   # so encrypted targets preview as raw (-w) sends
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
    # agents get enroll secrets; a viewer gets a shareable read-only 'ui' token (no expiry).
    kind = body.get("kind") or {"admin": "admin", "viewer": "ui"}.get(role, "enroll")
    if role not in ("admin", "agent", "viewer"):
        raise HTTPException(400, "role must be 'admin', 'viewer', or 'agent'")
    if kind not in ("admin", "enroll", "access", "ui"):
        raise HTTPException(400, "kind must be admin | enroll | access | ui")
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
    hint = ("enrollment secret - put on the agent as CAIRN_ENROLL_SECRET; it mints short-lived "
            "access tokens") if kind == "enroll" else (
            "read-only share token - hand it out, or send a link to /login?token=<this>"
            if kind == "ui" else "SAVE NOW - only its hash is stored")
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
          "snapper": (0, "Snapshots (snapper)"),
          "rclone": (1, "Off-site (rclone)"),
          "zfs-repl": (2, "Replication (ZFS)"),
          "borg-repo": (3, "Archive repos (borg)"),
          "restic": (3, "Archive repos (restic)"),
          "backupninja-handler": (4, "Scheduled jobs"),
          "schedules": (4, "Scheduled jobs"),
          "smart": (5, "Disk health (SMART)"),
          "kernel-errors": (6, "Hardware watch"),
          "zfs-events": (6, "Hardware watch")}

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
    ("ACK’D", "A known warning you've acknowledged - silenced (counts as healthy in the rollup) until "
              "the condition changes or the acknowledgement lapses. Distinct from UNKNOWN. Click to clear."),
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
  --ok:#1c8a63; --warn:#c07d21; --crit:#c1443a; --unk:#8090a0; --ack:#5b7fa6;
}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){
  --bg:#0d1621; --surf:#111e2c; --ink:#dbe6f2; --mut:#8496a8; --line:#213347;
  --acc:#4d9fff; --acc2:#9cc6f5; --accsoft:#16304b; --rail:#0e1a27; --heatbg:#1a2b3c;
  --ok:#34c98a; --warn:#e0a53a; --crit:#ff5b51; --unk:#7d90a4; --ack:#6d97c4;
}}
:root[data-theme=dark]{
  --bg:#0d1621; --surf:#111e2c; --ink:#dbe6f2; --mut:#8496a8; --line:#213347;
  --acc:#4d9fff; --acc2:#9cc6f5; --accsoft:#16304b; --rail:#0e1a27; --heatbg:#1a2b3c;
  --ok:#34c98a; --warn:#e0a53a; --crit:#ff5b51; --unk:#7d90a4; --ack:#6d97c4;
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
.warmbanner{margin:12px 16px 0;padding:9px 13px;border-radius:9px;font-size:12.5px;line-height:1.45;color:var(--ink);background:color-mix(in srgb,var(--warn) 14%,var(--surf));border:1px solid color-mix(in srgb,var(--warn) 45%,var(--line))}
.agenthdr{margin:18px 2px 7px;font-size:12px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--mut);display:flex;align-items:center;gap:8px}
.agenthdr:first-child{margin-top:4px}
.agdot{width:7px;height:7px;border-radius:50%;background:var(--ack);flex:none}
.agenttabs{display:flex;gap:12px;flex-wrap:wrap;margin:0 0 18px}
.agenttab{cursor:pointer;flex:1 1 230px;min-width:190px;transition:opacity .15s,box-shadow .15s;user-select:none}
.agenttab:not(.active){opacity:.58}
.agenttab:hover{opacity:1}
.agenttab.active{box-shadow:inset 0 0 0 2px var(--acc)}
.agenttab .verbtn{cursor:pointer}
.agentpane{display:block}
.reconbanner{margin:12px 16px 0;padding:9px 13px;border-radius:9px;font-size:12.5px;line-height:1.45;color:var(--ink);background:color-mix(in srgb,var(--warn) 16%,var(--surf));border:1px solid color-mix(in srgb,var(--warn) 50%,var(--line));display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.reconbtn{margin-left:auto;border:1px solid var(--line);background:var(--surf);color:var(--ink);border-radius:7px;padding:5px 12px;font-size:12px;cursor:pointer}
.reconbtn:hover{border-color:var(--warn)}
[hidden]{display:none!important}
.modalwrap{position:fixed;inset:0;background:rgba(0,0,0,.5);display:flex;align-items:center;justify-content:center;z-index:50;padding:20px}
.modalbox{background:var(--surf);border:1px solid var(--line);border-radius:12px;max-width:640px;width:100%;max-height:80vh;overflow:auto;box-shadow:0 12px 40px rgba(0,0,0,.4)}
.modalhd{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:1px solid var(--line);font-weight:600}
.modalx{border:0;background:none;color:var(--mut);font-size:22px;line-height:1;cursor:pointer}
.modalbody{padding:14px 18px}
.reconrow{padding:11px 0;border-bottom:1px solid var(--line)}
.reconrow:last-child{border-bottom:0}
.recondesc small{display:block;color:var(--mut);margin-top:4px;font-size:11.5px}
.reconacts{margin-top:9px;display:flex;gap:8px;flex-wrap:wrap}
.reconacts button{border:1px solid var(--line);background:var(--surf);color:var(--ink);border-radius:7px;padding:5px 11px;font-size:12px;cursor:pointer}
.reconacts button:hover{border-color:var(--ack)}
.reconacts button:disabled{opacity:.5;cursor:default}
/* recovery browser (Points / Versions / Deleted + Restore) */
.modalhd .rechdbtns{display:flex;align-items:center;gap:10px}
.recrefresh{border:1px solid var(--line);background:var(--surf);color:var(--acc);border-radius:7px;padding:4px 11px;font-size:11px;font-weight:600;cursor:pointer}
.recrefresh:hover{border-color:var(--acc)}
.recnote{margin:0 0 12px;font-size:12px;color:var(--mut);line-height:1.5}
.recnote code{font-family:"Roboto Mono",monospace;font-size:11px;background:var(--heatbg);padding:1px 5px;border-radius:4px}
.reccached{font-size:11px;color:var(--mut);margin:0 0 12px}
.rectblwrap{overflow-x:auto}
.rectbl{width:100%;border-collapse:collapse;font-size:12px}
.rectbl th{text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut);font-weight:700;padding:0 8px 6px;border-bottom:1px solid var(--line);white-space:nowrap}
.rectbl td{padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:middle}
.rectbl tbody tr:last-child td,.rectbl tr:last-child td{border-bottom:0}
.recsnap{font-family:"Roboto Mono",monospace}
.recsize,.recage{color:var(--mut);font-variant-numeric:tabular-nums;white-space:nowrap}
.recact{text-align:right;white-space:nowrap}
.recfile{margin-bottom:18px}
.recfp{font-family:"Roboto Mono",monospace;font-size:11px;color:var(--mut);word-break:break-all;margin-bottom:6px}
.recrestore{border:1px solid var(--line);background:var(--surf);color:var(--acc);border-radius:7px;padding:4px 11px;font-size:11px;font-weight:600;cursor:pointer}
.recrestore:hover{border-color:var(--acc)}
.recrestore:disabled{opacity:.5;cursor:default}
.reclive{font-size:10px;color:var(--mut);text-transform:uppercase;letter-spacing:.04em}
.recok{color:var(--ok);font-size:11px;word-break:break-all}
.recfail{color:var(--crit);font-size:11px;word-break:break-all}
.recwait{color:var(--mut);font-size:11px}
.recpre{white-space:pre-wrap;word-break:break-word;font-size:11px;max-height:40vh;overflow:auto;background:var(--heatbg);padding:10px;border-radius:8px}
.card.pair .pbadge{font-size:9.5px;text-transform:uppercase;letter-spacing:.04em;color:var(--mut);border:1px solid var(--line);border-radius:5px;padding:1px 6px;margin-right:8px}
.picn{width:15px;height:15px;vertical-align:-2px;margin-right:7px;color:var(--mut)}
.phalves{display:flex;flex-direction:column;gap:10px;margin-top:11px}
.phalf{display:flex;gap:9px;align-items:flex-start}
.phalf .pd{width:8px;height:8px;border-radius:50%;margin-top:4px;flex:none}
.phinfo{font-size:12px}
.phinfo .psev,.phinfo .prole{font-size:10.5px;color:var(--mut)}
.phinfo small{display:block;color:var(--mut);margin-top:2px;font-size:11px;line-height:1.35}
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
.card.ack{border-top-color:var(--ack);opacity:.86}
.card.ack .cs{color:var(--ack)}
.ackbtn{appearance:none;margin-top:11px;font:600 11.5px/1 "Red Hat Text",sans-serif;
  border:1px solid var(--line);background:var(--surf);color:var(--mut);border-radius:7px;padding:7px 10px;cursor:pointer}
.ackbtn:hover{color:var(--ink)}
.ackbtn.on{color:var(--ack);border-color:var(--ack)}
.card .ch{display:flex;align-items:center;justify-content:space-between;gap:8px}
.card .cn{font-family:"Red Hat Display";font-weight:700;font-size:15px;word-break:break-word}
.card .chr{display:inline-flex;align-items:center;gap:8px;flex:none}
.card .cbusy{display:none;width:8px;height:8px;border-radius:50%;background:var(--warn);
  animation:apulse 1.1s ease-in-out infinite}
.card.busy .cbusy{display:inline-block}
.card .scrubprog{margin-top:12px}
.card .scrubbar{height:6px;border-radius:4px;background:var(--line,rgba(128,128,128,.22));overflow:hidden}
.card .scrubbar>span{display:block;height:100%;background:var(--acc);border-radius:4px;transition:width .6s ease}
.card .scrublbl{font-family:"Roboto Mono";font-size:11px;color:var(--mut);margin-top:5px}
button.scrubbtn[disabled]{opacity:.6;cursor:progress}
.card .hidebtn{margin-top:10px;font-size:10.5px;color:var(--mut);background:none;border:0;padding:2px 0;
  cursor:pointer;text-decoration:underline;text-underline-offset:2px;opacity:.7}
.card .hidebtn:hover{opacity:1;color:var(--ink)}
.hidpane{margin-top:22px}
.hidpane .hidrow{display:flex;align-items:center;justify-content:space-between;gap:12px;
  padding:9px 4px;border-bottom:1px solid var(--line)}
.hidpane .hidrow:last-child{border-bottom:0}
.hidpane .hidn{font:12.5px/1.4 "Roboto Mono",monospace;color:var(--ink)}
.hidpane .hida{color:var(--mut);margin-left:10px;font-size:10.5px}
.hidpane .unhidebtn{flex:none;font-size:11px;font-weight:600;cursor:pointer;color:var(--acc);
  background:none;border:1px solid var(--line);border-radius:7px;padding:4px 11px;transition:border-color .15s}
.hidpane .unhidebtn:hover{border-color:var(--acc)}
.card .cs{font-size:10.5px;font-weight:700;letter-spacing:.05em;flex:none}
.card.ok .cs{color:var(--ok)} .card.warn .cs{color:var(--warn)} .card.crit .cs{color:var(--crit)} .card.unk .cs{color:var(--unk)}
.card.ack .cs{color:var(--ack)}
.card .src{font-family:"Roboto Mono";font-size:11.5px;color:var(--mut);margin-top:3px;overflow-wrap:anywhere;word-break:normal}
.card .row{display:flex;gap:16px;margin-top:12px;flex-wrap:wrap}
.card .mv{font-family:"Roboto Mono";font-weight:500;font-size:16px}
.card .ml{font-size:10px;letter-spacing:.06em;text-transform:uppercase;color:var(--mut)}
.card .why{color:var(--mut);font-size:12px;margin-top:11px;line-height:1.4}
.card .c321{display:inline-flex;align-items:center;gap:4px;margin-top:10px}
.card .c321l{font-size:9px;letter-spacing:.09em;text-transform:uppercase;color:var(--mut);font-weight:700;margin-right:4px}
.card .c321p{width:17px;height:17px;border-radius:5px;display:grid;place-items:center;
  font:800 11px/1 "Roboto Mono",monospace;color:#fff;cursor:default}
.card .c321p.met{background:var(--ok)} .card .c321p.unmet{background:var(--crit)}
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
.chist[hidden]{display:none}   /* a class selector's display: beats the UA [hidden] rule; force it */
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
/* scheduled-job card: backs-up + schedule + next/last run */
.jsched{margin-top:11px;display:flex;flex-direction:column;gap:5px}
.jrow{display:grid;grid-template-columns:62px 1fr;gap:9px;align-items:baseline}
.jrow .jk{font-size:9px;letter-spacing:.06em;text-transform:uppercase;color:var(--mut);font-weight:700}
.jrow .jv{color:var(--ink);font-family:"Roboto Mono",monospace;font-size:11.5px;word-break:break-word;line-height:1.4}
.jrun{color:var(--mut);font-family:"Roboto Mono",monospace;font-size:11px;margin-top:2px}
.logct{font-size:9px;font-weight:700;color:var(--mut);background:var(--rail);border:1px solid var(--line);
  border-radius:20px;padding:1px 6px;margin-left:4px}
.jlogpre{margin:0;padding:8px 10px;font:10.5px/1.5 "Roboto Mono",monospace;color:var(--ink);
  white-space:pre-wrap;word-break:break-word}
/* SMART per-drive card + detail table */
.smartcard .skpirow{display:grid;grid-template-columns:repeat(auto-fit,minmax(72px,1fr));gap:8px;margin-top:12px}
.smartcard .skpi{background:var(--rail);border:1px solid var(--line);border-radius:8px;padding:8px 9px}
.smartcard .skpi b{display:block;font-family:"Roboto Mono",monospace;font-size:14px;color:var(--ink);font-weight:600}
.smartcard .skpi span{font-size:9px;letter-spacing:.05em;text-transform:uppercase;color:var(--mut);font-weight:700}
.smartcard .skpi.ok b{color:var(--ok)} .smartcard .skpi.warn b{color:var(--warn)} .smartcard .skpi.crit b{color:var(--crit)}
.smprobe{font-size:10px;color:var(--mut);margin-left:10px;font-family:"Roboto Mono",monospace}
.smdet{margin-top:9px;max-height:360px;overflow:auto;border:1px solid var(--line);border-radius:7px}
.smdet[hidden]{display:none}
.smt{border-collapse:collapse;width:100%;font-family:"Roboto Mono",monospace;font-size:10.5px}
.smt th{text-align:left;color:var(--mut);font-weight:700;font-size:9px;letter-spacing:.05em;text-transform:uppercase;
  padding:5px 7px;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--surf)}
.smt td{padding:3px 7px;border-bottom:1px solid var(--heatbg);color:var(--ink);white-space:nowrap}
.smt td.aid{color:var(--mut)} .smt td.anm{white-space:normal;color:var(--acc2)} .smt td.araw{color:var(--mut);text-align:right}
.smt tr.bad td,.smt tr.bad td.anm{color:var(--crit)}
#actlog{padding:.6rem;background:var(--rail);border:1px solid var(--line);
  border-radius:9px;display:flex;flex-direction:column;gap:7px;min-height:1.4em}
#actlog .amsg{color:var(--mut);font:12px/1.5 "Roboto Mono",monospace;padding:2px 4px}
.actrow{display:flex;flex-direction:column;font:12px/1.4 "Roboto Mono",monospace;padding:7px 9px;
  background:var(--surf);border:1px solid var(--line);border-radius:8px}
.actrow .ahead{display:grid;grid-template-columns:auto 1fr auto auto;gap:10px;align-items:center}
.actrow.hasout .ahead{cursor:pointer}
.actrow .ad{width:8px;height:8px;border-radius:50%;flex:none}
.actrow .ad.ok{background:var(--ok)} .actrow .ad.crit{background:var(--crit)}
.actrow .ad.warn{background:var(--warn)} .actrow .ad.unk{background:var(--unk)}
.actrow.spin .ad{animation:apulse 1.1s ease-in-out infinite}
@keyframes apulse{0%,100%{opacity:.3}50%{opacity:1}}
.actrow .at{color:var(--ink);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.actrow .as{color:var(--mut);white-space:nowrap;font-size:10.5px;text-transform:uppercase;letter-spacing:.05em}
.actrow .acar{width:10px;color:var(--mut);font-size:10px;text-align:center}
.actrow.hasout .acar::before{content:"\\25B8";display:inline-block;transition:transform .15s}
.actrow.open .acar::before{transform:rotate(90deg)}
.actrow .aout{display:none;margin-top:7px;color:var(--mut);font-size:10.5px;white-space:pre-wrap;
  word-break:break-all;background:var(--rail);border:1px solid var(--line);border-radius:6px;padding:5px 7px;
  max-height:340px;overflow:auto}
.actrow.open .aout{display:block}
/* legend */
.legend{grid-column:1/-1;background:var(--rail);border-top:1px solid var(--line);padding:20px 24px 26px}
.legend h3{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--mut);font-weight:700;margin:0 0 14px}
.lg{display:grid;grid-template-columns:repeat(3,1fr);gap:13px 28px}
.lg dt{font-family:"Roboto Mono";font-weight:500;font-size:13px;color:var(--acc2);display:flex;gap:8px;align-items:center}
.lg dd{margin:3px 0 0;color:var(--mut);font-size:12px;line-height:1.45}
.lg .sw{width:11px;height:11px;border-radius:3px;flex:none}
/* collapsible panes - Coverage gaps · Activity · Metric key */
.paneh{display:flex;align-items:center;gap:9px;width:100%;appearance:none;border:0;background:transparent;
  text-align:left;cursor:pointer;padding:0;margin:0;color:inherit;font:inherit}
.paneh .pt{font-family:"Red Hat Display",sans-serif;font-size:11px;letter-spacing:.08em;
  text-transform:uppercase;color:var(--mut);font-weight:700}
.paneh:hover .pt{color:var(--ink)}
.paneh:focus-visible{outline:2px solid var(--acc);outline-offset:3px;border-radius:4px}
.paneh .pchev{margin-left:auto;color:var(--mut);font-size:9px;line-height:1;transition:transform .15s;flex:none}
.pane.collapsed .paneh .pchev{transform:rotate(-90deg)}
.paneh .pcount{font:600 10px/1 "Roboto Mono",monospace;color:var(--acc2);background:var(--surf);
  border:1px solid var(--line);border-radius:20px;padding:3px 8px}
.paneh .pcount:empty{display:none}
.paneh .pdot{width:9px;height:9px;border-radius:50%;background:var(--acc);flex:none;display:none;
  box-shadow:0 0 0 3px color-mix(in srgb,var(--acc) 22%,transparent);animation:apulse 1.4s ease-in-out infinite}
.pane.collapsed.alerted .paneh .pdot{display:inline-block}
.pane .pbody{margin-top:12px}
.pane.collapsed .pbody{display:none}
.pane.grp:not(:first-child){margin-top:22px}
.actpane{margin-top:22px}
/* top bar + hero toggle */
.topbar2{display:flex;align-items:center;gap:16px;flex-wrap:wrap;padding:14px 26px 2px}
.applogo{font-family:"Red Hat Display";font-weight:900;font-size:19px;letter-spacing:-.01em}
.seg{display:inline-flex;background:var(--surf);border:1px solid var(--line);border-radius:10px;padding:3px;gap:2px}
.topbar2 .seg{margin-left:auto}
.seg button{appearance:none;border:0;background:transparent;color:var(--mut);
  font:600 12.5px/1 "Red Hat Text",sans-serif;padding:8px 14px;border-radius:7px;cursor:pointer}
.seg button:hover{color:var(--ink)}
.signout{color:var(--acc);text-decoration:none;font-size:12.5px;white-space:nowrap}
.robadge{font-size:11px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;color:var(--mut);
  border:1px solid var(--line);border-radius:999px;padding:2px 9px;white-space:nowrap}
.verold{display:inline-block;margin-left:6px;font-size:11px;font-weight:600;color:var(--warn);
  border:1px solid var(--warn);border-radius:999px;padding:0 7px;white-space:nowrap}
.verbtn{margin-left:6px;font-size:11px;font-weight:600;color:#fff;background:var(--warn);
  border:1px solid var(--warn);border-radius:999px;padding:1px 9px;white-space:nowrap;cursor:pointer}
.verbtn:hover{filter:brightness(1.06)}
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
.sumchip{display:inline-flex;align-items:center;gap:7px;background:var(--surf);border:1px solid var(--line);
  border-radius:9px;padding:7px 12px;font:12px "Red Hat Text",sans-serif;color:var(--mut);cursor:pointer;
  appearance:none;-webkit-appearance:none}
.sumchip:hover{border-color:var(--acc2)}
.sumchip.active{border-color:var(--acc);box-shadow:0 0 0 2px color-mix(in srgb,var(--acc) 28%,transparent);color:var(--ink)}
.sumchip:focus-visible{outline:2px solid var(--acc);outline-offset:2px}
.filtering .pt{opacity:.6}   /* subtle cue that a severity filter is active */
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
.legs{display:flex;flex-direction:column;gap:7px;margin-top:12px}
.leg{display:grid;grid-template-columns:auto 1fr auto;gap:9px;align-items:center;font-size:12.5px}
.leg .legmark{width:17px;height:17px;border-radius:5px;display:grid;place-items:center;
  font-size:11px;font-weight:800;color:#fff;flex:none;line-height:1}
.leg.met .legmark{background:var(--ok)} .leg.unmet .legmark{background:var(--crit)}
.leg .legname{color:var(--ink);font-weight:600}
.leg .legval{color:var(--mut);font-family:"Roboto Mono";font-size:11px}
@media (max-width:760px){
  /* Hide the left rail on narrow screens - it would otherwise stack between the hero and the cards,
     eating vertical space; its gauge duplicates the hero's capacity tile. */
  .split{grid-template-columns:1fr} .rail{display:none}
  .lg{grid-template-columns:1fr} .tag{margin-left:0;text-align:left}
  .sumtiles{grid-template-columns:1fr} .sumasof{margin-left:0;text-align:left}
}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
</style>"""

# plain string (NOT an f-string) so JS ${...} and \n survive untouched
PAGE_SCRIPT = """<script>
var _seq=0, _busy={};
function cardBusy(target, delta){   // ref-counted; marks the card while it has actions in flight
  if(!target) return;
  _busy[target]=Math.max(0,(_busy[target]||0)+delta);
  var c=document.querySelector('.card[data-t="'+String(target).replace(/"/g,'')+'"]');
  if(c) c.classList.toggle('busy', _busy[target]>0);
}
function setRow(key, o){
  var el=document.getElementById('actlog'); var idle=el.querySelector('.amsg'); if(idle) idle.remove();
  var row=document.getElementById('actrow-'+key);
  if(!row){
    row=document.createElement('div'); row.className='actrow'; row.id='actrow-'+key;
    row.innerHTML='<div class="ahead"><span class="ad"></span><span class="at"></span>'+
      '<span class="as"></span><span class="acar"></span></div><div class="aout"></div>';
    row.querySelector('.ahead').addEventListener('click', function(){
      if(row.classList.contains('hasout')) row.classList.toggle('open'); });
    el.insertBefore(row, el.firstChild);            // newest on top
    while(el.children.length>15) el.removeChild(el.lastChild);   // cap the queue
  }
  if(o.dry===true) row.classList.add('dryrow');
  if(o.title!=null) row.querySelector('.at').textContent=o.title;
  if(o.state!=null) row.querySelector('.as').textContent=o.state;
  if(o.cls!=null) row.querySelector('.ad').className='ad '+o.cls;
  if(o.spin===true) row.classList.add('spin'); else if(o.spin===false) row.classList.remove('spin');
  if(o.out!==undefined){                            // only touch output when told to
    var out=row.querySelector('.aout'); var txt=(o.out||'').trim();
    if(txt){ out.textContent=txt; row.classList.add('hasout'); if(o.expand) row.classList.add('open'); }
    else { out.textContent=''; row.classList.remove('hasout','open'); }   // never show an empty box
  }
  updateActCount();
}
async function post(body){
  var key='q'+(++_seq); var dry=!!body.dryrun; var tag=dry?'[dry] ':'';
  cardBusy(body.target, +1); panePing('acts');
  setRow(key,{title:tag+body.action+' '+body.target, state:'submitting', cls:'warn', spin:true, dry:dry});
  var r,j;
  try{ r=await fetch('/api/v1/backup/actions',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify(body)}); j=await r.json(); }
  catch(e){ setRow(key,{state:'network error', cls:'crit', spin:false, out:String(e)}); cardBusy(body.target,-1); return; }
  if(!r.ok){ setRow(key,{state:'rejected', cls:'crit', spin:false, out:(j.detail||('HTTP '+r.status))}); cardBusy(body.target,-1); return; }
  setRow(key,{title:tag+'#'+j.id+' '+body.action+' '+body.target, state:'pending', cls:'warn', spin:true});
  poll(j.id, key, dry, body.target);
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
  var b={target:target, action:action, requested_by:'ui', dryrun:!!window.CAIRN_DRY};
  if(action==='sync') b.create_snapshot=createSnap;
  if(!(await confirmRun(b,label))) return;
  post(b);
}
async function actPrompt(target, action, field, msg){
  var v=prompt(msg); if(v===null) return;
  var b={target:target, action:action, requested_by:'ui', dryrun:!!window.CAIRN_DRY}; b[field]=v;
  if(!(await confirmRun(b, action+' '+target+' ['+(v||'(all)')+']'))) return;
  post(b);
}
async function replicateNow(name, agent, dry){
  // Queue an on-demand pull of this set on the off-site agent (reuses the intent flow + activity log).
  var b={target:name, action:'pull', agent:agent, requested_by:'ui', dryrun:!!dry||!!window.CAIRN_DRY};
  if(!(await confirmRun(b, 'pull "'+name+'" from home now'))) return;
  post(b);
}
async function updateAgent(name){
  if(!confirm('Update agent "'+name+'" to the latest version?\\nIt fetches new code and restarts, keeping every setting.')) return;
  try{ await fetch('/api/v1/backup/agents/'+encodeURIComponent(name)+'/update',{method:'POST'}); }
  catch(e){ alert('failed to queue update: '+e); return; }
  alert('Update queued for "'+name+'".\\nIt runs on the agent\\'s next check-in; its version here updates when done.');
}
async function ackTarget(t){
  if(!confirm('Acknowledge '+t+'?\\nSilences this warning until the condition changes or 14 days pass.')) return;
  try{ await fetch('/api/v1/backup/acks',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({target:t})}); }catch(e){ alert('ack failed: '+e); return; }
  location.reload();
}
async function unackTarget(t){
  try{ await fetch('/api/v1/backup/acks/'+encodeURIComponent(t),{method:'DELETE'}); }
  catch(e){ alert('clear failed: '+e); return; }
  location.reload();
}
async function hideTarget(tid){
  if(!confirm('Hide this target? It stops being monitored until you restore it from the Hidden section.')) return;
  try{ await fetch('/api/v1/backup/targets/'+tid+'/retire',{method:'POST'}); }
  catch(e){ alert('hide failed: '+e); return; }
  location.reload();
}
async function unhideTarget(tid){
  try{ await fetch('/api/v1/backup/targets/'+tid+'/unretire',{method:'POST'}); }
  catch(e){ alert('unhide failed: '+e); return; }
  location.reload();
}
async function poll(id, key, dry, target){
  var tag=dry?'[dry] ':'';
  for(var i=0;i<180;i++){
    var j; try{ j=await (await fetch('/api/v1/backup/actions/'+id)).json(); }catch(e){ break; }
    var st=j.state||'?';
    var done=['done','failed','stalled'].includes(st);
    var cls = st==='done'?'ok' : (st==='failed'||st==='stalled')?'crit' : 'warn';
    var res={}; try{res=JSON.parse(j.result||'{}')}catch(e){}
    if(!target) target=j.target;
    setRow(key,{title:tag+'#'+id+' '+(j.target||'')+' '+(j.action||''), state:actState(j.action,st)+(dry?' · dry':''),
                cls:cls, spin:!done, out: done?(res.output||''):undefined, expand: done&&cls==='crit'});
    if(done){ panePing('acts'); break; }             // completion is worth surfacing when collapsed
    await new Promise(s=>setTimeout(s,2000));
  }
  cardBusy(target, -1);   // clear the card indicator whether it finished, gave up, or errored
  refreshCards();         // pull the target's new status/history as soon as it settles
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
// Agent tabs: clicking an agent card switches to its pane; remember the choice per browser.
function showAgent(slug){
  document.querySelectorAll('[data-agpane]').forEach(function(p){ p.hidden = (p.getAttribute('data-agpane')!==slug); });
  document.querySelectorAll('[data-agtab]').forEach(function(t){ t.classList.toggle('active', t.getAttribute('data-agtab')===slug); });
  filterHidden(slug);
  try{ localStorage.setItem('bm_agtab', slug); }catch(e){}
}
function filterHidden(slug){   // the Hidden pane lives below Activity but follows the active agent tab
  var pane=document.querySelector('.hidpane'); if(!pane) return;
  var shown=0;
  pane.querySelectorAll('.hidrow').forEach(function(r){
    var mine=(r.getAttribute('data-hagent')===slug); r.hidden=!mine; if(mine) shown++;
  });
  pane.hidden=(shown===0);     // no lonely "Hidden" header when this agent has nothing hidden
}
(function(){ var s=null;
  try{ s=localStorage.getItem('bm_agtab'); }catch(e){}
  if(s && document.querySelector('[data-agpane="'+s+'"]')){ showAgent(s); return; }
  var t=document.querySelector('[data-agtab].active');   // no stored choice: use the server-active tab
  if(t) filterHidden(t.getAttribute('data-agtab'));
})();
function esc(s){return (s==null?'':String(s)).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function relTime(ts){ if(!ts) return ''; var s=Math.max(0, Date.now()/1000 - ts);
  if(s<90) return Math.round(s)+'s ago'; if(s<5400) return Math.round(s/60)+'m ago';
  if(s<172800) return Math.round(s/3600)+'h ago'; return Math.round(s/86400)+'d ago';}
// `zpool scrub` returns as soon as it STARTS the async scrub, so a scrub intent completes ("done")
// while the scrub itself runs for hours. Label it "started" so it doesn't read as "finished" - the
// real progress lives on the pool card's scrub bar.
function actState(action, st){ return (action==='scrub' && st==='done') ? 'started' : st; }
function renderHist(x){
  var st=x.state||'?';
  var cls = st==='done'?'ok' : st==='failed'?'crit' : (st==='pending'||st==='claimed')?'warn':'unk';
  var res={}; try{res=JSON.parse(x.result||'{}')}catch(e){}
  var out=(res.output||res.cmd||'').toString();
  var dry = out.indexOf('[DRYRUN]')===0 ? '<span class=hdry>dry</span>' : '';
  var when = relTime(x.result_ts||x.claimed_ts||x.created_ts);
  return '<div class=hrow><span class="hd '+cls+'"></span>'+
    '<span class=ha>'+esc(x.action)+' · '+esc(actState(x.action,st))+dry+'</span>'+
    '<span class=ht>'+when+'</span>'+
    (out?'<div class=hcmd>'+esc(out)+'</div>':'')+'</div>';
}
async function loadHist(target, box){
  try{
    var j=await (await fetch('/api/v1/backup/actions?limit=8&target='+encodeURIComponent(target))).json();
    var a=(j.actions||[]);
    box.innerHTML = a.length ? a.map(renderHist).join('') : '<div class=hempty>no actions yet</div>';
  }catch(e){ box.innerHTML='<div class=hempty>error loading history</div>'; }
}
function toggleSmart(btn){   // SMART detail table is server-rendered; just show/hide it
  var box=btn.parentNode.querySelector('.smdet'); if(!box) return;
  var open=btn.classList.toggle('open'); box.hidden=!open;
}
async function toggleHist(btn, target){
  var box=btn.nextElementSibling; var open=btn.classList.toggle('open');
  if(!open){ box.hidden=true; return; }
  box.hidden=false; box.innerHTML='<div class=hempty>loading…</div>';
  loadHist(target, box);
}
// ---- live refresh: cards + open History poll status in the background ----
function metricRowHtml(r){
  var p='';
  if(r.pool_cap_pct!=null) p+='<div><div class="mv">'+r.pool_cap_pct+'%</div><div class="ml">capacity</div></div>';
  if(r.repl_lag_s!=null) p+='<div><div class="mv">'+Math.floor(r.repl_lag_s/3600)+'h</div><div class="ml">repl lag</div></div>';
  if(r.archive_count!=null) p+='<div><div class="mv">'+r.archive_count+'</div><div class="ml">archives</div></div>';
  if(r.dedup_ratio!=null) p+='<div><div class="mv">'+r.dedup_ratio+'\\u00d7</div><div class="ml">dedup</div></div>';
  return p;
}
var _SEVC={CRIT:'crit',WARN:'warn',UNKNOWN:'unk',OK:'ok'};
var _cardSev={};
async function refreshCards(){
  var j; try{ j=await (await fetch('/api/v1/backup/status')).json(); }catch(e){ return; }
  (j.targets||[]).forEach(function(r){
    var c=document.querySelector('.card[data-t="'+String(r.name).replace(/"/g,'')+'"]'); if(!c) return;
    var cls=r.acked?'ack':(_SEVC[(r.severity||'').toUpperCase()]||'unk');
    var prev=_cardSev[r.name]; _cardSev[r.name]=cls;
    if(prev!==undefined && prev!==cls){          // a card changed state → flag its section if collapsed
      var sec=c.closest('.pane.grp');
      if(sec && sec.classList.contains('collapsed')) sec.classList.add('alerted');
    }
    var keep=(c.classList.contains('busy')?' busy':'')+(c.classList.contains('smartcard')?' smartcard':'');
    c.className='card '+cls+keep;   // updates the severity stripe, preserving card variants
    var cs=c.querySelector('.cs'); if(cs) cs.textContent=r.acked?'ACK\u2019D':(r.severity||'').toUpperCase();
    var mr=metricRowHtml(r), rowEl=c.querySelector('.row');
    if(mr && rowEl) rowEl.innerHTML=mr; else if(!mr && rowEl) rowEl.remove();
    var d=r.detail||{}, why=(d.reasons&&d.reasons.length)?d.reasons.join(', '):(r.last_error||'');
    var whyEl=c.querySelector('.why'); if(whyEl) whyEl.textContent=why;
    // live scrub state: disable/relabel the Scrub button + show/update the progress bar
    var sc=d.scrub||{}, running=(sc.state==='in_progress');
    var sb=c.querySelector('[data-scrub]');
    if(sb){
      if(running){ sb.disabled=true; sb.removeAttribute('onclick');
        sb.textContent=(sc.pct!=null)?('Scrubbing… '+Math.round(sc.pct)+'%'):'Scrubbing…'; }
      else{ sb.disabled=false; sb.textContent='Scrub';
        sb.setAttribute('onclick',"act('"+String(r.name).replace(/'/g,"\\'")+"','scrub',true)"); }
    }
    var sp=c.querySelector('[data-scrubprog]');
    if(sp){
      if(running){ sp.hidden=false;
        var fill=sp.querySelector('[data-scrubfill]'); if(fill&&sc.pct!=null) fill.style.width=sc.pct+'%';
        var lbl=sp.querySelector('[data-scrublbl]');
        if(lbl){ var tx='scrubbing'+(sc.pct!=null?(' '+Number(sc.pct).toFixed(1)+'%'):'')+(sc.eta?(' · '+sc.eta+' to go'):''); lbl.textContent=tx; }
      } else { sp.hidden=true; }
    }
  });
  document.querySelectorAll('.histbtn.open[data-t]').forEach(function(btn){   // keep open History current
    var box=btn.nextElementSibling, target=btn.getAttribute('data-t');       // ([data-t] excludes SMART-detail toggles)
    if(box && !box.hidden && target) loadHist(target, box);
  });
  if(typeof applyFilter==='function') applyFilter();   // re-honor an active severity filter after re-render
}
window.addEventListener('load', refreshCards);
setInterval(refreshCards, 20000);
function setHero(h){var p=document.querySelector('.panel'); if(!p) return;
  p.dataset.hero=h; try{localStorage.setItem('bm_hero',h)}catch(e){}}
(function(){try{var s=localStorage.getItem('bm_hero');
  if(s) document.querySelector('.panel').dataset.hero=s;}catch(e){}})();
function setDry(v){window.CAIRN_DRY=!!v; var p=document.querySelector('.panel');
  if(p) p.classList.toggle('drymode',!!v); try{localStorage.setItem('bm_dry', v?'1':'')}catch(e){}}
(function(){try{ if(localStorage.getItem('bm_dry')){ window.CAIRN_DRY=true;
  var c=document.getElementById('drychk'); if(c) c.checked=true;
  var p=document.querySelector('.panel'); if(p) p.classList.add('drymode'); } }catch(e){}})();
async function loadStream(){
  var el=document.getElementById('actlog'); if(!el) return;
  window._bmSeeding=true;
  try{
    var j=await (await fetch('/api/v1/backup/actions?limit=10')).json();
    var a=(j.actions||[]).slice().sort(function(x,y){return (x.created_ts||0)-(y.created_ts||0);});
    for(var i=0;i<a.length;i++){
      var x=a[i], st=x.state||'?', done=['done','failed','stalled'].indexOf(st)>=0;
      var cls = st==='done'?'ok':(st==='failed'||st==='stalled')?'crit':'warn';
      var res={}; try{res=JSON.parse(x.result||'{}')}catch(e){}
      var dry=false; try{dry=!!JSON.parse(x.opts||'{}').dryrun}catch(e){}
      var key='srv'+x.id, tag=dry?'[dry] ':'';
      setRow(key,{title:tag+'#'+x.id+' '+(x.target||'')+' '+(x.action||''), state:actState(x.action,st)+(dry?' · dry':''),
                  cls:cls, spin:!done, dry:dry, out: done?(res.output||''):undefined, expand:false});
      if(!done){ cardBusy(x.target, +1); poll(x.id, key, dry, x.target); }   // resume + mark card busy
    }
  }catch(e){}
  window._bmSeeding=false; updateActCount();
}
// ---- collapsible panes + "something changed while collapsed" indicator ----
function paneKey(id){return 'bm_pane_'+id;}
function togglePane(id){
  var p=document.querySelector('.pane[data-pane="'+id+'"]'); if(!p) return;
  var col=p.classList.toggle('collapsed');
  if(!col) p.classList.remove('alerted');            // opening it clears the "look here" dot
  try{localStorage.setItem(paneKey(id), col?'1':'')}catch(e){}
}
function panePing(id){                                // flag a collapsed pane; no-op while it's open
  if(window._bmSeeding) return;                      // don't flash on the initial page seed
  var p=document.querySelector('.pane[data-pane="'+id+'"]');
  if(p && p.classList.contains('collapsed')) p.classList.add('alerted');
}
(function(){                                          // restore each pane's collapsed state
  document.querySelectorAll('.pane[data-pane]').forEach(function(p){
    try{ if(localStorage.getItem(paneKey(p.getAttribute('data-pane')))) p.classList.add('collapsed'); }catch(e){}
  });
})();
function updateActCount(){                            // show in-flight count on the Activity header
  var el=document.getElementById('actlog'), c=document.getElementById('actcount'); if(!el||!c) return;
  var n=el.querySelectorAll('.actrow.spin').length; c.textContent = n?(n+' running'):'';
}
var _gapsig=null;
function gapHtml(g){var sev=(_SEVC[(g.severity||'').toUpperCase()]||'unk');
  return '<div class=gap><span class=d style="background:var(--'+sev+')"></span>'+
    '<div><b>'+esc(g.name)+'</b><small>'+esc(g.gap)+'</small></div></div>';}
async function refreshGaps(){
  var box=document.getElementById('gapsbody'); if(!box) return;
  var j; try{ j=await (await fetch('/api/v1/backup/coverage-gap')).json(); }catch(e){ return; }
  var gaps=(j.gaps||[]).slice(0,6);
  var sig=gaps.map(function(g){return g.name+'|'+g.gap+'|'+g.severity;}).join('~');
  if(sig===_gapsig) return;                           // unchanged → don't touch DOM or ping
  var first=(_gapsig===null); _gapsig=sig;
  box.innerHTML = gaps.length ? gaps.map(gapHtml).join('')
    : '<div class=gap><span class=d style="background:var(--ok)"></span><div><b>No gaps</b>'+
      '<small>everything snapshotted &amp; replicating</small></div></div>';
}
window.addEventListener('load', refreshGaps);
setInterval(refreshGaps, 20000);
var _AGSTATE={OK:'ONLINE',WARN:'STALE',CRIT:'MISSING'};
async function refreshAgents(){                          // agent liveness (dead-man's-switch surface)
  var j; try{ j=await (await fetch('/api/v1/backup/agents')).json(); }catch(e){ return; }
  var stale=0;
  (j.agents||[]).forEach(function(a){
    var c=document.querySelector('.card[data-a="'+String(a.name).replace(/"/g,'')+'"]'); if(!c) return;
    var cls=_SEVC[(a.severity||'').toUpperCase()]||'unk';
    // preserve the tab role/active state (this card doubles as a tab); only swap the severity class
    c.className='card '+cls+(c.classList.contains('agenttab')?' agenttab':'')+(c.classList.contains('active')?' active':'');
    var cs=c.querySelector('.cs'); if(cs) cs.textContent=_AGSTATE[a.severity]||a.severity;
    var ls=c.querySelector('[acls=ls]'); if(ls) ls.textContent=a.last_report_ts?relTime(a.last_report_ts):'never';
    // when an agent reports the current version, drop any lingering "update to X" button/badge
    // (the reported bug). Rebuilding the button in JS is avoided on purpose - a newly-outdated
    // agent (server bump while the page is open) gets its button on the next full reload.
    var vspan=c.querySelector('[data-ver]');
    if(vspan && a.version && !a.outdated){ vspan.textContent=a.version; }
    if(a.severity!=='OK') stale++;
  });
  var cnt=document.getElementById('agentcount'); if(cnt) cnt.textContent=stale?(stale+' stale'):'';
  var sec=document.querySelector('.pane[data-pane="grp:agents"]');
  if(sec && stale>0 && sec.classList.contains('collapsed')) sec.classList.add('alerted');
  if(typeof applyFilter==='function') applyFilter();
}
window.addEventListener('load', refreshAgents);
setInterval(refreshAgents, 20000);
// ---- live header (Attention verdict + severity counts) ----
var _CK={ok:'OK',warn:'WARN',crit:'CRIT',unk:'UNKNOWN'};
var _VMAP={OK:'All healthy',WARN:'Attention',CRIT:'Critical',UNKNOWN:'Unknown'};
async function refreshHeader(){
  var j; try{ j=await (await fetch('/api/v1/backup/health')).json(); }catch(e){ return; }
  var c=j.counts||{};
  document.querySelectorAll('.sumchip[data-sev]').forEach(function(ch){
    var b=ch.querySelector('b'); if(b) b.textContent=c[_CK[ch.getAttribute('data-sev')]]||0;
  });
  var vt=_VMAP[j.severity]||j.severity, vcls=_SEVC[j.severity]||'unk';
  var sv=document.getElementById('sumverd');
  if(sv){ sv.className='sumverd '+vcls;
    var e1=sv.querySelector('.vt'); if(e1) e1.textContent=vt;
    var e2=sv.querySelector('.vs'); if(e2) e2.textContent=(c.WARN||0)+' warning(s) · '+(c.CRIT||0)+' critical · '+(j.targets||0)+' targets';
  }
  var hv=document.getElementById('heatverd'); if(hv){ hv.className='verd '+vcls; hv.textContent=vt; }
  var ht=document.getElementById('heattag'); if(ht) ht.textContent=(j.targets||0)+' targets · '+(c.OK||0)+' ok · '+(c.WARN||0)+' warn · '+(c.CRIT||0)+' crit';
}
window.addEventListener('load', refreshHeader);
setInterval(refreshHeader, 20000);
// ---- click a header count to filter the fleet to that severity (toggle) ----
var _filter=null;
function applyFilter(){
  var f=_filter;
  document.querySelectorAll('.card').forEach(function(c){
    c.style.display = (!f || c.classList.contains(f)) ? '' : 'none';
  });
  document.querySelectorAll('.pane.grp').forEach(function(sec){          // hide sections with nothing shown
    if(!f){ sec.style.display=''; return; }
    var vis=false, cs=sec.querySelectorAll('.card');
    for(var i=0;i<cs.length;i++){ if(cs[i].style.display!=='none'){ vis=true; break; } }
    sec.style.display = vis ? '' : 'none';
  });
  document.querySelectorAll('.sumchip[data-sev]').forEach(function(ch){
    ch.classList.toggle('active', f===ch.getAttribute('data-sev'));
  });
  var p=document.querySelector('.panel'); if(p) p.classList.toggle('filtering', !!f);
}
function toggleFilter(sev){ _filter=(_filter===sev)?null:sev; applyFilter(); }
window.addEventListener('load', loadStream);
// ---- reconciliation modal: cross-agent target overlaps ----
async function openReconcile(){
  var m=document.getElementById('reconmodal'), b=document.getElementById('reconbody');
  b.innerHTML='<div class=hempty>loading…</div>'; m.hidden=false;
  try{ var j=await (await fetch('/api/v1/backup/reconcile')).json(); renderReconcile(j.overlaps||[]); }
  catch(e){ b.innerHTML='<div class=hempty>error loading overlaps</div>'; }
}
function closeReconcile(){ document.getElementById('reconmodal').hidden=true; }
function renderReconcile(ov){
  var b=document.getElementById('reconbody');
  if(!ov.length){ b.innerHTML='<div class=hempty>Nothing to reconcile.</div>'; return; }
  b.innerHTML='<p class=why style="margin:0 0 12px">Each row is one dataset tracked from two sides. '
    +'Retire the view you no longer want, or keep both.</p>'+ov.map(function(o){
    return '<div class=reconrow><div class=recondesc><b>'+esc(o.dataset)+'</b><small>'
      +'replication view: <b>'+esc(o.replication.agent)+'</b> / '+esc(o.replication.name)
      +' &nbsp;&harr;&nbsp; monitored by: <b>'+esc(o.monitor.agent)+'</b> / '+esc(o.monitor.name)
      +'</small></div><div class=reconacts>'
      +'<button onclick="reconAct(this,\\'retire\\','+o.replication.id+')">Retire '+esc(o.replication.agent)+' view</button>'
      +'<button onclick="reconAct(this,\\'retire\\','+o.monitor.id+')">Retire '+esc(o.monitor.agent)+' view</button>'
      +'<button onclick="reconAct(this,\\'dismiss\\',0,\\''+esc(o.pair)+'\\')">Keep both</button>'
      +'</div></div>';
  }).join('');
}
async function reconAct(btn, action, tid, pair){
  var body = action==='retire' ? {action:'retire',target_id:tid} : {action:'dismiss',pair:pair};
  var btns=btn.parentNode.querySelectorAll('button'); btns.forEach(function(x){x.disabled=true;});
  try{
    await fetch('/api/v1/backup/reconcile',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    var j=await (await fetch('/api/v1/backup/reconcile')).json(); var left=j.overlaps||[]; renderReconcile(left);
    if(!left.length){ closeReconcile(); location.reload(); }
  }catch(e){ btns.forEach(function(x){x.disabled=false;}); }
}
// ---- recovery browser: Points / Versions / Deleted, and copy-only Restore ----
// Points  = the dataset's snapshots (restore points).   Versions = one file's history across snapshots.
// Deleted = files gone from live but still in snapshots. Restore = copy a chosen version to staging.
var _recTarget=null, _recVers=[], _recLast=null, _recCachedTs=0;
function openRec(){ document.getElementById('recmodal').hidden=false; }
function closeRec(){ document.getElementById('recmodal').hidden=true; }
function recRefresh(){ if(_recLast) openRecover(_recLast.target, _recLast.kind, true); }
function recBanner(){   // "cached Nm ago" line when the listing was reused, else nothing
  return _recCachedTs ? '<p class=reccached>cached '+relTime(_recCachedTs)+' \\u00b7 Refresh to re-scan</p>' : '';
}
async function pollAction(id, maxTries){                // resolve to {state,output,cmd,action}
  var lim=maxTries||180;                                // default ~6 min; walks pass a larger value
  for(var i=0;i<lim;i++){
    var j=await (await fetch('/api/v1/backup/actions/'+id)).json();
    var st=j.state||'?';
    if(['done','failed','stalled'].includes(st)){
      var res={}; try{res=JSON.parse(j.result||'{}')}catch(e){}
      return {state:st, output:res.output||'', cmd:res.cmd||'', action:j.action};
    }
    await new Promise(s=>setTimeout(s,2000));
  }
  throw new Error('timed out');
}
async function openRecover(target, kind, refresh){
  var path=null;
  if(kind==='versions'){                                 // only Versions needs a single-file path
    if(refresh && _recLast){ path=_recLast.path; }
    else { path=prompt('List versions of (path relative to dataset root):'); if(path===null) return; }
  }
  _recTarget=target; _recLast={target:target, kind:kind, path:path}; _recCachedTs=0;
  var titles={points:'Restore points', versions:'File versions', deleted:'Deleted files'};
  document.getElementById('rectitle').textContent=titles[kind]+' \\u00b7 '+target+(path?(' / '+path):'');
  var rb=document.getElementById('recrefresh'); if(rb) rb.hidden=false;
  var body=document.getElementById('recbody');
  openRec();
  if(kind==='deleted'){ await openDeleted(target, refresh); return; }
  // points / versions stay live (points is cheap + freshness-sensitive; versions is per-file + fast)
  body.innerHTML='<div class=hempty>scanning '+esc(target)+'\\u2026</div>';
  var action = kind==='points' ? 'recover-points' : 'recover-search';
  var b={target:target, action:action, requested_by:'ui'}; if(path) b.path=path; if(refresh) b.refresh=true;
  var r,j;
  try{ r=await fetch('/api/v1/backup/actions',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}); j=await r.json(); }
  catch(e){ body.innerHTML='<div class=hempty>request failed: '+esc(String(e))+'</div>'; return; }
  if(!r.ok){ body.innerHTML='<div class=hempty>rejected: '+esc(j.detail||('HTTP '+r.status))+'</div>'; return; }
  if(j.cached){ _recCachedTs=j.cached_ts||0; }           // reused a recent scan (see recBanner)
  var out; try{ out=await pollAction(j.id); }
  catch(e){ body.innerHTML='<div class=hempty>scan did not finish: '+esc(String(e))+'</div>'; return; }
  if(out.state!=='done'){ body.innerHTML='<div class=hempty>scan '+esc(out.state)+':</div><pre class=recpre>'+esc(out.output||'(no output)')+'</pre>'; return; }
  if(kind==='points') renderPoints(out.output); else renderVersions(out.output, kind);
}
async function openDeleted(target, refresh){
  // Deleted is manifest-backed. Normal open serves the stored manifest instantly; a Refresh (or the very
  // first open before any nightly walk) runs a walk NOW that FILLS the manifest - the scan is kept, not
  // thrown away - then renders the fresh manifest. An explicit walk bypasses the agent's off-peak window.
  var body=document.getElementById('recbody');
  async function loadManifest(){
    try{ return await (await fetch('/api/v1/backup/recovery-manifest?target='+encodeURIComponent(target)+'&kind=deleted')).json(); }
    catch(e){ return null; }
  }
  if(!refresh){
    var mj=await loadManifest();
    if(mj && mj.present){ renderDeletedManifest(mj.manifest||{}, mj.walked_ts, mj.entry_count||0); return; }
  }
  body.innerHTML='<div class=hempty>walking '+esc(target)+' for deleted files (recursive; can take a few minutes)\\u2026<br>this also refreshes the saved list.</div>';
  var b={target:target, action:'recover-walk', requested_by:'ui'};
  var r,j;
  try{ r=await fetch('/api/v1/backup/actions',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}); j=await r.json(); }
  catch(e){ body.innerHTML='<div class=hempty>request failed: '+esc(String(e))+'</div>'; return; }
  if(!r.ok){ body.innerHTML='<div class=hempty>rejected: '+esc(j.detail||('HTTP '+r.status))+'</div>'; return; }
  var out; try{ out=await pollAction(j.id, 300); }        // walks are slower: allow ~10 min
  catch(e){ body.innerHTML='<div class=hempty>Walk still running \\u2014 it will finish in the background and fill the list. Reopen Deleted in a bit.</div>'; return; }
  if(out.state!=='done'){ body.innerHTML='<div class=hempty>walk '+esc(out.state)+':</div><pre class=recpre>'+esc(out.output||'(no output)')+'</pre>'; return; }
  var mj2=await loadManifest();
  if(mj2 && mj2.present){ renderDeletedManifest(mj2.manifest||{}, mj2.walked_ts, mj2.entry_count||0); }
  else { body.innerHTML='<div class=hempty>Walk finished \\u2014 no deleted files found in snapshots.</div>'; }
}
function renderPoints(txt){
  var body=document.getElementById('recbody');
  var lines=(txt||'').split('\\n').filter(function(l){return l.indexOf('\\t')>0;});
  if(!lines.length){ body.innerHTML='<div class=hempty>No snapshots for this dataset.</div>'; return; }
  var rows=lines.map(function(l){
    var p=l.split('\\t'); var full=p[0]; var epoch=parseInt(p[1],10)||0;
    var snap=full.indexOf('@')>=0?full.slice(full.indexOf('@')+1):full;
    var d=epoch?new Date(epoch*1000):null;
    return '<tr><td class=recsnap>'+esc(snap)+'</td><td>'+(d?d.toLocaleString():'')+'</td><td class=recage>'+(epoch?relTime(epoch):'')+'</td></tr>';
  }).reverse().join('');
  body.innerHTML=recBanner()+'<p class=recnote>'+lines.length+' restore point'+(lines.length==1?'':'s')+'. To recover files from one, use <b>Versions</b> (one file\\u2019s history) or <b>Deleted</b> (files no longer live).</p>'
    +'<div class=rectblwrap><table class=rectbl><thead><tr><th>Snapshot</th><th>Created</th><th>Age</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
}
function renderVersions(txt, kind){
  var body=document.getElementById('recbody'); _recVers=[];
  var data; try{ data=JSON.parse(txt||'{}'); }
  catch(e){ body.innerHTML='<div class=hempty>could not parse the scan result:</div><pre class=recpre>'+esc((txt||'').slice(0,4000))+'</pre>'; return; }
  var blocks=[];
  Object.keys(data||{}).forEach(function(k){
    var vers=(data[k]||[]); if(!vers.length) return;
    var rows=vers.map(function(v){
      var vp=v.path||''; var m=v.metadata||{}; var isLive=(vp===k);
      var act;
      if(isLive){ act='<span class=reclive>live</span>'; }
      else { _recVers.push(vp); act='<button class=recrestore data-vi="'+(_recVers.length-1)+'" onclick="doRestore(this)">Restore</button>'; }
      return '<tr><td>'+esc(m.modify_time||'')+'</td><td class=recsize>'+esc(m.size||'')+'</td><td class=recact>'+act+'</td></tr>';
    }).join('');
    blocks.push('<div class=recfile><div class=recfp>'+esc(k)+'</div><div class=rectblwrap><table class=rectbl>'
      +'<thead><tr><th>Version (modified)</th><th>Size</th><th></th></tr></thead><tbody>'+rows+'</tbody></table></div></div>');
  });
  if(!blocks.length){ body.innerHTML=recBanner()+'<div class=hempty>'+(kind==='deleted'?'No deleted files found in snapshots under that path.':'No other versions found for that path.')+'</div>'; return; }
  body.innerHTML=recBanner()+'<p class=recnote>Restore copies a version into the dataset\\u2019s <code>.bm-restores/</code> staging dir \\u2014 your live files are never touched.</p>'+blocks.join('');
}
function renderDeletedManifest(m, walkedTs, total){
  // manifest = { "<deleted path>": {path,size,modify_time,versions} } - newest version per file, already
  // newest-first from the server and capped there. Each row restores that last snapshot version. Refresh
  // re-runs a live whole-dataset walk. `total` is the full count before the cap (may exceed shown rows).
  var body=document.getElementById('recbody'); _recVers=[];
  var keys=Object.keys(m||{});   // server order = newest-modified first; don't re-sort
  var when='walked '+relTime(walkedTs)+' \\u00b7 Refresh to re-scan';
  if(!keys.length){ body.innerHTML='<p class=reccached>'+when+'</p><div class=hempty>No deleted files found in snapshots.</div>'; return; }
  var rows=keys.map(function(k){
    var e=m[k]||{}; _recVers.push(e.path||'');
    return '<tr><td class=recfp>'+esc(k)+'</td><td class=recsize>'+esc(e.size||'')+'</td><td>'+esc(e.modify_time||'')
      +'</td><td class=recact><button class=recrestore data-vi="'+(_recVers.length-1)+'" onclick="doRestore(this)">Restore</button></td></tr>';
  }).join('');
  var shown=keys.length, capped=(total && total>shown);
  body.innerHTML='<p class=reccached>'+when+' \\u00b7 '+(capped?('showing newest '+shown+' of '+total+' deleted files'):(shown+' deleted file'+(shown==1?'':'s')))+'</p>'
    +'<p class=recnote>Restore copies the file\\u2019s last snapshot version into <code>.bm-restores/</code> \\u2014 live files untouched.'
    +(capped?' Use <b>Versions</b> for a specific file not listed here.':'')+'</p>'
    +'<div class=rectblwrap><table class=rectbl><thead><tr><th>Deleted file</th><th>Size</th><th>Last modified</th><th></th></tr></thead><tbody>'+rows+'</tbody></table></div>';
}
async function doRestore(btn){
  var vp=_recVers[parseInt(btn.getAttribute('data-vi'),10)]; if(vp==null) return;
  if(!confirm("Restore this version?\\nIt is copied into the dataset's .bm-restores/ staging dir. Live files are not touched.")) return;
  btn.disabled=true; var td=btn.parentNode; td.innerHTML='<span class=recwait>restoring\\u2026</span>';
  var b={target:_recTarget, action:'restore', version:vp, requested_by:'ui'};
  var r,j;
  try{ r=await fetch('/api/v1/backup/actions',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}); j=await r.json(); }
  catch(e){ td.innerHTML='<span class=recfail>failed</span>'; return; }
  if(!r.ok){ td.innerHTML='<span class=recfail>'+esc(j.detail||('HTTP '+r.status))+'</span>'; return; }
  var out; try{ out=await pollAction(j.id); }catch(e){ td.innerHTML='<span class=recfail>timed out</span>'; return; }
  if(out.state==='done'){
    var dest=''; var mm=(out.output||'').match(/-> '([^']*)'/); if(mm) dest=mm[1];
    td.innerHTML='<span class=recok>restored'+(dest?(' \\u2192 '+esc(dest)):'')+'</span>';
  } else { td.innerHTML='<span class=recfail>'+esc(out.output||out.state)+'</span>'; }
}
</script>"""

def _acts(r, can_act, viewer=False):
    """Card action buttons - only when an EXECUTE-capable agent owns the target (else the intent
    would hang pending). Recovery (Points/Deleted/Versions) sits on a compact sub-row. A read-only
    viewer gets no controls at all (not even the report-only note)."""
    n = r["name"]; t = r["type"]
    if viewer:
        return ""
    if not can_act:
        return ('<div class="cact"><span class="ro">report-only</span></div>'
                if t in ("zfs-repl", "zfs-local") else "")
    rec = ""
    if t in ("zfs-repl", "zfs-local") and r.get("source"):
        rec = (f'<div class="crec">'
               f"<button onclick=\"openRecover('{n}','points')\" title=\"snapshots you can recover from\">Points</button>"
               f"<button onclick=\"openRecover('{n}','deleted')\" title=\"files deleted from live but still in snapshots\">Deleted</button>"
               f"<button onclick=\"openRecover('{n}','versions')\" title=\"every snapshot version of one file/path\">Versions</button>"
               f"</div>")
    if t == "zfs-repl":
        main = (f"<button class=pri onclick=\"act('{n}','sync',true)\">Replicate</button>"
                f"<button onclick=\"act('{n}','snapshot',true)\">Snapshot</button>"
                f"<button onclick=\"act('{n}','sync',false)\">no-snap</button>")
    elif t == "zfs-local":
        main = ""
        _d = json.loads(r.get("detail_json") or "{}")
        caps = _d.get("caps") or {}                       # absent (pre-caps agent) => show, as before
        # snapshot needs zfs delegation; hide the button on datasets this agent can't snapshot (e.g.
        # an OS root pool with no `zfs allow`), so it never queues an intent that only fails.
        if r.get("source") and caps.get("snapshot", True):
            main += f"<button class=pri onclick=\"act('{n}','snapshot',true)\">Snapshot</button>"
        # Scrub is a whole-POOL operation (only on a pool root) AND needs the provisioned sudo wrapper.
        if r.get("source") and "/" not in r["source"] and caps.get("scrub", True):
            sc = _d.get("scrub") or {}
            if sc.get("state") == "in_progress":
                pct = sc.get("pct")
                lbl = f"Scrubbing… {pct:.0f}%" if isinstance(pct, (int, float)) else "Scrubbing…"
                main += f'<button class=scrubbtn data-scrub disabled>{lbl}</button>'
            else:
                main += f'<button class=scrubbtn data-scrub onclick="act(\'{n}\',\'scrub\',true)">Scrub</button>'
    else:
        return ""
    return f'<div class="cact">{main}</div>{rec}'

def _cap(b):
    if not b:
        return "-"
    b = float(b)
    if b >= 1e12: return f"{b/1e12:.1f} TB"
    if b >= 1e9:  return f"{b/1e9:.0f} GB"
    return f"{b/1e6:.0f} MB"

def _ago(ts):
    if not ts:
        return ""
    s = max(0, int(time.time()) - int(ts))
    if s < 90:     return f"{s}s ago"
    if s < 5400:   return f"{s//60}m ago"
    if s < 172800: return f"{s//3600}h ago"
    return f"{s//86400}d ago"

def _when(ts):
    """Relative time that also handles the future (next scheduled run)."""
    if not ts:
        return ""
    s = int(ts) - int(time.time()); fut = s >= 0; s = abs(s)
    v = f"{max(1, s//60)}m" if s < 5400 else (f"{s//3600}h" if s < 172800 else f"{s//86400}d")
    return f"in {v}" if fut else f"{v} ago"

def _agent_card(a, viewer=False, tab=None, active=False):
    """Liveness card for one reporting agent - the dead-man's-switch surface (e.g. the vault). When
    `tab` (a slug) is given the card doubles as a TAB: clicking it switches to that agent's pane."""
    sev = SEVCLS.get(a["severity"], "unk")
    n = _esc(a["name"])
    cs = {"OK": "ONLINE", "WARN": "STALE", "CRIT": "MISSING"}.get(a["severity"], a["severity"])
    role = "execute-capable" if a.get("can_execute") else "report-only"
    last = (_ago(a["last_report_ts"]) if a.get("last_report_ts") else "never")
    ivl = _ago_s(a["report_interval"]) if a.get("report_interval") else "?"
    ver = a.get("version")
    if ver and a.get("outdated"):
        # A read-only viewer sees the badge; an admin gets a button that queues the agent's self-update.
        # stopPropagation so pressing Update on a tab doesn't also switch tabs.
        upd = (f'<span class=verold>update to {_esc(CAIRN_VERSION)}</span>' if viewer else
               f'<button class=verbtn onclick="event.stopPropagation();updateAgent(\'{n}\')" '
               f'title="fetch the latest code on this agent and restart it, keeping every setting">'
               f'update to {_esc(CAIRN_VERSION)}</button>')
        ver_html = (f'<div class=jrow><span class=jk>version</span>'
                    f'<span class=jv data-ver>{_esc(ver)} {upd}</span></div>')
    elif ver:
        ver_html = f'<div class=jrow><span class=jk>version</span><span class=jv data-ver>{_esc(ver)}</span></div>'
    else:
        ver_html = ""
    cls = f"card {sev}" + (f" agenttab{' active' if active else ''}" if tab else "")
    tabattrs = f' onclick="showAgent(\'{tab}\')" data-agtab="{tab}" role=tab' if tab else ""
    return (f'<div class="{cls}" data-a="{n}"{tabattrs}><div class="ch"><span class="cn">{n}</span>'
            f'<span class="chr"><span class="cs">{cs}</span></span></div>'
            f'<div class="src">{_esc(role)}</div>'
            f'<div class=jsched><div class=jrow><span class=jk>last seen</span>'
            f'<span class=jv acls="ls">{last}</span></div>'
            f'<div class=jrow><span class=jk>reports</span><span class=jv>every {ivl}</span></div>'
            f'{ver_html}</div></div>')

def _smart_card(r):
    """A per-drive pill: identity + the stats that matter at a glance, expandable to the full
    SMART attribute table (Scrutiny-style). Data is served from the collector's TTL cache."""
    d = json.loads(r.get("detail_json") or "{}")
    nm = r["name"]; n = _esc(nm)
    sev = SEVCLS.get(r["severity"], "unk")
    acked = r.get("acked")
    card_cls, cs_text = ("ack", "ACK’D") if acked else (sev, r["severity"])
    devname = _esc((d.get("dev") or "").split("/")[-1] or nm.split(":")[-1])
    proto = (d.get("proto") or "").upper()
    kind = ("NVMe SSD" if proto == "NVME"
            else "SSD" if d.get("is_ssd")
            else f'{d.get("rotation")} rpm HDD' if d.get("rotation") else "HDD")
    ident = " · ".join(x for x in [_esc(d.get("model") or "unknown model"),
                                    (f'SN {_esc(d.get("serial"))}' if d.get("serial") else ""),
                                    _esc(kind)] if x)
    tiles = []
    hs = "PASSED" if d.get("passed") is True else ("FAILED" if d.get("passed") is False else "-")
    tiles.append(("health", hs, "ok" if d.get("passed") is True else ("crit" if d.get("passed") is False else "")))
    if d.get("capacity"):            tiles.append(("capacity", _cap(d["capacity"]), ""))
    if d.get("temp") is not None:    tiles.append(("temp", f'{d["temp"]}°C', "warn" if d["temp"] >= 50 else ""))
    if d.get("power_on_hours") is not None:
        poh = d["power_on_hours"];   tiles.append(("power-on", f"{poh/8760:.1f} y", ""))
    if d.get("power_cycles") is not None:
        tiles.append(("cycles", f'{d["power_cycles"]:,}', ""))
    if d.get("pct_used") is not None:
        pu = d["pct_used"];          tiles.append(("life used", f"{pu}%", "warn" if pu >= 80 else ""))
    for lbl, key in (("reallocated", "realloc"), ("pending", "pending"),
                     ("offline unc", "offline_unc"), ("CRC/link", "crc")):
        v = d.get(key)
        if v:                        tiles.append((lbl, str(v), "warn"))
    kpi = "".join(f'<div class="skpi {c}"><b>{_esc(v)}</b><span>{_esc(l)}</span></div>' for l, v, c in tiles)
    rows = ""
    for a in d.get("attrs", []):
        aid = "" if a.get("id") is None else a["id"]
        raw = a.get("raw")
        crit = (a.get("id") in (5, 197, 198, 199) and raw not in (None, 0, "0")) \
            or (a.get("when_failed") not in (None, "", "-"))
        def _c(x): return "-" if x is None else _esc(x)
        rows += (f'<tr class="{"bad" if crit else ""}"><td class=aid>{_c(aid)}</td>'
                 f'<td class=anm>{_esc(a.get("name") or "")}</td><td>{_c(a.get("value"))}</td>'
                 f'<td>{_c(a.get("worst"))}</td><td>{_c(a.get("thresh"))}</td>'
                 f'<td class=araw>{_c(raw)}</td></tr>')
    optin_note = ('SMART detail is opt-in - health &amp; alerts here come from smartd. To add the '
                  'attribute table: <code>grant-access.sh --smart-detail</code> + set '
                  '<code>CAIRN_SMART_DETAIL=1</code> on the agent') if d.get("detail_optin") else \
                 ('no attribute table - re-run grant-access.sh --smart-detail and restart the agent')
    tbl = (f'<table class=smt><thead><tr><th>#</th><th>Attribute</th><th>Val</th><th>Wst</th>'
           f'<th>Thr</th><th>Raw</th></tr></thead><tbody>{rows}</tbody></table>' if rows
           else f'<div class=hempty>{optin_note}</div>')
    why = _esc(", ".join(d.get("reasons", [])) or (r.get("last_error") or ""))
    why_html = f'<div class="why">{why}</div>' if why else ""
    if acked:
        ack_html = (f'<button class="ackbtn on" onclick="unackTarget(\'{nm}\')" '
                    f'title="acknowledged - click to clear">✓ acknowledged</button>')
    elif r["severity"] in ("WARN", "CRIT"):
        ack_html = f'<button class=ackbtn onclick="ackTarget(\'{nm}\')">Acknowledge</button>'
    else:
        ack_html = ""
    probed = f'<span class=smprobe title="SMART is cached and refreshed periodically, not on every poll">read {_ago(d.get("probed_ts"))}</span>' if d.get("probed_ts") else ""
    return (f'<div class="card smartcard {card_cls}" data-t="{n}"><div class="ch">'
            f'<span class="cn">{devname}</span><span class="chr">'
            f'<span class="cbusy" title="action running"></span><span class="cs">{cs_text}</span></span></div>'
            f'<div class="src">{ident}</div><div class="skpirow">{kpi}</div>{why_html}{ack_html}'
            f'<div class=chistrow><button class="histbtn" onclick="toggleSmart(this)">SMART details</button>'
            f'{probed}<div class="smdet" hidden>{tbl}</div></div></div>')

PAIR_ICON = (  # two linked nodes with an arrow: source -> off-site copy (data replication)
    '<svg class=picn viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
    'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
    '<circle cx="5" cy="12" r="2.6"/><circle cx="19" cy="12" r="2.6"/>'
    '<path d="M7.6 12h8.8"/><path d="M14 9.2l2.6 2.8-2.6 2.8"/></svg>')

def _pair_card(v, capable=frozenset(), viewer=False):
    """One merged card for a guaranteed replication pair: the source->dest relationship up top, then
    each half (the sending agent + the off-site copy) with its own severity and snapshot freshness.
    If the off-site agent is execute-capable, an admin gets a 'Replicate now' button that queues an
    on-demand pull on that agent."""
    R = v["r"]; L = v["l"]; sev = SEVCLS.get(v["severity"], "unk")
    name = _esc(R["name"])
    subtitle = f'{_esc(R.get("source") or "")} &rarr; {_esc(v["dataset"])}'
    meta = []
    if R.get("tier"): meta.append(f'tier {R["tier"]}')
    if R.get("encrypted") or L.get("encrypted"): meta.append("enc")
    if meta: subtitle += " &middot; " + " &middot; ".join(_esc(m) for m in meta)
    def half(row, role):
        sevw = row["severity"]; age_s = row.get("snap_age_src_s")
        # The SOURCE half can't compute replication lag once its dest lives on another agent, so the
        # collector marks it UNKNOWN. But home DOES know its own source-snapshot freshness - the real
        # local signal, and the '3' end of 3-2-1 for the off-site half - so show THAT rather than a
        # contradictory "UNKNOWN" sitting next to a fresh snapshot. (28h/50h = the default repl ladder.)
        if role == "source" and sevw == "UNKNOWN" and age_s is not None:
            sevw = "CRIT" if age_s >= 50 * 3600 else "WARN" if age_s >= 28 * 3600 else "OK"
        hs = SEVCLS.get(sevw, "unk")
        age = (_ago_s(age_s) + " old") if age_s is not None else "no snapshot"
        # Only show the key status for ENCRYPTED datasets; zfs reports '-' for an unencrypted one,
        # which rendered as a meaningless "key -".
        _ks = (row.get("key_status") or "").strip()
        ks = f' &middot; key {_esc(_ks)}' if _ks and _ks not in ("-", "none", "n/a") else ""
        return (f'<div class=phalf><span class=pd style="background:var(--{hs})"></span>'
                f'<div class=phinfo><b>{_esc(row.get("agent") or "?")}</b> '
                f'<span class=psev>{_esc(sevw)}</span> <span class=prole>{role}</span>'
                f'<small>{_esc(row.get("source") or "")}<br>newest snapshot {age}{ks}</small></div></div>')
    # On-demand pull: only when the off-site (L) agent can execute, and never for a read-only viewer.
    act_html = ""
    if not viewer and L.get("agent") in capable:
        act_html = ('<div class="cact"><button class=pri onclick="replicateNow('
                    f"'{_esc(L['name'])}','{_esc(L['agent'])}')\">Replicate now</button>"
                    '<button onclick="replicateNow('
                    f"'{_esc(L['name'])}','{_esc(L['agent'])}',true)\">dry-run</button></div>")
    return (f'<div class="card pair {sev}" data-t="{name}"><div class=ch>'
            f'<span class=cn>{PAIR_ICON}{name}</span><span class=chr>'
            f'<span class="cbusy" title="pull running"></span>'
            f'<span class=pbadge>replication pair</span><span class=cs>{_esc(v["severity"])}</span></span></div>'
            f'<div class=src>{subtitle}</div>'
            f'<div class=phalves>{half(R, "source")}{half(L, "off-site copy")}</div>{act_html}</div>')

def _card(r, can_act, viewer=False):
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
    subtitle = src_line or d.get("summary") or ""     # event/health cards use a summary as their subtitle
    src_html = f'<div class="src">{_esc(subtitle)}</div>' if subtitle else ""
    mr_html = f'<div class="row">{mr}</div>' if mr else ""
    why_html = f'<div class="why">{why}</div>' if why else ""
    # live scrub progress bar (pool roots only): visible while a scrub runs, hidden otherwise so the
    # 20s refresh can surgically show/update/hide it without rebuilding the card.
    sc = d.get("scrub") or {}
    scrub_html = ""
    if r["type"] == "zfs-local" and r.get("source") and "/" not in r["source"]:
        inprog = sc.get("state") == "in_progress"
        pctnum = sc.get("pct") if isinstance(sc.get("pct"), (int, float)) else None
        pctw = pctnum if pctnum is not None else 0
        pctxt = f"{pctnum:.1f}%" if pctnum is not None else ""
        etatxt = f" · {_esc(sc.get('eta'))} to go" if sc.get("eta") else ""
        scrub_html = (f'<div class=scrubprog data-scrubprog{"" if inprog else " hidden"}>'
                      f'<div class=scrubbar><span data-scrubfill style="width:{pctw}%"></span></div>'
                      f'<div class=scrublbl data-scrublbl>scrubbing {pctxt}{etatxt}</div></div>')
    # backs-up + schedule + next/last run - for scheduled jobs (backupninja, syncoid/sanoid timers)
    bu, sc = d.get("backs_up"), d.get("schedule")
    lt, nt = (d.get("last_ts") or r.get("last_run_ts")), d.get("next_ts")
    sched_html = ""
    if bu or sc or lt or nt:
        js = ""
        if bu: js += f'<div class=jrow><span class=jk>backs up</span><span class=jv>{_esc(bu)}</span></div>'
        if sc: js += f'<div class=jrow><span class=jk>schedule</span><span class=jv>{_esc(sc)}</span></div>'
        runbits = []
        if lt: runbits.append(f"last {_when(lt)}")
        if nt: runbits.append(f"next {_when(nt)}")
        if runbits: js += f'<div class=jrun>{" · ".join(runbits)}</div>'
        sched_html = f'<div class=jsched>{js}</div>'
    # per-dataset 3-2-1 badge (replication sets only): each digit green if that leg is met.
    c321_html = ""
    if r["type"] == "zfs-repl" and r.get("source") and r.get("dest"):
        pools = {(r["source"] or "").split("/")[0], (r["dest"] or "").split("/")[0]}
        pools.discard("")
        copies = media = len(pools)
        offsite = 1 if r.get("location") == "offsite" else 0
        legs = [("3", copies >= 3, f"≥3 copies - {copies} of 3"),
                ("2", media >= 2, f"≥2 media - {media}"),
                ("1", offsite >= 1, "off-site copy" if offsite else "off-site - none (on-site only)")]
        chips = "".join(f'<span class="c321p {"met" if ok else "unmet"}" title="{ti}">{d}</span>'
                        for d, ok, ti in legs)
        c321_html = f'<div class=c321><span class=c321l>3-2-1</span>{chips}</div>'
    hist_html = ""
    if r["type"] in ("zfs-repl", "zfs-local"):   # the target types that receive action intents
        hist_html = (f'<div class=chistrow><button class=histbtn data-t="{n}" onclick="toggleHist(this,\'{nm}\')">'
                     f'History</button><div class=chist hidden></div></div>')
    # collapsible job log - the real failure/warning lines captured from the journal (or backupninja log)
    log_html = ""
    jr = d.get("journal")
    if jr:
        n_lines = len(jr); log_label = _esc(d.get("log_label") or "Job log")
        log_html = (f'<div class=chistrow><button class="histbtn" onclick="toggleSmart(this)">'
                    f'{log_label} <span class=logct>{n_lines}</span></button>'
                    f'<div class="smdet" hidden><pre class=jlogpre>{_esc(chr(10).join(jr))}</pre></div></div>')
    acked = r.get("acked")
    card_cls, cs_text = ("ack", "ACK’D") if acked else (sev, r["severity"])
    if viewer:      # read-only: show the ACK'D state as a static badge, but no acknowledge control
        ack_html = ('<span class="ackbtn on" title="acknowledged">✓ acknowledged</span>' if acked else "")
    elif acked:
        ack_html = (f'<button class="ackbtn on" onclick="unackTarget(\'{nm}\')" '
                    f'title="acknowledged - click to clear">✓ acknowledged</button>')
    elif r["severity"] in ("WARN", "CRIT"):
        ack_html = f'<button class=ackbtn onclick="ackTarget(\'{nm}\')">Acknowledge</button>'
    else:
        ack_html = ""
    title = _esc(d["label"]) if d.get("label") else n     # schedule cards carry a friendly label
    # Hide: stop monitoring a target you don't care about (e.g. an OS pool or a pool you don't back
    # up). Admin-only; restorable from the Hidden pane. target_id comes from the joined status row.
    hide_html = "" if (viewer or not r.get("target_id")) else (
        f'<button class=hidebtn onclick="hideTarget({int(r["target_id"])})" '
        f'title="stop monitoring this target (restore it from the Hidden section)">Hide</button>')
    return (f'<div class="card {card_cls}" data-t="{n}"><div class="ch"><span class="cn">{title}</span>'
            f'<span class="chr"><span class="cbusy" title="action running"></span>'
            f'<span class="cs">{cs_text}</span></span></div>{src_html}{sched_html}{c321_html}{mr_html}{scrub_html}{why_html}'
            f'{ack_html}{_acts(r, can_act, viewer)}{hist_html}{log_html}{hide_html}</div>')

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
        # Show the THREE legs of 3-2-1, not one pill per dataset. A leg is met only if EVERY
        # Tier-A dataset satisfies it (the fleet is as compliant as its weakest dataset).
        mc = min(c["copies"] for c in cards); mm = min(c["media"] for c in cards)
        mo = min(c["offsite"] for c in cards)
        legs_data = [("≥3 copies",   mc >= 3, f"{mc} of 3"),
                     ("≥2 media",    mm >= 2, f"{mm} of 2"),
                     ("≥1 off-site", mo >= 1, "yes" if mo >= 1 else "on-site only")]
        pills = "".join(
            f'<div class="leg {"met" if ok else "unmet"}"><span class=legmark>{"✓" if ok else "✗"}</span>'
            f'<span class=legname>{nm}</span><span class=legval>{vl}</span></div>'
            for nm, ok, vl in legs_data)
        s_big, s_cls = f"{npass} / {ntot}", ("ok" if npass == ntot else "crit" if npass == 0 else "warn")
        s_sub = "Tier-A datasets meeting all three legs"
    else:
        pills, s_big, s_cls, s_sub = "", "-", "unk", "no Tier-A datasets defined"
    arch = [r for r in rows if r["type"] == "borg-repo" and r.get("archive_count") is not None]
    tot_arch = sum(r["archive_count"] for r in arch)
    rp_sub = f"{tot_arch} borg archives across {len(arch)} repos" if arch else "no borg repos"
    cap_cls = "crit" if gpct >= 92 else "warn" if gpct >= 85 else "ok"
    c = h["counts"]
    chips = "".join(f'<button class=sumchip data-sev={SEVCLS[k]} onclick="toggleFilter(\'{SEVCLS[k]}\')" '
                    f'title="show only {k} - click again to clear"><i style="background:var(--{SEVCLS[k]})"></i>'
                    f'<b>{c.get(k,0)}</b> {k}</button>' for k in ("OK", "WARN", "CRIT", "UNKNOWN"))
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
      <div class="sumverd {vcls}" id=sumverd>{shield}<div><div class=vt>{verdict}</div><div class=vs>{vsub}</div></div></div>
      <div class=sumchips>{chips}</div>
      <div class=sumasof>as of<br><b>{ts}</b></div>
    </div>
    <div class=sumtiles>
      <div class=stile><div class=lbl>3-2-1 coverage</div>
        <div class=big style="color:var(--{s_cls})">{s_big}</div><div class=sub>{s_sub}</div>
        <div class=legs>{pills}</div></div>
      <div class=stile><div class=lbl>Capacity · busiest pool</div>
        <div class=big style="color:var(--{cap_cls})">{gpct}%</div><div class=sub>{_esc(glabel)}</div>{meter}</div>
      <div class=stile><div class=lbl>Restore points</div>
        <div class=big>{tot_arch}</div><div class=sub>{rp_sub}</div></div>
    </div>"""

def _shell(inner):
    return (f"<!doctype html><html lang=en><head><meta charset=utf-8>"
            f"<meta name=viewport content=\"width=device-width,initial-scale=1\">"
            f"<link rel=icon href=/favicon.ico>"
            f"<title>Cairn</title>{FONTS}{PAGE_STYLE}</head><body>"
            f"<div class=panel>{inner}"
            f"<form id=lo method=post action=/logout hidden></form></div>{PAGE_SCRIPT}</body></html>")

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    viewer = getattr(request.state, "role", "admin") == "viewer"
    with db() as conn:
        rows = latest_status(conn)
        capable = {x["name"] for x in conn.execute(
            "SELECT name FROM agents WHERE can_execute=1").fetchall()}
        agents = agent_states(conn)
        overlaps = find_overlaps(conn)
        pair_views, paired_keys = pairing(conn, rows)
        retired = [] if viewer else _retired_rows(conn)   # for the Hidden pane (admins can restore)
    rows = [r for r in rows if (r["agent"], r["name"]) not in paired_keys]  # halves render as one pair card
    h = health()
    if not rows:
        return _shell(
            '<div class=hero><div class=hero-top><h2>Cairn</h2>'
            '<span class="verd unk">&#9203; Waiting for first check-in</span></div>'
            '<p class=why style="margin-top:14px;max-width:60ch">No agent has reported yet. Once an '
            'agent enrolls (see AGENT.md) it reads this host\'s ZFS / borg / backupninja and fills in '
            'the dashboard within one poll interval - nothing is wrong, it is just starting up.</p></div>')

    multi_agent = len({r.get("agent") for r in rows}) > 1
    rows.sort(key=lambda r: ((r.get("agent") or "~") if multi_agent else "", _group(r)[0], r["name"]))
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

    # Per-agent TABS: each agent's liveness card doubles as a tab; its pane holds that agent's own
    # targets (grouped by type into collapsible sections) PLUS the replication pairs it participates in.
    # A two-sided pair (home source -> vault copy) shows in BOTH halves' tabs, so the vault tab is a
    # complete off-site view. The busiest agent (home) is the default tab.
    def _slug(s): return re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-")

    def _grouped(subset, agslug):
        subset = sorted(subset, key=lambda r: (_group(r)[0], r["name"]))
        out, cur = "", None
        for r in subset:
            g = _group(r)[1]
            if g != cur:
                if cur is not None:
                    out += "</div></div></section>"
                pid = f"grp:{agslug}:{_slug(g)}"
                out += (f'<section class="pane grp" data-pane="{_esc(pid)}">'
                        f'<button class="paneh" onclick="togglePane(\'{_esc(pid)}\')">'
                        f'<span class=pt>{_esc(g)}</span><span class=pdot></span>'
                        f'<span class=pchev>&#9662;</span></button><div class=pbody><div class=cards>')
                cur = g
            out += _smart_card(r) if r["type"] == "smart" else \
                _card(r, (r.get("agent") in capable) and not viewer, viewer)
        if cur is not None:
            out += "</div></div></section>"
        return out

    def _pairs_pane(pvlist, agslug):
        if not pvlist:
            return ""
        pv = sorted(pvlist, key=lambda v: (SEV_ORDER.get(v["severity"], 9), v["r"]["name"]))
        inner = "".join(_pair_card(v, capable, viewer) for v in pv)
        pid = f"grp:{agslug}:replication"
        return (f'<section class="pane grp" data-pane="{_esc(pid)}">'
                f'<button class=paneh onclick="togglePane(\'{_esc(pid)}\')">'
                f'<span class=pt>Replication</span><span class=pdot></span>'
                f'<span class=pchev>&#9662;</span></button>'
                f'<div class=pbody><div class=cards>{inner}</div></div></section>')

    tcount = {}
    for r in rows:
        k = r.get("agent") or "?"; tcount[k] = tcount.get(k, 0) + 1
    agent_order = sorted(agents, key=lambda a: (-tcount.get(a["name"], 0), a["name"]))
    tabs_html, panes_html = "", ""
    for i, a in enumerate(agent_order):
        ag = a["name"]; agslug = _slug(ag) or "agent"; is_active = (i == 0)
        subset = [r for r in rows if (r.get("agent") or "?") == ag]
        my_pairs = [v for v in pair_views
                    if v["r"].get("agent") == ag or v["l"].get("agent") == ag]
        content = _pairs_pane(my_pairs, agslug) + _grouped(subset, agslug) \
            or '<div class=why style="padding:12px 2px">No targets reported by this agent yet.</div>'
        tabs_html += _agent_card(a, viewer, tab=agslug, active=is_active)
        panes_html += f'<div class=agentpane data-agpane="{agslug}"{"" if is_active else " hidden"}>{content}</div>'
    agents_tabs_html = (f'<div class=agenttabs role=tablist>{tabs_html}</div>{panes_html}'
                        if tabs_html else
                        '<div class=why style="padding:12px 2px">No agents enrolled yet.</div>')

    # Hidden pane: targets an admin chose to stop monitoring, each restorable. Rendered once below
    # Activity (it is the lowest-priority thing on the board), but each row is tagged with its agent
    # so filterHidden() shows only the active tab's hidden targets - the pane follows the selected tab
    # and stays hidden entirely when that agent has nothing hidden. Flat rows, no count badge: it
    # should recede, not advertise itself. Starts with `hidden` so JS filters before it ever paints.
    hidden_html = ""
    if retired:
        items = "".join(
            f'<div class=hidrow data-hagent="{_esc(_slug(x["agent"]))}">'
            f'<span class=hidn>{_esc(x["name"])}'
            f'<span class=hida>{_esc(x["agent"])} &middot; {_esc(x["type"])}</span></span>'
            f'<button class=unhidebtn onclick="unhideTarget({int(x["id"])})">Unhide</button></div>'
            for x in retired)
        hidden_html = (
            '<div class="pane hidpane" data-pane=hidden hidden>'
            '<button class=paneh onclick="togglePane(\'hidden\')"><span class=pt>Hidden</span>'
            '<span class=pchev>&#9662;</span></button>'
            f'<div class=pbody>{items}</div></div>')

    leg = ""
    for term, desc in LEGEND:
        sw = ('<span class=sw style="background:linear-gradient(90deg,var(--ok),var(--warn),var(--crit))"></span>'
              if term.startswith("OK") else "")
        leg += f"<div><dt>{sw}{term}</dt><dd>{desc}</dd></div>"

    # "Warming up" banner: if even the NEWEST status across the board is well past the slowest agent's
    # interval, the data is not current (Cairn just (re)started, or agents are behind) - say so instead
    # of letting a stale/report-only-looking board read as truth.
    now_ts = int(time.time())
    newest = max((r.get("ts") or 0) for r in rows)
    intervals = [a.get("report_interval") or 0 for a in agents if a.get("report_interval")]
    slowest = max(intervals) if intervals else 300
    warm_banner = ""
    if newest and (now_ts - newest) > max(slowest * 2, 180):
        mins = (now_ts - newest) // 60
        warm_banner = (
            '<div class=warmbanner>&#9203; <b>Warming up.</b> The newest agent check-in is '
            f'{mins} min old, so the board below may be incomplete and action buttons stay disabled '
            'until an execute-capable agent reports. If Cairn just started or restarted this clears '
            'within a poll interval; if it persists, check the Agents section for a stale agent.</div>')

    recon_banner = ""
    if overlaps and not viewer:   # reconciling is a mutating action; a viewer can't act on it
        n = len(overlaps)
        recon_banner = (
            '<div class=reconbanner>&#9878; '
            f'{n} target overlap{"s" if n != 1 else ""} to reconcile - a replication and a direct '
            'monitor point at the same dataset (e.g. an off-site copy that moved to a vault). '
            '<button class=reconbtn onclick="openReconcile()">Reconcile</button></div>')

    c = h["counts"]; ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(h["ts"]))
    verdict = {"OK": "All healthy", "WARN": "Attention", "CRIT": "Critical",
               "UNKNOWN": "Unknown"}.get(h["severity"], h["severity"])
    vcls = SEVCLS.get(h["severity"], "unk")
    steel_hero = _hero_steel(rows, h, gpct, glabel)
    dry_html = "" if viewer else (
        '<label class=drysw title="When on, every action runs a safe dry-run probe (native -n / read-only) instead of executing">'
        '<input type=checkbox id=drychk onchange="setDry(this.checked)"><span>Dry-run</span></label>')
    ro_badge = '<span class=robadge title="read-only account - viewing only">read-only</span>' if viewer else ""
    return _shell(f"""
  <div class=topbar2><h2 class=applogo>Cairn</h2>
    <div class=seg role=tablist>
      <button data-h=steel onclick="setHero('steel')">Summary</button>
      <button data-h=heat onclick="setHero('heat')">14-day fleet</button></div>
    {ro_badge}{dry_html}
    <a class=signout href=# onclick="lo.submit();return false">sign out</a></div>
  {warm_banner}{recon_banner}
  <div id=hero-steel class=herox>{steel_hero}</div>
  <div id=hero-heat class=herox><div class=hero>
    <div class=hero-top><span class="verd {vcls}" id=heatverd>{verdict}</span>
      <span class=tag id=heattag>{h['targets']} targets · {c.get('OK',0)} ok · {c.get('WARN',0)} warn · {c.get('CRIT',0)} crit · as of {ts}</span></div>
    <div class=heat><div class=heatspan>Last 14 days &nbsp;·&nbsp; {heat_span}</div>
      <table>{heat_rows}</table></div></div></div>
  <div class=split>
    <div class=rail>
      <div class=gauge-wrap><canvas id=gauge width=300 height=300></canvas>
        <div class=gauge-cap>Busiest pool<span>{glabel} · {gpct}% used</span></div></div>
      <div class=railsec><h3>Coverage gaps</h3><div id=gapsbody>{gaps_html}</div></div>
    </div>
    <div class=main>{agents_tabs_html}
      <div class="pane actpane" data-pane=acts>
        <button class=paneh onclick="togglePane('acts')"><span class=pt>Activity</span><span class=pcount id=actcount></span><span class=pdot></span><span class=pchev>&#9662;</span></button>
        <div class=pbody><div id=actlog><span class=amsg>idle - actions stream here.</span></div></div></div>
      {hidden_html}</div>
    <div class=legend><h3>Metric key</h3><dl class=lg>{leg}</dl></div>
  </div>
  <div id=reconmodal class=modalwrap hidden onclick="if(event.target===this)closeReconcile()">
    <div class=modalbox>
      <div class=modalhd>Reconcile target overlaps<button class=modalx onclick="closeReconcile()">&times;</button></div>
      <div id=reconbody class=modalbody></div>
    </div></div>
  <div id=recmodal class=modalwrap hidden onclick="if(event.target===this)closeRec()">
    <div class=modalbox>
      <div class=modalhd><span id=rectitle>Recovery</span>
        <span class=rechdbtns><button class=recrefresh id=recrefresh onclick="recRefresh()" title="re-run the scan (bypass cache)" hidden>Refresh</button>
        <button class=modalx onclick="closeRec()">&times;</button></span></div>
      <div id=recbody class=modalbody></div>
    </div></div>
  <script>var GP={{pct:{gpct},label:"{glabel}"}};</script>""")
