#!/usr/bin/env python3
"""bmtoken - mint / list / revoke backup-monitor auth tokens directly in the DB.

Same hash-at-rest store the API uses (only sha256(token) is stored). For operators with DB
access - handy to bootstrap per-agent tokens before the API is reachable, or offline.

  bmtoken.py mint --role agent --label vault    # prints the token ONCE
  bmtoken.py mint --role admin --label me
  bmtoken.py list
  bmtoken.py revoke --label vault

Env: BM_DB (default /var/lib/backup-monitor/backup-monitor.db)
"""
import argparse, hashlib, os, secrets, sqlite3, sys, time

DB = os.environ.get("BM_DB", "/var/lib/backup-monitor/backup-monitor.db")

def _h(t):
    return hashlib.sha256(t.encode()).hexdigest()

def _c():
    os.makedirs(os.path.dirname(DB) or ".", exist_ok=True)
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row
    c.execute("""CREATE TABLE IF NOT EXISTS auth_tokens(
        hash TEXT PRIMARY KEY, role TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'access',
        label TEXT UNIQUE, parent TEXT, expires_ts INTEGER,
        created_ts INTEGER, last_used_ts INTEGER, active INTEGER DEFAULT 1)""")
    return c

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("mint"); m.add_argument("--role", required=True, choices=["admin", "agent"])
    m.add_argument("--label", required=True)
    m.add_argument("--kind", choices=["admin", "enroll", "access"],
                   help="default: admin->admin, agent->enroll (a per-agent enrollment secret)")
    sub.add_parser("list")
    rv = sub.add_parser("revoke"); rv.add_argument("--label", required=True)
    a = ap.parse_args()
    c = _c()
    if a.cmd == "mint":
        kind = a.kind or ("admin" if a.role == "admin" else "enroll")
        tok = secrets.token_hex(32)
        try:
            c.execute("INSERT INTO auth_tokens(hash,role,kind,label,created_ts,active) VALUES(?,?,?,?,?,1)",
                      (_h(tok), a.role, kind, a.label, int(time.time())))
            c.commit()
        except sqlite3.IntegrityError:
            sys.exit(f"label '{a.label}' already exists")
        var = "BM_ENROLL_SECRET" if kind == "enroll" else "BM_API_TOKEN/admin token"
        print(f"role={a.role} kind={kind} label={a.label}\nSECRET: {tok}\n"
              f"(save now - only its hash is stored; put it on the agent as {var})")
    elif a.cmd == "list":
        for r in c.execute("SELECT label,role,active,created_ts,last_used_ts FROM auth_tokens ORDER BY role,label"):
            used = time.strftime("%Y-%m-%d %H:%M", time.localtime(r["last_used_ts"])) if r["last_used_ts"] else "never"
            print(f"  [{'x' if r['active'] else ' '}] {r['role']:5} {r['label']:20} last-used {used}")
    elif a.cmd == "revoke":
        if a.label == "bootstrap-admin":
            print("note: bootstrap-admin is re-seeded from BM_ADMIN_TOKEN at API startup; unset that env too")
        n = c.execute("UPDATE auth_tokens SET active=0 WHERE label=?", (a.label,)).rowcount
        c.commit()
        print(f"revoked {n} token(s) labelled '{a.label}'")

if __name__ == "__main__":
    main()
