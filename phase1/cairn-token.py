#!/usr/bin/env python3
"""cairn-token - mint / list / revoke cairn auth tokens directly in the DB.

Same hash-at-rest store the API uses (only sha256(token) is stored). For operators with DB
access - handy to bootstrap per-agent tokens before the API is reachable, or offline.

  cairn-token.py mint --role agent  --label vault    # prints the token ONCE
  cairn-token.py mint --role admin  --label me
  cairn-token.py mint --role viewer --label demo     # read-only share token (no expiry)
  cairn-token.py list
  cairn-token.py revoke --label vault

Env: CAIRN_DB (default /var/lib/cairn/cairn.db)
"""
import argparse, hashlib, os, secrets, sqlite3, sys, time

DB = os.environ.get("CAIRN_DB", "/var/lib/cairn/cairn.db")

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
    m = sub.add_parser("mint"); m.add_argument("--role", required=True, choices=["admin", "agent", "viewer"])
    m.add_argument("--label", required=True)
    m.add_argument("--kind", choices=["admin", "enroll", "access", "ui"],
                   help="default: admin->admin, viewer->ui (shareable RO token), agent->enroll")
    sub.add_parser("list")
    rv = sub.add_parser("revoke"); rv.add_argument("--label", required=True)
    a = ap.parse_args()
    c = _c()
    if a.cmd == "mint":
        kind = a.kind or {"admin": "admin", "viewer": "ui"}.get(a.role, "enroll")
        tok = secrets.token_hex(32)
        try:
            c.execute("INSERT INTO auth_tokens(hash,role,kind,label,created_ts,active) VALUES(?,?,?,?,?,1)",
                      (_h(tok), a.role, kind, a.label, int(time.time())))
            c.commit()
        except sqlite3.IntegrityError:
            sys.exit(f"label '{a.label}' already exists")
        hint = {"enroll": "put it on the agent as CAIRN_ENROLL_SECRET",
                "ui": "share it, or send a link to /login?token=<this>"}.get(
                    kind, "use it as the admin token / CAIRN_API_TOKEN")
        print(f"role={a.role} kind={kind} label={a.label}\nSECRET: {tok}\n"
              f"(save now - only its hash is stored; {hint})")
    elif a.cmd == "list":
        for r in c.execute("SELECT label,role,active,created_ts,last_used_ts FROM auth_tokens ORDER BY role,label"):
            used = time.strftime("%Y-%m-%d %H:%M", time.localtime(r["last_used_ts"])) if r["last_used_ts"] else "never"
            print(f"  [{'x' if r['active'] else ' '}] {r['role']:5} {r['label']:20} last-used {used}")
    elif a.cmd == "revoke":
        if a.label == "bootstrap-admin":
            print("note: bootstrap-admin is re-seeded from CAIRN_ADMIN_TOKEN at API startup; unset that env too")
        n = c.execute("UPDATE auth_tokens SET active=0 WHERE label=?", (a.label,)).rowcount
        c.commit()
        print(f"revoked {n} token(s) labelled '{a.label}'")

if __name__ == "__main__":
    main()
