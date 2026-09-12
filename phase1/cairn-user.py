#!/usr/bin/env python3
"""cairn-user - manage named password accounts for the Cairn dashboard.

Passwords are never stored: only a salted PBKDF2-SHA256 hash (same hash-at-rest posture as tokens).
A successful login mints a short-lived session token whose role is copied from the account, so a
person signs in with a username + password instead of pasting a raw token.

  cairn-user.py add   alice --role admin        # prompts for a password (twice)
  cairn-user.py add   demo  --role viewer        # read-only account
  cairn-user.py add   bob   --role viewer --password-stdin < pw.txt
  cairn-user.py passwd alice                      # change a password
  cairn-user.py role  bob --role admin            # change a role
  cairn-user.py list
  cairn-user.py disable bob                        # keep the row, block login
  cairn-user.py enable  bob
  cairn-user.py remove  bob

Env: CAIRN_DB (default /var/lib/cairn/cairn.db)
"""
import argparse, getpass, hashlib, os, secrets, sqlite3, sys, time

DB = os.environ.get("CAIRN_DB", "/var/lib/cairn/cairn.db")
ROLES = ("admin", "viewer")

def _pw_hash(pw, salt=None, iters=200_000):
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iters)
    return f"pbkdf2_sha256${iters}${salt.hex()}${dk.hex()}"

def _c():
    os.makedirs(os.path.dirname(DB) or ".", exist_ok=True)
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row
    c.execute("""CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY, pass_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'viewer', created_ts INTEGER, active INTEGER DEFAULT 1)""")
    return c

def _kill_sessions(c, username):
    """Invalidate any live session tokens for this account, so a password change, role change,
    disable, or removal takes effect immediately instead of waiting for the session to expire.
    The API records the owning username in each session token's `parent` column, matched here exactly."""
    return c.execute("UPDATE auth_tokens SET active=0 WHERE kind='session' AND active=1 AND parent=?",
                     (username,)).rowcount

def _read_pw(args, confirm):
    if getattr(args, "password_stdin", False):
        pw = sys.stdin.readline().rstrip("\n")
    else:
        pw = getpass.getpass("password: ")
        if confirm and pw != getpass.getpass("confirm : "):
            sys.exit("passwords do not match")
    if not pw:
        sys.exit("empty password")
    return pw

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add");    a.add_argument("username"); a.add_argument("--role", choices=ROLES, default="viewer"); a.add_argument("--password-stdin", action="store_true")
    p = sub.add_parser("passwd"); p.add_argument("username"); p.add_argument("--password-stdin", action="store_true")
    r = sub.add_parser("role");   r.add_argument("username"); r.add_argument("--role", choices=ROLES, required=True)
    sub.add_parser("list")
    for name in ("disable", "enable", "remove"):
        sp = sub.add_parser(name); sp.add_argument("username")
    args = ap.parse_args()
    c = _c()
    now = int(time.time())

    if args.cmd == "add":
        pw = _read_pw(args, confirm=True)
        try:
            c.execute("INSERT INTO users(username,pass_hash,role,created_ts,active) VALUES(?,?,?,?,1)",
                      (args.username, _pw_hash(pw), args.role, now))
            c.commit()
        except sqlite3.IntegrityError:
            sys.exit(f"user '{args.username}' already exists (use passwd / role)")
        print(f"added {args.username} (role={args.role})")
    elif args.cmd == "passwd":
        pw = _read_pw(args, confirm=True)
        n = c.execute("UPDATE users SET pass_hash=? WHERE username=?", (_pw_hash(pw), args.username)).rowcount
        k = _kill_sessions(c, args.username) if n else 0
        c.commit()
        if not n: sys.exit(f"no such user '{args.username}'")
        print(f"password changed for {args.username}" + (f" ({k} session(s) signed out)" if k else ""))
    elif args.cmd == "role":
        n = c.execute("UPDATE users SET role=? WHERE username=?", (args.role, args.username)).rowcount
        k = _kill_sessions(c, args.username) if n else 0   # force re-login so the new role takes effect
        c.commit()
        if not n: sys.exit(f"no such user '{args.username}'")
        print(f"{args.username} -> role={args.role}" + (f" ({k} session(s) signed out)" if k else ""))
    elif args.cmd == "list":
        for u in c.execute("SELECT username,role,active,created_ts FROM users ORDER BY role,username"):
            made = time.strftime("%Y-%m-%d", time.localtime(u["created_ts"])) if u["created_ts"] else "?"
            print(f"  [{'x' if u['active'] else ' '}] {u['role']:6} {u['username']:20} added {made}")
    elif args.cmd in ("disable", "enable"):
        n = c.execute("UPDATE users SET active=? WHERE username=?",
                      (1 if args.cmd == "enable" else 0, args.username)).rowcount
        k = _kill_sessions(c, args.username) if (n and args.cmd == "disable") else 0
        c.commit()
        if not n: sys.exit(f"no such user '{args.username}'")
        print(f"{args.cmd}d {args.username}" + (f" ({k} session(s) signed out)" if k else ""))
    elif args.cmd == "remove":
        k = _kill_sessions(c, args.username)
        n = c.execute("DELETE FROM users WHERE username=?", (args.username,)).rowcount
        c.commit()
        if not n: sys.exit(f"no such user '{args.username}'")
        print(f"removed {args.username}" + (f" ({k} session(s) signed out)" if k else ""))

if __name__ == "__main__":
    main()
