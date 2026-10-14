#!/usr/bin/env python3
"""cairn-agent-rename - rename an agent in the API's database, keeping its history.

The API files everything an agent reports under the agent's name (CAIRN_AGENT_NAME): its targets and
their status history, retired targets, removable-drive links, past actions. Changing only the
agent's CAIRN_AGENT_NAME would leave a silent ghost agent (which alerts) and start every card over
under the new name. This renames the agent across the database in one transaction instead.

Run it ON THE API HOST, inside the API container, with the agent STOPPED:

  # 1. on the agent's host
  systemctl --user stop cairn-agent
  # 2. on the API host (backs up the database first, then renames)
  docker compose exec api python3 /app/phase1/cairn-agent-rename.py local mclife --force
  #    (podman: podman compose exec ...; --dry-run first to see what changes; --force because the
  #    agent was only just stopped)
  # 3. on the agent's host: set CAIRN_AGENT_NAME=mclife where the agent reads it (the unit's
  #    Environment= line wins over cairn.env), then
  systemctl --user start cairn-agent
  # 4. in OTHER agents' targets.yaml: any dest_agent / source_agent naming the old name

Refuses when the new name is already in use, or when the old agent reported recently (it would
re-create the old name on its next report). A just-stopped agent looks the same, so after stopping it
re-run with --force. Start the agent under the new name only after the rename succeeded: starting it
first creates the new name as a separate, empty agent, and the rename then refuses. Tokens keep working: they
aren't bound to the name, but the enrollment token's label is renamed too when it matches.

Env: CAIRN_DB (default /data/cairn.db, the container's path)
"""
import argparse, os, re, shutil, sqlite3, sys, time

DB = os.environ.get("CAIRN_DB", "/data/cairn.db")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def agent_columns(c):
    """[(table, column)] for every column literally named 'agent' (future tables included)."""
    out = []
    for (t,) in c.execute("SELECT name FROM sqlite_master WHERE type='table'"):
        for col in c.execute(f"PRAGMA table_info({t})"):
            if col[1] == "agent":
                out.append((t, "agent"))
    return out


def _cols(c, table):
    return {r[1] for r in c.execute(f"PRAGMA table_info({table})")}


def plan(c, old, new):
    """[(description, sql, params, rowcount)] of every change, or raises SystemExit with the reason."""
    if not NAME_RE.match(new):
        sys.exit(f"'{new}' isn't a valid agent name (letters, digits, . _ -; up to 64)")
    if old == new:
        sys.exit("old and new names are the same")
    if not c.execute("SELECT 1 FROM agents WHERE name=?", (old,)).fetchone():
        names = ", ".join(r[0] for r in c.execute("SELECT name FROM agents ORDER BY name"))
        sys.exit(f"no agent named '{old}' (agents: {names})")
    if c.execute("SELECT 1 FROM agents WHERE name=?", (new,)).fetchone():
        sys.exit(f"an agent named '{new}' already exists; pick another name")
    cols = agent_columns(c)
    for t, col in cols:
        if c.execute(f"SELECT 1 FROM {t} WHERE {col}=? LIMIT 1", (new,)).fetchone():
            sys.exit(f"'{new}' already has rows in {t}; pick another name")
    steps = []
    def step(desc, sql, params, count_sql, count_params):
        n = c.execute(count_sql, count_params).fetchone()[0]
        if n:
            steps.append((desc, sql, params, n))
    step("agents", "UPDATE agents SET name=? WHERE name=?", (new, old),
         "SELECT COUNT(*) FROM agents WHERE name=?", (old,))
    for t, col in cols:
        step(f"{t}.{col}", f"UPDATE {t} SET {col}=? WHERE {col}=?", (new, old),
             f"SELECT COUNT(*) FROM {t} WHERE {col}=?", (old,))
    if "claimed_by" in _cols(c, "intents"):
        step("intents.claimed_by (action history)", "UPDATE intents SET claimed_by=? WHERE claimed_by=?",
             (new, old), "SELECT COUNT(*) FROM intents WHERE claimed_by=?", (old,))
    # "keep both" reconcile dismissals are keyed "agent:name|agent:name"
    pairs = [r[0] for r in c.execute("SELECT pair FROM reconcile_dismissed")] if _has(c, "reconcile_dismissed") else []
    for p in pairs:
        parts = p.split("|")
        np = "|".join((new + s[len(old):]) if s.startswith(old + ":") else s for s in parts)
        if np != p:
            steps.append((f"reconcile_dismissed '{p}'", "UPDATE OR IGNORE reconcile_dismissed SET pair=? WHERE pair=?",
                          (np, p), 1))
    if _has(c, "auth_tokens"):
        tc = _cols(c, "auth_tokens")
        if "label" in tc and not c.execute("SELECT 1 FROM auth_tokens WHERE label=?", (new,)).fetchone():
            step("auth_tokens.label (enrollment token)", "UPDATE auth_tokens SET label=? WHERE label=?", (new, old),
                 "SELECT COUNT(*) FROM auth_tokens WHERE label=?", (old,))
        if "parent" in tc:
            step("auth_tokens.parent (its access tokens)", "UPDATE auth_tokens SET parent=? WHERE parent=?",
                 (new, old), "SELECT COUNT(*) FROM auth_tokens WHERE parent=?", (old,))
    return steps


def _has(c, table):
    return bool(c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone())


def recently_active(c, old, now=None):
    """Seconds since the old agent last reported, when that's within ~2 of its report cycles."""
    now = now or int(time.time())
    r = c.execute("SELECT last_report_ts, report_interval FROM agents WHERE name=?", (old,)).fetchone()
    if not r or not r[0]:
        return None
    age = now - r[0]
    return age if age < max(2 * (r[1] or 120), 600) else None


def backup(db):
    dest = f"{db}.bak-rename-{time.strftime('%Y%m%d-%H%M%S')}"
    need = os.path.getsize(db)
    free = shutil.disk_usage(os.path.dirname(os.path.abspath(db))).free
    if free < need * 1.2:
        sys.exit(f"not enough free space for a backup ({need >> 20} MiB needed, {free >> 20} MiB free); "
                 "free some space or pass --no-backup")
    src = sqlite3.connect(db)
    with sqlite3.connect(dest) as d:
        src.backup(d)
    src.close()
    return dest


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("old"); ap.add_argument("new")
    ap.add_argument("--dry-run", action="store_true", help="show what would change, change nothing")
    ap.add_argument("--force", action="store_true", help="rename even though the old agent reported recently")
    ap.add_argument("--no-backup", action="store_true", help="skip the database backup")
    ap.add_argument("--db", default=DB)
    a = ap.parse_args()
    if not os.path.isfile(a.db):
        sys.exit(f"no database at {a.db} (run this inside the API container, or set CAIRN_DB / --db)")
    c = sqlite3.connect(a.db, timeout=30)
    steps = plan(c, a.old, a.new)
    print(f"rename agent '{a.old}' -> '{a.new}' in {a.db}:")
    for desc, _, _, n in steps:
        print(f"  {desc}: {n} row(s)")
    age = recently_active(c, a.old)
    if age is not None and not a.force and not a.dry_run:
        sys.exit(f"'{a.old}' reported {age}s ago. If it's still running it would re-create '{a.old}' on its next "
                 "report, so stop it first (systemctl --user stop cairn-agent on its host). The database can't tell "
                 "a just-stopped agent from a running one: once it's stopped, re-run with --force. Don't start it "
                 "under the new name until this has succeeded")
    if a.dry_run:
        print("dry run: nothing changed")
        return 0
    c.close()
    if not a.no_backup:
        print(f"  backup: {backup(a.db)}")
    c = sqlite3.connect(a.db, timeout=30)
    try:
        c.execute("BEGIN IMMEDIATE")
        steps = plan(c, a.old, a.new)          # re-check under the write lock
        for _, sql, params, _ in steps:
            c.execute(sql, params)
        c.commit()
    except BaseException:
        c.rollback()
        raise
    print(f"done. Now, on that agent's host: set CAIRN_AGENT_NAME={a.new} where the agent reads it (the unit's\n"
          f"Environment= line wins over cairn.env) and start it. Then change any dest_agent / source_agent\n"
          f"'{a.old}' in OTHER agents' targets.yaml; the dashboard's configuration banner lists any left.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
