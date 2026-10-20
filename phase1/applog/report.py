"""Reading the log back: the numbers for a range, by action and by day, and a searchable page of rows.

Percentiles come from SQL (ORDER BY ms LIMIT 1 OFFSET n), never by pulling every duration into Python. Days before
today come from the daily rollup, which outlives the raw rows.
"""
import datetime as dt
import json
import sqlite3

from . import core

RANGES = {"1": 1, "7": 7, "30": 30, "90": 90, "all": None}
PAGE = 150


def _since(days):
    span = RANGES.get(str(days), 7)
    if span is None:
        return "0000"
    return (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=span)).strftime("%Y-%m-%d %H:%M:%S")


def percentile(con, where, args, p=0.95):
    t = core.cfg().table
    n = con.execute(f"SELECT COUNT(*) FROM {t} WHERE {where} AND ms IS NOT NULL", args).fetchone()[0]
    if not n:
        return None, None
    off = min(n - 1, max(0, int(n * p + 0.5) - 1))
    v = con.execute(f"SELECT ms FROM {t} WHERE {where} AND ms IS NOT NULL ORDER BY ms LIMIT 1 OFFSET ?",
                    args + [off]).fetchone()[0]
    top = con.execute(f"SELECT MAX(ms) FROM {t} WHERE {where}", args).fetchone()[0]
    return v, top


def report(days="7", q="", kind="", problems=False, before=None, who=""):
    t = core.cfg().table
    since = _since(days)
    where, args = ["at >= ?"], [since]
    if kind:
        where.append("kind = ?"), args.append(kind)
    if who:
        where.append("who = ?"), args.append(who)
    if q:
        like = f"%{q}%"
        where.append("(path LIKE ? OR form LIKE ? OR changes LIKE ? OR error LIKE ? OR who LIKE ? OR rid = ?)")
        args += [like] * 5 + [q]
    if problems:
        where.append(core.PROBLEM)
    con = core._connect()
    try:
        page = where + (["id < ?"] if before else [])
        rows = [dict(r) for r in con.execute(f"SELECT * FROM {t} WHERE {' AND '.join(page)} ORDER BY id DESC LIMIT ?",
                                             args + ([before] if before else []) + [PAGE + 1])]
        one = lambda sql: con.execute(sql, (since,)).fetchone()[0]
        p95, slowest = percentile(con, "at >= ? AND method IS NOT NULL", [since])
        stats = {
            "requests": one(f"SELECT COUNT(*) FROM {t} WHERE at >= ? AND method IS NOT NULL"),
            "changes": one(f"SELECT COUNT(*) FROM {t} WHERE at >= ? AND method NOT IN ('GET','HEAD')"),
            "failed": one(f"SELECT COUNT(*) FROM {t} WHERE at >= ? AND (status >= 500 OR error IS NOT NULL)"),
            "refused": one(f"SELECT COUNT(*) FROM {t} WHERE at >= ? AND status BETWEEN 400 AND 499"),
            "reported": one(f"SELECT COUNT(*) FROM {t} WHERE at >= ? AND method IS NULL AND source != 'job' "
                            f"AND {core.PROBLEM}"),
            # A job's crash, or a failure a worker reported through /events (source job, kind job:stt-failed).
            "jobs_failed": one(f"SELECT COUNT(*) FROM {t} WHERE at >= ? AND source = 'job' AND {core.PROBLEM}"),
            "people": one(f"SELECT COUNT(DISTINCT who) FROM {t} WHERE at >= ?"),
            "p95": p95, "slowest": slowest,
        }
        kinds = []
        for r in con.execute(f"SELECT kind, COUNT(*) AS n, SUM({core.PROBLEM}) AS failed FROM {t} WHERE at >= ? "
                             f"GROUP BY kind ORDER BY n DESC LIMIT 60", (since,)):
            kp95, kmax = percentile(con, "at >= ? AND kind = ?", [since, r["kind"]])
            kinds.append({"kind": r["kind"], "n": r["n"], "failed": r["failed"] or 0, "p95": kp95, "slowest": kmax})
        by_day = _by_day(con, since)
    finally:
        con.close()
    for r in rows:
        for k in ("form", "changes"):
            try:
                r[k] = json.loads(r[k]) if r[k] else None
            except ValueError:
                pass
        r["problem"] = bool((r["status"] or 0) >= 500 or r["error"]
                            or r["kind"].endswith((":error", ":crash", "-failed")))
    more = len(rows) > PAGE
    return {"stats": stats, "kinds": kinds, "by_day": by_day, "entries": rows[:PAGE],
            "next_before": rows[PAGE - 1]["id"] if more else None, "keep_days": core.cfg().keep_days,
            "version": core.VERSION}


def _by_day(con, since):
    t = core.cfg().table
    today = dt.datetime.now(dt.timezone.utc).date().isoformat()
    days = {}
    for r in con.execute(f"SELECT day, SUM(n) AS n, SUM(failed) AS failed, MAX(p95) AS p95 FROM {t}_daily "
                         f"WHERE day >= ? AND day < ? GROUP BY day", (since[:10], today)):
        days[r["day"]] = {"day": r["day"], "n": r["n"], "failed": r["failed"], "p95": r["p95"]}
    for r in con.execute(f"SELECT substr(at, 1, 10) AS day, COUNT(*) AS n, SUM({core.PROBLEM}) AS failed FROM {t} "
                         f"WHERE at >= ? GROUP BY day", (max(since, today),)):
        p95, _ = percentile(con, "at >= ? AND method IS NOT NULL", [today])
        days[r["day"]] = {"day": r["day"], "n": r["n"], "failed": r["failed"] or 0, "p95": p95}
    # a day the rollup hasn't reached yet (first run after an upgrade) still shows, from the raw rows
    for r in con.execute(f"SELECT substr(at, 1, 10) AS day, COUNT(*) AS n, SUM({core.PROBLEM}) AS failed FROM {t} "
                         f"WHERE at >= ? AND at < ? GROUP BY day", (since, today)):
        days.setdefault(r["day"], {"day": r["day"], "n": r["n"], "failed": r["failed"] or 0, "p95": None})
    return sorted(days.values(), key=lambda d: d["day"], reverse=True)[:400]


def rollup(con, today):
    """Summarize each finished day not yet summarized: per action, count, problems, p95 and max."""
    t = core.cfg().table
    con.row_factory = sqlite3.Row
    done = {r[0] for r in con.execute(f"SELECT DISTINCT day FROM {t}_daily")}
    raw = [r[0] for r in con.execute(f"SELECT DISTINCT substr(at, 1, 10) FROM {t} WHERE at < ?", (today.isoformat(),))]
    for day in raw:
        if day in done or len(day) != 10:
            continue
        nxt = (dt.date.fromisoformat(day) + dt.timedelta(days=1)).isoformat()
        for r in con.execute(f"SELECT kind, COUNT(*) AS n, SUM({core.PROBLEM}) AS failed FROM {t} "
                             f"WHERE at >= ? AND at < ? GROUP BY kind", (day, nxt)).fetchall():
            p95, top = percentile(con, "at >= ? AND at < ? AND kind = ?", [day, nxt, r["kind"]])
            con.execute(f"INSERT OR REPLACE INTO {t}_daily (day, kind, n, failed, p95, max) VALUES (?,?,?,?,?,?)",
                        (day, r["kind"], r["n"], r["failed"] or 0, p95, top))
    con.commit()
