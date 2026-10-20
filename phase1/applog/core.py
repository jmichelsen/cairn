"""The debug log: one row per request, background pass and client event, in the app's own SQLite.

Standard library only. The adapters (httpserver, flask_ext, asgi) call begin() when a request starts and finish()
when its response is ready; jobs use `with job("name")`. Everything a request or job writes through a traced
connection (attach/connect) is recorded, masked by the app's column declarations. See docs/RULES.md.
"""
import contextvars
import datetime as dt
import hashlib
import hmac
import json
import re
import secrets as _secrets
import sqlite3
import sys
import threading
import time
import traceback
from contextlib import contextmanager
from dataclasses import dataclass, field

from . import sqlmask

VERSION = "0.1.7"

SECRET_FIELD = re.compile(r"pass|^pw$|token|secret|^key$|_key$|credential|signature|auth|cookie|session", re.I)
EVENT_KIND = re.compile(r"^[a-z][a-z0-9_.:-]{0,59}$")
PROBLEM = ("(status >= 500 OR error IS NOT NULL OR kind LIKE '%:error' OR kind LIKE '%:crash' "
           "OR kind LIKE '%-failed')")


@dataclass
class Config:
    db_path: object                       # a path, or a function returning one (tests repoint it)
    app: str = "app"                      # names the client header, X-<App>-App, and the stdout logger
    table: str = "activity"
    # What a write may show. Every column of every table must be in one of these; check_declared() fails otherwise.
    columns: dict = field(default_factory=dict)         # {table: {loggable columns}}
    secret_columns: dict = field(default_factory=dict)  # {table: {columns never shown}}
    secret_tables: set = field(default_factory=set)     # statements reduced to "-- INSERT tokens (hidden)"
    secret_rows: dict = field(default_factory=dict)     # {table: (key column, {keys})}: settings' token rows
    ignore_tables: set = field(default_factory=set)     # not checked (caches, FTS shadow tables)
    # What a request may show of what was sent: off unless the route's kind is listed.
    send: dict = field(default_factory=dict)            # {kind: {fields} | True (all fields, secret names masked)}
    never_send: set = field(default_factory=set)        # kinds that never show what was sent, whatever send says
    anonymous: set = field(default_factory=set)         # kinds logged with no person, rid, form or SQL; date only
    strict: bool = False                                # people logged only as a code that changes daily, and
                                                        # tracebacks keep frames and types, never exception messages
    pseudonym_key: bytes = b""                          # HMAC key for codes; from the app's secret
    secret_paths: list = field(default_factory=list)    # regexes; group 1 of each is masked in logged paths
    private_query: set = field(default_factory=set)     # query names whose values are masked: search words (?q=)
    routes: list = field(default_factory=list)          # [(regex on the path, "kind")] for slugs: /quotes/[A-Z]+
    strip_prefix: str = ""                              # "/api/v1": kinds read "POST /settings"
    reads: str = "slow"                                 # all | slow (slow or failed reads only) | none
    slow_ms: int = 1000
    quiet: set = field(default_factory=set)             # paths with no row and no line (health checks); one
                                                        # ending in "/" covers everything under it (/static/)
    skip_kinds: set = field(default_factory=set)        # kinds with no row (the /events post, reading the log)
    keep_days: int = 400
    sources: set = field(default_factory=lambda: {"web", "app", "app:widget", "app:worker", "device", "guest"})
    client_batch: int = 50
    client_value: int = 4000
    client_daily: int = 2000                            # rows per client per day from /events
    stdout: bool = True


_cfg = None
_rec = contextvars.ContextVar("applog_rec", default=None)
_forever = set()             # secrets known for the life of the process
_maintained = {"day": None}
_daily_counts = {}           # (who, day) -> client events today
_orphans = {"stmts": [], "since": 0.0}
_lock = threading.Lock()
MAX_CHANGES, MAX_STATEMENT, MAX_FIELD = 200, 600, 400


def configure(**kw):
    """Set the app's rules and make sure the log tables exist. Call once at startup, before the first request."""
    global _cfg
    _cfg = Config(**kw)
    with _connect() as con:
        ensure_schema(con)
    return _cfg


def cfg():
    if _cfg is None:
        raise RuntimeError("applog.configure() hasn't been called")
    return _cfg


def _db_path():
    p = cfg().db_path
    return p() if callable(p) else p


def _connect():
    con = sqlite3.connect(_db_path(), timeout=5)
    con.row_factory = sqlite3.Row
    return con


COLUMNS = (("id", "INTEGER PRIMARY KEY"), ("at", "TEXT NOT NULL"), ("rid", "TEXT"), ("source", "TEXT NOT NULL"),
           ("who", "TEXT"), ("kind", "TEXT NOT NULL"), ("method", "TEXT"), ("path", "TEXT"), ("status", "INTEGER"),
           ("ms", "INTEGER"), ("form", "TEXT"), ("changes", "TEXT"), ("error", "TEXT"), ("client", "TEXT"),
           ("client_at", "TEXT"))


def ensure_schema(con):
    t = cfg().table
    con.execute(f"CREATE TABLE IF NOT EXISTS {t} ({', '.join(f'{n} {d}' for n, d in COLUMNS)})")
    have = {r[1] for r in con.execute(f"PRAGMA table_info({t})")}
    for n, d in COLUMNS:
        if n not in have:
            con.execute(f"ALTER TABLE {t} ADD COLUMN {n} {d.replace(' NOT NULL', '')}")
    con.execute(f"CREATE INDEX IF NOT EXISTS {t}_at ON {t}(at)")
    con.execute(f"CREATE INDEX IF NOT EXISTS {t}_kind ON {t}(kind, at)")
    con.execute(f"CREATE INDEX IF NOT EXISTS {t}_rid ON {t}(rid)")
    # One row per day and action, kept for good: the long view after the raw rows are pruned.
    con.execute(f"CREATE TABLE IF NOT EXISTS {t}_daily (day TEXT NOT NULL, kind TEXT NOT NULL, n INTEGER NOT NULL, "
                f"failed INTEGER NOT NULL, p95 INTEGER, max INTEGER, PRIMARY KEY (day, kind))")
    con.commit()


def app_header():
    """The header each app's client sends its version in: X-Suisha-App, X-Feast-App."""
    return f"X-{cfg().app.capitalize()}-App"


def now():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def rid():
    return _secrets.token_hex(4)


# ---- secrets and people -----------------------------------------------------------------------------------------------
def secret(value, forever=False):
    """A value that must never be logged, known only at run time (a token just minted). It's masked wherever it turns
    up in this request's or job's row; forever=True for the life of the process."""
    if not value or not isinstance(value, str) or len(value) < 6:
        return
    if forever:
        _forever.add(value)
    rec = _rec.get()
    if rec is not None:
        rec["scrub"].add(value)


def signed_in(who):
    """Who this request turned out to be (a sign-in learns it only in the handler)."""
    rec = _rec.get()
    if rec is not None:
        rec["who"] = who


def pseudonym(value, daily=False):
    """A short code for a person, stable (or stable for one UTC day), keyed so it can't be reversed by guessing."""
    if value is None:
        return None
    msg = f"{value}|{dt.datetime.now(dt.timezone.utc).date() if daily else ''}".encode()
    return "p-" + hmac.new(cfg().pseudonym_key or b"applog", msg, hashlib.sha256).hexdigest()[:6]


def _scrubbed(text, rec=None):
    if text is None:
        return None
    for s in _forever | (rec["scrub"] if rec else set()):
        text = text.replace(s, "…")
    return text


def clip(v):
    v = v if isinstance(v, str) else json.dumps(v, default=str)
    return v if len(v) <= MAX_FIELD else v[:MAX_FIELD] + "…"


def sent(fields, kind):
    """What was sent, as far as the route allows: nothing unless its kind is in send, never for never_send."""
    c = cfg()
    allow = c.send.get(kind)
    if not fields or not allow or kind in c.never_send or kind in c.anonymous:
        return None
    out = {}
    for k, v in fields.items():
        k = str(k)[:60]
        if allow is not True and k not in allow:
            continue
        out[k] = "[hidden]" if SECRET_FIELD.search(k) else clip(v)
    return out or None


def is_quiet(path):
    """No row and no line: a health check, or anything under a quiet prefix ("/static/", photo files)."""
    bare = (path or "").split("?", 1)[0]
    q = cfg().quiet
    return bare in q or any(p.endswith("/") and bare.startswith(p) for p in q)


def mask_path(path):
    """A path and query fit to log: secret segments and secret-named query values masked."""
    if path is None:
        return None
    base, _, query = path.partition("?")
    for pat in cfg().secret_paths:
        base = re.sub(pat, lambda m: m.group(0).replace(m.group(1), "…"), base)
    if query:
        parts = []
        for pair in query.split("&"):
            k, eq, v = pair.partition("=")
            parts.append(f"{k}=…" if eq and (SECRET_FIELD.search(k) or k in cfg().private_query) else pair)
        base += "?" + "&".join(parts)[:300]
    return base


_ID = re.compile(r"^(\d+|[0-9a-f]{8,}|[0-9a-f-]{36})$", re.I)


def kind_for(method, path):
    """'POST /transactions/:id': the route, not the address. App routes first, then ids replaced."""
    c = cfg()
    p = path.split("?", 1)[0]
    if c.strip_prefix and p.startswith(c.strip_prefix):
        p = p[len(c.strip_prefix):] or "/"
    for pat, name in c.routes:
        if re.fullmatch(pat, p):
            return f"{method} {name}"
    return f"{method} " + "/".join(":id" if _ID.match(s) else s for s in p.split("/"))


def error_text(exc=None):
    """The traceback of the exception being handled (or exc), for a row. In strict mode only its frames and exception
    types: a message can quote whatever the code was handling (a kid's message, a search), and the log outlives it."""
    if exc is None:
        exc = sys.exc_info()[1]
    if exc is None:
        return None
    if _cfg is None or not _cfg.strict:
        return "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))[-6000:]
    parts, seen, e = [], set(), exc
    while e is not None and id(e) not in seen and len(seen) < 10:
        seen.add(id(e))
        frames = "".join(f'  File "{f.filename.rsplit("/", 1)[-1]}", line {f.lineno}, in {f.name}\n'
                         for f in traceback.extract_tb(e.__traceback__))
        parts.append(f"Traceback (most recent call last):\n{frames}{type(e).__qualname__} (message hidden)\n")
        e = e.__cause__ or e.__context__
    return "\n".join(reversed(parts))[-6000:]


def count_writes():
    """This request's or job's writes are recorded as counts per table ("INSERT messages x37"), never as statements:
    a device's batch upload, whose rows are content and whose number would swamp the row."""
    rec = _rec.get()
    if rec is not None and rec.get("counts") is None:
        rec["counts"], rec["pending_counts"] = {}, {}


def _count(rec, statement):
    if statement.startswith("--"):
        return
    verb, table, _ = sqlmask.verb_and_table(sqlmask.tokens(statement))
    key = f"{verb} {table or '?'}"
    rec["pending_counts"][key] = rec["pending_counts"].get(key, 0) + 1


# ---- capture --------------------------------------------------------------------------------------------------------
def begin(request_id=None):
    """Start recording writes for this request or job (this thread, or this asyncio task)."""
    rec = {"rid": request_id or rid(), "t0": time.perf_counter(), "saved": [], "pending": [], "undone": [], "dropped": 0,
           "scrub": set(), "who": None, "undeclared": set()}
    _rec.set(rec)
    return rec


def current():
    return _rec.get()


def end():
    """Stop recording. Returns (ms, changes). Uncommitted writes come back marked "-- not saved": call this before
    rolling back a crashed request, so the record of what it tried survives the rollback."""
    rec = _rec.get()
    _rec.set(None)
    if rec is None:
        return None, None
    changes = rec["saved"] + [f"-- not saved: {s}" for s in rec["undone"] + rec["pending"]]
    if rec.get("counts") is not None:
        changes += [f"{k} x{n}" for k, n in sorted(rec["counts"].items())]
        changes += [f"-- not saved: {k} x{n}" for k, n in sorted(rec["pending_counts"].items())]
    if rec["dropped"]:
        changes.append(f"-- and {rec['dropped']} more")
    return round((time.perf_counter() - rec["t0"]) * 1000), ([_scrubbed(s, rec) for s in changes] or None)


def _rules(rec):
    c = cfg()
    return sqlmask.Rules(columns=c.columns, secret_columns=c.secret_columns, secret_tables=c.secret_tables,
                         secret_rows=c.secret_rows, columns_of=_columns_of,
                         scrub=list(_forever | (rec["scrub"] if rec else set())))


_cols_cache = {}


def _columns_of(table):
    if table not in _cols_cache:
        try:
            with _connect() as con:
                _cols_cache[table] = [r[1] for r in con.execute(f"PRAGMA table_info({table})")]
        except sqlite3.Error:
            return None
    return _cols_cache[table]


def trace(statement):
    """SQLite's trace hook (attach/connect set it). Runs on the thread that executed the statement."""
    try:
        s = statement.strip()
        word = s[:8].upper()
        rec = _rec.get()
        if rec is None:
            if word.startswith(sqlmask.WRITES):
                _orphan(s)
            return
        counting = rec.get("counts") is not None
        if word.startswith("COMMIT") or word.startswith("RELEASE") or word.startswith("END"):
            rec["saved"] += rec["pending"]
            rec["pending"] = []
            if counting:
                for k, n in rec["pending_counts"].items():
                    rec["counts"][k] = rec["counts"].get(k, 0) + n
                rec["pending_counts"] = {}
        elif word.startswith("ROLLBACK"):
            # Rolled back inside the handler (a `with con:` block meeting an exception) before the adapter could
            # call end(): keep the record of what was tried (BUGS 39).
            rec["undone"] += rec["pending"]
            rec["pending"] = []
            if counting:
                rec["pending_counts"] = {}
        elif counting and word.startswith(sqlmask.WRITES):
            _count(rec, s)
        elif word.startswith(sqlmask.WRITES):
            if len(rec["saved"]) + len(rec["pending"]) >= MAX_CHANGES:
                rec["dropped"] += 1
                return
            rules = _rules(rec)
            m = sqlmask.mask(s, rules)
            if m is None:
                return
            rec["undeclared"] |= rules.undeclared
            rec["pending"].append(m if len(m) <= MAX_STATEMENT else m[:MAX_STATEMENT] + "…")
    except Exception:  # never let logging break a statement
        sys.stderr.write("applog trace failed:\n" + traceback.format_exc())


def _orphan(statement):
    """A write from a thread serving no request or job: logged anyway, gathered into one row a minute, so the gap is
    visible instead of silent. Wrap the thread's work in job() to give it its own row."""
    m = sqlmask.mask(statement, _rules(None))
    with _lock:
        if len(_orphans["stmts"]) < MAX_CHANGES:
            _orphans["stmts"].append(m)
        due = time.monotonic() - _orphans["since"] > 60
    if due:
        flush_orphans()


def flush_orphans():
    with _lock:
        stmts, _orphans["stmts"], _orphans["since"] = _orphans["stmts"], [], time.monotonic()
    if stmts:
        write({"at": now(), "source": "job", "kind": "job:unattributed", "changes": stmts})


def attach(con):
    con.set_trace_callback(trace)
    return con


def connect(path=None, **kw):
    """sqlite3.connect with the trace hook set. Use it for every connection the app writes through."""
    return attach(sqlite3.connect(path or _db_path(), **kw))


# ---- rows -------------------------------------------------------------------------------------------------------------
def finish(*, method, path, status, ms=None, changes=None, who=None, source="web", client=None, form=None,
           error=None, request_id=None, kind=None, rec=None):
    """Build, print and store the row for a finished request, following the app's rules. Never raises."""
    try:
        c = cfg()
        if is_quiet(path) and (status or 0) < 500:
            return None
        kind = kind or kind_for(method, path)
        failed = (status or 0) >= 400 or error
        read = method in ("GET", "HEAD")
        # A read that wrote something (a history row, a last-seen mark) is a change, so it's always a row.
        store = kind not in c.skip_kinds and not (read and not failed and not changes and (
            c.reads == "none" or (c.reads == "slow" and (ms or 0) < c.slow_ms)))
        if rec and rec.get("who") is not None:
            who = rec["who"]
        if c.strict and who is not None:
            who = pseudonym(who, daily=True)
        row = {"at": now(), "rid": request_id, "source": source, "who": who, "kind": kind, "method": method,
               "path": _scrubbed(mask_path(path), rec), "status": status, "ms": ms, "form": form,
               "changes": changes, "error": _scrubbed(error, rec), "client": (client or "")[:120] or None}
        if kind in c.anonymous:
            row.update(at=row["at"][:10], rid=None, who=None, form=None, changes=None, ms=None,
                       path=kind.split(" ", 1)[-1], client=None)
        if c.stdout:
            line(row)
        if store:
            write(row)
        if rec and rec.get("undeclared"):
            sys.stderr.write(f"applog: undeclared columns masked: {sorted(map(str, rec['undeclared']))}\n")
        return row
    except Exception:
        sys.stderr.write("applog finish failed:\n" + traceback.format_exc())
        return None


def line(row):
    """One JSON line on stdout per request."""
    out = {"at": row["at"], "rid": row.get("rid"), "src": row["source"], "kind": row.get("kind"),
           "path": row.get("path"), "status": row.get("status"), "ms": row.get("ms")}
    if row.get("who"):
        out["who"] = row["who"]
    if row.get("error"):
        out["error"] = row["error"].strip().splitlines()[-1][:300]
    print(json.dumps(out, separators=(",", ":")), flush=True)


def write(row):
    """One row, on its own connection: the request's connection may be mid-transaction or rolled back. Never
    raises. Once a UTC day it also rolls up yesterday and prunes rows past keep_days."""
    try:
        c = cfg()
        row = dict(row)
        for k in ("form", "changes"):
            if row.get(k) is not None and not isinstance(row[k], str):
                row[k] = json.dumps(row[k], separators=(",", ":"), ensure_ascii=False, default=str)
        con = _connect()
        try:
            con.execute(f"INSERT INTO {c.table} ({','.join(row)}) VALUES ({','.join('?' * len(row))})",
                        tuple(row.values()))
            con.commit()
            today = dt.datetime.now(dt.timezone.utc).date()
            if _maintained["day"] != today:
                _maintained["day"] = today
                maintain(con, today)
        finally:
            con.close()
    except Exception:
        sys.stderr.write("applog write failed:\n" + traceback.format_exc())


def maintain(con, today):
    from .report import rollup
    rollup(con, today)
    cutoff = (today - dt.timedelta(days=cfg().keep_days)).isoformat()
    con.execute(f"DELETE FROM {cfg().table} WHERE at < ?", (cutoff,))
    con.commit()


@contextmanager
def job(name, always=False):
    """A background pass: its writes and any crash in one row (source job, kind job:<name>). Without always, a pass
    that wrote nothing and didn't fail leaves no row. The exception still reaches the caller."""
    if _rec.get() is not None:  # inside a request or another job: that row covers it
        yield
        return
    rec = begin()
    error = None
    try:
        yield rec
    except BaseException:
        error = error_text()
        raise
    finally:
        ms, changes = end()
        if always or changes or error:
            row = {"at": now(), "rid": rec["rid"], "source": "job", "kind": f"job:{name}", "ms": ms,
                   "changes": changes, "error": _scrubbed(error, rec), "status": 500 if error else None}
            if cfg().stdout and (error or always):
                line(row)
            write(row)


def in_job(name, always=False):
    """Decorator form of job(), for a thread's target."""
    def wrap(fn):
        def run(*a, **kw):
            with job(name, always):
                return fn(*a, **kw)
        run.__name__ = getattr(fn, "__name__", "job")
        return run
    return wrap


def client_events(items, *, source, who, client, request_id):
    """Events from a page, the app or a device: [{kind, at, path, data, source?}]. Returns how many were kept.
    Capped per batch, per value and per client per day; a kind must look like 'screen' or 'load-failed'."""
    c = cfg()
    day = dt.datetime.now(dt.timezone.utc).date()
    key = (who or client or "?", day)
    n = 0
    for e in (items or [])[:c.client_batch]:
        if not (isinstance(e, dict) and isinstance(e.get("kind"), str) and EVENT_KIND.match(e["kind"].strip())):
            continue
        with _lock:
            if _daily_counts.get(key, 0) >= c.client_daily:
                break
            _daily_counts[key] = _daily_counts.get(key, 0) + 1
            if len(_daily_counts) > 10000:
                for k in [k for k in _daily_counts if k[1] != day]:
                    del _daily_counts[k]
        src = source
        sub = e.get("source")
        if isinstance(sub, str) and f"{source}:{sub}" in c.sources:
            src = f"{source}:{sub}"
        at = e.get("at") if isinstance(e.get("at"), str) and len(e["at"]) <= 40 else None
        data = e.get("data") if isinstance(e.get("data"), dict) else {}
        data = {str(k)[:60]: "[hidden]" if SECRET_FIELD.search(str(k)) else
                (v if isinstance(v, (int, float, bool)) or v is None else _scrubbed(str(v)[:c.client_value]))
                for k, v in list(data.items())[:40]}
        write({"at": now(), "rid": request_id, "source": src,
               "who": pseudonym(who, daily=True) if c.strict and who else who,
               "kind": f"{source}:{e['kind'].strip()}",
               "path": _scrubbed(mask_path(str(e.get("path") or "")[:300])) or None,
               "form": data or None, "client": (client or "")[:120] or None, "client_at": at})
        n += 1
    return n


# ---- declarations -----------------------------------------------------------------------------------------------------
def undeclared(con=None):
    """Columns in the database that are in neither columns nor secret_columns (and tables in neither list). A test
    asserts this is empty, so a new column can't be logged, or leak, by accident."""
    c = cfg()
    own = None if con is not None else _connect()
    con = con or own
    try:
        missing = []
        skip = {c.table, f"{c.table}_daily"} | set(c.ignore_tables)
        for (t,) in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"):
            if t in skip or t in c.secret_tables:
                continue
            ok = set(c.columns.get(t, ())) | set(c.secret_columns.get(t, ()))
            if t not in c.columns and t not in c.secret_columns:
                missing.append(t)
                continue
            missing += [f"{t}.{r[1]}" for r in con.execute(f"PRAGMA table_info({t})") if r[1] not in ok]
        return missing
    finally:
        if own:
            own.close()


def declaration(con):
    """A starting declaration for an existing database: every column loggable except ones whose names look secret.
    Print it, then move what shouldn't be shown into secret_columns by hand."""
    cols, secret = {}, {}
    for (t,) in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"):
        for r in con.execute(f"PRAGMA table_info({t})"):
            looks = re.search(r"pass|token|secret|hash|credential|signature|cookie|session|number|^key_|_key$", r[1], re.I)
            (secret if looks else cols).setdefault(t, []).append(r[1])
    return cols, secret
