"""Adapter for http.server (BaseHTTPRequestHandler): suisha, nihongo, watchtower, yaoki.

    class Handler(applog.httpserver.Logged, BaseHTTPRequestHandler):
        def do_GET(self):  self.logged(self._route_get)
        def do_POST(self): self.logged(self._route_post)
        def applog_who(self):      return (username, "app" | "web") or None   # cached; called once per request
        def applog_body(self):     return the parsed JSON body or None        # for "what was sent"
        def applog_rollback(self): roll back the app's connection after a crash or any 4xx/5xx answer

The row is written when the headers go out (end_headers), before the body: a client that reads the response can
already find its row, so tests never poll. X-Request-Id is added to every response. A crash becomes a 500 naming the
request id, its half-done transaction is rolled back after its writes are recorded, and the traceback is in the row.
Any other answer of 400 or more rolls back too, as it's sent: a write the route left uncommitted is "not saved".
"""
import sys
import time
import traceback
from urllib.parse import parse_qs, urlsplit

from . import core


class Logged:
    applog_api = "/api/"  # paths that get a row; everything else (static files) gets only the stdout line

    def log_message(self, fmt, *args):
        pass  # http.server's own line would print secret paths; the applog line replaces it

    def log_request(self, code="-", size="-"):
        pass

    # ---- hooks the app overrides ----
    def applog_who(self):
        return None

    def applog_body(self):
        return None

    def applog_rollback(self):
        pass

    def applog_error_body(self, request_id):
        return ('{"error": "server error (request %s)"}' % request_id).encode()

    # ---- the wrapper ----
    def logged(self, route):
        self.applog_rid = core.rid()
        self.applog_status = None
        self.applog_error = None
        self.applog_kind = None   # a route may name itself: self.applog_kind = "GET /quotes/:ticker"
        self._applog_done = False
        self._applog_snapshot = None
        path = self.path
        self._applog_api = urlsplit(path).path.startswith(self.applog_api)
        self._applog_t0 = time.perf_counter()
        self._applog_rec = core.begin(self.applog_rid) if self._applog_api else None
        try:
            route()
        except Exception:
            self.applog_error = core.error_text()
            if self._applog_done:  # crashed after its headers went out: the row is written, so add the crash
                core.write({"at": core.now(), "rid": self.applog_rid, "source": "web", "status": 500,
                            "kind": self.applog_kind or core.kind_for(self.command, self.path),
                            "error": self.applog_error})
            self._applog_snapshot = core.end()  # before the rollback, so "not saved" survives it
            try:
                self.applog_rollback()
            except Exception:
                sys.stderr.write("applog rollback failed:\n" + traceback.format_exc())
            if self.applog_status is None:
                try:
                    body = self.applog_error_body(self.applog_rid)
                    self.send_response(500)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except Exception:
                    pass
        finally:
            if not self._applog_done:
                self._applog_finish()
            if core.current() is not None:
                core.end()

    def send_response(self, code, message=None):
        self.applog_status = code
        if code >= 400 and self._applog_snapshot is None and not self._applog_done and hasattr(self, "_applog_t0"):
            # A refusal after a write (BUGS 38): record what it tried, then undo it, or a shared connection stays
            # mid-transaction and every later write waits on the lock. (A crash has already done both.)
            if self._applog_api:
                self._applog_snapshot = core.end()
            try:
                self.applog_rollback()
            except Exception:
                sys.stderr.write("applog rollback failed:\n" + traceback.format_exc())
        super().send_response(code, message)
        if getattr(self, "applog_rid", None):
            self.send_header("X-Request-Id", self.applog_rid)

    def end_headers(self):
        if getattr(self, "applog_rid", None) and not self._applog_done:
            self._applog_finish()
        super().end_headers()

    def _applog_finish(self):
        self._applog_done = True
        try:
            ms = round((time.perf_counter() - self._applog_t0) * 1000)
            changes = None
            if self._applog_api:
                snap = self._applog_snapshot or core.end()
                changes = snap[1]
            who = None
            try:
                found = self.applog_who()
            except Exception:
                found = None
            app_version = self.headers.get(core.app_header())
            if found:
                who, source = found
            else:
                source = "app" if app_version else "web"
            kind = self.applog_kind or core.kind_for(self.command, self.path)
            if self.command in ("GET", "HEAD"):
                fields = {k: v[0] for k, v in parse_qs(urlsplit(self.path).query).items()}
            else:
                try:
                    fields = self.applog_body()
                except Exception:
                    fields = None
            form = core.sent(fields if isinstance(fields, dict) else None, kind)
            client = f"app {app_version}" if app_version else self.headers.get("User-Agent", "")
            bare = urlsplit(self.path).path
            static = not self._applog_api
            if static and (self.applog_status or 0) < 500:
                if core.cfg().stdout and not core.is_quiet(bare) and "." not in bare.rsplit("/", 1)[-1]:
                    core.line({"at": core.now(), "rid": self.applog_rid, "source": source, "kind": kind,
                               "path": core.mask_path(self.path), "status": self.applog_status, "ms": ms})
                return
            core.finish(method=self.command, path=self.path, status=self.applog_status, ms=ms, changes=changes,
                        who=who, source=source, client=client, form=form, error=self.applog_error,
                        request_id=self.applog_rid, kind=kind, rec=self._applog_rec)
        except Exception:
            sys.stderr.write("applog failed:\n" + traceback.format_exc())
