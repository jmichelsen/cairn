"""Adapter for Flask: feast-list, foothold. Importing this module needs Flask; the rest of applog doesn't.

    applog.flask_ext.init_app(app, who=lambda: (g.person_id, "app" if g.api else "web") or None,
                              rollback=lambda: get_db().rollback())

Kinds are the Flask endpoint ("POST admin.identify_save"), so there's no path guessing. Pages and API reads
alike follow the reads policy (a slow or failed page is a row); put asset and photo prefixes in quiet ("/static/"). Every connection the app
writes through must be traced: applog.attach(con) where it's opened. Remove gunicorn's access log
(no --access-logfile): it prints secret paths. The row is written in after_request, before the response returns.
"""
import traceback

from flask import g, got_request_exception, request

from . import core


def init_app(app, who=None, rollback=None):
    def _start():
        g.applog_rid = core.rid()
        g.applog_error = None
        g.applog_rec = core.begin(g.applog_rid)

    def _error(sender, exception, **extra):
        g.applog_error = core.error_text(exception)

    def _finish(resp):
        rec = g.get("applog_rec")
        if rec is None:
            return resp
        ms, changes = core.end()  # before any rollback: what it tried survives as "-- not saved"
        g.applog_rec = None
        if (g.get("applog_error") or resp.status_code >= 400) and rollback:  # a crash or a refusal (BUGS 38)
            try:
                rollback()
            except Exception:
                pass
        resp.headers["X-Request-Id"] = g.applog_rid
        kind = f"{request.method} {request.endpoint}" if request.endpoint else core.kind_for(request.method, request.path)
        found = None
        try:
            found = who() if who else None
        except Exception:
            pass
        version = request.headers.get(core.app_header())
        person, source = found if found else (None, "app" if version else "web")
        if request.method in ("GET", "HEAD"):
            fields = request.args.to_dict()
        else:
            fields = request.get_json(silent=True) if request.is_json else request.form.to_dict()
        core.finish(method=request.method, path=request.full_path.rstrip("?"), status=resp.status_code, ms=ms,
                    changes=changes, who=person, source=source, client=f"app {version}" if version else
                    request.headers.get("User-Agent", ""), form=core.sent(fields if isinstance(fields, dict) else None,
                                                                          kind),
                    error=g.get("applog_error"), request_id=g.applog_rid, kind=kind, rec=rec)
        return resp

    app.before_request(_start)
    app.after_request(_finish)
    got_request_exception.connect(_error, app, weak=False)  # a local function: a weak reference would vanish
