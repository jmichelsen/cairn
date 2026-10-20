"""Adapter for ASGI (FastAPI, Starlette): cairn. No dependencies.

    app.add_middleware(applog.asgi.Middleware, who=lambda scope: ("ui:" + label, "web") or None,
                       rollback=lambda: db.rollback())

Run uvicorn with --no-access-log: its line prints query strings, which is how cairn's share tokens leaked. The
kind is the matched route's path template when the framework records it (scope["route"].path), else the path with
ids replaced. Sync endpoints run in a thread pool that copies the request's context, so their writes are credited.
A crash becomes a 500 naming the request id.
"""
import json
import sys
import traceback

from . import core

MAX_BODY = 64 * 1024


class Middleware:
    def __init__(self, app, who=None, rollback=None, api_prefix="/"):
        self.app, self.who, self.rollback, self.api_prefix = app, who, rollback, api_prefix

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        request_id = core.rid()
        rec = core.begin(request_id)
        state = {"status": None, "done": False, "error": None, "body": b""}
        method = scope["method"]

        async def receive_logged():
            msg = await receive()
            if msg["type"] == "http.request" and len(state["body"]) < MAX_BODY:
                state["body"] += msg.get("body", b"")[:MAX_BODY - len(state["body"])]
            return msg

        def finish():
            if state["done"]:
                return
            state["done"] = True
            ms, changes = core.end()
            if (state["error"] or (state["status"] or 0) >= 400) and self.rollback:  # a crash or a refusal (BUGS 38)
                try:
                    self.rollback()
                except Exception:
                    sys.stderr.write("applog rollback failed:\n" + traceback.format_exc())
            headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
            route = scope.get("route")
            kind = f"{method} {route.path}" if getattr(route, "path", None) else core.kind_for(method, scope["path"])
            found = None
            try:
                found = self.who(scope) if self.who else None
            except Exception:
                pass
            version = headers.get(core.app_header().lower())
            person, source = found if found else (None, "app" if version else "web")
            qs = scope.get("query_string", b"").decode()
            path = scope["path"] + ("?" + qs if qs else "")
            fields = None
            if method in ("GET", "HEAD"):
                fields = dict(p.partition("=")[::2] for p in qs.split("&") if p)
            elif state["body"]:
                try:
                    fields = json.loads(state["body"])
                except ValueError:
                    fields = None
            core.finish(method=method, path=path, status=state["status"], ms=ms, changes=changes, who=person,
                        source=source, client=f"app {version}" if version else headers.get("user-agent", ""),
                        form=core.sent(fields if isinstance(fields, dict) else None, kind), error=state["error"],
                        request_id=request_id, kind=kind, rec=rec)

        async def send_logged(msg):
            if msg["type"] == "http.response.start":
                state["status"] = msg["status"]
                msg = dict(msg, headers=list(msg.get("headers", [])) + [(b"x-request-id", request_id.encode())])
                finish()
            await send(msg)

        try:
            await self.app(scope, receive_logged, send_logged)
        except Exception:
            state["error"] = core.error_text()
            if state["status"] is None:
                body = json.dumps({"error": f"server error (request {request_id})"}).encode()
                await send_logged({"type": "http.response.start", "status": 500,
                                   "headers": [(b"content-type", b"application/json"),
                                               (b"content-length", str(len(body)).encode())]})
                await send({"type": "http.response.body", "body": body})
            else:
                core.write({"at": core.now(), "rid": request_id, "source": "web", "status": 500,
                            "kind": core.kind_for(method, scope["path"]), "error": state["error"]})
        finally:
            if not state["done"]:
                finish()
            if core.current() is rec:
                core.end()
