#!/usr/bin/env python3
"""cairn notify self-test - the dead-man's-switch on the ALERTER ITSELF.

cairn's alerting silently died once because the deployed notify config carried the *.example
placeholders (NOTIFY_EMAIL=you@example.com, SMTP_HOST=smtp.example.com, a comment-string Gotify
token): alerts fired on every CRIT but delivered NONE for days, noticed only by opening the
dashboard. A liveness ping ("the API is up") would NOT have caught it - the API was up, the loop
ran, only DELIVERY was broken.

So this self-test verifies the real delivery path notify.sh uses - config is non-placeholder AND the
transports are reachable - and the caller pushes the verdict to an uptime-kuma Push monitor. Kuma is
an independent watchdog (separate container + its own notification channels): if cairn can't alert
you, Kuma can. If the pings stop (API down) or go 'down' (delivery broken), Kuma alerts.

Pure + injectable so it unit-tests without touching the network. Mirrors notify.sh's env contract:
  email  : MAIL_MODE (smtp|relay|sendmail), NOTIFY_EMAIL, SMTP_HOST/PORT (MSMTPD_* fallbacks)
  gotify : GOTIFY_URL + GOTIFY_TOKEN (only when configured; used for CRIT pushes)
"""
import socket
import time
import urllib.parse
import urllib.request

__all__ = ["selftest", "kuma_push", "is_placeholder"]

# tokens that mean "never filled in" - the exact class that broke alerting
_PLACEHOLDER_MARKERS = ("example.com", "example.org", "changeme", "your-", "yourhost",
                        "<", ">", "e.g.", "app token", "app_token")


def is_placeholder(v):
    """True if a config value is empty, a stray inline comment, or an obvious *.example placeholder."""
    if v is None:
        return True
    v = str(v).strip()
    if not v or v.startswith("#"):     # empty, or an inline-comment-as-value (SMTP_USER= # blank...)
        return True
    low = v.lower()
    return any(m in low for m in _PLACEHOLDER_MARKERS)


def _tcp_greet(host, port, timeout=6.0, connect=socket.create_connection):
    """Open host:port and read the server greeting. Returns (ok, detail). Proves the SMTP relay is
    actually reachable - catches an unresolvable/placeholder host and a down relay."""
    try:
        with connect((host, int(port)), timeout) as sock:
            sock.settimeout(timeout)
            try:
                greet = sock.recv(256).decode("latin-1", "replace").strip()
            except OSError:
                greet = ""
        # SMTP servers answer '220 ...'; a relay may greet slower - reachability is the real signal,
        # so a successful connect with no/again-unexpected greeting is still OK (just noted).
        if greet[:3] == "220":
            return True, f"reachable, greeting {greet[:60]!r}"
        return True, (f"reachable, greeting {greet[:60]!r}" if greet else "reachable (no greeting read)")
    except OSError as e:
        return False, f"connect failed: {e}"


def _http_get(url, timeout=8, ua="cairn-heartbeat/1.0"):
    """GET a URL, return (code, err). urllib default UA is blocked by some fronts (Cloudflare 1010),
    so send a real one - internal Kuma/Gotify don't care, but it keeps the helper reusable."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": ua})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, None
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception as e:
        return None, str(e)


def check_email(env, connect=socket.create_connection):
    """Verify the email delivery path (the WARN+CRIT channel). Returns a check dict."""
    mode = (env.get("MAIL_MODE") or "smtp").strip().lower()
    to = env.get("NOTIFY_EMAIL")
    # recipient: a real address is required for smtp/relay (the relay ignores /etc/aliases, so 'root'
    # or unset silently goes nowhere); sendmail can resolve 'root' locally.
    if is_placeholder(to) or (mode in ("smtp", "relay") and (not to or to.strip() == "root")):
        return dict(name="email", ok=False, detail=f"NOTIFY_EMAIL not a real address ({to!r})")
    if mode == "sendmail":
        import os
        path = "/usr/sbin/sendmail"
        ok = os.access(path, os.X_OK)
        return dict(name="email", ok=ok,
                    detail=f"sendmail mode, {path} {'executable' if ok else 'MISSING'}; to={to}")
    if mode not in ("smtp", "relay"):
        return dict(name="email", ok=False, detail=f"unknown MAIL_MODE {mode!r}")
    host = env.get("SMTP_HOST") or env.get("MSMTPD_HOST") or "127.0.0.1"
    port = env.get("SMTP_PORT") or env.get("MSMTPD_PORT") or "2500"
    if is_placeholder(host):
        return dict(name="email", ok=False, detail=f"SMTP_HOST is a placeholder ({host!r})")
    ok, detail = _tcp_greet(host, port, connect=connect)
    return dict(name="email", ok=ok, detail=f"{mode} {host}:{port} - {detail}; to={to}")


def check_gotify(env, http=_http_get):
    """Verify Gotify (the CRIT push channel) IF it is configured. Returns a check dict, or None when
    Gotify isn't set up at all (email-only is a valid deployment, so absence is not a failure)."""
    url = env.get("GOTIFY_URL")
    token = env.get("GOTIFY_TOKEN")
    configured = bool((url or "").strip()) or bool((token or "").strip())
    if not configured:
        return None
    if is_placeholder(url):
        return dict(name="gotify", ok=False, detail=f"GOTIFY_URL is a placeholder ({url!r})")
    if is_placeholder(token) or token.strip() == "CHANGEME_app_token":
        return dict(name="gotify", ok=False, detail="GOTIFY_TOKEN is a placeholder/comment string")
    base = url.rstrip("/")
    code, err = http(base + "/health")
    if code is None:
        return dict(name="gotify", ok=False, detail=f"{base}/health unreachable: {err}")
    # /health is unauthenticated; token validity isn't deep-checked here (Gotify app tokens have no
    # non-destructive validate endpoint), but notify.sh reports a 401 honestly on the real CRIT push.
    ok = 200 <= code < 400
    return dict(name="gotify", ok=ok, detail=f"{base}/health HTTP {code} (token present, format OK)")


def selftest(env, connect=socket.create_connection, http=_http_get):
    """Run all delivery-path checks. Returns (ok, checks). ok is True only if every configured
    channel is healthy - email is always required; Gotify is required only when configured."""
    checks = []
    checks.append(check_email(env, connect=connect))
    g = check_gotify(env, http=http)
    if g is not None:
        checks.append(g)
    ok = all(c["ok"] for c in checks)
    return ok, checks


def kuma_push(url, ok, msg, ping_ms=None, timeout=8, http=None):
    """Push the verdict to an uptime-kuma Push monitor. status=up on pass, down on fail (so Kuma
    alerts immediately on a broken path, not only when pings stop). Returns (code, err); no-op
    (None, 'no url') when the push URL isn't configured."""
    if not url:
        return None, "no url"
    q = {"status": "up" if ok else "down", "msg": (msg or "")[:180]}
    if ping_ms is not None:
        q["ping"] = str(int(ping_ms))
    full = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(q)
    getter = http or _http_get
    code, err = getter(full, timeout=timeout)
    return code, err


def run_once(env, kuma_url=None, connect=socket.create_connection, http=_http_get):
    """One heartbeat cycle: self-test, then push to Kuma. Returns a dict summary for logging/API."""
    t0 = time.monotonic()
    ok, checks = selftest(env, connect=connect, http=http)
    ping_ms = (time.monotonic() - t0) * 1000.0
    summary = "; ".join(f"{c['name']}:{'ok' if c['ok'] else 'FAIL'}" for c in checks) or "no channels"
    msg = ("alerts deliverable (" + summary + ")") if ok else ("ALERT DELIVERY BROKEN - " + summary)
    code, err = kuma_push(kuma_url, ok, msg, ping_ms=ping_ms, http=http)
    return dict(ok=ok, checks=checks, msg=msg, ping_ms=round(ping_ms, 1),
                kuma_code=code, kuma_err=err, ts=int(time.time()))


if __name__ == "__main__":   # manual: env from a sourced cairn.env, prints the verdict
    import json, os
    print(json.dumps(run_once(os.environ, os.environ.get("CAIRN_KUMA_PUSH_URL")), indent=2))
