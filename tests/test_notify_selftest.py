"""Unit tests for the notify self-test (the dead-man's-switch on cairn's OWN alerting). Network I/O
is injected, so these run offline. The named failure cases are the exact placeholder-config class
that once silently killed alert delivery for days."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "phase1"))
import notify_selftest as ns  # noqa: E402

REAL = {"MAIL_MODE": "smtp", "NOTIFY_EMAIL": "admin@real.example",  # note: .example TLD, not example.com
        "SMTP_HOST": "msmtpd", "SMTP_PORT": "2500"}


class _FakeSock:
    def __init__(self, greet=b"220 relay ready"):
        self._g = greet

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def settimeout(self, *a):
        pass

    def recv(self, n):
        return self._g


def _ok_connect(addr, timeout):
    return _FakeSock()


def _refused(addr, timeout):
    raise OSError("Connection refused")


def _http_ok(url, timeout=8, ua=None):
    return 200, None


def _http_down(url, timeout=8, ua=None):
    return None, "unreachable"


def _real(**over):
    # REAL uses a real-looking address; is_placeholder keys on the literal "example.com" marker, so
    # give NOTIFY_EMAIL a concrete value for the happy path.
    e = dict(REAL, NOTIFY_EMAIL="ops@homelab.lan")
    e.update(over)
    return e


def test_good_email_only_passes():
    ok, ch = ns.selftest(_real(), connect=_ok_connect, http=_http_ok)
    assert ok and [c["name"] for c in ch] == ["email"]


def test_placeholder_smtp_host_fails():   # SMTP_HOST=smtp.example.com  (the outage)
    ok, ch = ns.selftest(_real(SMTP_HOST="smtp.example.com"), connect=_ok_connect)
    assert not ok and "placeholder" in ch[0]["detail"]


def test_placeholder_recipient_fails():   # NOTIFY_EMAIL=you@example.com  (the outage)
    ok, ch = ns.selftest(_real(NOTIFY_EMAIL="you@example.com"), connect=_ok_connect)
    assert not ok


def test_root_recipient_on_relay_fails():  # relay ignores /etc/aliases -> 'root' goes nowhere
    ok, ch = ns.selftest(_real(NOTIFY_EMAIL="root"), connect=_ok_connect)
    assert not ok


def test_unreachable_relay_fails():
    ok, ch = ns.selftest(_real(), connect=_refused)
    assert not ok and "connect failed" in ch[0]["detail"]


def test_gotify_placeholder_token_fails():  # a comment-string token (the outage)
    env = _real(GOTIFY_URL="http://gotify", GOTIFY_TOKEN="   # a Gotify application token")
    ok, ch = ns.selftest(env, connect=_ok_connect, http=_http_ok)
    assert not ok and any(c["name"] == "gotify" and not c["ok"] for c in ch)


def test_gotify_healthy_passes():
    env = _real(GOTIFY_URL="http://gotify", GOTIFY_TOKEN="A_realish_token")
    ok, ch = ns.selftest(env, connect=_ok_connect, http=_http_ok)
    assert ok and len(ch) == 2


def test_gotify_unreachable_fails():
    env = _real(GOTIFY_URL="http://gotify", GOTIFY_TOKEN="A_realish_token")
    ok, ch = ns.selftest(env, connect=_ok_connect, http=_http_down)
    assert not ok


def test_kuma_push_up_and_down():
    seen = {}

    def cap(url, timeout=8, ua=None):
        seen["url"] = url
        return 200, None

    ns.kuma_push("http://kuma:3001/api/push/abc", True, "deliverable", ping_ms=12.7, http=cap)
    assert "status=up" in seen["url"] and "ping=12" in seen["url"]
    ns.kuma_push("http://kuma:3001/api/push/abc?x=1", False, "BROKEN", http=cap)
    assert "status=down" in seen["url"] and seen["url"].count("?") == 1


def test_kuma_push_noop_without_url():
    assert ns.kuma_push("", True, "x") == (None, "no url")


def test_is_placeholder():
    for bad in (None, "", "  ", "# comment", "you@example.com", "smtp.example.com",
                "CHANGEME_app_token", "<token>", "e.g. https://gotify"):
        assert ns.is_placeholder(bad), bad
    for good in ("ops@homelab.lan", "msmtpd", "http://gotify", "A_X_rab6JBwps7h"):
        assert not ns.is_placeholder(good), good
