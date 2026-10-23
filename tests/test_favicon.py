"""The app icon must serve before login (browsers fetch it from the login page) and must be the real
icon, not the old 1x1 placeholder that some browsers drew as a black square."""
import os
import sys
import tempfile

os.environ.setdefault("CAIRN_DB", os.path.join(tempfile.mkdtemp(), "cairn-test.db"))
os.environ.setdefault("CAIRN_ADMIN_TOKEN", "test-admin-token")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "phase1"))
import api  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

web = TestClient(api.app, base_url="https://cairn.test")


def test_svg_icon_serves_without_login():
    r = web.get("/favicon.svg")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("image/svg+xml")
    assert r.text.startswith("<svg") and "<ellipse" in r.text


def test_ico_is_a_real_multi_size_icon():
    r = web.get("/favicon.ico")
    assert r.status_code == 200 and r.headers["content-type"] == "image/x-icon"
    # ICONDIR header: reserved 0, type 1 (icon), then the image count
    assert r.content[:4] == b"\x00\x00\x01\x00" and int.from_bytes(r.content[4:6], "little") == 3


def test_pages_link_the_svg_icon():
    assert "href=/favicon.svg" in api.LOGIN_HTML
    assert "href=/favicon.svg" in web.get("/login").text
