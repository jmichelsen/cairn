"""The debug log (applog, rules in phase1/activity.py): every change logged with what it wrote, secrets never,
every column declared, crashes captured with a request id, reads only when slow or failed."""
import json
import os
import sys
import tempfile
import unittest

os.environ.setdefault("CAIRN_DB", os.path.join(tempfile.mkdtemp(), "cairn-test.db"))
os.environ.setdefault("CAIRN_ADMIN_TOKEN", "test-admin-token")
os.environ.setdefault("CAIRN_AGENT_TOKENS", "test-agent-token-123")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "phase1"))
import api  # noqa: E402
import applog  # noqa: E402
from applog import testkit  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

ADMIN = os.environ["CAIRN_ADMIN_TOKEN"]
AGENT = os.environ["CAIRN_AGENT_TOKENS"].split(",")[0]
PASSWORD = "correct horse battery staple 42"


def rows(**where):
    con = applog.core._connect()
    try:
        out = [dict(r) for r in con.execute("SELECT * FROM activity ORDER BY id")]
    finally:
        con.close()
    return [r for r in out if all(r.get(k) == v for k, v in where.items())]


class ActivityLog(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        api._seed_tokens()
        with api.db() as c:
            c.execute("INSERT OR REPLACE INTO users(username,pass_hash,role,created_ts,active) VALUES(?,?,?,0,1)",
                      ("alice", api._pw_hash(PASSWORD), "viewer"))
            c.commit()
        cls.web = TestClient(api.app, base_url="https://cairn.test")
        cls.minted = []

    def admin(self, method, path, **kw):
        return self.web.request(method, path, headers={"X-Backup-Token": ADMIN, **kw.pop("headers", {})}, **kw)

    def test_every_column_is_declared(self):
        testkit.assert_declared(self)

    def test_a_change_is_logged_with_its_writes_and_who_did_it(self):
        r = self.admin("POST", "/api/v1/backup/tokens", json={"role": "viewer", "label": "log-test", "kind": "ui"})
        self.assertEqual(r.status_code, 200)
        self.minted.append(r.json()["token"])
        rid = r.headers["x-request-id"]
        row = rows(rid=rid)[0]
        self.assertEqual(row["kind"], "POST /api/v1/backup/tokens")
        self.assertEqual(row["who"], "bootstrap-admin")
        self.assertIn("auth_tokens", row["changes"])
        self.assertIn("log-test", row["changes"])             # the label is shown
        testkit.assert_absent(self, [r.json()["token"], api._hash(r.json()["token"])])

    def test_password_sign_in_is_credited_and_the_password_never_logged(self):
        r = self.web.post("/login", data={"username": "alice", "password": PASSWORD}, follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        row = rows(rid=r.headers["x-request-id"])[0]
        self.assertEqual(row["who"], "alice")
        session = r.cookies.get("bm_token")
        self.minted.append(session)
        testkit.assert_absent(self, [PASSWORD, session, api._hash(session)])

    def test_a_legacy_share_link_never_logs_its_token(self):
        tok = self.admin("POST", "/api/v1/backup/tokens", json={"role": "viewer", "label": "share-test",
                                                                "kind": "ui"}).json()["token"]
        with testkit.capture_stdout():
            r = self.web.get(f"/login?token={tok}", follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        testkit.assert_absent(self, [tok, api._hash(tok)])

    def test_an_agent_report_is_one_counted_row(self):
        r = self.web.post("/api/v1/backup/report", headers={"X-Backup-Token": AGENT}, json={
            "agent": "home", "interval": 900, "statuses": [
                {"name": f"t{i}", "type": "zfs-local", "severity": "OK", "detail_json": "{}"} for i in range(5)]})
        self.assertEqual(r.status_code, 200)
        row = rows(rid=r.headers["x-request-id"])[0]
        self.assertEqual(row["source"], "device")
        self.assertIn("INSERT status x5", row["changes"])

    def test_reads_are_rows_only_when_they_fail(self):
        ok = self.admin("GET", "/api/v1/backup/health")
        self.assertEqual(rows(rid=ok.headers["x-request-id"]), [])
        refused = self.web.get("/api/v1/backup/health", headers={"X-Backup-Token": "not-a-token"})
        self.assertEqual(refused.status_code, 401)
        self.assertEqual(len(rows(rid=refused.headers["x-request-id"])), 1)

    def test_a_crash_is_a_500_naming_its_request_id(self):
        def boom():
            with api.db() as c:
                c.execute("INSERT INTO acks(target,sig,ts,note) VALUES('half','x',0,'written before the crash')")
                raise RuntimeError("kaboom")
        api.app.add_api_route("/api/v1/backup/_test_boom", boom, methods=["POST"])
        crashing = TestClient(api.app, base_url="https://cairn.test", raise_server_exceptions=False)
        r = crashing.post("/api/v1/backup/_test_boom", headers={"X-Backup-Token": ADMIN})
        self.assertEqual(r.status_code, 500)
        rid = r.headers["x-request-id"]
        self.assertIn(rid, r.json()["error"])
        row = rows(rid=rid)[0]
        self.assertIn("kaboom", row["error"])
        self.assertIn("not saved", row["changes"])
        with api.db() as c:   # the half-write was never committed
            self.assertIsNone(c.execute("SELECT 1 FROM acks WHERE target='half'").fetchone())

    def test_a_client_crash_report_is_logged_for_any_signed_in_role(self):
        viewer = self.admin("POST", "/api/v1/backup/tokens", json={"role": "viewer", "label": "phone-ev",
                                                                   "kind": "ui"}).json()["token"]
        r = self.web.post("/api/v1/backup/events", headers={"X-Backup-Token": viewer, "X-Cairn-App": "0.3.0"},
                          json={"events": [{"kind": "crash", "at": "2026-10-19T09:00:00.000-06:00",
                                            "data": {"report": "java.lang.IllegalStateException: x",
                                                     "token": viewer}}]})
        self.assertEqual(r.json(), {"logged": 1})
        row = rows(kind="app:crash")[-1]
        self.assertEqual(row["who"], "phone-ev")
        self.assertEqual(row["client"], "app 0.3.0")
        self.assertNotIn(viewer, json.dumps(row))   # a secret-looking key is hidden

    def test_the_log_is_for_admins_only(self):
        viewer = self.admin("POST", "/api/v1/backup/tokens", json={"role": "viewer", "label": "ro-log",
                                                                   "kind": "ui"}).json()["token"]
        self.assertEqual(self.web.get("/api/v1/backup/log", headers={"X-Backup-Token": viewer}).status_code, 403)
        r = self.admin("GET", "/api/v1/backup/log?days=7")
        self.assertEqual(r.status_code, 200)
        self.assertIn("stats", r.json())
        page = self.admin("GET", "/log")
        self.assertEqual(page.status_code, 200)
        self.assertIn("renderLog", page.text)

    def test_secrets_minted_anywhere_never_reach_the_log(self):
        testkit.assert_absent(self, [ADMIN, AGENT, PASSWORD, api._hash(ADMIN), api._hash(AGENT)] + self.minted)


if __name__ == "__main__":
    unittest.main()
