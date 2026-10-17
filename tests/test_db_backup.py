import os
import sqlite3
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "phase1"))
import api  # noqa: E402


def _setup(tmp_path, monkeypatch, keep=2):
    db = tmp_path / "cairn.db"
    c = sqlite3.connect(db)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("CREATE TABLE t (x)")
    c.execute("INSERT INTO t VALUES (42)")
    c.commit()
    c.close()
    bk = tmp_path / "backups"
    monkeypatch.setattr(api, "DB", str(db))
    monkeypatch.setattr(api, "DB_BACKUP_DIR", str(bk))
    monkeypatch.setattr(api, "DB_BACKUP_KEEP", keep)
    return bk


def test_snapshot_is_consistent_and_written_once_per_day(tmp_path, monkeypatch):
    bk = _setup(tmp_path, monkeypatch)
    path = api._db_backup_once(force=True)
    assert path and os.path.exists(path)
    assert sqlite3.connect(path).execute("SELECT x FROM t").fetchone() == (42,)
    assert api._db_backup_once(force=True) is None      # today's already there
    assert not [f for f in os.listdir(bk) if f.endswith(".tmp")]


def test_keeps_only_newest(tmp_path, monkeypatch):
    bk = _setup(tmp_path, monkeypatch, keep=2)
    bk.mkdir()
    for d in ("2020-01-01", "2020-01-02", "2020-01-03"):
        (bk / f"cairn-{d}.db").write_bytes(b"old")
    api._db_backup_once(force=True)
    left = sorted(os.listdir(bk))
    assert len(left) == 2 and "cairn-2020-01-03.db" in left


def test_skips_when_disk_is_short(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)

    class St:
        f_bavail = 0
        f_frsize = 4096
    monkeypatch.setattr(api.os, "statvfs", lambda p: St())
    assert api._db_backup_once(force=True) is None


def test_waits_for_the_hour_and_honours_off(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(api, "DB_BACKUP_HOUR", None)
    assert api._db_backup_once() is None
    monkeypatch.setattr(api, "DB_BACKUP_HOUR", 24)        # never reached
    assert api._db_backup_once() is None
