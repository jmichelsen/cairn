"""Checks every app runs in its own tests (docs/RULES.md "Tests").

    from applog import testkit
    testkit.assert_absent(self, [PASSWORD, token, token_hash, "kid's message text"])
    testkit.assert_declared(self)

assert_absent scans every column of every log row, the daily rollup and anything captured from stdout.
"""
import contextlib
import io
import sqlite3

from . import core

_captured = io.StringIO()


@contextlib.contextmanager
def capture_stdout():
    """Keep the stdout lines printed inside the block, so assert_absent can scan them too."""
    import sys
    real = sys.stdout
    tee = _Tee(real, _captured)
    sys.stdout = tee
    try:
        yield _captured
    finally:
        sys.stdout = real


class _Tee:
    def __init__(self, *outs):
        self.outs = outs

    def write(self, s):
        for o in self.outs:
            o.write(s)
        return len(s)

    def flush(self):
        for o in self.outs:
            o.flush()


def everything():
    """All logged text: every row of the log and its rollup, and captured stdout."""
    t = core.cfg().table
    con = sqlite3.connect(core._db_path())
    try:
        parts = []
        for table in (t, f"{t}_daily"):
            for row in con.execute(f"SELECT * FROM {table}"):
                parts.append(" ".join("" if v is None else str(v) for v in row))
        return "\n".join(parts) + "\n" + _captured.getvalue()
    finally:
        con.close()


def assert_absent(test, values):
    text = everything()
    for v in values:
        if v:
            test.assertNotIn(str(v), text, f"logged a value that must never be logged: {str(v)[:12]}…")


def assert_declared(test):
    test.assertEqual(core.undeclared(), [], "columns with no logging declaration: add each to columns (shown) "
                                            "or secret_columns (never shown) in applog.configure()")
