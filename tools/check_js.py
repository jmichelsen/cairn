#!/usr/bin/env python3
"""Lint the inline JavaScript embedded in Cairn's server-rendered HTML.

The dashboard ships a large inline <script> (PAGE_SCRIPT) plus a few smaller ones built inside
Python string literals / f-strings in phase1/api.py. A Python-level escaping slip - e.g. a single
backslash \\' where JS-inside-a-JS-string needs \\\\' in the non-raw PAGE_SCRIPT - emits invalid
JavaScript that silently kills the WHOLE inline script at runtime, leaving every button dead with
NO server-side error. Code review keeps missing it; this catches it mechanically.

We parse phase1/api.py with `ast`, reconstruct every string the way Python actually renders it
(plain literals decoded; f-strings with each {expr} replaced by a neutral `0` placeholder), pull
out every <script>...</script> block, and run `node --check` on each. Exit non-zero on any error.

Run locally:  python3 tools/check_js.py      (needs node on PATH)
"""
import ast
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API = os.path.join(ROOT, "phase1", "api.py")
SCRIPT_RE = re.compile(r"<script\b[^>]*>(.*?)</script>", re.S | re.I)


def _joined(node):
    """Reconstruct an f-string's text, each {expr} replaced by a neutral JS placeholder (0)."""
    parts = []
    for v in node.values:
        if isinstance(v, ast.Constant) and isinstance(v.value, str):
            parts.append(v.value)
        elif isinstance(v, ast.FormattedValue):
            parts.append("0")
    return "".join(parts)


def _strings(tree):
    """Yield (label, rendered_text) for every str literal and f-string in the module."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield (f"api.py:{node.lineno} literal", node.value)
        elif isinstance(node, ast.JoinedStr):
            yield (f"api.py:{node.lineno} f-string", _joined(node))


def main():
    node = shutil.which("node")
    if not node:
        print("check_js: FATAL - `node` not found on PATH (install nodejs)", file=sys.stderr)
        return 2
    tree = ast.parse(open(API, encoding="utf-8").read(), filename=API)
    blocks = [(label, js) for label, text in _strings(tree)
              for js in SCRIPT_RE.findall(text) if js.strip()]
    if not blocks:
        print("check_js: FATAL - no <script> blocks found in phase1/api.py (did it move?)",
              file=sys.stderr)
        return 2
    failures = 0
    for label, js in blocks:
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
            f.write(js)
            path = f.name
        r = subprocess.run([node, "--check", path], capture_output=True, text=True)
        os.unlink(path)
        if r.returncode == 0:
            print(f"check_js: OK    {label}  ({len(js)} chars)")
        else:
            failures += 1
            print(f"check_js: FAIL  {label}\n{r.stderr.strip()}", file=sys.stderr)
    if failures:
        print(f"check_js: {failures} inline script block(s) FAILED", file=sys.stderr)
        return 1
    print(f"check_js: all {len(blocks)} inline script block(s) valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
