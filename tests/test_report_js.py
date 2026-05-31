"""Runs the JS unit suite via `node --test`; skipped when node is unavailable."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent
_JS_DIR = _ROOT / "js"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_js_unit_suite_passes():
    # Expand the glob to explicit file paths before passing to node.
    # node v25 raises MODULE_NOT_FOUND when given a directory arg, and when
    # given *no* file args it falls back to cwd auto-discovery — which can
    # silently pass with zero tests run.  Explicit files + the assertion below
    # prevent both failure modes.
    test_files = sorted(_JS_DIR.glob("**/*.test.js"))
    assert test_files, "no JS test files found under tests/js"
    proc = subprocess.run(
        ["node", "--test", *[str(f) for f in test_files]],
        capture_output=True,
        text=True,
        cwd=str(_ROOT.parent),
    )
    assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr
