# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
Regression tests for /qa findings:
  ISSUE-004 — APK files silently unsupported in dextrace run (wrong error msg)
  ISSUE-005 — directory-as-input gives wrong exit code in dextrace run

Found by /qa on 2026-04-11
Report: .gstack/qa-reports/qa-report-dextrace-2026-04-11.md
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from dextrace.cli.main import main

FIXTURE_P1 = Path(__file__).parent / "fixtures" / "samples" / "p1_const_return.dex"
ENTRY_P1 = "Lp1;->main()I"


# ---------------------------------------------------------------------------
# ISSUE-004: APK files return "expected a .dex file" instead of working
# ---------------------------------------------------------------------------

def _make_apk_with_dex(path, dex_bytes: bytes) -> None:
    """Build a minimal APK (zip) containing the given DEX bytes as classes.dex."""
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("classes.dex", dex_bytes)


def _make_apk_without_dex(path) -> None:
    """Build a minimal APK (zip) that does NOT contain classes.dex."""
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")


def test_cli_run_apk_with_classes_dex_succeeds(tmp_path):
    """
    Regression: ISSUE-004 — dextrace run must accept .apk files that contain
    classes.dex. Previously returned "expected a .dex file, got: '.apk'" (exit 1).
    Found by /qa on 2026-04-11
    Report: .gstack/qa-reports/qa-report-dextrace-2026-04-11.md
    """
    apk = tmp_path / "test.apk"
    _make_apk_with_dex(str(apk), FIXTURE_P1.read_bytes())

    stdout_buf = io.StringIO()
    with patch("sys.stdout", stdout_buf):
        rc = main(["run", str(apk), "--entry", ENTRY_P1])

    assert rc == 0
    assert "42" in stdout_buf.getvalue()


def test_cli_run_apk_no_classes_dex_exits_3(tmp_path):
    """
    Regression: ISSUE-004 — APK without classes.dex must exit 3 with [ERROR].
    Previously gave "expected a .dex file, got: '.apk'" (exit 1, wrong message).
    Found by /qa on 2026-04-11
    """
    apk = tmp_path / "no_dex.apk"
    _make_apk_without_dex(str(apk))

    stderr_buf = io.StringIO()
    with patch("sys.stderr", stderr_buf):
        rc = main(["run", str(apk), "--entry", ENTRY_P1])

    assert rc == 3
    assert "[ERROR]" in stderr_buf.getvalue()
    assert "classes.dex" in stderr_buf.getvalue()


def test_cli_run_bad_apk_exits_3(tmp_path):
    """
    Regression: ISSUE-004 — non-ZIP .apk must exit 3 with [ERROR].
    Previously gave "expected a .dex file, got: '.apk'" (exit 1, wrong message).
    Found by /qa on 2026-04-11
    """
    apk = tmp_path / "bad.apk"
    apk.write_bytes(b"this is not a zip archive")

    stderr_buf = io.StringIO()
    with patch("sys.stderr", stderr_buf):
        rc = main(["run", str(apk), "--entry", ENTRY_P1])

    assert rc == 3
    assert "[ERROR]" in stderr_buf.getvalue()


# ---------------------------------------------------------------------------
# ISSUE-005: directory-as-input gives exit 3 instead of exit 1
# ---------------------------------------------------------------------------

def test_cli_run_directory_input_exits_1(tmp_path):
    """
    Regression: ISSUE-005 — a directory named *.dex previously hit read_bytes()
    which raised IsADirectoryError, caught by the parse-error handler (exit 3).
    Now exits 1 (user error) with [ERROR] not a file.
    Found by /qa on 2026-04-11
    Report: .gstack/qa-reports/qa-report-dextrace-2026-04-11.md
    """
    dex_dir = tmp_path / "classes.dex"
    dex_dir.mkdir()

    stderr_buf = io.StringIO()
    with patch("sys.stderr", stderr_buf):
        rc = main(["run", str(dex_dir), "--entry", ENTRY_P1])

    assert rc == 1
    assert "[ERROR]" in stderr_buf.getvalue()
    assert "not a file" in stderr_buf.getvalue()
