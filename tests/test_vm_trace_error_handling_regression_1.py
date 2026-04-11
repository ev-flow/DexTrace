# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
Regression tests for /qa findings:
  ISSUE-002 — malformed DEX emits traceback instead of clean [ERROR] message
  ISSUE-003 — APK without classes.dex raises unhandled KeyError

Found by /qa on 2026-04-11
Report: .gstack/qa-reports/qa-report-dextrace-2026-04-11.md
"""

from __future__ import annotations

import io
import zipfile
from unittest.mock import patch

import pytest

from dextrace.cli.main import main
from dextrace.vm.decoder import DexParseError, walk_method

# ---------------------------------------------------------------------------
# ISSUE-002: malformed DEX raises traceback instead of [ERROR]
# ---------------------------------------------------------------------------


def test_walk_method_malformed_dex_raises_parse_error():
    """
    Regression: ISSUE-002 — malformed DEX bytes must raise DexParseError,
    not a raw ValueError or struct.error traceback.
    Found by /qa on 2026-04-11
    Report: .gstack/qa-reports/qa-report-dextrace-2026-04-11.md
    """
    bad_bytes = b"not a dex file at all"
    with pytest.raises(DexParseError, match="File too small"):
        walk_method(bad_bytes, "Lp1;->main()I")


def test_walk_method_empty_bytes_raises_parse_error():
    """
    Regression: ISSUE-002 — empty byte string must raise DexParseError.
    Found by /qa on 2026-04-11
    """
    with pytest.raises(DexParseError):
        walk_method(b"", "Lp1;->main()I")


def test_cli_malformed_dex_exits_3(tmp_path):
    """
    Regression: ISSUE-002 — CLI must exit 3 (parse error) and print [ERROR]
    for a malformed DEX file. Previously raised an uncaught traceback.
    Found by /qa on 2026-04-11
    """
    bad_dex = tmp_path / "bad.dex"
    bad_dex.write_bytes(b"not a dex file")

    stderr_buf = io.StringIO()
    with patch("sys.stderr", stderr_buf):
        rc = main(["trace", str(bad_dex), "--entry", "Lp1;->main()I"])

    assert rc == 3
    assert "[ERROR]" in stderr_buf.getvalue()
    assert "malformed DEX" in stderr_buf.getvalue()


# ---------------------------------------------------------------------------
# ISSUE-003: APK without classes.dex raises unhandled KeyError
# ---------------------------------------------------------------------------


def _make_apk_without_dex(path):
    """Build a minimal APK (zip) that does NOT contain classes.dex."""
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")


def test_cli_apk_no_classes_dex_exits_3(tmp_path):
    """
    Regression: ISSUE-003 — CLI must exit 3 (parse error) and print [ERROR]
    for an APK that has no classes.dex. Previously raised an unhandled KeyError.
    Found by /qa on 2026-04-11
    Report: .gstack/qa-reports/qa-report-dextrace-2026-04-11.md
    """
    apk = tmp_path / "no_dex.apk"
    _make_apk_without_dex(str(apk))

    stderr_buf = io.StringIO()
    with patch("sys.stderr", stderr_buf):
        rc = main(["trace", str(apk), "--entry", "Lp1;->main()I"])

    assert rc == 3
    assert "[ERROR]" in stderr_buf.getvalue()
    assert "classes.dex" in stderr_buf.getvalue()


# ---------------------------------------------------------------------------
# REVIEW-001: non-.dex non-ZIP file hits ApkReader and raises uncaught BadZipFile
# ---------------------------------------------------------------------------


def test_cli_non_zip_non_dex_exits_3(tmp_path):
    """
    Review finding: a file that is neither a valid DEX nor a valid ZIP hits
    ApkReader.__init__ which raises zipfile.BadZipFile. Previously this
    propagated as an uncaught exception. Now it must exit 3 with [ERROR].
    """
    bad_apk = tmp_path / "not_a_zip.apk"
    bad_apk.write_bytes(b"this is not a zip archive")

    stderr_buf = io.StringIO()
    with patch("sys.stderr", stderr_buf):
        rc = main(["trace", str(bad_apk), "--entry", "Lp1;->main()I"])

    assert rc == 3
    assert "[ERROR]" in stderr_buf.getvalue()
