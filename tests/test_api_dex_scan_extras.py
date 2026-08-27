# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

from __future__ import annotations

import zipfile
from pathlib import Path

from dextrace.api import extract_declared_methods, extract_strings
from tests.fixtures.dex_factory import build_minimal_test_dex


def test_extract_declared_methods_smoke(tmp_path: Path):
    """Minimal DEX has one concrete method: LTest;-><init>()V (code_off != 0)."""
    dex_file = tmp_path / "test.dex"
    dex_file.write_bytes(build_minimal_test_dex())

    result = extract_declared_methods(str(dex_file))

    assert isinstance(result, list)
    assert result == ["LTest;-><init>()V"]


def test_extract_declared_methods_no_dex_returns_empty(tmp_path: Path):
    """An APK with no classes.dex yields an empty list, not an error."""
    apk_file = tmp_path / "no_dex.apk"
    with zipfile.ZipFile(apk_file, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"")

    assert extract_declared_methods(str(apk_file)) == []


def test_extract_strings_smoke(tmp_path: Path):
    """String pool comes back in string_ids index order, duplicates intact."""
    dex_file = tmp_path / "test.dex"
    dex_file.write_bytes(build_minimal_test_dex())

    result = extract_strings(str(dex_file))

    assert result == [
        "LTest;",
        "Ljava/lang/Object;",
        "Ljava/lang/String;",
        "Ljava/lang/StringBuilder;",
        "<init>",
        "append",
        "V",
        "LL",
        "HELLO",
    ]


def test_extract_strings_no_dex_returns_empty(tmp_path: Path):
    """An APK with no classes.dex yields an empty list, not an error."""
    apk_file = tmp_path / "no_dex.apk"
    with zipfile.ZipFile(apk_file, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"")

    assert extract_strings(str(apk_file)) == []
