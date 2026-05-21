# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


import zipfile
from pathlib import Path
from dextrace.core.apk_metadata import ApkMetadata


def test_apk_metadata_collects_basic_fields(tmp_path: Path):
    apk_path = tmp_path / "fake.apk"
    with zipfile.ZipFile(apk_path, "w") as z:
        z.writestr("AndroidManifest.xml", b"<manifest/>")
        z.writestr("classes.dex", b"hello")  # invalid, expecting error

    meta = ApkMetadata(str(apk_path)).get_metadata()

    assert meta["filename"] == "fake.apk"
    assert "entries" in meta
    assert "manifest" in meta
    assert "dex_files" in meta


def test_apk_metadata_records_dex_error(tmp_path: Path):
    apk_path = tmp_path / "fake.apk"
    with zipfile.ZipFile(apk_path, "w") as z:
        z.writestr("classes.dex", b"small")  # too small for valid DEX

    meta = ApkMetadata(str(apk_path)).get_metadata()
    dex_info = meta["dex_files"][0]

    assert dex_info["name"] == "classes.dex"
    assert "error" in dex_info
