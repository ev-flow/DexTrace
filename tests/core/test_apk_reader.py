# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


import zipfile
from pathlib import Path
from dextrace.core.apk_reader import ApkReader


def test_apk_reader_lists_entries(tmp_path: Path):
    apk_path = tmp_path / "fake.apk"
    with zipfile.ZipFile(apk_path, "w") as z:
        z.writestr("classes.dex", b"hello")
        z.writestr("AndroidManifest.xml", b"<manifest/>")

    reader = ApkReader(str(apk_path))
    entries = reader.list_entries()

    assert "classes.dex" in entries
    assert "AndroidManifest.xml" in entries


def test_apk_reader_extracts_file(tmp_path: Path):
    apk_path = tmp_path / "fake.apk"
    with zipfile.ZipFile(apk_path, "w") as z:
        z.writestr("test.txt", b"abcdef")

    reader = ApkReader(str(apk_path))
    content = reader.read_file("test.txt")

    assert content == b"abcdef"


def test_apk_reader_iter_dex_files(tmp_path: Path):
    apk_path = tmp_path / "fake.apk"
    with zipfile.ZipFile(apk_path, "w") as z:
        z.writestr("classes.dex", b"dexcontent")
        z.writestr("notdex.txt", b"nope")

    reader = ApkReader(str(apk_path))
    dex_files = reader.iter_dex_files()

    assert len(dex_files) == 1
    name, data = dex_files[0]
    assert name == "classes.dex"
    assert data == b"dexcontent"
