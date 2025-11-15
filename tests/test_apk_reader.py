# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


import zipfile
from dextrace.apk.reader import ApkReader


def test_apkreader_info(tmp_path):
    apk_path = tmp_path / "fake.apk"
    with zipfile.ZipFile(apk_path, "w") as z:
        # 非法 DEX（太短） → 預期會出現 "error"
        z.writestr("classes.dex", b"hello")
        z.writestr("AndroidManifest.xml", b"<manifest/>")

    reader = ApkReader(str(apk_path))
    info = reader.get_info()

    assert info["filename"] == "fake.apk"

    # dex_files 現在是 list[dict]
    dex_names = [d["name"] for d in info["dex_files"]]
    assert "classes.dex" in dex_names

    # 測試錯誤處理
    dex_entry = next(d for d in info["dex_files"] if d["name"] == "classes.dex")
    assert "error" in dex_entry
    assert dex_entry["error"].startswith("File too small")


