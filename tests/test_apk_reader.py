# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

import zipfile
from dextrace.apk.reader import ApkReader

def test_apkreader_info(tmp_path):
    apk_path = tmp_path / "fake.apk"
    with zipfile.ZipFile(apk_path, "w") as z:
        z.writestr("classes.dex", b"hello")
        z.writestr("AndroidManifest.xml", b"<manifest/>")

    reader = ApkReader(str(apk_path))
    info = reader.get_info()

    assert info["filename"] == "fake.apk"
    assert "classes.dex" in info["dex_files"]

    dex_files = list(reader.get_dex_files())
    assert len(dex_files) == 1
    name, raw, idx = dex_files[0]
    assert name == "classes.dex"
    assert raw == b"hello"
    assert idx == 0
