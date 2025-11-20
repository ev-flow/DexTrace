# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


import json
import zipfile
from dextrace.cli.main import main
from pathlib import Path


def test_cli_meta(tmp_path, capsys):
    apk_path = tmp_path / "fake.apk"
    with zipfile.ZipFile(apk_path, "w") as z:
        z.writestr("AndroidManifest.xml", b"<manifest/>")
        z.writestr("classes.dex", b"hello")

    exit_code = main(["meta", str(apk_path)])
    assert exit_code == 0 or exit_code == 1

    output = capsys.readouterr().out
    meta = json.loads(output)

    assert meta["filename"] == "fake.apk"
    assert "entries" in meta
    assert "manifest" in meta
    assert "dex_files" in meta
