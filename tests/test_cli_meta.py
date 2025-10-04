# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

from dextrace.cli.main import main
from pathlib import Path
import zipfile
import json
import sys


def test_cli_meta(tmp_path, capsys):
    apk_path = tmp_path / "demo.apk"
    with zipfile.ZipFile(apk_path, "w") as z:
        z.writestr("classes.dex", b"hello")
        z.writestr("AndroidManifest.xml", b"<manifest/>")

    # 直接呼叫 main()
    main(["meta", str(apk_path)])

    out, _ = capsys.readouterr()
    data = json.loads(out)
    assert data["filename"] == "demo.apk"
    assert "classes.dex" in data["dex_files"]
