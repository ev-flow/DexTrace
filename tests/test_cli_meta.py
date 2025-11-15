# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

from dextrace.cli.main import main
from pathlib import Path
import zipfile
import json
import sys


def test_cli_meta(tmp_path, capsys):
    apk_path = tmp_path / "fake.apk"
    with zipfile.ZipFile(apk_path, "w") as z:
        z.writestr("classes.dex", b"hello")  # invalid DEX, expected error
        z.writestr("AndroidManifest.xml", b"<manifest/>")

    # 執行 CLI：dextrace meta <path>
    from dextrace.cli.main import main
    exit_code = main(["meta", str(apk_path)])
    assert exit_code == 0

    # 擷取 CLI 輸出
    captured = capsys.readouterr().out
    info = json.loads(captured)

    assert info["filename"] == "fake.apk"

    # 因為 dex_files 是 list[dict] → 不能再用 "in" 直接比對字串
    dex_names = [d["name"] for d in info["dex_files"]]
    assert "classes.dex" in dex_names

    # 檢查錯誤正常寫入
    entry = next(d for d in info["dex_files"] if d["name"] == "classes.dex")
    assert "error" in entry
    assert entry["error"].startswith("File too small")
