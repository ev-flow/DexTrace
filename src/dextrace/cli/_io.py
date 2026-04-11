# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
cli/_io.py — Shared DEX/APK loading helper for CLI subcommands.
"""

from __future__ import annotations

import zipfile
from pathlib import Path


def load_dex_bytes(input_path: Path) -> tuple[bytes, str]:
    """
    Load DEX bytes from a .dex file or extract classes.dex from an .apk.

    Returns (dex_bytes, dex_filename).
    Raises SystemExit with a user-facing message on error.
    """
    if input_path.suffix.lower() == ".dex":
        return input_path.read_bytes(), input_path.name

    # APK branch: extract classes.dex from the ZIP archive.
    try:
        from dextrace.core.apk_reader import ApkReader
        apk = ApkReader(str(input_path))
    except zipfile.BadZipFile:
        raise SystemExit(f"not a valid APK (bad zip): {input_path.name}")

    if "classes.dex" not in apk.list_entries():
        raise SystemExit("APK does not contain classes.dex")

    return apk.read_file("classes.dex"), "classes.dex"
