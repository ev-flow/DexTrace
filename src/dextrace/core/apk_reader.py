# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
Low-level APK reader.

Responsible only for:
- opening the APK as a ZIP archive
- listing entries
- reading raw file contents
"""

import io
import os
import zipfile
from typing import List, Tuple


class ApkReader:
    """Low-level reader for APK files. No parsing logic is implemented here."""

    def __init__(self, apk_path: str):
        if not os.path.isfile(apk_path):
            raise FileNotFoundError(f"APK not found: {apk_path}")
        self.apk_path = apk_path
        with open(apk_path, "rb") as f:
            raw = bytearray(f.read())
        self._zip = zipfile.ZipFile(io.BytesIO(raw), "r")

    def list_entries(self) -> List[str]:
        """Return the list of entries inside the APK."""
        return self._zip.namelist()

    def read_file(self, name: str) -> bytes:
        """Read a file from the APK by name and return its raw bytes."""
        with self._zip.open(name) as f:
            return f.read()

    def iter_dex_files(self) -> list[Tuple[str, bytes]]:
        """Return a list of (filename, raw_bytes) for all *.dex entries."""
        return [
            (name, self.read_file(name))
            for name in sorted(self.list_entries())
            if name.endswith(".dex")
        ]
