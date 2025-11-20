# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


"""
High-level APK metadata extraction.

This module builds a structured metadata dictionary for an APK:
- file hashes
- ZIP entries
- manifest information
- DEX header information
"""

import os
import hashlib
from typing import Dict, Any

from .apk_reader import ApkReader
from .manifest_parser import ManifestParser
from .dex_header import parse_dex_header


class ApkMetadata:
    """High-level metadata aggregator for a single APK file."""

    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.reader = ApkReader(apk_path)

    # ---------------- public API ---------------- #

    def get_metadata(self) -> Dict[str, Any]:
        """Return a dictionary containing static APK metadata."""
        entries = self.reader.list_entries()

        info: Dict[str, Any] = {
            "filename": os.path.basename(self.apk_path),
            "filesize": os.path.getsize(self.apk_path),
            "md5": self._calc_hash("md5"),
            "sha1": self._calc_hash("sha1"),
            "sha256": self._calc_hash("sha256"),
            "entries": entries,
            "dex_files": [],
        }

        # Manifest
        if "AndroidManifest.xml" in entries:
            manifest_bytes = self.reader.read_file("AndroidManifest.xml")
            info["manifest"] = ManifestParser.parse(manifest_bytes)
        else:
            info["manifest"] = {"error": "No manifest found"}

        # DEX headers
        for name, raw in self.reader.iter_dex_files():
            try:
                header = parse_dex_header(data=raw)
                info["dex_files"].append(
                    {
                        "name": name,
                        "header": header.to_dict(),
                    }
                )
            except Exception as exc:
                info["dex_files"].append(
                    {
                        "name": name,
                        "error": str(exc),
                    }
                )

        return info

    def get_info(self) -> Dict[str, Any]:
        """
        Backward-compatible alias for get_metadata().

        Older code and tests may still call ApkReader.get_info() or a similar
        API. This method preserves that behavior while allowing new code to use
        get_metadata() explicitly.
        """
        return self.get_metadata()

    # ---------------- internal helpers ---------------- #

    def _calc_hash(self, algo: str) -> str:
        """Calculate a file hash (md5, sha1, sha256)."""
        h = hashlib.new(algo)
        with open(self.apk_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
