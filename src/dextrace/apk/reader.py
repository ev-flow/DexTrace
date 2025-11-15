# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

from pathlib import Path
import os, zipfile, hashlib
from typing import Dict, Generator, Tuple, Any
from ..manifest.axml_parser import ManifestInspector
from ..errors import BadAxmlFormat
from ..dex.dex_header import parse_dex_header


class ApkReader:
    """Read basic information and dex files from an APK."""

    def __init__(self, apk_path: str):
        if not os.path.isfile(apk_path):
            raise FileNotFoundError(f"APK not found: {apk_path}")
        self.apk_path = apk_path
        self._zip = zipfile.ZipFile(apk_path, "r")

    def get_info(self) -> Dict[str, Any]:
        info = {
            "filename": os.path.basename(self.apk_path),
            "filesize": os.path.getsize(self.apk_path),
            "md5": self._calc_hash("md5"),
            "sha1": self._calc_hash("sha1"),
            "sha256": self._calc_hash("sha256"),
            "entries": self._zip.namelist(),
            "dex_files": list(),
        }

        if "AndroidManifest.xml" in info["entries"]:
            with self._zip.open("AndroidManifest.xml") as f:
                data = f.read()
                try:
                    info["manifest"] = ManifestInspector.parse(data)
                except BadAxmlFormat:
                    info["manifest"] = {"error": "Bad AXML format"}

        else:
            info["manifest"] = {"error": "No manifest found"}

        # --- Parse DEX headers ---
        dex_entries = sorted([f for f in info["entries"] if f.endswith(".dex")])
        for dex_name in dex_entries:
            with self._zip.open(dex_name) as f:
                raw = f.read()
                tmp_path = Path(f"/tmp/{dex_name}")
                tmp_path.write_bytes(raw)

                try:
                    header = parse_dex_header(str(tmp_path))
                    info["dex_files"].append({
                        "name": dex_name,
                        "header": header.to_dict(),
                    })
                except Exception as e:
                    info["dex_files"].append({
                        "name": dex_name,
                        "error": str(e),
                    })
                finally:
                    tmp_path.unlink(missing_ok=True)

        return info

    def get_dex_files(self) -> Generator[Tuple[str, bytes, int], None, None]:
        """Yield each dex file as (filename, raw_bytes, index)."""
        dex_files = sorted([f for f in self._zip.namelist() if f.endswith(".dex")])
        for idx, name in enumerate(dex_files):
            with self._zip.open(name) as dex:
                yield (name, dex.read(), idx)

    def _calc_hash(self, algo: str) -> str:
        """Calculate file hash (md5, sha1, sha256)."""
        h = hashlib.new(algo)
        with open(self.apk_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
