# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


import hashlib
import os


def compute_hashes(path: str):
    result = {}
    for algo in ("md5", "sha1", "sha256"):
        h = hashlib.new(algo)
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        result[algo] = h.hexdigest()
    result["filesize"] = os.path.getsize(path)
    return result
