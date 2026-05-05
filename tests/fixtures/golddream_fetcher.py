# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
tests/fixtures/golddream_fetcher.py — Lazy fetcher for the GoldDream sample.

Lookup order:
  1. $DEXTRACE_GOLDDREAM_APK env var → absolute path to a local copy
  2. ~/codespace/dextrace_enforcements/<sha256>.apk
  3. ~/.cache/dextrace/golddream.apk (cached fetch)

SHA256-locked. Tests skip on FetcherError so offline runs remain green.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

GOLDDREAM_SHA256 = (
    "eca3a3666b0fd72028431431e7fae6774a8ca692e35ae3cb44fd8f2aa418f746"
)
GOLDDREAM_APK_FILENAME = f"{GOLDDREAM_SHA256.upper()}.apk"

CACHE_DIR = Path.home() / ".cache" / "dextrace"


class FetcherError(RuntimeError):
    pass


def _verify(path: Path) -> Path:
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    if sha.lower() != GOLDDREAM_SHA256.lower():
        raise FetcherError(
            f"SHA256 mismatch for {path}: got {sha}, want {GOLDDREAM_SHA256}"
        )
    return path


def get_apk_path() -> Path:
    """Return a Path to the GoldDream APK, raising FetcherError if unavailable."""
    # 1. Env var override
    env_path = os.environ.get("DEXTRACE_GOLDDREAM_APK")
    if env_path:
        return _verify(Path(env_path))

    # 2. Local file in dextrace_enforcements root
    local = (
        Path(__file__).parents[4]
        / GOLDDREAM_APK_FILENAME
    )
    if local.exists():
        return _verify(local)

    # 3. Cache
    cached = CACHE_DIR / "golddream.apk"
    if cached.exists():
        return _verify(cached)

    raise FetcherError(
        f"GoldDream APK not found. Set DEXTRACE_GOLDDREAM_APK or place the APK at {local}"
    )
