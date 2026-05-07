# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
tests/fixtures/droidkungfu_fetcher.py — Lazy fetcher for the DroidKungFu sample.

Lookup order:
  1. $DEXTRACE_DROIDKUNGFU_APK env var → absolute path to a local copy
  2. ~/codespace/dextrace_enforcements/<sha256>.apk
  3. ~/codespace/dextrace_enforcements/scenario_droidkungfu/<sha256>.apk

SHA256-locked. Tests skip on FetcherError so offline runs remain green.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

DROIDKUNGFU_SHA256 = (
    "d277c97b1a8a78f859672b4a20e74b3313e9f964e68a6e857c1e9d33763434a5"
)
DROIDKUNGFU_APK_FILENAME = f"{DROIDKUNGFU_SHA256.upper()}.apk"


class FetcherError(RuntimeError):
    pass


def _verify(path: Path) -> Path:
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    if sha.lower() != DROIDKUNGFU_SHA256.lower():
        raise FetcherError(
            f"SHA256 mismatch for {path}: got {sha}, want {DROIDKUNGFU_SHA256}"
        )
    return path


def get_apk_path() -> Path:
    """Return a Path to the DroidKungFu APK, raising FetcherError if unavailable."""
    # 1. Env var override
    env_path = os.environ.get("DEXTRACE_DROIDKUNGFU_APK")
    if env_path:
        return _verify(Path(env_path))

    # 2. Local file in dextrace_enforcements root
    local = Path(__file__).parents[4] / DROIDKUNGFU_APK_FILENAME
    if local.exists():
        return _verify(local)

    # 3. scenario_droidkungfu subfolder
    scenario = (
        Path(__file__).parents[4]
        / "scenario_droidkungfu"
        / DROIDKUNGFU_APK_FILENAME
    )
    if scenario.exists():
        return _verify(scenario)

    raise FetcherError(
        f"DroidKungFu APK not found. Set DEXTRACE_DROIDKUNGFU_APK or place "
        f"the APK at {local}"
    )
