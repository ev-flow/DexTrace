# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
tests/fixtures/p4_ahmyth_fetcher.py — Lazy fetcher for the P4 malware sample.

Why not commit the APK? Real malware in tests/fixtures/ trips AV scanners on
contributor laptops, CI runners, and forge mirrors. Quark and other security
tooling solve this by fetching on demand from a malware corpus URL with a
SHA256 lock.

Lookup order (first hit wins):
  1. $DEXTRACE_AHMYTH_APK env var → an absolute path to a local copy
  2. ~/.cache/dextrace/p4_ahmyth.apk (cached previous fetch)
  3. Download from $DEXTRACE_AHMYTH_URL (defaults to MalwareBazaar)

Every path verifies SHA256 before returning. Tests should call get_apk_path()
inside a pytest fixture and pytest.skip() on FetcherError so offline runs
remain green.
"""

from __future__ import annotations

import hashlib
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

AHMYTH_SHA256 = "f39b1a25c299ff532df840c6216fee41c8eb70787aba5e51624aae7b8eccc12c"

# MalwareBazaar publishes Ahmyth under this hash; the URL is stable and signed.
DEFAULT_URL = (
    "https://mb-api.abuse.ch/api/v1/"
    f"file/{AHMYTH_SHA256}/?action=get_file"
)

CACHE_DIR = Path.home() / ".cache" / "dextrace"
CACHE_PATH = CACHE_DIR / "p4_ahmyth.apk"


class FetcherError(Exception):
    """Raised when the APK cannot be located, downloaded, or verified."""


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify(path: Path) -> None:
    actual = _sha256(path)
    if actual != AHMYTH_SHA256:
        raise FetcherError(
            f"checksum mismatch: {path} sha256={actual} expected={AHMYTH_SHA256}"
        )


def _try_env_path() -> Optional[Path]:
    env = os.environ.get("DEXTRACE_AHMYTH_APK")
    if not env:
        return None
    p = Path(env)
    if not p.exists():
        raise FetcherError(f"$DEXTRACE_AHMYTH_APK points to missing file: {p}")
    _verify(p)
    return p


def _try_cache() -> Optional[Path]:
    if not CACHE_PATH.exists():
        return None
    try:
        _verify(CACHE_PATH)
    except FetcherError:
        # Stale cache (different hash). Remove and re-fetch.
        CACHE_PATH.unlink(missing_ok=True)
        return None
    return CACHE_PATH


def _try_download() -> Path:
    url = os.environ.get("DEXTRACE_AHMYTH_URL", DEFAULT_URL)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = CACHE_PATH.with_suffix(".apk.partial")
    try:
        urllib.request.urlretrieve(url, tmp)
    except (urllib.error.URLError, OSError) as exc:
        tmp.unlink(missing_ok=True)
        raise FetcherError(f"download failed from {url}: {exc}") from exc
    try:
        _verify(tmp)
    except FetcherError:
        tmp.unlink(missing_ok=True)
        raise
    tmp.replace(CACHE_PATH)
    return CACHE_PATH


def get_apk_path() -> Path:
    """
    Return a path to a verified Ahmyth.apk, fetching if necessary.

    Raises FetcherError if no source yields a valid APK. Tests should catch
    and pytest.skip() so offline contributors don't see red runs.
    """
    p = _try_env_path()
    if p is not None:
        return p
    p = _try_cache()
    if p is not None:
        return p
    return _try_download()
