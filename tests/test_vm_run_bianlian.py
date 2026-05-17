# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
BianLian regression test — String.<init>([B)V stub + return-object resolution.

Regression for: return: 8 instead of return: "setting"

Root cause:
  1. No stub for Ljava/lang/String;-><init>([B)V → void external miss silently
     ignored, leaving the heap String entry with value=None.
  2. _handle_return_object returned the raw heap handle (integer 8) instead of
     the resolved Python string.

Fix:
  1. Added stub_string_init_bytes in android_stubs/text.py that reads the byte
     array from the heap and decodes it as Latin-1.
  2. engine.run() now resolves Ljava/lang/String; heap handles to their Python
     str values before returning to the caller.

One-liner verification:
  dextrace run samples/bianlian/bianlian.apk \\
    --entry "Llady/cheap/sting/bot/components/injects/system/InjAccessibilityService;->increasematch()Ljava/lang/String;"
  # Expected: return: "setting"
"""

from __future__ import annotations

from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).parent.parent.parent
_APK = _REPO_ROOT / "samples" / "bianlian" / "bianlian.apk"

pytestmark = pytest.mark.skipif(
    not _APK.exists(),
    reason="bianlian.apk not present (place at samples/bianlian/bianlian.apk)",
)

_ENTRY = (
    "Llady/cheap/sting/bot/components/injects/system/InjAccessibilityService;"
    "->increasematch()Ljava/lang/String;"
)


@pytest.fixture(scope="module")
def vm():
    from dextrace.cli._io import load_dex_bytes
    from dextrace.core.dex_code_map import build_sig_to_codeoff_map
    from dextrace.core.dex_resolver import DexResolver
    from dextrace.vm.engine import DalvikVM

    dex, _ = load_dex_bytes(_APK)
    resolver = DexResolver(dex)
    return DalvikVM(dex, resolver, build_sig_to_codeoff_map(dex, resolver))


def test_increasematch_returns_string_not_handle(vm):
    result = vm.run(_ENTRY)
    assert isinstance(result, str), f"expected str, got {type(result).__name__}: {result!r}"
    assert result == "setting"
