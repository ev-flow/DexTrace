# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
Packed-switch dispatch integration test via the full VM.

Fixture: tests/fixtures/samples/packed_switch.dex
  LPackedSwitchTest;->switchCast(I)I:
    switch (n) {
      case 0: return 100;
      case 1: return 150;
      case 2: return 200;
      case 3: return 250;
      default: return -1;
    }
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dextrace.core.dex_code_map import build_sig_to_codeoff_map
from dextrace.core.dex_resolver import DexResolver
from dextrace.vm.engine import DalvikVM

FIXTURE = Path(__file__).parent / "fixtures" / "samples" / "packed_switch.dex"
ENTRY = "LPackedSwitchTest;->switchCast(I)I"


@pytest.fixture(scope="module")
def vm():
    dex = FIXTURE.read_bytes()
    resolver = DexResolver(dex)
    sig_map = build_sig_to_codeoff_map(dex, resolver)
    return DalvikVM(dex, resolver, sig_map)


@pytest.mark.parametrize(
    "n,expected",
    [
        (0, 100),
        (1, 150),
        (2, 200),  # plan target
        (3, 250),
    ],
)
def test_packed_switch_case_match(vm, n, expected):
    assert vm.run(ENTRY, [n]) == expected


@pytest.mark.parametrize("n", [-1, 4, 99, -100])
def test_packed_switch_default_falls_through(vm, n):
    # Out-of-range keys hit the default branch (`const/4 v0, #-1; return v0`).
    assert vm.run(ENTRY, [n]) == -1
