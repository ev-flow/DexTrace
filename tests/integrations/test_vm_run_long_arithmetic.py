# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
Long arithmetic integration test via the full VM.

Fixture: tests/fixtures/samples/long_arith.dex
  Lp5b;->longSum(I)J:
      long a = (long) n;
      long b = a + a;          // 2n
      long c = b * 150L;       // 300n
      return c;
  -> 100 * 300 = 30000
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dextrace.core.dex_code_map import build_sig_to_codeoff_map
from dextrace.core.dex_resolver import DexResolver
from dextrace.vm.engine import DalvikVM

FIXTURE = Path(__file__).parent.parent / "fixtures" / "samples" / "long_arith.dex"
ENTRY = "Lp5b;->longSum(I)J"


@pytest.fixture(scope="module")
def vm():
    dex = FIXTURE.read_bytes()
    resolver = DexResolver(dex)
    sig_map = build_sig_to_codeoff_map(dex, resolver)
    return DalvikVM(dex, resolver, sig_map)


def test_long_sum_100_returns_30000(vm):
    assert vm.run(ENTRY, [100]) == 30000


def test_long_sum_zero(vm):
    assert vm.run(ENTRY, [0]) == 0


def test_long_sum_negative_input_works(vm):
    # n = -10 -> (-10 + -10) * 150 = -20 * 150 = -3000
    assert vm.run(ENTRY, [-10]) == -3000
