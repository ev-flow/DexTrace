# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
P5e integration test — array round-trip via the full VM.

Fixture: tests/fixtures/samples/p5e_arrays.dex
  Lp5e;->arraySum()I:
      int[] arr = new int[3];               // new-array
      fill-array-data arr, [10, 20, 30];     // fill-array-data
      int n = arr.length;                    // array-length
      int s = 0;
      for (int i = 0; i < n; i++) s += arr[i];   // aget
      return s;
  -> 60
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dextrace.core.dex_code_map import build_sig_to_codeoff_map
from dextrace.core.dex_resolver import DexResolver
from dextrace.vm.engine import DalvikVM

FIXTURE = Path(__file__).parent / "fixtures" / "samples" / "p5e_arrays.dex"
ENTRY = "Lp5e;->arraySum()I"


@pytest.fixture(scope="module")
def vm():
    dex = FIXTURE.read_bytes()
    resolver = DexResolver(dex)
    sig_map = build_sig_to_codeoff_map(dex, resolver)
    return DalvikVM(dex, resolver, sig_map)


def test_array_sum_returns_60(vm):
    # 10 + 20 + 30 = 60
    assert vm.run(ENTRY) == 60


def test_repeat_run_produces_same_result(vm):
    # Heap is reset on every run() — second invocation must not see stale state.
    assert vm.run(ENTRY) == 60
    assert vm.run(ENTRY) == 60
