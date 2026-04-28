# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
P5a integration test — try / catch / throw / move-exception.

Fixture: tests/fixtures/samples/p5a_try_catch.dex
  class Lp5a; {
      public static int divCatch(int a, int b) {
          try {
              return a / b;
          } catch (ArithmeticException e) {
              return -1;
          }
      }
  }

One-liner verification (Phase 5a):
  dextrace run tests/fixtures/samples/p5a_try_catch.dex \\
      --entry 'Lp5a;->divCatch(II)I' --arg 10 --arg 0
  # → return: -1
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dextrace.core.dex_code_map import build_sig_to_codeoff_map
from dextrace.core.dex_resolver import DexResolver
from dextrace.vm.engine import DalvikVM

FIXTURE = Path(__file__).parent / "fixtures" / "samples" / "p5a_try_catch.dex"
ENTRY = "Lp5a;->divCatch(II)I"


def test_fixture_exists():
    assert FIXTURE.exists(), f"P5a fixture not found: {FIXTURE}"


@pytest.fixture(scope="module")
def vm():
    dex = FIXTURE.read_bytes()
    resolver = DexResolver(dex)
    sig_map = build_sig_to_codeoff_map(dex, resolver)
    return DalvikVM(dex, resolver, sig_map)


def test_div_zero_returns_minus_one(vm):
    """The plan's headline: divCatch(10, 0) → -1 via ArithmeticException catch."""
    assert vm.run(ENTRY, [10, 0]) == -1


def test_happy_path_skips_catch(vm):
    """Non-zero divisor returns the quotient — catch never fires."""
    assert vm.run(ENTRY, [30, 6]) == 5


def test_truncate_toward_zero_in_happy_path(vm):
    """Dalvik div is truncate-toward-zero, not floor: -100/7 = -14, not -15."""
    assert vm.run(ENTRY, [-100, 7]) == -14


def test_consecutive_runs_isolate_state(vm):
    """run() must reset heap/state so a prior thrown exception doesn't leak."""
    assert vm.run(ENTRY, [1, 0]) == -1   # throws + catches
    assert vm.run(ENTRY, [10, 2]) == 5   # next call: clean run
    assert vm.run(ENTRY, [4, 0]) == -1   # third: throws again, catches again
