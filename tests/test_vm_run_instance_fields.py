# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
P5d integration test — instance + static field round-trip via the full VM.

Fixture: tests/fixtures/samples/p5d_fields.dex
  Lp5d;->fieldRoundtrip(I)I:
      Box box = new Box();
      box.n   = arg;          // iput
      int t   = box.n;        // iget
      t       = t * 2;
      Lp5d.total = t;         // sput
      return Lp5d.total;      // sget
  -> 21 -> 42
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dextrace.core.dex_code_map import build_sig_to_codeoff_map
from dextrace.core.dex_resolver import DexResolver
from dextrace.vm.engine import DalvikVM

FIXTURE = Path(__file__).parent / "fixtures" / "samples" / "p5d_fields.dex"
ENTRY = "Lp5d;->fieldRoundtrip(I)I"


@pytest.fixture(scope="module")
def vm():
    dex = FIXTURE.read_bytes()
    resolver = DexResolver(dex)
    sig_map = build_sig_to_codeoff_map(dex, resolver)
    return DalvikVM(dex, resolver, sig_map)


def test_field_roundtrip_21_returns_42(vm):
    assert vm.run(ENTRY, [21]) == 42


def test_field_roundtrip_zero(vm):
    assert vm.run(ENTRY, [0]) == 0


def test_field_roundtrip_negative_input(vm):
    # arg = -7 -> iput/iget then *2 then sput/sget -> -14
    assert vm.run(ENTRY, [-7]) == -14


def test_static_state_does_not_bleed_between_runs(vm):
    # First run leaves Lp5d;->total = 42 in the *previous* run's static map.
    # The engine clears static_fields at run() entry, so a fresh run with a
    # different arg must not pick up the stale value.
    assert vm.run(ENTRY, [100]) == 200
    assert vm.run(ENTRY, [3]) == 6
