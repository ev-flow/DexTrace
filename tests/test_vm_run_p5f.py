# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
P5f integration test — invoke-interface routes through runtime vtable.

Fixture: tests/fixtures/samples/p5f_interface.dex
  Lp5f;->callIFace()I:
      Lp5f obj = new Lp5f();
      return obj.value();           // invoke-interface dispatch on runtime class
  -> 7

Why this matters: invoke-interface and invoke-virtual share the same vtable
lookup path in the engine. Both resolve `(name, proto)` against the receiver's
runtime class, regardless of how the static target is declared in the DEX.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dextrace.core.dex_code_map import build_sig_to_codeoff_map
from dextrace.core.dex_resolver import DexResolver
from dextrace.vm.engine import DalvikVM

FIXTURE = Path(__file__).parent / "fixtures" / "samples" / "p5f_interface.dex"
ENTRY = "Lp5f;->callIFace()I"


@pytest.fixture(scope="module")
def vm():
    dex = FIXTURE.read_bytes()
    resolver = DexResolver(dex)
    sig_map = build_sig_to_codeoff_map(dex, resolver)
    return DalvikVM(dex, resolver, sig_map)


def test_invoke_interface_dispatches_to_runtime_class(vm):
    assert vm.run(ENTRY) == 7


def test_repeat_run_isolates_heap(vm):
    # Each run() resets the heap; the freshly-allocated Lp5f instance must
    # still resolve value()I against the same vtable on subsequent runs.
    assert vm.run(ENTRY) == 7
    assert vm.run(ENTRY) == 7
