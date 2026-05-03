# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
P5a × P5d integration test — null-receiver iget-object throws NPE,
P5a's catch walker resolves it via the seeded Java exception hierarchy,
and the in-method handler returns the sentinel.

Fixture: tests/fixtures/samples/p5a_x_p5d_npe.dex
  Lp5ad;->igetNpe()I:
      Object o = null;
      try   { return o.ref; }                    // iget-object on null
      catch (NullPointerException) { return 99; }
  -> 99
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dextrace.core.dex_code_map import build_sig_to_codeoff_map
from dextrace.core.dex_resolver import DexResolver
from dextrace.vm.engine import DalvikVM

FIXTURE = Path(__file__).parent / "fixtures" / "samples" / "p5a_x_p5d_npe.dex"
ENTRY = "Lp5ad;->igetNpe()I"


@pytest.fixture(scope="module")
def vm():
    dex = FIXTURE.read_bytes()
    resolver = DexResolver(dex)
    sig_map = build_sig_to_codeoff_map(dex, resolver)
    return DalvikVM(dex, resolver, sig_map)


def test_iget_object_null_receiver_caught(vm):
    # iget-object on null → _ThrowSignal(NullPointerException) → caught by the
    # in-method try/catch → returns sentinel 99. If the engine had instead let
    # the NPE escape, run() would raise DexTraceVMError("uncaught: ...").
    assert vm.run(ENTRY) == 99
