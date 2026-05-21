# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
Const-return VM execution integration test.

Fixture: tests/fixtures/samples/const_return.dex
  class Lp1; { public static int main() { const/16 v0, 42; return v0; } }

One-liner verification:
  dextrace run tests/fixtures/samples/const_return.dex \
      --entry 'Lp1;->main()I'
"""

from __future__ import annotations

from pathlib import Path

FIXTURE = (
    Path(__file__).parent / "fixtures" / "samples" / "const_return.dex"
)
ENTRY = "Lp1;->main()I"


def test_fixture_exists():
    assert FIXTURE.exists(), f"fixture not found: {FIXTURE}"


class TestVMRunConstReturn:
    def test_python_api_returns_42(self):
        """DalvikVM.run() on const_return.dex must return 42."""
        from dextrace.core.dex_resolver import DexResolver
        from dextrace.core.dex_code_map import build_sig_to_codeoff_map
        from dextrace.vm.engine import DalvikVM

        dex_bytes = FIXTURE.read_bytes()
        resolver = DexResolver(dex_bytes)
        sig_map = build_sig_to_codeoff_map(dex_bytes, resolver)

        vm = DalvikVM(dex_bytes, resolver, sig_map)
        result = vm.run(ENTRY, args=[])

        assert result == 42

