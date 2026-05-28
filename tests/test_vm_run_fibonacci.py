# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
Fibonacci VM execution integration test.

Fixture: tests/fixtures/samples/fib_recursive.dex
  class LFibonacciTest; {
      public static int fib(int n) {
          if (n <= 1) return n;
          return fib(n-1) + fib(n-2);
      }
  }

One-liner verification:
  python -m dextrace run tests/fixtures/samples/fib_recursive.dex \
      --entry 'LFibonacciTest;->fib(I)I' --arg 10 | grep 'return: 55'
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from unittest.mock import patch

import pytest

FIXTURE = (
    Path(__file__).parent / "fixtures" / "samples" / "fib_recursive.dex"
)
ENTRY = "LFibonacciTest;->fib(I)I"


def test_fixture_exists():
    assert FIXTURE.exists(), f"fixture not found: {FIXTURE}"


class TestVMRunFibonacci:
    def test_python_api_base_cases(self):
        """fib(0) == 0, fib(1) == 1."""
        from dextrace.core.dex_resolver import DexResolver
        from dextrace.core.dex_code_map import build_sig_to_codeoff_map
        from dextrace.vm.engine import DalvikVM

        dex_bytes = FIXTURE.read_bytes()
        resolver = DexResolver(dex_bytes)
        sig_map = build_sig_to_codeoff_map(dex_bytes, resolver)
        vm = DalvikVM(dex_bytes, resolver, sig_map)

        assert vm.run(ENTRY, args=[0]) == 0
        assert vm.run(ENTRY, args=[1]) == 1

    def test_python_api_small_values(self):
        """fib(2)==1, fib(3)==2, fib(5)==5."""
        from dextrace.core.dex_resolver import DexResolver
        from dextrace.core.dex_code_map import build_sig_to_codeoff_map
        from dextrace.vm.engine import DalvikVM

        dex_bytes = FIXTURE.read_bytes()
        resolver = DexResolver(dex_bytes)
        sig_map = build_sig_to_codeoff_map(dex_bytes, resolver)
        vm = DalvikVM(dex_bytes, resolver, sig_map)

        assert vm.run(ENTRY, args=[2]) == 1
        assert vm.run(ENTRY, args=[3]) == 2
        assert vm.run(ENTRY, args=[5]) == 5

    def test_python_api_fib10(self):
        """fib(10) == 55."""
        from dextrace.core.dex_resolver import DexResolver
        from dextrace.core.dex_code_map import build_sig_to_codeoff_map
        from dextrace.vm.engine import DalvikVM

        dex_bytes = FIXTURE.read_bytes()
        resolver = DexResolver(dex_bytes)
        sig_map = build_sig_to_codeoff_map(dex_bytes, resolver)
        vm = DalvikVM(dex_bytes, resolver, sig_map)

        assert vm.run(ENTRY, args=[10]) == 55

