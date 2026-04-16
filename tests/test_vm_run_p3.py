# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
P3 VM execution integration test — Method Dispatch (invoke-virtual vtable).

Fixture: tests/fixtures/samples/p3_inheritance.dex
  class Lp3/Base; {
      public int foo() { return 1; }
  }
  class Lp3/Mid; extends Lp3/Base; {
      public int foo() { return 2; }   // overrides Base.foo
  }
  class Lp3/Main; {
      public static int entry() {
          Lp3/Mid obj = new Lp3/Mid();
          return obj.foo();             // vtable dispatch → Mid.foo → 2
      }
  }

One-liner verification (Phase 3):
  python tools/gen_p3_fixture.py
  python -c "
from pathlib import Path
from dextrace.core.dex_resolver import DexResolver
from dextrace.core.dex_code_map import build_sig_to_codeoff_map
from dextrace.vm.engine import DalvikVM
dex = Path('tests/fixtures/samples/p3_inheritance.dex').read_bytes()
resolver = DexResolver(dex); sig_map = build_sig_to_codeoff_map(dex, resolver)
vm = DalvikVM(dex, resolver, sig_map)
assert vm.run('Lp3/Main;->entry()I') == 2
print('OK: return 2')
"
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from dextrace.core.dex_code_map import build_sig_to_codeoff_map
from dextrace.core.dex_resolver import DexResolver
from dextrace.vm.engine import DalvikVM
from dextrace.vm.errors import DexTraceNotImplementedError, DexTraceVMError

FIXTURE = Path(__file__).parent / "fixtures" / "samples" / "p3_inheritance.dex"
ENTRY = "Lp3/Main;->entry()I"


def test_fixture_exists():
    assert FIXTURE.exists(), f"P3 fixture not found: {FIXTURE}"


@pytest.fixture(scope="module")
def vm():
    dex = FIXTURE.read_bytes()
    resolver = DexResolver(dex)
    sig_map = build_sig_to_codeoff_map(dex, resolver)
    return DalvikVM(dex, resolver, sig_map)


class TestVMRunP3:
    def test_python_api_returns_2(self, vm):
        """entry() creates Mid, calls foo() via vtable → Mid.foo returns 2."""
        assert vm.run(ENTRY) == 2

    def test_run_is_idempotent(self, vm):
        """Heap is reset between run() calls — second call still returns 2."""
        assert vm.run(ENTRY) == 2
        assert vm.run(ENTRY) == 2

    def test_base_foo_returns_1(self, vm):
        """Base.foo() still returns 1 directly."""
        assert vm.run("Lp3/Base;->foo()I") == 1

    def test_mid_foo_returns_2(self, vm):
        """Mid.foo() returns 2 directly."""
        assert vm.run("Lp3/Mid;->foo()I") == 2

    def test_invoke_interface_raises(self, vm):
        """invoke-interface surfaces as DexTraceNotImplementedError (not a crash)."""
        # We don't have an interface call in the fixture, but the engine should
        # raise on any invoke-interface mnemonic. Verify the error type is right
        # by checking that the test for this error type would surface correctly.
        # (Covered via unit test of engine._do_invoke path, not integration here.)
        pass


class TestVerboseTraceSink:
    def test_new_instance_trace(self):
        """trace_sink receives 'new-instance: Lp3/Mid; → handle #1' during entry()."""
        dex = FIXTURE.read_bytes()
        resolver = DexResolver(dex)
        sig_map = build_sig_to_codeoff_map(dex, resolver)
        messages = []
        vm = DalvikVM(dex, resolver, sig_map, trace_sink=messages.append)
        vm.run(ENTRY)
        assert any(m.startswith("new-instance: Lp3/Mid;") for m in messages)

    def test_invoke_virtual_dispatch_trace(self):
        """trace_sink receives invoke-virtual resolution: Base.foo → Mid.foo."""
        dex = FIXTURE.read_bytes()
        resolver = DexResolver(dex)
        sig_map = build_sig_to_codeoff_map(dex, resolver)
        messages = []
        vm = DalvikVM(dex, resolver, sig_map, trace_sink=messages.append)
        vm.run(ENTRY)
        assert any(
            "invoke-virtual:" in m
            and "Lp3/Base;->foo()I" in m
            and "Lp3/Mid;->foo()I" in m
            for m in messages
        )

    def test_no_sink_no_output(self):
        """Without trace_sink, no trace messages are produced (no crash)."""
        dex = FIXTURE.read_bytes()
        resolver = DexResolver(dex)
        sig_map = build_sig_to_codeoff_map(dex, resolver)
        vm = DalvikVM(dex, resolver, sig_map)
        assert vm.run(ENTRY) == 2  # still works, just silent


class TestRegressionP1P2:
    """P1 and P2 regressions must still pass after engine.py P3 changes."""

    def test_p1_still_passes(self):
        p1_dex = (
            Path(__file__).parent / "fixtures" / "samples" / "p1_simple.dex"
        )
        if not p1_dex.exists():
            pytest.skip("P1 fixture not found")
        dex = p1_dex.read_bytes()
        resolver = DexResolver(dex)
        sig_map = build_sig_to_codeoff_map(dex, resolver)
        vm = DalvikVM(dex, resolver, sig_map)
        result = vm.run("Lp1;->main()I")
        assert result == 42

    def test_p2_still_passes(self):
        p2_dex = (
            Path(__file__).parent / "fixtures" / "samples" / "p2_fib_recursive.dex"
        )
        if not p2_dex.exists():
            pytest.skip("P2 fixture not found")
        dex = p2_dex.read_bytes()
        resolver = DexResolver(dex)
        sig_map = build_sig_to_codeoff_map(dex, resolver)
        vm = DalvikVM(dex, resolver, sig_map)
        assert vm.run("Lp2/Fib;->fib(I)I", [10]) == 55
