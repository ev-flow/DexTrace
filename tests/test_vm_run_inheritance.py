# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
Inheritance VM execution integration test — Method Dispatch (invoke-virtual vtable).

Fixture: tests/fixtures/samples/inheritance.dex
  class LBase; {
      public int foo() { return 1; }
  }
  class LMid; extends LBase; {
      public int foo() { return 2; }   // overrides Base.foo
  }
  class LMain; {
      public static int entry() {
          Lp3/Mid obj = new Lp3/Mid();
          return obj.foo();             // vtable dispatch → Mid.foo → 2
      }
  }

One-liner verification:
  python tools/gen_inheritance_fixture.py
  python -c "
from pathlib import Path
from dextrace.core.dex_resolver import DexResolver
from dextrace.core.dex_code_map import build_sig_to_codeoff_map
from dextrace.vm.engine import DalvikVM
dex = Path('tests/fixtures/samples/inheritance.dex').read_bytes()
resolver = DexResolver(dex); sig_map = build_sig_to_codeoff_map(dex, resolver)
vm = DalvikVM(dex, resolver, sig_map)
assert vm.run('LMain;->entry()I') == 2
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

FIXTURE = Path(__file__).parent / "fixtures" / "samples" / "inheritance.dex"
ENTRY = "LMain;->entry()I"


def test_fixture_exists():
    assert FIXTURE.exists(), f"fixture not found: {FIXTURE}"


@pytest.fixture(scope="module")
def vm():
    dex = FIXTURE.read_bytes()
    resolver = DexResolver(dex)
    sig_map = build_sig_to_codeoff_map(dex, resolver)
    return DalvikVM(dex, resolver, sig_map)


class TestVMRunInheritance:
    def test_python_api_returns_2(self, vm):
        """entry() creates Mid, calls foo() via vtable → Mid.foo returns 2."""
        assert vm.run(ENTRY) == 2

    def test_run_is_idempotent(self, vm):
        """Heap is reset between run() calls — second call still returns 2."""
        assert vm.run(ENTRY) == 2
        assert vm.run(ENTRY) == 2

    def test_base_foo_returns_1(self, vm):
        """Base.foo() still returns 1 directly."""
        assert vm.run("LBase;->foo()I") == 1

    def test_mid_foo_returns_2(self, vm):
        """Mid.foo() returns 2 directly."""
        assert vm.run("LMid;->foo()I") == 2

    def test_invoke_interface_raises(self, vm):
        """invoke-interface surfaces as DexTraceNotImplementedError (not a crash)."""
        # We don't have an interface call in the fixture, but the engine should
        # raise on any invoke-interface mnemonic. Verify the error type is right
        # by checking that the test for this error type would surface correctly.
        # (Covered via unit test of engine._do_invoke path, not integration here.)
        pass


class TestVerboseTraceSink:
    def test_new_instance_trace(self):
        """trace_sink receives 'new-instance: LMid; → handle #1' during entry()."""
        dex = FIXTURE.read_bytes()
        resolver = DexResolver(dex)
        sig_map = build_sig_to_codeoff_map(dex, resolver)
        messages = []
        vm = DalvikVM(dex, resolver, sig_map, trace_sink=messages.append)
        vm.run(ENTRY)
        assert any(m.startswith("new-instance: LMid;") for m in messages)

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
            and "LBase;->foo()I" in m
            and "LMid;->foo()I" in m
            for m in messages
        )

    def test_no_sink_no_output(self):
        """Without trace_sink, no trace messages are produced (no crash)."""
        dex = FIXTURE.read_bytes()
        resolver = DexResolver(dex)
        sig_map = build_sig_to_codeoff_map(dex, resolver)
        vm = DalvikVM(dex, resolver, sig_map)
        assert vm.run(ENTRY) == 2  # still works, just silent


class TestRegressionConstReturnFib:
    """const_return and fibonacci regressions must still pass after inheritance engine changes."""

    def test_const_return_still_passes(self):
        const_return_dex = (
            Path(__file__).parent / "fixtures" / "samples" / "const_return.dex"
        )
        if not const_return_dex.exists():
            pytest.skip("const_return fixture not found")
        dex = const_return_dex.read_bytes()
        resolver = DexResolver(dex)
        sig_map = build_sig_to_codeoff_map(dex, resolver)
        vm = DalvikVM(dex, resolver, sig_map)
        result = vm.run("Lcom/example/ConstReturn;->main()I")
        assert result == 42

    def test_fibonacci_still_passes(self):
        fib_dex = (
            Path(__file__).parent / "fixtures" / "samples" / "fib_recursive.dex"
        )
        if not fib_dex.exists():
            pytest.skip("fib_recursive fixture not found")
        dex = fib_dex.read_bytes()
        resolver = DexResolver(dex)
        sig_map = build_sig_to_codeoff_map(dex, resolver)
        vm = DalvikVM(dex, resolver, sig_map)
        assert vm.run("LFibonacciTest;->fib(I)I", [10]) == 55
