# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
Try/catch integration test — exceptions from arithmetic, field access, and stubs.

Three scenarios sharing the same try/catch unwinding machinery:

  TestDivByZero       — ArithmeticException raised by div, caught in same method
  TestNullReceiver    — NullPointerException from iget-object on null receiver
  TestStubException   — _ThrowSignal raised by a stub passes through to the
                        in-method catch block

One-liner verification (any scenario):
  dextrace run tests/fixtures/samples/try_catch.dex \\
      --entry 'Lp5a;->divCatch(II)I' --arg 10 --arg 0
  # → return: -1
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dextrace.core.dex_code_map import build_sig_to_codeoff_map
from dextrace.core.dex_resolver import DexResolver
from dextrace.vm.android_stubs import VOID
from dextrace.vm.engine import DalvikVM
from dextrace.vm.errors import DexTraceVMError
from dextrace.vm.signals import _ThrowSignal

FIXTURES = Path(__file__).parent.parent / "fixtures" / "samples"


def _build_vm(dex_path: Path, **kwargs) -> DalvikVM:
    dex = dex_path.read_bytes()
    resolver = DexResolver(dex)
    sig_map = build_sig_to_codeoff_map(dex, resolver)
    return DalvikVM(dex, resolver, sig_map, **kwargs)


# ---------------------------------------------------------------------------
# Scenario 1: ArithmeticException (div by zero) caught in same method
# ---------------------------------------------------------------------------
#
# Fixture: try_catch.dex
#   class Lp5a; {
#       public static int divCatch(int a, int b) {
#           try   { return a / b; }
#           catch (ArithmeticException e) { return -1; }
#       }
#   }
# ---------------------------------------------------------------------------


class TestDivByZero:
    ENTRY = "Lp5a;->divCatch(II)I"

    @pytest.fixture(scope="class")
    def vm(self) -> DalvikVM:
        return _build_vm(FIXTURES / "try_catch.dex")

    def test_fixture_exists(self) -> None:
        assert (FIXTURES / "try_catch.dex").exists()

    def test_div_zero_returns_minus_one(self, vm: DalvikVM) -> None:
        assert vm.run(self.ENTRY, [10, 0]) == -1

    def test_happy_path_skips_catch(self, vm: DalvikVM) -> None:
        assert vm.run(self.ENTRY, [30, 6]) == 5

    def test_truncate_toward_zero_in_happy_path(self, vm: DalvikVM) -> None:
        # Dalvik div is truncate-toward-zero, not floor: -100/7 = -14, not -15.
        assert vm.run(self.ENTRY, [-100, 7]) == -14

    def test_consecutive_runs_isolate_state(self, vm: DalvikVM) -> None:
        # run() must reset heap/state so a prior thrown exception doesn't leak.
        assert vm.run(self.ENTRY, [1, 0]) == -1
        assert vm.run(self.ENTRY, [10, 2]) == 5
        assert vm.run(self.ENTRY, [4, 0]) == -1


# ---------------------------------------------------------------------------
# Scenario 2: NullPointerException from iget-object on null receiver
# ---------------------------------------------------------------------------
#
# Fixture: try_catch_npe_with_fields.dex
#   Lp5ad;->igetNpe()I:
#       Object o = null;
#       try   { return o.ref; }   // iget-object on null → NPE
#       catch (NullPointerException) { return 99; }
# ---------------------------------------------------------------------------


class TestNullReceiver:
    ENTRY = "Lp5ad;->igetNpe()I"

    @pytest.fixture(scope="class")
    def vm(self) -> DalvikVM:
        return _build_vm(FIXTURES / "try_catch_npe_with_fields.dex")

    def test_iget_object_null_receiver_caught(self, vm: DalvikVM) -> None:
        # iget-object on null → _ThrowSignal(NullPointerException) → caught by
        # the in-method try/catch → returns sentinel 99.
        assert vm.run(self.ENTRY) == 99


# ---------------------------------------------------------------------------
# Scenario 3: Stub-thrown exceptions pass through to in-method catch
# ---------------------------------------------------------------------------
#
# Fixture: try_catch_with_stubs.dex
#   Lp5x;->openCatch()I:
#       try   { Ldemo/Net;->openConnection(); return 0 }
#       catch (Ljava/io/IOException;) { return 1 }
# ---------------------------------------------------------------------------


_EXTERNAL_SIG = "Ldemo/Net;->openConnection()V"


def _ioexception_stub(args, heap, api_calls):
    api_calls.append({"sig": _EXTERNAL_SIG, "raised": "IOException"})
    raise _ThrowSignal("Ljava/io/IOException;")


def _ok_stub(args, heap, api_calls):
    api_calls.append({"sig": _EXTERNAL_SIG, "raised": None})
    return VOID


class TestStubException:
    ENTRY = "Lp5x;->openCatch()I"
    FIXTURE = FIXTURES / "try_catch_with_stubs.dex"

    def _make_vm(self, stub_fn) -> DalvikVM:
        return _build_vm(self.FIXTURE, stub_registry={_EXTERNAL_SIG: stub_fn})

    def test_stub_raising_ioexception_is_caught(self) -> None:
        vm = self._make_vm(_ioexception_stub)
        assert vm.run(self.ENTRY) == 1

    def test_stub_returning_void_falls_through_try(self) -> None:
        vm = self._make_vm(_ok_stub)
        assert vm.run(self.ENTRY) == 0

    def test_stub_python_exception_still_wraps_as_vm_error(self) -> None:
        # The _invoke_stub allowlist is narrow: only DexTraceVMError /
        # NotImplemented / _ThrowSignal pass through. Other Python exceptions
        # still get wrapped as DexTraceVMError("stub failed: ...").
        def buggy_stub(args, heap, api_calls):
            raise RuntimeError("simulated stub bug")

        vm = self._make_vm(buggy_stub)
        with pytest.raises(DexTraceVMError, match="stub failed"):
            vm.run(self.ENTRY)
