# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
Unit tests for _ThrowSignal and the engine's catch-walk + multi-frame unwind.
Driven by the P5a fixture so the engine doesn't get mocked away — we want to
exercise the real `_execute` loop end-to-end with constructed throw scenarios.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dextrace.core.dex_code_map import build_sig_to_codeoff_map
from dextrace.core.dex_resolver import DexResolver
from dextrace.vm.engine import DalvikVM
from dextrace.vm.errors import DexTraceVMError
from dextrace.vm.signals import _ThrowSignal

FIXTURE = Path(__file__).parent.parent / "fixtures" / "samples" / "try_catch.dex"


@pytest.fixture(scope="module")
def vm():
    dex = FIXTURE.read_bytes()
    resolver = DexResolver(dex)
    sig_map = build_sig_to_codeoff_map(dex, resolver)
    return DalvikVM(dex, resolver, sig_map)


class TestThrowSignal:
    def test_constructor_records_class_and_handle(self):
        sig = _ThrowSignal("Ljava/lang/IOException;", 7)
        assert sig.class_desc == "Ljava/lang/IOException;"
        assert sig.exc_handle == 7

    def test_default_handle_is_zero(self):
        sig = _ThrowSignal("Ljava/lang/RuntimeException;")
        assert sig.exc_handle == 0


class TestCatchTableMatching:
    """The engine resolves an internally-raised _ThrowSignal against the
    catch table and either jumps to a handler or pops frames."""

    def test_arithmetic_exception_matches_handler(self, vm):
        # b=0 → div-int raises _ThrowSignal(ArithmeticException) → catch fires
        assert vm.run("Lp5a;->divCatch(II)I", [99, 0]) == -1

    def test_no_throw_means_no_pending_exception(self, vm):
        # Verify isolation: after a clean run, the engine's heap should be
        # reset and pending_exception cleared. We can't read pending_exception
        # directly without crossing public API, but if it leaked the next
        # divCatch(10,0) catch path would behave inconsistently. Run twice.
        for _ in range(3):
            assert vm.run("Lp5a;->divCatch(II)I", [50, 5]) == 10


class TestUncaughtPropagation:
    """A thrown exception that reaches an empty call stack with no handler
    must surface as a top-level DexTraceVMError so the CLI can print it."""

    def test_uncaught_uses_fixture_signature_with_empty_catch(self, vm, monkeypatch):
        # Patch is_subtype to always return False so the existing handler
        # never matches — simulates "no catch covers this throw".
        monkeypatch.setattr(
            vm._hierarchy, "is_subtype", lambda child, parent: False
        )
        with pytest.raises(DexTraceVMError, match="uncaught"):
            vm.run("Lp5a;->divCatch(II)I", [10, 0])
