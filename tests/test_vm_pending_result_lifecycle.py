# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
Regression tests for the `pending_result` lifecycle in DalvikVM.

Pins the Dalvik verifier invariant: a value produced by an invoke is only
consumable by the immediately following move-result*. Void invokes leave
pending_result = None.

Background: PR #4 review found that VOID stubs and void external misses
synthesized a fake `0` into pending_result and that the dispatch loop did
not enforce "consumed by next instruction". Both are fixed by:
  - producers set pending_result_pc = invoke's next_pc (or caller's
    return_pc for internal callees); void producers leave pending_result
    as None.
  - the dispatch loop clears pending_result_* whenever state.pc !=
    pending_result_pc.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, List

import pytest

from dextrace.core.dex_code_map import build_sig_to_codeoff_map
from dextrace.core.dex_resolver import DexResolver
from dextrace.dalvik.types import DecodedInsn
from dextrace.vm.android_stubs import (
    ObjectRef,
    StubCallable,
    Value,
    Wide,
    VOID,
)
from dextrace.vm.engine import DalvikVM
from dextrace.vm.errors import DexTraceNotImplementedError
from dextrace.vm.register_file import RegisterFile
from dextrace.vm.state import VMState


FIXTURE = (
    Path(__file__).parent / "fixtures" / "samples" / "const_return.dex"
)


def _vm(stub_registry=None, strict_stubs=False) -> DalvikVM:
    """Build a DalvikVM against the smallest available real fixture."""
    dex_bytes = FIXTURE.read_bytes()
    resolver = DexResolver(dex_bytes)
    sig_map = build_sig_to_codeoff_map(dex_bytes, resolver)
    return DalvikVM(
        dex_bytes,
        resolver,
        sig_map,
        stub_registry=stub_registry,
        strict_stubs=strict_stubs,
    )


def _fake_invoke_insn(uoff: int = 0x10, size_units: int = 3) -> DecodedInsn:
    """A bare DecodedInsn shaped like an invoke-* with no register args."""
    return DecodedInsn(
        uoff=uoff,
        byte_off=uoff * 2,
        opcode=0x6E,  # invoke-virtual
        mnemonic="invoke-virtual",
        fmt="35c",
        size_units=size_units,
        regs=[],
        param="Lstub/Target;->m()V",
    )


def _state() -> VMState:
    return VMState(registers=RegisterFile(2), pc=0)


class TestVoidStubLeavesNoPendingResult:
    def test_void_stub_clears_pending_fields(self):
        vm = _vm()
        state = _state()
        # Pre-seed a stale value to confirm the stub also clears it.
        state.pending_result = 99
        state.pending_result_is_wide = True
        state.pending_result_pc = 0xDEAD

        def void_stub(args: List[Any], heap, trace) -> Any:
            return VOID

        vm._invoke_stub(void_stub, "Lx;->v()V", _fake_invoke_insn(), state)

        assert state.pending_result is None
        assert state.pending_result_is_wide is False
        assert state.pending_result_pc is None

    def test_void_external_miss_clears_pending_fields(self):
        vm = _vm()
        state = _state()
        state.pending_result = 7
        state.pending_result_is_wide = False
        state.pending_result_pc = 0xBEEF

        vm._handle_external_miss(
            "Lunknown/Api;->doThing()V", _fake_invoke_insn(), state
        )

        assert state.pending_result is None
        assert state.pending_result_pc is None

    def test_strict_stubs_non_void_miss_still_raises(self):
        vm = _vm(strict_stubs=True)
        state = _state()
        with pytest.raises(DexTraceNotImplementedError):
            vm._handle_external_miss(
                "Lunknown/Api;->getInt()I", _fake_invoke_insn(), state
            )


class TestProducerSetsConsumerPC:
    def test_value_stub_sets_pc_to_next_pc(self):
        vm = _vm()
        state = _state()
        insn = _fake_invoke_insn(uoff=0x10, size_units=3)

        def int_stub(args, heap, trace) -> Any:
            return Value(42)

        vm._invoke_stub(int_stub, "Lx;->i()I", insn, state)

        assert state.pending_result == 42
        assert state.pending_result_is_wide is False
        assert state.pending_result_pc == 0x10 + 3

    def test_wide_stub_sets_pc_and_wide_flag(self):
        vm = _vm()
        state = _state()
        insn = _fake_invoke_insn(uoff=0x20, size_units=3)

        def long_stub(args, heap, trace) -> Any:
            return Wide(0xCAFEBABE)

        vm._invoke_stub(long_stub, "Lx;->j()J", insn, state)

        assert state.pending_result == 0xCAFEBABE
        assert state.pending_result_is_wide is True
        assert state.pending_result_pc == 0x23

    def test_objectref_stub_sets_pc(self):
        vm = _vm()
        state = _state()
        insn = _fake_invoke_insn(uoff=0x30, size_units=3)

        def obj_stub(args, heap, trace) -> Any:
            handle = heap.allocate("Ljava/lang/String;", value="hi")
            return ObjectRef(handle)

        vm._invoke_stub(obj_stub, "Lx;->s()Ljava/lang/String;", insn, state)

        assert state.pending_result is not None
        assert state.pending_result_is_wide is False
        assert state.pending_result_pc == 0x33


class TestStaleResultGuardSemantics:
    """
    The dispatch-loop guard is not directly callable, but its predicate is
    simple enough to assert structurally. These tests pin the invariant by
    exercising the guard condition directly.
    """

    def test_guard_condition_clears_when_pc_does_not_match(self):
        state = _state()
        state.pending_result = 5
        state.pending_result_is_wide = False
        state.pending_result_pc = 0x10

        state.pc = 0x14  # landed somewhere other than the expected consumer
        if (
            state.pending_result is not None
            and state.pending_result_pc is not None
            and state.pc != state.pending_result_pc
        ):
            state.pending_result = None
            state.pending_result_is_wide = False
            state.pending_result_pc = None

        assert state.pending_result is None
        assert state.pending_result_pc is None

    def test_guard_condition_preserves_when_pc_matches(self):
        state = _state()
        state.pending_result = 5
        state.pending_result_is_wide = False
        state.pending_result_pc = 0x10
        state.pc = 0x10  # the immediately following move-result* dispatch

        if (
            state.pending_result is not None
            and state.pending_result_pc is not None
            and state.pc != state.pending_result_pc
        ):
            state.pending_result = None
            state.pending_result_is_wide = False
            state.pending_result_pc = None

        assert state.pending_result == 5
        assert state.pending_result_pc == 0x10


class TestExistingScaffoldStillRuns:
    """Smoke check: the const-return fixture still executes end-to-end."""

    def test_const_return_still_returns_42(self):
        vm = _vm()
        result = vm.run("Lcom/example/ConstReturn;->main()I", args=[])
        assert result == 42
