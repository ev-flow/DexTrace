# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
Regression tests for null-receiver semantics in DalvikVM._do_invoke.

Dalvik/JVM semantics require invoke-virtual / invoke-interface to raise
NullPointerException on a null receiver before the callee runs, even when
a stub is registered for the static callee signature.

Background: PR #4 review found that the stub registry was consulted before
the receiver was validated, so a stubbed virtual/interface call with
receiver register = 0 would silently invoke the stub instead of failing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, List

import pytest

from dextrace.core.dex_code_map import build_sig_to_codeoff_map
from dextrace.core.dex_resolver import DexResolver
from dextrace.dalvik.types import DecodedInsn
from dextrace.vm.android_stubs import VOID
from dextrace.vm.engine import DalvikVM
from dextrace.vm.errors import DexTraceVMError
from dextrace.vm.register_file import RegisterFile
from dextrace.vm.state import VMState


FIXTURE = (
    Path(__file__).parent / "fixtures" / "samples" / "const_return.dex"
)

STUB_SIG = "Lstub/Target;->m()V"


def _vm(stub_registry=None) -> DalvikVM:
    dex_bytes = FIXTURE.read_bytes()
    resolver = DexResolver(dex_bytes)
    sig_map = build_sig_to_codeoff_map(dex_bytes, resolver)
    return DalvikVM(
        dex_bytes,
        resolver,
        sig_map,
        stub_registry=stub_registry,
    )


def _invoke_insn(mnemonic: str, opcode: int, receiver_reg: str = "v0") -> DecodedInsn:
    return DecodedInsn(
        uoff=0x10,
        byte_off=0x20,
        opcode=opcode,
        mnemonic=mnemonic,
        fmt="35c",
        size_units=3,
        regs=[receiver_reg],
        param=STUB_SIG,
    )


def _state_with_v0(value: int) -> VMState:
    rf = RegisterFile(2)
    rf.set(0, value)
    return VMState(registers=rf, pc=0x10)


class _StubSpy:
    def __init__(self) -> None:
        self.calls: List[tuple] = []

    def __call__(self, args, heap, trace) -> Any:
        self.calls.append(tuple(args))
        return VOID


class TestNullReceiverBeforeStub:
    def test_invoke_virtual_null_receiver_raises_before_stub(self):
        spy = _StubSpy()
        vm = _vm(stub_registry={STUB_SIG: spy})
        state = _state_with_v0(0)
        insn = _invoke_insn("invoke-virtual", 0x6E)

        with pytest.raises(DexTraceVMError, match="null receiver"):
            vm._do_invoke(insn, state, caller_code_off=0)

        assert spy.calls == []

    def test_invoke_interface_null_receiver_raises_before_stub(self):
        spy = _StubSpy()
        vm = _vm(stub_registry={STUB_SIG: spy})
        state = _state_with_v0(0)
        insn = _invoke_insn("invoke-interface", 0x72)

        with pytest.raises(DexTraceVMError, match="null receiver"):
            vm._do_invoke(insn, state, caller_code_off=0)

        assert spy.calls == []

    def test_invoke_virtual_range_null_receiver_raises_before_stub(self):
        spy = _StubSpy()
        vm = _vm(stub_registry={STUB_SIG: spy})
        state = _state_with_v0(0)
        insn = _invoke_insn("invoke-virtual/range", 0x74)

        with pytest.raises(DexTraceVMError, match="null receiver"):
            vm._do_invoke(insn, state, caller_code_off=0)

        assert spy.calls == []


class TestNonNullReceiverStillDispatchesStub:
    def test_invoke_virtual_nonnull_receiver_calls_stub(self):
        spy = _StubSpy()
        vm = _vm(stub_registry={STUB_SIG: spy})
        # Allocate a real object on the heap so get_class resolves cleanly.
        handle = vm._heap.allocate("Lstub/Target;", value=None)
        state = _state_with_v0(handle)
        insn = _invoke_insn("invoke-virtual", 0x6E)

        result = vm._do_invoke(insn, state, caller_code_off=0)

        assert result is None  # stub path returns None
        assert len(spy.calls) == 1
