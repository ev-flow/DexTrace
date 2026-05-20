# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
Unit tests for vm/engine.py — frame push/pop, register isolation, and
pending_result lifecycle invariants.
"""

from pathlib import Path

import pytest
from unittest.mock import MagicMock, patch
from typing import Dict, List

from dextrace.core.dex_code_map import build_sig_to_codeoff_map
from dextrace.core.dex_resolver import DexResolver
from dextrace.dalvik.types import DecodedInsn
from dextrace.vm.call_frame import CallFrame
from dextrace.vm.engine import DalvikVM, _ReturnSignal
from dextrace.vm.errors import DexTraceVMError
from dextrace.vm.register_file import RegisterFile
from dextrace.vm.state import VMState


def _insn(
    uoff, mnemonic, regs=None, param=None, size_units=1, target_uoff=None
):
    return DecodedInsn(
        uoff=uoff,
        byte_off=uoff * 2,
        opcode=0x00,
        mnemonic=mnemonic,
        fmt="10x",
        size_units=size_units,
        regs=list(regs or []),
        param=param,
        target_uoff=target_uoff,
    )


class TestCallReturnRegisterIsolation:
    """OV-6: callee must not clobber caller registers."""

    def test_snapshot_is_independent(self):
        """RegisterFile.snapshot() gives a fully independent copy."""
        caller_rf = RegisterFile(4)
        caller_rf.set(0, 100)
        caller_rf.set(1, 200)

        snap = caller_rf.snapshot()

        # Simulate callee clobbering what it thinks are its own registers
        caller_rf.set(0, 999)
        caller_rf.set(1, 888)

        # Snapshot should be unaffected
        assert snap.get(0) == 100
        assert snap.get(1) == 200

    def test_return_restores_caller_registers(self):
        """After a _ReturnSignal is caught, caller registers must be restored."""
        # Caller state: v0=10, v1=20
        caller_rf = RegisterFile(4)
        caller_rf.set(0, 10)
        caller_rf.set(1, 20)

        state = VMState(registers=caller_rf, pc=5)

        # Simulate pushing a call frame (what _do_invoke does)
        frame = CallFrame(
            return_pc=5,
            method_desc="Ltest;->callee()I",
            caller_registers=caller_rf.snapshot(),
            caller_code_off=0xCAFE,
        )
        # Switch to callee registers
        callee_rf = RegisterFile(3)
        callee_rf.set(0, 777)
        state.call_stack.append(frame)
        state.registers = callee_rf
        state.pc = 0

        # Simulate callee clobbering its registers
        state.registers.set(0, 999)

        # Simulate _ReturnSignal catch: restore caller
        ret_signal = _ReturnSignal(42)
        restored_frame = state.call_stack.pop()
        state.registers = restored_frame.caller_registers
        state.pc = restored_frame.return_pc

        # Caller's v0 and v1 must be the original values
        assert state.registers.get(0) == 10
        assert state.registers.get(1) == 20
        assert state.pc == 5

    def test_pending_result_set_on_return(self):
        """Return value must be placed in pending_result, not clobber registers."""
        caller_rf = RegisterFile(4)
        caller_rf.set(0, 10)

        state = VMState(registers=caller_rf, pc=7)
        state.pending_result = None

        frame = CallFrame(
            return_pc=7,
            method_desc="Ltest;->callee()I",
            caller_registers=caller_rf.snapshot(),
            caller_code_off=0,
        )
        callee_rf = RegisterFile(2)
        state.call_stack.append(frame)
        state.registers = callee_rf

        # Return 42
        ret_signal = _ReturnSignal(42, is_wide=False)
        restored_frame = state.call_stack.pop()
        state.registers = restored_frame.caller_registers
        state.pc = restored_frame.return_pc
        state.pending_result = ret_signal.value
        state.pending_result_is_wide = ret_signal.is_wide

        # Caller registers untouched; return value in pending_result
        assert state.registers.get(0) == 10
        assert state.pending_result == 42
        assert not state.pending_result_is_wide


class TestStalePendingResultCleared:
    """Regression: external stub leaves pending_result=0; caller skips
    move-result; engine must clear pending_result before entering the next
    internal callee, not raise DexTraceVMError."""

    def test_pending_result_reset_on_internal_invoke(self):
        fixture = (
            Path(__file__).parent.parent
            / "fixtures"
            / "samples"
            / "const_return.dex"
        )
        dex_bytes = fixture.read_bytes()
        resolver = DexResolver(dex_bytes)
        sig_map = build_sig_to_codeoff_map(dex_bytes, resolver)
        vm = DalvikVM(dex_bytes, resolver, sig_map)

        # OV-2: run() resets pending_result=None on entry, so a stale value
        # from a prior external call doesn't trip the stale guard.
        result = vm.run("Lp1;->main()I", args=[])
        assert result == 42
