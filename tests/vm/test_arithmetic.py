# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""Unit tests for arithmetic handlers."""

import pytest
from unittest.mock import MagicMock

from dextrace.dalvik.types import DecodedInsn
from dextrace.vm.errors import DexTraceVMError, DexTraceNotImplementedError
from dextrace.vm.signals import _ThrowSignal
from dextrace.vm.handlers.arithmetic import (
    handle_shr_int,
    handle_ushr_int,
    handle_div_int,
    handle_rem_int,
)
from dextrace.vm.register_file import RegisterFile
from dextrace.vm.state import VMState


def _make_insn(regs, param=None, uoff=0):
    return DecodedInsn(
        uoff=uoff,
        byte_off=uoff * 2,
        opcode=0x00,
        mnemonic="test",
        fmt="23x",
        size_units=2,
        regs=list(regs),
        param=param,
    )


def _make_state(*values):
    """Create a VMState with registers pre-set to values[0], values[1], ..."""
    rf = RegisterFile(max(len(values), 4))
    for i, v in enumerate(values):
        rf.set(i, v)
    return VMState(registers=rf, pc=0)


class TestShiftSemantics:
    def test_shr_fills_sign_bit(self):
        """shr-int: arithmetic right shift — sign bit propagates."""
        state = _make_state(0, 0x8000_0000, 1)
        # v0 = dest, v1 = 0x80000000 (stored as signed -2147483648), v2 = 1
        state.registers.set(
            1, 0x8000_0000
        )  # stored as unsigned; i32 will treat as -ve
        insn = _make_insn(["v0", "v1", "v2"])
        handle_shr_int(insn, state)
        result = state.registers.get(0)
        # i32(0x80000000) = -2147483648; >> 1 = -1073741824 = 0xC0000000 signed
        assert result == -1073741824

    def test_shr_negative_sign_extends(self):
        """shr-int on -8 >> 2 should give -2."""
        state = _make_state(0, 0, 2)
        state.registers.set(1, -8)  # Python stores as-is; i32(-8) = -8
        insn = _make_insn(["v0", "v1", "v2"])
        handle_shr_int(insn, state)
        assert state.registers.get(0) == -2

    def test_ushr_fills_zero(self):
        """ushr-int: logical right shift — high bits filled with 0."""
        state = _make_state(0, 0, 1)
        state.registers.set(1, 0x8000_0000)
        insn = _make_insn(["v0", "v1", "v2"])
        handle_ushr_int(insn, state)
        result = state.registers.get(0)
        # u32(0x80000000) >> 1 = 0x40000000 (no sign extension)
        assert result == 0x4000_0000

    def test_ushr_negative_value_zero_fills(self):
        """ushr-int on -1 >> 1 should give 0x7FFFFFFF (not -1 >> 1 = -1)."""
        state = _make_state(0, 0, 1)
        state.registers.set(1, -1)  # all bits set
        insn = _make_insn(["v0", "v1", "v2"])
        handle_ushr_int(insn, state)
        assert state.registers.get(0) == 0x7FFF_FFFF

    def test_ushr_zero_shift_keeps_signed_value(self):
        """ushr-int -1 >>> 0 == -1: a 0-bit shift must leave the register as the
        signed 32-bit value, not the unsigned 0xFFFFFFFF."""
        state = _make_state(0, 0, 0)
        state.registers.set(1, -1)  # all bits set
        state.registers.set(2, 0)  # shift count 0
        insn = _make_insn(["v0", "v1", "v2"])
        handle_ushr_int(insn, state)
        assert state.registers.get(0) == -1


class TestDivisionErrors:
    def test_div_by_zero_raises_arithmetic_exception(self):
        """div-int by zero raises _ThrowSignal(ArithmeticException), Java-faithful."""
        state = _make_state(0, 10, 0)
        insn = _make_insn(["v0", "v1", "v2"])
        with pytest.raises(_ThrowSignal) as exc_info:
            handle_div_int(insn, state)
        assert exc_info.value.class_desc == "Ljava/lang/ArithmeticException;"

    def test_rem_by_zero_raises_arithmetic_exception(self):
        state = _make_state(0, 10, 0)
        insn = _make_insn(["v0", "v1", "v2"])
        with pytest.raises(_ThrowSignal) as exc_info:
            handle_rem_int(insn, state)
        assert exc_info.value.class_desc == "Ljava/lang/ArithmeticException;"

    def test_div_truncates_toward_zero(self):
        """Dalvik div: truncate-toward-zero, not floor division."""
        state = _make_state(0, -7, 2)
        insn = _make_insn(["v0", "v1", "v2"])
        handle_div_int(insn, state)
        # -7 / 2 truncated = -3 (not -4 like Python floor)
        assert state.registers.get(0) == -3

    def test_rem_truncate_toward_zero(self):
        """Dalvik rem: same sign as dividend."""
        state = _make_state(0, -7, 2)
        insn = _make_insn(["v0", "v1", "v2"])
        handle_rem_int(insn, state)
        # -7 % 2 Java-style = -1 (not 1 like Python)
        assert state.registers.get(0) == -1


class TestUnimplementedOpcode:
    def test_unimplemented_opcode_raises_with_mnemonic(self):
        """DexTraceNotImplementedError should name the opcode."""
        from dextrace.vm.handlers.field import _stub
        from dextrace.dalvik.types import DecodedInsn

        insn = DecodedInsn(
            uoff=4,
            byte_off=8,
            opcode=0x52,
            mnemonic="iget",
            fmt="22c",
            size_units=2,
            regs=["v0", "v1"],
        )
        state = _make_state(0, 0)
        with pytest.raises(DexTraceNotImplementedError, match="iget"):
            _stub(insn, state)
