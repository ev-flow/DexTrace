# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""Unit tests for vm/handlers/arithmetic.py — 32-bit and wide variants."""

from __future__ import annotations

import math

import pytest

from dextrace.vm.errors import DexTraceNotImplementedError
from dextrace.vm.handlers import arithmetic
from dextrace.vm.handlers.arithmetic import (
    handle_div_int,
    handle_rem_int,
    handle_shr_int,
    handle_ushr_int,
)
from dextrace.vm.int_ops import (
    bits_to_f32,
    bits_to_f64,
    f32_to_bits,
    f64_to_bits,
)
from dextrace.vm.signals import _ThrowSignal

from .conftest import make_insn, make_state


def _eval():
    """Build a fresh eval table (registration is one-shot)."""
    table = {}
    arithmetic.register(table)
    return table


# ---------------------------------------------------------------------------
# 32-bit shift semantics
# ---------------------------------------------------------------------------


class TestShiftSemantics:
    def test_shr_fills_sign_bit(self):
        state = make_state(0, 0x8000_0000, 1)
        state.registers.set(1, 0x8000_0000)
        handle_shr_int(make_insn(["v0", "v1", "v2"]), state)
        # i32(0x80000000) = -2147483648; >> 1 = -1073741824
        assert state.registers.get(0) == -1073741824

    def test_shr_negative_sign_extends(self):
        state = make_state(0, 0, 2)
        state.registers.set(1, -8)
        handle_shr_int(make_insn(["v0", "v1", "v2"]), state)
        assert state.registers.get(0) == -2

    def test_ushr_fills_zero(self):
        state = make_state(0, 0, 1)
        state.registers.set(1, 0x8000_0000)
        handle_ushr_int(make_insn(["v0", "v1", "v2"]), state)
        assert state.registers.get(0) == 0x4000_0000

    def test_ushr_negative_value_zero_fills(self):
        state = make_state(0, 0, 1)
        state.registers.set(1, -1)
        handle_ushr_int(make_insn(["v0", "v1", "v2"]), state)
        assert state.registers.get(0) == 0x7FFF_FFFF


# ---------------------------------------------------------------------------
# 32-bit division / remainder error semantics
# ---------------------------------------------------------------------------


class TestDivisionErrors:
    def test_div_by_zero_raises_arithmetic_exception(self):
        state = make_state(0, 10, 0)
        with pytest.raises(_ThrowSignal) as exc_info:
            handle_div_int(make_insn(["v0", "v1", "v2"]), state)
        assert exc_info.value.class_desc == "Ljava/lang/ArithmeticException;"

    def test_rem_by_zero_raises_arithmetic_exception(self):
        state = make_state(0, 10, 0)
        with pytest.raises(_ThrowSignal) as exc_info:
            handle_rem_int(make_insn(["v0", "v1", "v2"]), state)
        assert exc_info.value.class_desc == "Ljava/lang/ArithmeticException;"

    def test_div_truncates_toward_zero(self):
        # Dalvik div: truncate-toward-zero, not floor.
        state = make_state(0, -7, 2)
        handle_div_int(make_insn(["v0", "v1", "v2"]), state)
        assert state.registers.get(0) == -3

    def test_rem_truncate_toward_zero(self):
        # Dalvik rem: same sign as dividend.
        state = make_state(0, -7, 2)
        handle_rem_int(make_insn(["v0", "v1", "v2"]), state)
        assert state.registers.get(0) == -1


class TestUnimplementedOpcode:
    def test_unimplemented_opcode_raises_with_mnemonic(self):
        from dextrace.dalvik.types import DecodedInsn
        from dextrace.vm.handlers.field import _stub

        insn = DecodedInsn(
            uoff=4,
            byte_off=8,
            opcode=0x52,
            mnemonic="iget",
            fmt="22c",
            size_units=2,
            regs=["v0", "v1"],
        )
        state = make_state(0, 0)
        with pytest.raises(DexTraceNotImplementedError, match="iget"):
            _stub(insn, state)


# ---------------------------------------------------------------------------
# 32-bit 2addr + literal variants
# ---------------------------------------------------------------------------


class TestArithmetic2addrAndLit:
    def test_add_int_2addr(self):
        state = make_state(10, 5)
        arithmetic.handle_add_int_2addr(make_insn(["v0", "v1"]), state)
        assert state.registers.get(0) == 15

    def test_sub_int_2addr(self):
        state = make_state(10, 3)
        arithmetic.handle_sub_int_2addr(make_insn(["v0", "v1"]), state)
        assert state.registers.get(0) == 7

    def test_rsub_int(self):
        # rsub-int: dest = lit - vB  →  100 - 7 = 93
        state = make_state(0, 7)
        arithmetic.handle_rsub_int(make_insn(["v0", "v1"], param="100"), state)
        assert state.registers.get(0) == 93

    def test_rsub_int_lit8(self):
        state = make_state(0, 3)
        arithmetic.handle_rsub_int_lit8(make_insn(["v0", "v1"], param="10"), state)
        assert state.registers.get(0) == 7

    def test_mul_int_2addr(self):
        state = make_state(6, 7)
        arithmetic.handle_mul_int_2addr(make_insn(["v0", "v1"]), state)
        assert state.registers.get(0) == 42

    def test_mul_int_lit8(self):
        state = make_state(0, 6)
        arithmetic.handle_mul_int_lit8(make_insn(["v0", "v1"], param="7"), state)
        assert state.registers.get(0) == 42

    def test_mul_int_lit16(self):
        state = make_state(0, 100)
        arithmetic.handle_mul_int_lit16(make_insn(["v0", "v1"], param="1000"), state)
        assert state.registers.get(0) == 100_000

    def test_div_int_2addr(self):
        state = make_state(10, 3)
        arithmetic.handle_div_int_2addr(make_insn(["v0", "v1"]), state)
        assert state.registers.get(0) == 3

    def test_div_int_lit8(self):
        state = make_state(0, 9)
        arithmetic.handle_div_int_lit8(make_insn(["v0", "v1"], param="3"), state)
        assert state.registers.get(0) == 3

    def test_div_int_lit8_by_zero_raises(self):
        state = make_state(0, 9)
        with pytest.raises(_ThrowSignal):
            arithmetic.handle_div_int_lit8(make_insn(["v0", "v1"], param="0"), state)

    def test_div_int_lit16_by_zero_raises(self):
        state = make_state(0, 9)
        with pytest.raises(_ThrowSignal):
            arithmetic.handle_div_int_lit16(make_insn(["v0", "v1"], param="0"), state)

    def test_div_int_2addr_by_zero_raises(self):
        state = make_state(9, 0)
        with pytest.raises(_ThrowSignal):
            arithmetic.handle_div_int_2addr(make_insn(["v0", "v1"]), state)

    def test_rem_int_2addr(self):
        state = make_state(10, 3)
        arithmetic.handle_rem_int_2addr(make_insn(["v0", "v1"]), state)
        assert state.registers.get(0) == 1

    def test_rem_int_lit8(self):
        state = make_state(0, 10)
        arithmetic.handle_rem_int_lit8(make_insn(["v0", "v1"], param="3"), state)
        assert state.registers.get(0) == 1

    def test_rem_int_lit8_by_zero_raises(self):
        state = make_state(0, 5)
        with pytest.raises(_ThrowSignal):
            arithmetic.handle_rem_int_lit8(make_insn(["v0", "v1"], param="0"), state)

    def test_rem_int_lit16_by_zero_raises(self):
        state = make_state(0, 5)
        with pytest.raises(_ThrowSignal):
            arithmetic.handle_rem_int_lit16(make_insn(["v0", "v1"], param="0"), state)

    def test_rem_int_2addr_by_zero_raises(self):
        state = make_state(5, 0)
        with pytest.raises(_ThrowSignal):
            arithmetic.handle_rem_int_2addr(make_insn(["v0", "v1"]), state)

    def test_and_int_2addr(self):
        state = make_state(0b1100, 0b1010)
        arithmetic.handle_and_int_2addr(make_insn(["v0", "v1"]), state)
        assert state.registers.get(0) == 0b1000

    def test_and_int_lit8(self):
        state = make_state(0, 0xFF)
        arithmetic.handle_and_int_lit8(make_insn(["v0", "v1"], param="15"), state)
        assert state.registers.get(0) == 15

    def test_or_int_2addr(self):
        state = make_state(0b0100, 0b0010)
        arithmetic.handle_or_int_2addr(make_insn(["v0", "v1"]), state)
        assert state.registers.get(0) == 0b0110

    def test_or_int_lit8(self):
        state = make_state(0, 0b1000)
        arithmetic.handle_or_int_lit8(make_insn(["v0", "v1"], param="4"), state)
        assert state.registers.get(0) == 0b1100

    def test_xor_int_2addr(self):
        state = make_state(0b1010, 0b1100)
        arithmetic.handle_xor_int_2addr(make_insn(["v0", "v1"]), state)
        assert state.registers.get(0) == 0b0110

    def test_xor_int_lit8(self):
        state = make_state(0, 0b1111)
        arithmetic.handle_xor_int_lit8(make_insn(["v0", "v1"], param="5"), state)
        assert state.registers.get(0) == 0b1010

    def test_shl_int_2addr(self):
        state = make_state(1, 3)
        arithmetic.handle_shl_int_2addr(make_insn(["v0", "v1"]), state)
        assert state.registers.get(0) == 8

    def test_shl_int_lit8(self):
        state = make_state(0, 1)
        arithmetic.handle_shl_int_lit8(make_insn(["v0", "v1"], param="4"), state)
        assert state.registers.get(0) == 16

    def test_shr_int_2addr(self):
        state = make_state(-8, 2)
        arithmetic.handle_shr_int_2addr(make_insn(["v0", "v1"]), state)
        assert state.registers.get(0) == -2

    def test_ushr_int_2addr(self):
        state = make_state(0x8000_0000, 1)
        arithmetic.handle_ushr_int_2addr(make_insn(["v0", "v1"]), state)
        assert state.registers.get(0) == 0x4000_0000

    def test_neg_int(self):
        state = make_state(0, 5)
        arithmetic.handle_neg_int(make_insn(["v0", "v1"]), state)
        assert state.registers.get(0) == -5

    def test_not_int(self):
        state = make_state(0, 0)
        arithmetic.handle_not_int(make_insn(["v0", "v1"]), state)
        assert state.registers.get(0) == -1  # ~0 = -1 in two's complement

    def test_add_int_lit16(self):
        state = make_state(0, 10)
        arithmetic.handle_add_int_lit16(make_insn(["v0", "v1"], param="1000"), state)
        assert state.registers.get(0) == 1010


# ---------------------------------------------------------------------------
# Wide (64-bit) long arithmetic
# ---------------------------------------------------------------------------


class TestLongBinary:
    def test_add_long(self):
        s = make_state()
        s.registers.set_wide(0, 1_000_000_000_000)
        s.registers.set_wide(2, 2_000_000_000_000)
        _eval()["add-long"](make_insn(["v4", "v0", "v2"]), s)
        assert s.registers.get_wide(4) == 3_000_000_000_000

    def test_mul_long_overflow_wraps_to_s64(self):
        s = make_state()
        s.registers.set_wide(0, 1 << 62)
        s.registers.set_wide(2, 4)
        # (1<<62) * 4 = 1<<64, truncates to 0 in i64
        _eval()["mul-long"](make_insn(["v4", "v0", "v2"]), s)
        assert s.registers.get_wide(4) == 0

    def test_div_long_truncates_toward_zero(self):
        # Java: -7 / 2 = -3 (truncate toward zero), NOT Python's floor -4
        s = make_state()
        s.registers.set_wide(0, (-7) & 0xFFFF_FFFF_FFFF_FFFF)
        s.registers.set_wide(2, 2)
        _eval()["div-long"](make_insn(["v4", "v0", "v2"]), s)
        result_bits = s.registers.get_wide(4)
        if result_bits >= 0x8000_0000_0000_0000:
            result_bits -= 0x1_0000_0000_0000_0000
        assert result_bits == -3

    def test_div_long_by_zero_raises_arithmetic_exception(self):
        s = make_state()
        s.registers.set_wide(0, 100)
        s.registers.set_wide(2, 0)
        with pytest.raises(_ThrowSignal) as exc:
            _eval()["div-long"](make_insn(["v4", "v0", "v2"]), s)
        assert exc.value.class_desc == "Ljava/lang/ArithmeticException;"

    def test_rem_long_truncates_toward_zero(self):
        # Java: -7 % 2 = -1
        s = make_state()
        s.registers.set_wide(0, (-7) & 0xFFFF_FFFF_FFFF_FFFF)
        s.registers.set_wide(2, 2)
        _eval()["rem-long"](make_insn(["v4", "v0", "v2"]), s)
        bits = s.registers.get_wide(4)
        if bits >= 0x8000_0000_0000_0000:
            bits -= 0x1_0000_0000_0000_0000
        assert bits == -1

    def test_and_long(self):
        s = make_state()
        s.registers.set_wide(0, 0xFFFF_FFFF_FFFF_FFFF)
        s.registers.set_wide(2, 0x0F0F_0F0F_0F0F_0F0F)
        _eval()["and-long"](make_insn(["v4", "v0", "v2"]), s)
        bits = s.registers.get_wide(4)
        assert bits == 0x0F0F_0F0F_0F0F_0F0F

    def test_shl_long_shifts_by_low_6_bits(self):
        s = make_state()
        s.registers.set_wide(0, 1)
        s.registers.set(2, 33)
        _eval()["shl-long"](make_insn(["v4", "v0", "v2"]), s)
        assert s.registers.get_wide(4) == 1 << 33


class TestLongUnary:
    def test_neg_long(self):
        s = make_state()
        s.registers.set_wide(0, 12345)
        _eval()["neg-long"](make_insn(["v2", "v0"], fmt="12x"), s)
        bits = s.registers.get_wide(2)
        if bits >= 0x8000_0000_0000_0000:
            bits -= 0x1_0000_0000_0000_0000
        assert bits == -12345

    def test_not_long(self):
        s = make_state()
        s.registers.set_wide(0, 0)
        _eval()["not-long"](make_insn(["v2", "v0"], fmt="12x"), s)
        # ~0 = -1 in i64 = 0xFFFFFFFFFFFFFFFF unsigned
        assert s.registers.get_wide(2) == 0xFFFF_FFFF_FFFF_FFFF


# ---------------------------------------------------------------------------
# Wide float / double arithmetic
# ---------------------------------------------------------------------------


class TestFloatBinary:
    def test_add_float(self):
        s = make_state()
        s.registers.set(0, f32_to_bits(1.5))
        s.registers.set(1, f32_to_bits(2.25))
        _eval()["add-float"](make_insn(["v2", "v0", "v1"]), s)
        assert math.isclose(bits_to_f32(s.registers.get(2)), 3.75)

    def test_div_float_by_zero_returns_infinity(self):
        # IEEE 754: x / 0 = +Inf (when x positive nonzero)
        s = make_state()
        s.registers.set(0, f32_to_bits(1.0))
        s.registers.set(1, f32_to_bits(0.0))
        _eval()["div-float"](make_insn(["v2", "v0", "v1"]), s)
        assert math.isinf(bits_to_f32(s.registers.get(2)))

    def test_div_zero_by_zero_returns_nan(self):
        s = make_state()
        s.registers.set(0, f32_to_bits(0.0))
        s.registers.set(1, f32_to_bits(0.0))
        _eval()["div-float"](make_insn(["v2", "v0", "v1"]), s)
        assert math.isnan(bits_to_f32(s.registers.get(2)))


class TestFloatUnary:
    def test_neg_float(self):
        s = make_state()
        s.registers.set(0, f32_to_bits(3.14))
        _eval()["neg-float"](make_insn(["v1", "v0"], fmt="12x"), s)
        assert math.isclose(bits_to_f32(s.registers.get(1)), -3.14, rel_tol=1e-6)


class TestDoubleBinary:
    def test_mul_double(self):
        s = make_state()
        s.registers.set_wide(0, f64_to_bits(2.5))
        s.registers.set_wide(2, f64_to_bits(4.0))
        _eval()["mul-double"](make_insn(["v4", "v0", "v2"]), s)
        assert math.isclose(bits_to_f64(s.registers.get_wide(4)), 10.0)

    def test_rem_double_uses_fmod(self):
        s = make_state()
        s.registers.set_wide(0, f64_to_bits(7.5))
        s.registers.set_wide(2, f64_to_bits(2.0))
        _eval()["rem-double"](make_insn(["v4", "v0", "v2"]), s)
        assert math.isclose(bits_to_f64(s.registers.get_wide(4)), 1.5)
