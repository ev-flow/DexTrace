# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
P5b unit tests for long / float / double arithmetic handlers.

Each test pokes registers manually, dispatches via the eval table, and
verifies the result. Float/double values use IEEE 754 bit patterns in
the register file.
"""

from __future__ import annotations

from dataclasses import replace

import math

import pytest

from dextrace.dalvik.types import DecodedInsn
from dextrace.vm.handlers import arithmetic
from dextrace.vm.int_ops import (
    bits_to_f32,
    bits_to_f64,
    f32_to_bits,
    f64_to_bits,
)
from dextrace.vm.register_file import RegisterFile
from dextrace.vm.signals import _ThrowSignal
from dextrace.vm.state import VMState


def _insn(regs, **kw):
    return DecodedInsn(
        uoff=0,
        byte_off=0,
        opcode=0,
        mnemonic=kw.get("mnemonic", "test"),
        fmt=kw.get("fmt", "23x"),
        size_units=2,
        regs=regs,
        param=kw.get("param"),
    )


def _state(rf_size=8) -> VMState:
    return VMState(registers=RegisterFile(rf_size), pc=0)


def _eval():
    """Build a fresh eval table (registration is one-shot)."""
    table = {}
    arithmetic.register(table)
    return table


# ---------------------------------------------------------------------------
# Long arithmetic
# ---------------------------------------------------------------------------


class TestLongBinary:
    def test_add_long(self):
        s = _state()
        s.registers.set_wide(0, 1_000_000_000_000)  # ~1e12, exceeds int32
        s.registers.set_wide(2, 2_000_000_000_000)
        _eval()["add-long"](_insn(["v4", "v0", "v2"]), s)
        assert s.registers.get_wide(4) == 3_000_000_000_000

    def test_mul_long_overflow_wraps_to_s64(self):
        s = _state()
        s.registers.set_wide(0, 1 << 62)
        s.registers.set_wide(2, 4)
        # (1<<62) * 4 = 1<<64, which truncates to 0 in i64
        _eval()["mul-long"](_insn(["v4", "v0", "v2"]), s)
        assert s.registers.get_wide(4) == 0

    def test_div_long_truncates_toward_zero(self):
        # Java: -7 / 2 = -3 (truncate toward zero), NOT Python's floor -4
        s = _state()
        # set_wide stores unsigned, so for -7L we store the 64-bit two's complement
        s.registers.set_wide(0, (-7) & 0xFFFF_FFFF_FFFF_FFFF)
        s.registers.set_wide(2, 2)
        _eval()["div-long"](_insn(["v4", "v0", "v2"]), s)
        # Result should be -3 in i64 (= 0xFFFFFFFFFFFFFFFD as unsigned)
        result_bits = s.registers.get_wide(4)
        # interpret as signed
        if result_bits >= 0x8000_0000_0000_0000:
            result_bits -= 0x1_0000_0000_0000_0000
        assert result_bits == -3

    def test_div_long_by_zero_raises_arithmetic_exception(self):
        s = _state()
        s.registers.set_wide(0, 100)
        s.registers.set_wide(2, 0)
        with pytest.raises(_ThrowSignal) as exc:
            _eval()["div-long"](_insn(["v4", "v0", "v2"]), s)
        assert exc.value.class_desc == "Ljava/lang/ArithmeticException;"

    def test_rem_long_truncates_toward_zero(self):
        # Java: -7 % 2 = -1
        s = _state()
        s.registers.set_wide(0, (-7) & 0xFFFF_FFFF_FFFF_FFFF)
        s.registers.set_wide(2, 2)
        _eval()["rem-long"](_insn(["v4", "v0", "v2"]), s)
        bits = s.registers.get_wide(4)
        if bits >= 0x8000_0000_0000_0000:
            bits -= 0x1_0000_0000_0000_0000
        assert bits == -1

    def test_and_long(self):
        s = _state()
        s.registers.set_wide(0, 0xFFFF_FFFF_FFFF_FFFF)
        s.registers.set_wide(2, 0x0F0F_0F0F_0F0F_0F0F)
        _eval()["and-long"](_insn(["v4", "v0", "v2"]), s)
        # Result interpreted as signed i64
        bits = s.registers.get_wide(4)
        assert bits == 0x0F0F_0F0F_0F0F_0F0F

    def test_shl_long_shifts_by_low_6_bits(self):
        s = _state()
        s.registers.set_wide(0, 1)
        s.registers.set(2, 33)  # count = 33 (& 0x3F = 33)
        _eval()["shl-long"](_insn(["v4", "v0", "v2"]), s)
        assert s.registers.get_wide(4) == 1 << 33


class TestLongUnary:
    def test_neg_long(self):
        s = _state()
        s.registers.set_wide(0, 12345)
        _eval()["neg-long"](_insn(["v2", "v0"], fmt="12x"), s)
        bits = s.registers.get_wide(2)
        if bits >= 0x8000_0000_0000_0000:
            bits -= 0x1_0000_0000_0000_0000
        assert bits == -12345

    def test_not_long(self):
        s = _state()
        s.registers.set_wide(0, 0)
        _eval()["not-long"](_insn(["v2", "v0"], fmt="12x"), s)
        # ~0 = -1 in i64 = 0xFFFFFFFFFFFFFFFF unsigned
        assert s.registers.get_wide(2) == 0xFFFF_FFFF_FFFF_FFFF


# ---------------------------------------------------------------------------
# Float arithmetic
# ---------------------------------------------------------------------------


class TestFloatBinary:
    def test_add_float(self):
        s = _state()
        s.registers.set(0, f32_to_bits(1.5))
        s.registers.set(1, f32_to_bits(2.25))
        _eval()["add-float"](_insn(["v2", "v0", "v1"]), s)
        assert math.isclose(bits_to_f32(s.registers.get(2)), 3.75)

    def test_div_float_by_zero_returns_infinity(self):
        # IEEE 754: x / 0 = +Inf (when x positive nonzero)
        s = _state()
        s.registers.set(0, f32_to_bits(1.0))
        s.registers.set(1, f32_to_bits(0.0))
        _eval()["div-float"](_insn(["v2", "v0", "v1"]), s)
        assert math.isinf(bits_to_f32(s.registers.get(2)))

    def test_div_zero_by_zero_returns_nan(self):
        s = _state()
        s.registers.set(0, f32_to_bits(0.0))
        s.registers.set(1, f32_to_bits(0.0))
        _eval()["div-float"](_insn(["v2", "v0", "v1"]), s)
        assert math.isnan(bits_to_f32(s.registers.get(2)))


class TestFloatUnary:
    def test_neg_float(self):
        s = _state()
        s.registers.set(0, f32_to_bits(3.14))
        _eval()["neg-float"](_insn(["v1", "v0"], fmt="12x"), s)
        assert math.isclose(bits_to_f32(s.registers.get(1)), -3.14, rel_tol=1e-6)


# ---------------------------------------------------------------------------
# Double arithmetic
# ---------------------------------------------------------------------------


class TestDoubleBinary:
    def test_mul_double(self):
        s = _state()
        s.registers.set_wide(0, f64_to_bits(2.5))
        s.registers.set_wide(2, f64_to_bits(4.0))
        _eval()["mul-double"](_insn(["v4", "v0", "v2"]), s)
        assert math.isclose(bits_to_f64(s.registers.get_wide(4)), 10.0)

    def test_rem_double_uses_fmod(self):
        # Java: 7.5 % 2.0 = 1.5 (NOT Python's 7.5 - 2*round(7.5/2) = 1.5 — same here)
        s = _state()
        s.registers.set_wide(0, f64_to_bits(7.5))
        s.registers.set_wide(2, f64_to_bits(2.0))
        _eval()["rem-double"](_insn(["v4", "v0", "v2"]), s)
        assert math.isclose(bits_to_f64(s.registers.get_wide(4)), 1.5)
