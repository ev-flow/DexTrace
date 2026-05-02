# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/handlers/arithmetic.py — Integer arithmetic instruction handlers.

Shift contracts (from int_ops.py):
  shl-int:  i32(u32(a) << (b & 0x1F))
  shr-int:  i32(a) >> (b & 0x1F)          — arithmetic (sign-extends)
  ushr-int: u32(a) >> (b & 0x1F)          — logical (zero-fills)
"""

from __future__ import annotations

import math
import operator

from dextrace.dalvik.types import DecodedInsn
from dextrace.vm.errors import DexTraceVMError
from dextrace.vm.int_ops import (
    bits_to_f32,
    bits_to_f64,
    f32_to_bits,
    f64_to_bits,
    i32,
    i64,
    reg_index,
    u32,
    u64,
)
from dextrace.vm.signals import _ThrowSignal
from dextrace.vm.state import VMState

# P5a: integer div/rem by zero must surface as a Java-faithful
# ArithmeticException so user-code `try/catch (ArithmeticException)` blocks
# fire correctly. Raise via _ThrowSignal so the engine walks the catch table
# instead of producing a top-level VM error.
_ARITHMETIC_EXC = "Ljava/lang/ArithmeticException;"


# ---------------------------------------------------------------------------
# Java-faithful long div/rem (truncate-toward-zero, NOT Python's floor //).
# Required because `int(a / b)` loses precision for 64-bit values that overflow
# the 53-bit float mantissa.
# ---------------------------------------------------------------------------


def _trunc_div_long(a: int, b: int) -> int:
    sign = -1 if (a < 0) ^ (b < 0) else 1
    return sign * (abs(a) // abs(b))


def _trunc_rem_long(a: int, b: int) -> int:
    return a - b * _trunc_div_long(a, b)


# ---------------------------------------------------------------------------
# IEEE-754 division / remainder. Java/Dalvik float div by zero returns
# Inf/NaN, never throws — Python raises ZeroDivisionError, so we shim.
# ---------------------------------------------------------------------------


def _ieee_div(a: float, b: float) -> float:
    if b == 0.0:
        if a == 0.0:
            return float("nan")
        return math.copysign(float("inf"), a) * math.copysign(1.0, b)
    return a / b


def _ieee_rem(a: float, b: float) -> float:
    if b == 0.0 or math.isinf(a):
        return float("nan")
    return math.fmod(a, b)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get3(insn: DecodedInsn, state: VMState):
    """Return (dest_idx, a, b) for 23x-format binary ops: op vA, vB, vC."""
    dest = reg_index(insn.regs[0])
    a = state.registers.get(reg_index(insn.regs[1]))
    b = state.registers.get(reg_index(insn.regs[2]))
    return dest, a, b


def _get2(insn: DecodedInsn, state: VMState):
    """Return (dest_idx, a, b) for 12x-format /2addr ops: op vA, vB (vA is both dest and src1)."""
    dest = reg_index(insn.regs[0])
    a = state.registers.get(dest)
    b = state.registers.get(reg_index(insn.regs[1]))
    return dest, a, b


def _get_lit(insn: DecodedInsn, state: VMState):
    """Return (dest_idx, a, lit) for 22b/22s lit ops: op vAA, vBB, #+CC."""
    dest = reg_index(insn.regs[0])
    a = state.registers.get(reg_index(insn.regs[1]))
    lit = int(insn.param)
    return dest, a, lit


# ---------------------------------------------------------------------------
# add-int
# ---------------------------------------------------------------------------


def handle_add_int(insn: DecodedInsn, state: VMState) -> None:
    dest, a, b = _get3(insn, state)
    state.registers.set(dest, i32(a + b))


def handle_add_int_2addr(insn: DecodedInsn, state: VMState) -> None:
    dest, a, b = _get2(insn, state)
    state.registers.set(dest, i32(a + b))


def handle_add_int_lit8(insn: DecodedInsn, state: VMState) -> None:
    dest, a, lit = _get_lit(insn, state)
    state.registers.set(dest, i32(a + lit))


def handle_add_int_lit16(insn: DecodedInsn, state: VMState) -> None:
    dest, a, lit = _get_lit(insn, state)
    state.registers.set(dest, i32(a + lit))


# ---------------------------------------------------------------------------
# sub-int
# ---------------------------------------------------------------------------


def handle_sub_int(insn: DecodedInsn, state: VMState) -> None:
    dest, a, b = _get3(insn, state)
    state.registers.set(dest, i32(a - b))


def handle_sub_int_2addr(insn: DecodedInsn, state: VMState) -> None:
    dest, a, b = _get2(insn, state)
    state.registers.set(dest, i32(a - b))


def handle_rsub_int(insn: DecodedInsn, state: VMState) -> None:
    # rsub-int vA, vB, #+CCCC  (result = literal - vB)
    dest = reg_index(insn.regs[0])
    b = state.registers.get(reg_index(insn.regs[1]))
    lit = int(insn.param)
    state.registers.set(dest, i32(lit - b))


def handle_rsub_int_lit8(insn: DecodedInsn, state: VMState) -> None:
    handle_rsub_int(insn, state)


# ---------------------------------------------------------------------------
# mul-int
# ---------------------------------------------------------------------------


def handle_mul_int(insn: DecodedInsn, state: VMState) -> None:
    dest, a, b = _get3(insn, state)
    state.registers.set(dest, i32(a * b))


def handle_mul_int_2addr(insn: DecodedInsn, state: VMState) -> None:
    dest, a, b = _get2(insn, state)
    state.registers.set(dest, i32(a * b))


def handle_mul_int_lit8(insn: DecodedInsn, state: VMState) -> None:
    dest, a, lit = _get_lit(insn, state)
    state.registers.set(dest, i32(a * lit))


def handle_mul_int_lit16(insn: DecodedInsn, state: VMState) -> None:
    dest, a, lit = _get_lit(insn, state)
    state.registers.set(dest, i32(a * lit))


# ---------------------------------------------------------------------------
# div-int
# ---------------------------------------------------------------------------


def handle_div_int(insn: DecodedInsn, state: VMState) -> None:
    dest, a, b = _get3(insn, state)
    if b == 0:
        raise _ThrowSignal(_ARITHMETIC_EXC)
    state.registers.set(dest, i32(int(a / b)))  # truncate toward zero


def handle_div_int_2addr(insn: DecodedInsn, state: VMState) -> None:
    dest, a, b = _get2(insn, state)
    if b == 0:
        raise _ThrowSignal(_ARITHMETIC_EXC)
    state.registers.set(dest, i32(int(a / b)))


def handle_div_int_lit8(insn: DecodedInsn, state: VMState) -> None:
    dest, a, lit = _get_lit(insn, state)
    if lit == 0:
        raise _ThrowSignal(_ARITHMETIC_EXC)
    state.registers.set(dest, i32(int(a / lit)))


def handle_div_int_lit16(insn: DecodedInsn, state: VMState) -> None:
    dest, a, lit = _get_lit(insn, state)
    if lit == 0:
        raise _ThrowSignal(_ARITHMETIC_EXC)
    state.registers.set(dest, i32(int(a / lit)))


# ---------------------------------------------------------------------------
# rem-int
# ---------------------------------------------------------------------------


def handle_rem_int(insn: DecodedInsn, state: VMState) -> None:
    dest, a, b = _get3(insn, state)
    if b == 0:
        raise _ThrowSignal(_ARITHMETIC_EXC)
    # Dalvik: truncate-toward-zero remainder (same as Java %)
    state.registers.set(dest, i32(int(a - b * int(a / b))))


def handle_rem_int_2addr(insn: DecodedInsn, state: VMState) -> None:
    dest, a, b = _get2(insn, state)
    if b == 0:
        raise _ThrowSignal(_ARITHMETIC_EXC)
    state.registers.set(dest, i32(int(a - b * int(a / b))))


def handle_rem_int_lit8(insn: DecodedInsn, state: VMState) -> None:
    dest, a, lit = _get_lit(insn, state)
    if lit == 0:
        raise _ThrowSignal(_ARITHMETIC_EXC)
    state.registers.set(dest, i32(int(a - lit * int(a / lit))))


def handle_rem_int_lit16(insn: DecodedInsn, state: VMState) -> None:
    dest, a, lit = _get_lit(insn, state)
    if lit == 0:
        raise _ThrowSignal(_ARITHMETIC_EXC)
    state.registers.set(dest, i32(int(a - lit * int(a / lit))))


# ---------------------------------------------------------------------------
# and-int / or-int / xor-int
# ---------------------------------------------------------------------------


def handle_and_int(insn: DecodedInsn, state: VMState) -> None:
    dest, a, b = _get3(insn, state)
    state.registers.set(dest, i32(a & b))


def handle_and_int_2addr(insn: DecodedInsn, state: VMState) -> None:
    dest, a, b = _get2(insn, state)
    state.registers.set(dest, i32(a & b))


def handle_and_int_lit8(insn: DecodedInsn, state: VMState) -> None:
    dest, a, lit = _get_lit(insn, state)
    state.registers.set(dest, i32(a & lit))


def handle_and_int_lit16(insn: DecodedInsn, state: VMState) -> None:
    dest, a, lit = _get_lit(insn, state)
    state.registers.set(dest, i32(a & lit))


def handle_or_int(insn: DecodedInsn, state: VMState) -> None:
    dest, a, b = _get3(insn, state)
    state.registers.set(dest, i32(a | b))


def handle_or_int_2addr(insn: DecodedInsn, state: VMState) -> None:
    dest, a, b = _get2(insn, state)
    state.registers.set(dest, i32(a | b))


def handle_or_int_lit8(insn: DecodedInsn, state: VMState) -> None:
    dest, a, lit = _get_lit(insn, state)
    state.registers.set(dest, i32(a | lit))


def handle_or_int_lit16(insn: DecodedInsn, state: VMState) -> None:
    dest, a, lit = _get_lit(insn, state)
    state.registers.set(dest, i32(a | lit))


def handle_xor_int(insn: DecodedInsn, state: VMState) -> None:
    dest, a, b = _get3(insn, state)
    state.registers.set(dest, i32(a ^ b))


def handle_xor_int_2addr(insn: DecodedInsn, state: VMState) -> None:
    dest, a, b = _get2(insn, state)
    state.registers.set(dest, i32(a ^ b))


def handle_xor_int_lit8(insn: DecodedInsn, state: VMState) -> None:
    dest, a, lit = _get_lit(insn, state)
    state.registers.set(dest, i32(a ^ lit))


def handle_xor_int_lit16(insn: DecodedInsn, state: VMState) -> None:
    dest, a, lit = _get_lit(insn, state)
    state.registers.set(dest, i32(a ^ lit))


# ---------------------------------------------------------------------------
# shl-int / shr-int / ushr-int
# ---------------------------------------------------------------------------


def handle_shl_int(insn: DecodedInsn, state: VMState) -> None:
    dest, a, b = _get3(insn, state)
    state.registers.set(dest, i32(u32(a) << (b & 0x1F)))


def handle_shl_int_2addr(insn: DecodedInsn, state: VMState) -> None:
    dest, a, b = _get2(insn, state)
    state.registers.set(dest, i32(u32(a) << (b & 0x1F)))


def handle_shl_int_lit8(insn: DecodedInsn, state: VMState) -> None:
    dest, a, lit = _get_lit(insn, state)
    state.registers.set(dest, i32(u32(a) << (lit & 0x1F)))


def handle_shr_int(insn: DecodedInsn, state: VMState) -> None:
    # Arithmetic right shift: sign-fills vacated bits
    dest, a, b = _get3(insn, state)
    state.registers.set(dest, i32(a) >> (b & 0x1F))


def handle_shr_int_2addr(insn: DecodedInsn, state: VMState) -> None:
    dest, a, b = _get2(insn, state)
    state.registers.set(dest, i32(a) >> (b & 0x1F))


def handle_shr_int_lit8(insn: DecodedInsn, state: VMState) -> None:
    dest, a, lit = _get_lit(insn, state)
    state.registers.set(dest, i32(a) >> (lit & 0x1F))


def handle_ushr_int(insn: DecodedInsn, state: VMState) -> None:
    # Logical right shift: zero-fills, result always >= 0
    dest, a, b = _get3(insn, state)
    state.registers.set(dest, u32(a) >> (b & 0x1F))


def handle_ushr_int_2addr(insn: DecodedInsn, state: VMState) -> None:
    dest, a, b = _get2(insn, state)
    state.registers.set(dest, u32(a) >> (b & 0x1F))


def handle_ushr_int_lit8(insn: DecodedInsn, state: VMState) -> None:
    dest, a, lit = _get_lit(insn, state)
    state.registers.set(dest, u32(a) >> (lit & 0x1F))


# ---------------------------------------------------------------------------
# neg-int / not-int
# ---------------------------------------------------------------------------


def handle_neg_int(insn: DecodedInsn, state: VMState) -> None:
    dest = reg_index(insn.regs[0])
    src = reg_index(insn.regs[1])
    state.registers.set(dest, i32(-state.registers.get(src)))


def handle_not_int(insn: DecodedInsn, state: VMState) -> None:
    dest = reg_index(insn.regs[0])
    src = reg_index(insn.regs[1])
    state.registers.set(dest, i32(~state.registers.get(src)))


# ===========================================================================
# P5b: Wide arithmetic (long / float / double)
# ===========================================================================
#
# Long values occupy a vN:vN+1 register pair via get_wide / set_wide.
# Float values occupy a single register holding the IEEE 754 single-precision
# bit pattern. Double values occupy a register pair holding the double-precision
# bit pattern. Conversion to/from Python floats happens at handler boundaries
# via int_ops.f32_to_bits / bits_to_f32 / f64_to_bits / bits_to_f64.
# ---------------------------------------------------------------------------


# --- long binary helpers -----------------------------------------------------


def _long2(insn: DecodedInsn, state: VMState, op) -> None:
    dest = reg_index(insn.regs[0])
    a = i64(state.registers.get_wide(reg_index(insn.regs[1])))
    b = i64(state.registers.get_wide(reg_index(insn.regs[2])))
    state.registers.set_wide(dest, i64(op(a, b)))


def _long2addr(insn: DecodedInsn, state: VMState, op) -> None:
    dest = reg_index(insn.regs[0])
    a = i64(state.registers.get_wide(dest))
    b = i64(state.registers.get_wide(reg_index(insn.regs[1])))
    state.registers.set_wide(dest, i64(op(a, b)))


# --- long div/rem (Java truncate-toward-zero, raise on b==0) ----------------


def _long_div(insn: DecodedInsn, state: VMState) -> None:
    dest = reg_index(insn.regs[0])
    a = i64(state.registers.get_wide(reg_index(insn.regs[1])))
    b = i64(state.registers.get_wide(reg_index(insn.regs[2])))
    if b == 0:
        raise _ThrowSignal(_ARITHMETIC_EXC)
    state.registers.set_wide(dest, i64(_trunc_div_long(a, b)))


def _long_div_2addr(insn: DecodedInsn, state: VMState) -> None:
    dest = reg_index(insn.regs[0])
    a = i64(state.registers.get_wide(dest))
    b = i64(state.registers.get_wide(reg_index(insn.regs[1])))
    if b == 0:
        raise _ThrowSignal(_ARITHMETIC_EXC)
    state.registers.set_wide(dest, i64(_trunc_div_long(a, b)))


def _long_rem(insn: DecodedInsn, state: VMState) -> None:
    dest = reg_index(insn.regs[0])
    a = i64(state.registers.get_wide(reg_index(insn.regs[1])))
    b = i64(state.registers.get_wide(reg_index(insn.regs[2])))
    if b == 0:
        raise _ThrowSignal(_ARITHMETIC_EXC)
    state.registers.set_wide(dest, i64(_trunc_rem_long(a, b)))


def _long_rem_2addr(insn: DecodedInsn, state: VMState) -> None:
    dest = reg_index(insn.regs[0])
    a = i64(state.registers.get_wide(dest))
    b = i64(state.registers.get_wide(reg_index(insn.regs[1])))
    if b == 0:
        raise _ThrowSignal(_ARITHMETIC_EXC)
    state.registers.set_wide(dest, i64(_trunc_rem_long(a, b)))


# --- long shifts (count is a single int reg, low 6 bits) --------------------


def _long_shift(insn: DecodedInsn, state: VMState, op) -> None:
    dest = reg_index(insn.regs[0])
    val = state.registers.get_wide(reg_index(insn.regs[1]))
    cnt = state.registers.get(reg_index(insn.regs[2])) & 0x3F
    state.registers.set_wide(dest, op(val, cnt))


def _long_shift_2addr(insn: DecodedInsn, state: VMState, op) -> None:
    dest = reg_index(insn.regs[0])
    val = state.registers.get_wide(dest)
    cnt = state.registers.get(reg_index(insn.regs[1])) & 0x3F
    state.registers.set_wide(dest, op(val, cnt))


def _shl_long_op(val: int, cnt: int) -> int:
    return i64(u64(val) << cnt)


def _shr_long_op(val: int, cnt: int) -> int:
    return i64(i64(val) >> cnt)


def _ushr_long_op(val: int, cnt: int) -> int:
    return u64(val) >> cnt


# --- long unary -------------------------------------------------------------


def handle_neg_long(insn: DecodedInsn, state: VMState) -> None:
    dest = reg_index(insn.regs[0])
    src = reg_index(insn.regs[1])
    state.registers.set_wide(dest, i64(-i64(state.registers.get_wide(src))))


def handle_not_long(insn: DecodedInsn, state: VMState) -> None:
    dest = reg_index(insn.regs[0])
    src = reg_index(insn.regs[1])
    state.registers.set_wide(dest, i64(~i64(state.registers.get_wide(src))))


# --- float binary -----------------------------------------------------------


def _float2(insn: DecodedInsn, state: VMState, op) -> None:
    dest = reg_index(insn.regs[0])
    a = bits_to_f32(state.registers.get(reg_index(insn.regs[1])))
    b = bits_to_f32(state.registers.get(reg_index(insn.regs[2])))
    state.registers.set(dest, f32_to_bits(op(a, b)))


def _float2addr(insn: DecodedInsn, state: VMState, op) -> None:
    dest = reg_index(insn.regs[0])
    a = bits_to_f32(state.registers.get(dest))
    b = bits_to_f32(state.registers.get(reg_index(insn.regs[1])))
    state.registers.set(dest, f32_to_bits(op(a, b)))


def handle_neg_float(insn: DecodedInsn, state: VMState) -> None:
    dest = reg_index(insn.regs[0])
    src = reg_index(insn.regs[1])
    state.registers.set(
        dest, f32_to_bits(-bits_to_f32(state.registers.get(src)))
    )


# --- double binary ----------------------------------------------------------


def _double2(insn: DecodedInsn, state: VMState, op) -> None:
    dest = reg_index(insn.regs[0])
    a = bits_to_f64(state.registers.get_wide(reg_index(insn.regs[1])))
    b = bits_to_f64(state.registers.get_wide(reg_index(insn.regs[2])))
    state.registers.set_wide(dest, f64_to_bits(op(a, b)))


def _double2addr(insn: DecodedInsn, state: VMState, op) -> None:
    dest = reg_index(insn.regs[0])
    a = bits_to_f64(state.registers.get_wide(dest))
    b = bits_to_f64(state.registers.get_wide(reg_index(insn.regs[1])))
    state.registers.set_wide(dest, f64_to_bits(op(a, b)))


def handle_neg_double(insn: DecodedInsn, state: VMState) -> None:
    dest = reg_index(insn.regs[0])
    src = reg_index(insn.regs[1])
    state.registers.set_wide(
        dest, f64_to_bits(-bits_to_f64(state.registers.get_wide(src)))
    )


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register(eval_table: dict) -> None:
    pairs = [
        ("add-int", handle_add_int),
        ("add-int/2addr", handle_add_int_2addr),
        ("add-int/lit8", handle_add_int_lit8),
        ("add-int/lit16", handle_add_int_lit16),
        ("sub-int", handle_sub_int),
        ("sub-int/2addr", handle_sub_int_2addr),
        ("rsub-int", handle_rsub_int),
        ("rsub-int/lit8", handle_rsub_int_lit8),
        ("mul-int", handle_mul_int),
        ("mul-int/2addr", handle_mul_int_2addr),
        ("mul-int/lit8", handle_mul_int_lit8),
        ("mul-int/lit16", handle_mul_int_lit16),
        ("div-int", handle_div_int),
        ("div-int/2addr", handle_div_int_2addr),
        ("div-int/lit8", handle_div_int_lit8),
        ("div-int/lit16", handle_div_int_lit16),
        ("rem-int", handle_rem_int),
        ("rem-int/2addr", handle_rem_int_2addr),
        ("rem-int/lit8", handle_rem_int_lit8),
        ("rem-int/lit16", handle_rem_int_lit16),
        ("and-int", handle_and_int),
        ("and-int/2addr", handle_and_int_2addr),
        ("and-int/lit8", handle_and_int_lit8),
        ("and-int/lit16", handle_and_int_lit16),
        ("or-int", handle_or_int),
        ("or-int/2addr", handle_or_int_2addr),
        ("or-int/lit8", handle_or_int_lit8),
        ("or-int/lit16", handle_or_int_lit16),
        ("xor-int", handle_xor_int),
        ("xor-int/2addr", handle_xor_int_2addr),
        ("xor-int/lit8", handle_xor_int_lit8),
        ("xor-int/lit16", handle_xor_int_lit16),
        ("shl-int", handle_shl_int),
        ("shl-int/2addr", handle_shl_int_2addr),
        ("shl-int/lit8", handle_shl_int_lit8),
        ("shr-int", handle_shr_int),
        ("shr-int/2addr", handle_shr_int_2addr),
        ("shr-int/lit8", handle_shr_int_lit8),
        ("ushr-int", handle_ushr_int),
        ("ushr-int/2addr", handle_ushr_int_2addr),
        ("ushr-int/lit8", handle_ushr_int_lit8),
        ("neg-int", handle_neg_int),
        ("not-int", handle_not_int),
    ]
    for name, fn in pairs:
        eval_table[name] = fn

    # ---- P5b: long binary (closures over op functions) --------------------
    long_binary = [
        ("add-long", operator.add),
        ("sub-long", operator.sub),
        ("mul-long", operator.mul),
        ("and-long", operator.and_),
        ("or-long", operator.or_),
        ("xor-long", operator.xor),
    ]
    for name, op in long_binary:
        eval_table[name] = (lambda i, s, _op=op: _long2(i, s, _op))
        eval_table[name + "/2addr"] = (
            lambda i, s, _op=op: _long2addr(i, s, _op)
        )

    # div-long / rem-long: zero-check, Java truncate-toward-zero
    eval_table["div-long"] = _long_div
    eval_table["div-long/2addr"] = _long_div_2addr
    eval_table["rem-long"] = _long_rem
    eval_table["rem-long/2addr"] = _long_rem_2addr

    # long shifts (count is single int reg, low 6 bits)
    long_shifts = [
        ("shl-long", _shl_long_op),
        ("shr-long", _shr_long_op),
        ("ushr-long", _ushr_long_op),
    ]
    for name, op in long_shifts:
        eval_table[name] = (lambda i, s, _op=op: _long_shift(i, s, _op))
        eval_table[name + "/2addr"] = (
            lambda i, s, _op=op: _long_shift_2addr(i, s, _op)
        )

    # long unary
    eval_table["neg-long"] = handle_neg_long
    eval_table["not-long"] = handle_not_long

    # ---- P5b: float binary -------------------------------------------------
    # Float div/rem do NOT raise — IEEE 754 returns Inf/NaN.
    float_binary = [
        ("add-float", operator.add),
        ("sub-float", operator.sub),
        ("mul-float", operator.mul),
        ("div-float", _ieee_div),
        ("rem-float", _ieee_rem),
    ]
    for name, op in float_binary:
        eval_table[name] = (lambda i, s, _op=op: _float2(i, s, _op))
        eval_table[name + "/2addr"] = (
            lambda i, s, _op=op: _float2addr(i, s, _op)
        )
    eval_table["neg-float"] = handle_neg_float

    # ---- P5b: double binary ------------------------------------------------
    double_binary = [
        ("add-double", operator.add),
        ("sub-double", operator.sub),
        ("mul-double", operator.mul),
        ("div-double", _ieee_div),
        ("rem-double", _ieee_rem),
    ]
    for name, op in double_binary:
        eval_table[name] = (lambda i, s, _op=op: _double2(i, s, _op))
        eval_table[name + "/2addr"] = (
            lambda i, s, _op=op: _double2addr(i, s, _op)
        )
    eval_table["neg-double"] = handle_neg_double
