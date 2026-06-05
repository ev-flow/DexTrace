# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/handlers/type_conv.py — Type conversion instruction handlers.

Covers int<->long, int<->float, int<->double, long<->float, long<->double,
float<->double, and the int narrowing ops (int-to-byte, int-to-char,
int-to-short).
"""

from __future__ import annotations

import struct

from dextrace.dalvik.types import DecodedInsn
from dextrace.vm.int_ops import i32, i64, reg_index
from dextrace.vm.state import VMState

# Saturation bounds for float/double -> integral conversions.
INT_MIN, INT_MAX = -(2**31), 2**31 - 1
LONG_MIN, LONG_MAX = -(2**63), 2**63 - 1

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _float_to_integral(f: float, lo: int, hi: int) -> int:
    """Java/Dalvik float->integral narrowing.

    Python's int() raises on NaN/Infinity and wraps finite overflow; Dalvik
    instead produces deterministic saturated values: NaN -> 0, +Inf / overflow
    -> hi, -Inf / underflow -> lo, finite in-range -> truncate toward zero.
    """
    if f != f:  # NaN
        return 0
    if f == float("inf"):
        return hi
    if f == float("-inf"):
        return lo
    v = int(f)  # finite: truncates toward zero
    return hi if v > hi else lo if v < lo else v


def _float_bits(f: float) -> int:
    """Pack a Python float as IEEE-754 single, return as int."""
    result: int = struct.unpack(">I", struct.pack(">f", f))[0]
    return result


def _double_bits(f: float) -> int:
    """Pack a Python float as IEEE-754 double, return as int."""
    result: int = struct.unpack(">Q", struct.pack(">d", f))[0]
    return result


def _bits_to_float(n: int) -> float:
    result: float = struct.unpack(">f", struct.pack(">I", n & 0xFFFF_FFFF))[0]
    return result


def _bits_to_double(n: int) -> float:
    result: float = struct.unpack(
        ">d", struct.pack(">Q", n & 0xFFFF_FFFF_FFFF_FFFF)
    )[0]
    return result


# ---------------------------------------------------------------------------
# Int narrowing
# ---------------------------------------------------------------------------


def handle_int_to_byte(insn: DecodedInsn, state: VMState) -> None:
    dest = reg_index(insn.regs[0])
    src = reg_index(insn.regs[1])
    v = state.registers.get(src) & 0xFF
    state.registers.set(dest, i32(v if v < 0x80 else v - 0x100))


def handle_int_to_char(insn: DecodedInsn, state: VMState) -> None:
    dest = reg_index(insn.regs[0])
    src = reg_index(insn.regs[1])
    state.registers.set(dest, state.registers.get(src) & 0xFFFF)


def handle_int_to_short(insn: DecodedInsn, state: VMState) -> None:
    dest = reg_index(insn.regs[0])
    src = reg_index(insn.regs[1])
    v = state.registers.get(src) & 0xFFFF
    state.registers.set(dest, i32(v if v < 0x8000 else v - 0x10000))


# ---------------------------------------------------------------------------
# Int <-> Long
# ---------------------------------------------------------------------------


def handle_int_to_long(insn: DecodedInsn, state: VMState) -> None:
    dest = reg_index(insn.regs[0])
    src = reg_index(insn.regs[1])
    v = i32(state.registers.get(src))  # sign-extend
    state.registers.set_wide(dest, v & 0xFFFF_FFFF_FFFF_FFFF)


def handle_long_to_int(insn: DecodedInsn, state: VMState) -> None:
    dest = reg_index(insn.regs[0])
    src = reg_index(insn.regs[1])
    v = state.registers.get_wide(src)
    state.registers.set(dest, i32(v & 0xFFFF_FFFF))


# ---------------------------------------------------------------------------
# Int <-> Float
# ---------------------------------------------------------------------------


def handle_int_to_float(insn: DecodedInsn, state: VMState) -> None:
    dest = reg_index(insn.regs[0])
    src = reg_index(insn.regs[1])
    v = i32(state.registers.get(src))
    state.registers.set(dest, _float_bits(float(v)))


def handle_float_to_int(insn: DecodedInsn, state: VMState) -> None:
    dest = reg_index(insn.regs[0])
    src = reg_index(insn.regs[1])
    f = _bits_to_float(state.registers.get(src))
    state.registers.set(dest, i32(_float_to_integral(f, INT_MIN, INT_MAX)))


# ---------------------------------------------------------------------------
# Int <-> Double
# ---------------------------------------------------------------------------


def handle_int_to_double(insn: DecodedInsn, state: VMState) -> None:
    dest = reg_index(insn.regs[0])
    src = reg_index(insn.regs[1])
    v = i32(state.registers.get(src))
    state.registers.set_wide(dest, _double_bits(float(v)))


def handle_double_to_int(insn: DecodedInsn, state: VMState) -> None:
    dest = reg_index(insn.regs[0])
    src = reg_index(insn.regs[1])
    d = _bits_to_double(state.registers.get_wide(src))
    state.registers.set(dest, i32(_float_to_integral(d, INT_MIN, INT_MAX)))


# ---------------------------------------------------------------------------
# Long <-> Float
# ---------------------------------------------------------------------------


def handle_long_to_float(insn: DecodedInsn, state: VMState) -> None:
    dest = reg_index(insn.regs[0])
    src = reg_index(insn.regs[1])
    v = state.registers.get_wide(src)
    # interpret as signed 64-bit
    if v >= 0x8000_0000_0000_0000:
        v -= 0x1_0000_0000_0000_0000
    state.registers.set(dest, _float_bits(float(v)))


def handle_float_to_long(insn: DecodedInsn, state: VMState) -> None:
    dest = reg_index(insn.regs[0])
    src = reg_index(insn.regs[1])
    f = _bits_to_float(state.registers.get(src))
    state.registers.set_wide(
        dest, i64(_float_to_integral(f, LONG_MIN, LONG_MAX)) & 0xFFFF_FFFF_FFFF_FFFF
    )


# ---------------------------------------------------------------------------
# Long <-> Double
# ---------------------------------------------------------------------------


def handle_long_to_double(insn: DecodedInsn, state: VMState) -> None:
    dest = reg_index(insn.regs[0])
    src = reg_index(insn.regs[1])
    v = state.registers.get_wide(src)
    if v >= 0x8000_0000_0000_0000:
        v -= 0x1_0000_0000_0000_0000
    state.registers.set_wide(dest, _double_bits(float(v)))


def handle_double_to_long(insn: DecodedInsn, state: VMState) -> None:
    dest = reg_index(insn.regs[0])
    src = reg_index(insn.regs[1])
    d = _bits_to_double(state.registers.get_wide(src))
    state.registers.set_wide(
        dest, i64(_float_to_integral(d, LONG_MIN, LONG_MAX)) & 0xFFFF_FFFF_FFFF_FFFF
    )


# ---------------------------------------------------------------------------
# Float <-> Double
# ---------------------------------------------------------------------------


def handle_float_to_double(insn: DecodedInsn, state: VMState) -> None:
    dest = reg_index(insn.regs[0])
    src = reg_index(insn.regs[1])
    f = _bits_to_float(state.registers.get(src))
    state.registers.set_wide(dest, _double_bits(f))


def handle_double_to_float(insn: DecodedInsn, state: VMState) -> None:
    dest = reg_index(insn.regs[0])
    src = reg_index(insn.regs[1])
    d = _bits_to_double(state.registers.get_wide(src))
    state.registers.set(dest, _float_bits(d))


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register(eval_table: dict) -> None:
    pairs = [
        ("int-to-byte", handle_int_to_byte),
        ("int-to-char", handle_int_to_char),
        ("int-to-short", handle_int_to_short),
        ("int-to-long", handle_int_to_long),
        ("long-to-int", handle_long_to_int),
        ("int-to-float", handle_int_to_float),
        ("float-to-int", handle_float_to_int),
        ("int-to-double", handle_int_to_double),
        ("double-to-int", handle_double_to_int),
        ("long-to-float", handle_long_to_float),
        ("float-to-long", handle_float_to_long),
        ("long-to-double", handle_long_to_double),
        ("double-to-long", handle_double_to_long),
        ("float-to-double", handle_float_to_double),
        ("double-to-float", handle_double_to_float),
    ]
    for name, fn in pairs:
        eval_table[name] = fn
