# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/handlers/compare.py — Comparison instruction handlers.

Covers:
  cmp-long
  cmpl-float / cmpg-float
  cmpl-double / cmpg-double

Dalvik semantics:
  cmp-long:    result = (a > b) ? 1 : (a < b) ? -1 : 0
  cmpl-float:  result = (a > b) ? 1 : (a < b) ? -1 : 0; NaN -> -1
  cmpg-float:  result = (a > b) ? 1 : (a < b) ? -1 : 0; NaN -> +1
  cmpl-double: same as cmpl-float but for doubles
  cmpg-double: same as cmpg-float but for doubles
"""

from __future__ import annotations

import math
import struct

from dextrace.dalvik.types import DecodedInsn
from dextrace.vm.int_ops import reg_index
from dextrace.vm.state import VMState


def _bits_to_float(n: int) -> float:
    return struct.unpack(">f", struct.pack(">I", n & 0xFFFF_FFFF))[0]


def _bits_to_double(n: int) -> float:
    return struct.unpack(">d", struct.pack(">Q", n & 0xFFFF_FFFF_FFFF_FFFF))[0]


# ---------------------------------------------------------------------------
# cmp-long (23x)
# ---------------------------------------------------------------------------


def handle_cmp_long(insn: DecodedInsn, state: VMState) -> None:
    dest = reg_index(insn.regs[0])
    a = state.registers.get_wide(reg_index(insn.regs[1]))
    b = state.registers.get_wide(reg_index(insn.regs[2]))
    # interpret as signed
    if a >= 0x8000_0000_0000_0000:
        a -= 0x1_0000_0000_0000_0000
    if b >= 0x8000_0000_0000_0000:
        b -= 0x1_0000_0000_0000_0000
    state.registers.set(dest, 1 if a > b else (-1 if a < b else 0))


# ---------------------------------------------------------------------------
# cmpl-float / cmpg-float (23x)
# ---------------------------------------------------------------------------


def handle_cmpl_float(insn: DecodedInsn, state: VMState) -> None:
    dest = reg_index(insn.regs[0])
    a = _bits_to_float(state.registers.get(reg_index(insn.regs[1])))
    b = _bits_to_float(state.registers.get(reg_index(insn.regs[2])))
    if math.isnan(a) or math.isnan(b):
        state.registers.set(dest, -1)
    else:
        state.registers.set(dest, 1 if a > b else (-1 if a < b else 0))


def handle_cmpg_float(insn: DecodedInsn, state: VMState) -> None:
    dest = reg_index(insn.regs[0])
    a = _bits_to_float(state.registers.get(reg_index(insn.regs[1])))
    b = _bits_to_float(state.registers.get(reg_index(insn.regs[2])))
    if math.isnan(a) or math.isnan(b):
        state.registers.set(dest, 1)
    else:
        state.registers.set(dest, 1 if a > b else (-1 if a < b else 0))


# ---------------------------------------------------------------------------
# cmpl-double / cmpg-double (23x)
# ---------------------------------------------------------------------------


def handle_cmpl_double(insn: DecodedInsn, state: VMState) -> None:
    dest = reg_index(insn.regs[0])
    a = _bits_to_double(state.registers.get_wide(reg_index(insn.regs[1])))
    b = _bits_to_double(state.registers.get_wide(reg_index(insn.regs[2])))
    if math.isnan(a) or math.isnan(b):
        state.registers.set(dest, -1)
    else:
        state.registers.set(dest, 1 if a > b else (-1 if a < b else 0))


def handle_cmpg_double(insn: DecodedInsn, state: VMState) -> None:
    dest = reg_index(insn.regs[0])
    a = _bits_to_double(state.registers.get_wide(reg_index(insn.regs[1])))
    b = _bits_to_double(state.registers.get_wide(reg_index(insn.regs[2])))
    if math.isnan(a) or math.isnan(b):
        state.registers.set(dest, 1)
    else:
        state.registers.set(dest, 1 if a > b else (-1 if a < b else 0))


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register(eval_table: dict) -> None:
    pairs = [
        ("cmp-long", handle_cmp_long),
        ("cmpl-float", handle_cmpl_float),
        ("cmpg-float", handle_cmpg_float),
        ("cmpl-double", handle_cmpl_double),
        ("cmpg-double", handle_cmpg_double),
    ]
    for name, fn in pairs:
        eval_table[name] = fn
