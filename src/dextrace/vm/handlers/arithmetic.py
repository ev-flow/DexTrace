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

from dextrace.dalvik.types import DecodedInsn
from dextrace.vm.errors import DexTraceVMError
from dextrace.vm.int_ops import i32, u32, reg_index
from dextrace.vm.state import VMState

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
        raise DexTraceVMError(f"div-int by zero (pc={insn.uoff:#06x})")
    state.registers.set(dest, i32(int(a / b)))  # truncate toward zero


def handle_div_int_2addr(insn: DecodedInsn, state: VMState) -> None:
    dest, a, b = _get2(insn, state)
    if b == 0:
        raise DexTraceVMError(f"div-int by zero (pc={insn.uoff:#06x})")
    state.registers.set(dest, i32(int(a / b)))


def handle_div_int_lit8(insn: DecodedInsn, state: VMState) -> None:
    dest, a, lit = _get_lit(insn, state)
    if lit == 0:
        raise DexTraceVMError(f"div-int by zero (pc={insn.uoff:#06x})")
    state.registers.set(dest, i32(int(a / lit)))


def handle_div_int_lit16(insn: DecodedInsn, state: VMState) -> None:
    dest, a, lit = _get_lit(insn, state)
    if lit == 0:
        raise DexTraceVMError(f"div-int by zero (pc={insn.uoff:#06x})")
    state.registers.set(dest, i32(int(a / lit)))


# ---------------------------------------------------------------------------
# rem-int
# ---------------------------------------------------------------------------


def handle_rem_int(insn: DecodedInsn, state: VMState) -> None:
    dest, a, b = _get3(insn, state)
    if b == 0:
        raise DexTraceVMError(f"rem-int by zero (pc={insn.uoff:#06x})")
    # Dalvik: truncate-toward-zero remainder (same as Java %)
    state.registers.set(dest, i32(int(a - b * int(a / b))))


def handle_rem_int_2addr(insn: DecodedInsn, state: VMState) -> None:
    dest, a, b = _get2(insn, state)
    if b == 0:
        raise DexTraceVMError(f"rem-int by zero (pc={insn.uoff:#06x})")
    state.registers.set(dest, i32(int(a - b * int(a / b))))


def handle_rem_int_lit8(insn: DecodedInsn, state: VMState) -> None:
    dest, a, lit = _get_lit(insn, state)
    if lit == 0:
        raise DexTraceVMError(f"rem-int by zero (pc={insn.uoff:#06x})")
    state.registers.set(dest, i32(int(a - lit * int(a / lit))))


def handle_rem_int_lit16(insn: DecodedInsn, state: VMState) -> None:
    dest, a, lit = _get_lit(insn, state)
    if lit == 0:
        raise DexTraceVMError(f"rem-int by zero (pc={insn.uoff:#06x})")
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
