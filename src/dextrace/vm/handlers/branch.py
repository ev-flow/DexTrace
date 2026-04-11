# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/handlers/branch.py — Branch and goto instruction handlers.

Branch opcodes use target_uoff (already computed by the disassembler) rather
than decoding the raw offset literal ourselves.

Covers:
  if-eq / if-ne / if-lt / if-ge / if-gt / if-le   (22t, two-register)
  if-eqz / if-nez / if-ltz / if-gez / if-gtz / if-lez  (21t, one-register vs zero)
  goto / goto/16 / goto/32
"""

from __future__ import annotations

from dextrace.dalvik.types import DecodedInsn
from dextrace.vm.errors import DexTraceNotImplementedError
from dextrace.vm.int_ops import reg_index
from dextrace.vm.state import VMState

_SENTINEL = object()  # marks "branch taken" — engine reads state.pc


# ---------------------------------------------------------------------------
# Two-register conditionals (22t)
# ---------------------------------------------------------------------------

def handle_if_eq(insn: DecodedInsn, state: VMState) -> None:
    a = state.registers.get(reg_index(insn.regs[0]))
    b = state.registers.get(reg_index(insn.regs[1]))
    if a == b:
        state.pc = insn.target_uoff

def handle_if_ne(insn: DecodedInsn, state: VMState) -> None:
    a = state.registers.get(reg_index(insn.regs[0]))
    b = state.registers.get(reg_index(insn.regs[1]))
    if a != b:
        state.pc = insn.target_uoff

def handle_if_lt(insn: DecodedInsn, state: VMState) -> None:
    a = state.registers.get(reg_index(insn.regs[0]))
    b = state.registers.get(reg_index(insn.regs[1]))
    if a < b:
        state.pc = insn.target_uoff

def handle_if_ge(insn: DecodedInsn, state: VMState) -> None:
    a = state.registers.get(reg_index(insn.regs[0]))
    b = state.registers.get(reg_index(insn.regs[1]))
    if a >= b:
        state.pc = insn.target_uoff

def handle_if_gt(insn: DecodedInsn, state: VMState) -> None:
    a = state.registers.get(reg_index(insn.regs[0]))
    b = state.registers.get(reg_index(insn.regs[1]))
    if a > b:
        state.pc = insn.target_uoff

def handle_if_le(insn: DecodedInsn, state: VMState) -> None:
    a = state.registers.get(reg_index(insn.regs[0]))
    b = state.registers.get(reg_index(insn.regs[1]))
    if a <= b:
        state.pc = insn.target_uoff


# ---------------------------------------------------------------------------
# One-register-vs-zero conditionals (21t)
# ---------------------------------------------------------------------------

def handle_if_eqz(insn: DecodedInsn, state: VMState) -> None:
    a = state.registers.get(reg_index(insn.regs[0]))
    if a == 0:
        state.pc = insn.target_uoff

def handle_if_nez(insn: DecodedInsn, state: VMState) -> None:
    a = state.registers.get(reg_index(insn.regs[0]))
    if a != 0:
        state.pc = insn.target_uoff

def handle_if_ltz(insn: DecodedInsn, state: VMState) -> None:
    a = state.registers.get(reg_index(insn.regs[0]))
    if a < 0:
        state.pc = insn.target_uoff

def handle_if_gez(insn: DecodedInsn, state: VMState) -> None:
    a = state.registers.get(reg_index(insn.regs[0]))
    if a >= 0:
        state.pc = insn.target_uoff

def handle_if_gtz(insn: DecodedInsn, state: VMState) -> None:
    a = state.registers.get(reg_index(insn.regs[0]))
    if a > 0:
        state.pc = insn.target_uoff

def handle_if_lez(insn: DecodedInsn, state: VMState) -> None:
    a = state.registers.get(reg_index(insn.regs[0]))
    if a <= 0:
        state.pc = insn.target_uoff


# ---------------------------------------------------------------------------
# Goto (unconditional)
# ---------------------------------------------------------------------------

def handle_goto(insn: DecodedInsn, state: VMState) -> None:
    state.pc = insn.target_uoff

def handle_goto_16(insn: DecodedInsn, state: VMState) -> None:
    state.pc = insn.target_uoff

def handle_goto_32(insn: DecodedInsn, state: VMState) -> None:
    state.pc = insn.target_uoff


# ---------------------------------------------------------------------------
# Switch — not required for P1/P2; raise to signal missing feature
# ---------------------------------------------------------------------------

def handle_packed_switch(insn: DecodedInsn, state: VMState) -> None:
    raise DexTraceNotImplementedError(
        f"packed-switch not implemented (pc={insn.uoff:#06x})"
    )

def handle_sparse_switch(insn: DecodedInsn, state: VMState) -> None:
    raise DexTraceNotImplementedError(
        f"sparse-switch not implemented (pc={insn.uoff:#06x})"
    )


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register(eval_table: dict) -> None:
    pairs = [
        ("if-eq",  handle_if_eq),
        ("if-ne",  handle_if_ne),
        ("if-lt",  handle_if_lt),
        ("if-ge",  handle_if_ge),
        ("if-gt",  handle_if_gt),
        ("if-le",  handle_if_le),
        ("if-eqz", handle_if_eqz),
        ("if-nez", handle_if_nez),
        ("if-ltz", handle_if_ltz),
        ("if-gez", handle_if_gez),
        ("if-gtz", handle_if_gtz),
        ("if-lez", handle_if_lez),
        ("goto",        handle_goto),
        ("goto/16",     handle_goto_16),
        ("goto/32",     handle_goto_32),
        ("packed-switch", handle_packed_switch),
        ("sparse-switch", handle_sparse_switch),
    ]
    for name, fn in pairs:
        eval_table[name] = fn
