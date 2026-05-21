# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/handlers/move.py — move and const instruction handlers.

Covers:
  const*, const-string*, move*, move-result*
"""

from __future__ import annotations

from dextrace.dalvik.types import DecodedInsn
from dextrace.vm.errors import DexTraceVMError
from dextrace.vm.int_ops import i32, reg_index
from dextrace.vm.state import VMState

# ---------------------------------------------------------------------------
# Const
# ---------------------------------------------------------------------------


def handle_nop(  # pylint: disable=unused-argument
    insn: DecodedInsn, state: VMState
) -> None:
    pass


def handle_const4(insn: DecodedInsn, state: VMState) -> None:
    # const/4 vA, #+B  (4-bit signed literal)
    dest = reg_index(insn.regs[0])
    val = i32(int(insn.param or 0))
    state.registers.set(dest, val)


def handle_const16(insn: DecodedInsn, state: VMState) -> None:
    # const/16 vAA, #+BBBB
    dest = reg_index(insn.regs[0])
    val = i32(int(insn.param or 0))
    state.registers.set(dest, val)


def handle_const(insn: DecodedInsn, state: VMState) -> None:
    # const vAA, #+BBBBBBBB
    dest = reg_index(insn.regs[0])
    val = i32(int(insn.param or 0))
    state.registers.set(dest, val)


def handle_const_high16(insn: DecodedInsn, state: VMState) -> None:
    # const/high16 vAA, #+BBBB0000
    dest = reg_index(insn.regs[0])
    val = i32(int(insn.param or 0) << 16)
    state.registers.set(dest, val)


def handle_const_wide16(insn: DecodedInsn, state: VMState) -> None:
    # const-wide/16 vAA, #+BBBB
    dest = reg_index(insn.regs[0])
    state.registers.set_wide(dest, int(insn.param or 0))


def handle_const_wide32(insn: DecodedInsn, state: VMState) -> None:
    # const-wide/32 vAA, #+BBBBBBBB
    dest = reg_index(insn.regs[0])
    state.registers.set_wide(dest, int(insn.param or 0))


def handle_const_wide(insn: DecodedInsn, state: VMState) -> None:
    # const-wide vAA, #+BBBBBBBBBBBBBBBB
    dest = reg_index(insn.regs[0])
    state.registers.set_wide(dest, int(insn.param or 0))


def handle_const_wide_high16(insn: DecodedInsn, state: VMState) -> None:
    # const-wide/high16 vAA, #+BBBB000000000000
    dest = reg_index(insn.regs[0])
    state.registers.set_wide(dest, int(insn.param or 0) << 48)


# const-string and const-string/jumbo are heap-allocating opcodes (P5d) and
# live in engine.py as closures so they can capture the heap reference.


# ---------------------------------------------------------------------------
# Move
# ---------------------------------------------------------------------------


def handle_move(insn: DecodedInsn, state: VMState) -> None:
    # move vA, vB
    dest = reg_index(insn.regs[0])
    src = reg_index(insn.regs[1])
    state.registers.set(dest, state.registers.get(src))


def handle_move_from16(insn: DecodedInsn, state: VMState) -> None:
    # move/from16 vAA, vBBBB
    handle_move(insn, state)


def handle_move_16(insn: DecodedInsn, state: VMState) -> None:
    # move/16 vAAAA, vBBBB
    handle_move(insn, state)


def handle_move_wide(insn: DecodedInsn, state: VMState) -> None:
    # move-wide vA, vB
    dest = reg_index(insn.regs[0])
    src = reg_index(insn.regs[1])
    state.registers.set_wide(dest, state.registers.get_wide(src))


def handle_move_wide_from16(insn: DecodedInsn, state: VMState) -> None:
    handle_move_wide(insn, state)


def handle_move_wide_16(insn: DecodedInsn, state: VMState) -> None:
    handle_move_wide(insn, state)


def handle_move_object(insn: DecodedInsn, state: VMState) -> None:
    handle_move(insn, state)


def handle_move_object_from16(insn: DecodedInsn, state: VMState) -> None:
    handle_move(insn, state)


def handle_move_object_16(insn: DecodedInsn, state: VMState) -> None:
    handle_move(insn, state)


# ---------------------------------------------------------------------------
# move-result*  (consume pending_result — OV-3)
# ---------------------------------------------------------------------------


def handle_move_result(insn: DecodedInsn, state: VMState) -> None:
    if state.pending_result is None:
        raise DexTraceVMError("move-result: no pending result")
    if state.pending_result_is_wide:
        raise DexTraceVMError(
            "move-result: pending result is wide, use move-result-wide"
        )
    dest = reg_index(insn.regs[0])
    val = state.pending_result
    state.pending_result = None
    state.pending_result_is_wide = False
    state.registers.set(
        dest, int(val) if not isinstance(val, str) else hash(val) & 0xFFFF_FFFF
    )


def handle_move_result_wide(insn: DecodedInsn, state: VMState) -> None:
    if state.pending_result is None:
        raise DexTraceVMError("move-result-wide: no pending result")
    if not state.pending_result_is_wide:
        raise DexTraceVMError("move-result-wide: pending result is not wide")
    dest = reg_index(insn.regs[0])
    val = int(state.pending_result)
    state.pending_result = None
    state.pending_result_is_wide = False
    state.registers.set_wide(dest, val)


def handle_move_result_object(insn: DecodedInsn, state: VMState) -> None:
    # For P1/P2: treat object results same as 32-bit ints
    if state.pending_result is None:
        raise DexTraceVMError("move-result-object: no pending result")
    dest = reg_index(insn.regs[0])
    val = state.pending_result
    state.pending_result = None
    state.pending_result_is_wide = False
    state.registers.set(
        dest, int(val) if not isinstance(val, str) else hash(val) & 0xFFFF_FFFF
    )


# ---------------------------------------------------------------------------
# move-exception (P5a)  — consume state.pending_exception
# ---------------------------------------------------------------------------


def handle_move_exception(insn: DecodedInsn, state: VMState) -> None:
    if state.pending_exception is None:
        raise DexTraceVMError(
            "move-exception: no pending exception "
            "(catch entered without a matched throw)"
        )
    dest = reg_index(insn.regs[0])
    handle = state.pending_exception
    state.pending_exception = None
    state.registers.set(dest, handle)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register(eval_table: dict) -> None:
    eval_table["nop"] = handle_nop
    eval_table["const/4"] = handle_const4
    eval_table["const/16"] = handle_const16
    eval_table["const"] = handle_const
    eval_table["const/high16"] = handle_const_high16
    eval_table["const-wide/16"] = handle_const_wide16
    eval_table["const-wide/32"] = handle_const_wide32
    eval_table["const-wide"] = handle_const_wide
    eval_table["const-wide/high16"] = handle_const_wide_high16
    # const-string / const-string/jumbo / const-class are registered by the
    # engine — they need the heap.
    eval_table["move"] = handle_move
    eval_table["move/from16"] = handle_move_from16
    eval_table["move/16"] = handle_move_16
    eval_table["move-wide"] = handle_move_wide
    eval_table["move-wide/from16"] = handle_move_wide_from16
    eval_table["move-wide/16"] = handle_move_wide_16
    eval_table["move-object"] = handle_move_object
    eval_table["move-object/from16"] = handle_move_object_from16
    eval_table["move-object/16"] = handle_move_object_16
    eval_table["move-result"] = handle_move_result
    eval_table["move-result-wide"] = handle_move_result_wide
    eval_table["move-result-object"] = handle_move_result_object
    eval_table["move-exception"] = handle_move_exception
