# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/handlers/array.py — Array operations (P5e).

Covers all 19 array opcodes:
  new-array, array-length
  filled-new-array, filled-new-array/range
  fill-array-data                                 (engine-inline; needs raw bytes)
  aget / aget-wide / aget-object / aget-{boolean,byte,char,short}
  aput / aput-wide / aput-object / aput-{boolean,byte,char,short}

Heap model:
  Each array is a HeapEntry whose `value` is a Python list. `class_desc`
  carries the full Dalvik array descriptor (e.g. "[I", "[Ljava/lang/String;").
  ObjectHeap.get_array(handle) returns the underlying list; bounds checks
  and signal-raising live here in the handler so heap.py stays unaware of
  vm.signals (and the import graph stays acyclic).

Exception semantics (composes with P5a catch walker):
  - null array on array-length / aget*/aput* → NullPointerException
  - negative length on new-array            → NegativeArraySizeException
  - index < 0 or >= length on aget*/aput*   → ArrayIndexOutOfBoundsException

filled-new-array / filled-new-array-range:
  Allocate the array, copy each register value into it, and surface the
  handle via state.pending_result so the next move-result-object picks it
  up (mirrors invoke* return semantics).

fill-array-data is registered by the engine (not here) because it needs
raw access to the code-unit bytes via the parser; the handler module does
not see code_off. This matches the packed/sparse-switch split in P5c.
"""

from __future__ import annotations

from dextrace.dalvik.types import DecodedInsn
from dextrace.vm.errors import DexTraceVMError
from dextrace.vm.heap import ObjectHeap
from dextrace.vm.int_ops import reg_index
from dextrace.vm.signals import _ThrowSignal
from dextrace.vm.state import VMState


def _array_desc(insn: DecodedInsn) -> str:
    desc = insn.param
    if not desc:
        raise DexTraceVMError(
            f"{insn.mnemonic} at pc={insn.uoff:#06x}: missing type descriptor"
        )
    return desc


def _check_array(handle: int) -> None:
    if handle == 0:
        raise _ThrowSignal("Ljava/lang/NullPointerException;", 0)


def _check_index(arr: list, idx: int) -> None:
    if idx < 0 or idx >= len(arr):
        raise _ThrowSignal("Ljava/lang/ArrayIndexOutOfBoundsException;", 0)


def register(eval_table: dict, heap: ObjectHeap) -> None:
    """Register P5e array handlers, capturing the heap reference."""

    # ------------------------------------------------------------------
    # Allocation
    # ------------------------------------------------------------------

    def handle_new_array(insn: DecodedInsn, state: VMState) -> None:
        # new-array vA, vB, type@CCCC  (22c): A = dest, B = length register.
        length = state.registers.get(reg_index(insn.regs[1]))
        if length < 0:
            raise _ThrowSignal("Ljava/lang/NegativeArraySizeException;", 0)
        handle = heap.allocate_array(_array_desc(insn), length)
        state.registers.set(reg_index(insn.regs[0]), handle)

    def handle_array_length(insn: DecodedInsn, state: VMState) -> None:
        # array-length vA, vB (12x): B is the array, A is the dest.
        handle = state.registers.get(reg_index(insn.regs[1]))
        _check_array(handle)
        arr = heap.get_array(handle)
        state.registers.set(reg_index(insn.regs[0]), len(arr))

    def handle_filled_new_array(insn: DecodedInsn, state: VMState) -> None:
        # filled-new-array {vC..vG}, type@BBBB (35c): explicit register list.
        # filled-new-array/range {vCCCC..}, type@BBBB (3rc): range form,
        # but the disassembler hands us the same regs[] list either way.
        # The constructed handle is published via pending_result; a later
        # move-result-object writes it to a register.
        desc = _array_desc(insn)
        length = len(insn.regs)
        handle = heap.allocate_array(desc, length)
        arr = heap.get_array(handle)
        for i, r in enumerate(insn.regs):
            arr[i] = state.registers.get(reg_index(r))
        state.pending_result = handle
        state.pending_result_is_wide = False

    # ------------------------------------------------------------------
    # aget / aput families
    # All formats use 23x: AA|op|CC|BB. regs[] = [AA, BB, CC]:
    #   AA = value reg (dest for aget*, src for aput*)
    #   BB = array reg
    #   CC = index reg
    # ------------------------------------------------------------------

    def _aget(insn: DecodedInsn, state: VMState) -> None:
        handle = state.registers.get(reg_index(insn.regs[1]))
        _check_array(handle)
        arr = heap.get_array(handle)
        idx = state.registers.get(reg_index(insn.regs[2]))
        _check_index(arr, idx)
        state.registers.set(reg_index(insn.regs[0]), int(arr[idx]))

    def _aget_wide(insn: DecodedInsn, state: VMState) -> None:
        handle = state.registers.get(reg_index(insn.regs[1]))
        _check_array(handle)
        arr = heap.get_array(handle)
        idx = state.registers.get(reg_index(insn.regs[2]))
        _check_index(arr, idx)
        state.registers.set_wide(reg_index(insn.regs[0]), int(arr[idx]))

    def _aput(insn: DecodedInsn, state: VMState) -> None:
        handle = state.registers.get(reg_index(insn.regs[1]))
        _check_array(handle)
        arr = heap.get_array(handle)
        idx = state.registers.get(reg_index(insn.regs[2]))
        _check_index(arr, idx)
        arr[idx] = state.registers.get(reg_index(insn.regs[0]))

    def _aput_wide(insn: DecodedInsn, state: VMState) -> None:
        handle = state.registers.get(reg_index(insn.regs[1]))
        _check_array(handle)
        arr = heap.get_array(handle)
        idx = state.registers.get(reg_index(insn.regs[2]))
        _check_index(arr, idx)
        arr[idx] = state.registers.get_wide(reg_index(insn.regs[0]))

    eval_table["new-array"] = handle_new_array
    eval_table["array-length"] = handle_array_length
    eval_table["filled-new-array"] = handle_filled_new_array
    eval_table["filled-new-array/range"] = handle_filled_new_array

    # Narrow + object + 4 typed primitive widths share _aget; -wide is its own.
    eval_table["aget"] = _aget
    eval_table["aget-object"] = _aget
    eval_table["aget-boolean"] = _aget
    eval_table["aget-byte"] = _aget
    eval_table["aget-char"] = _aget
    eval_table["aget-short"] = _aget
    eval_table["aget-wide"] = _aget_wide

    eval_table["aput"] = _aput
    eval_table["aput-object"] = _aput
    eval_table["aput-boolean"] = _aput
    eval_table["aput-byte"] = _aput
    eval_table["aput-char"] = _aput
    eval_table["aput-short"] = _aput
    eval_table["aput-wide"] = _aput_wide

    # fill-array-data is registered by the engine — it needs raw insns bytes.
