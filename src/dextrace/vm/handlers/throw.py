# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/handlers/throw.py — `throw vAA` opcode (format 11x, opcode 0x27).

Reads the exception object handle from the named register and raises a
`_ThrowSignal` with the heap-resolved class descriptor. The engine catches
the signal in its dispatch loop and walks the catch table.

Edge case: throwing a null register (handle == 0) raises NullPointerException
exactly as the Dalvik spec requires. Without this branch, heap.get_class(0)
would raise its own DexTraceVMError ("null receiver") and bypass the
catch table entirely — a divCatch-style sample would never see its catch
block fire.
"""

from __future__ import annotations

from dextrace.dalvik.types import DecodedInsn
from dextrace.vm.heap import ObjectHeap
from dextrace.vm.int_ops import reg_index
from dextrace.vm.signals import _ThrowSignal
from dextrace.vm.state import VMState


def register(eval_table: dict, heap: ObjectHeap) -> None:
    """Register `throw` against `eval_table`, capturing `heap` in a closure."""

    def handle_throw(insn: DecodedInsn, state: VMState) -> None:
        handle = state.registers.get(reg_index(insn.regs[0]))
        if handle == 0:
            raise _ThrowSignal("Ljava/lang/NullPointerException;", 0)
        class_desc = heap.get_class(handle)
        raise _ThrowSignal(class_desc, handle)

    eval_table["throw"] = handle_throw
