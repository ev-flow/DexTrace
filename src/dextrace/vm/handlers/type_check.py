# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/handlers/type_check.py — check-cast, instance-of, monitor-enter, monitor-exit.

P5c semantics (per Dalvik spec):

  check-cast vAA, type@BBBB
    Null is always castable; a non-null receiver whose runtime class is not a
    subtype of the target throws ClassCastException. The register is left
    unchanged on success — Dalvik does not write back.

  instance-of vA, vB, type@CCCC
    Writes 1 to vA if vB is non-null AND its runtime class is a subtype of
    the target type, else 0.

  monitor-enter / monitor-exit vAA
    Single-threaded VM: locking is a no-op. Null receiver → NullPointerException
    as the JVM spec mandates. An optional trace_sink fires on every enter/exit
    so analysts can see locking activity in --verbose runs.
"""

from __future__ import annotations

from typing import Callable, Optional

from dextrace.dalvik.types import DecodedInsn
from dextrace.vm.class_hierarchy import ClassHierarchy
from dextrace.vm.heap import ObjectHeap
from dextrace.vm.int_ops import reg_index
from dextrace.vm.signals import _ThrowSignal
from dextrace.vm.state import VMState


def register(
    eval_table: dict,
    heap: ObjectHeap,
    hierarchy: ClassHierarchy,
    trace_sink: Optional[Callable[[str], None]] = None,
) -> None:
    """Register P5c type-check + monitor handlers, capturing heap/hierarchy."""

    def handle_check_cast(insn: DecodedInsn, state: VMState) -> None:
        handle = state.registers.get(reg_index(insn.regs[0]))
        if handle == 0:
            return
        target = insn.param
        runtime_class = heap.get_class(handle)
        if not hierarchy.is_subtype(runtime_class, target):
            raise _ThrowSignal("Ljava/lang/ClassCastException;", 0)

    def handle_instance_of(insn: DecodedInsn, state: VMState) -> None:
        dest = reg_index(insn.regs[0])
        src = reg_index(insn.regs[1])
        handle = state.registers.get(src)
        if handle == 0:
            state.registers.set(dest, 0)
            return
        target = insn.param
        runtime_class = heap.get_class(handle)
        result = 1 if hierarchy.is_subtype(runtime_class, target) else 0
        state.registers.set(dest, result)

    def handle_monitor_enter(insn: DecodedInsn, state: VMState) -> None:
        handle = state.registers.get(reg_index(insn.regs[0]))
        if handle == 0:
            raise _ThrowSignal("Ljava/lang/NullPointerException;", 0)
        if trace_sink is not None:
            trace_sink(f"monitor-enter: handle #{handle}")

    def handle_monitor_exit(insn: DecodedInsn, state: VMState) -> None:
        handle = state.registers.get(reg_index(insn.regs[0]))
        if handle == 0:
            raise _ThrowSignal("Ljava/lang/NullPointerException;", 0)
        if trace_sink is not None:
            trace_sink(f"monitor-exit: handle #{handle}")

    eval_table["check-cast"] = handle_check_cast
    eval_table["instance-of"] = handle_instance_of
    eval_table["monitor-enter"] = handle_monitor_enter
    eval_table["monitor-exit"] = handle_monitor_exit
