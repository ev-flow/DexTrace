# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/handlers/field.py — Instance and static field access.

Covers all 28 field opcodes:
  iget / iget-wide / iget-object / iget-{boolean,byte,char,short}
  iput / iput-wide / iput-object / iput-{boolean,byte,char,short}
  sget / sget-wide / sget-object / sget-{boolean,byte,char,short}
  sput / sput-wide / sput-object / sput-{boolean,byte,char,short}

Field reference shape:
  insn.param is the full Dalvik field signature ("Lcls;->name:type"),
  produced by DexResolver.get_field_sig. We store and look up by this
  exact key — class + name + type — so an inherited field with the same
  simple name on a different class can never collide.

Instance fields live on each HeapEntry's instance_fields dict. Static
fields live in a VM-owned dict passed in via register(); the engine
clears it at run() entry so consecutive runs see isolated state.

Null receiver semantics:
  iget*/iput* on a null receiver (handle == 0) raise _ThrowSignal
  with NullPointerException so an in-method catch can handle it.
  Mirrors the JVM behavior monitor-* already uses in type_check.py.

Typed primitive widths (boolean/byte/char/short) narrow on read: the
typed iget/sget opcode defines the visible element width, so byte/short
sign-extend, char zero-extends, and boolean normalizes to 0/1 (see the
width helpers in int_ops.py). The store keeps the raw int; narrowing the
producer cannot do (a valid 32-bit int like 255 is not a valid byte).

`_stub` is preserved at module scope: an existing regression test
(tests/vm/test_arithmetic.py) calls it directly to verify the
"unimplemented opcode" message format. The new register() no longer
binds it, but the symbol stays.
"""

from __future__ import annotations

from typing import Any, Dict

from dextrace.dalvik.types import DecodedInsn
from dextrace.vm.errors import DexTraceNotImplementedError, DexTraceVMError
from dextrace.vm.heap import ObjectHeap
from dextrace.vm.int_ops import i8, i16, reg_index, u1, u16
from dextrace.vm.signals import _ThrowSignal
from dextrace.vm.state import VMState


def _stub(insn: DecodedInsn, state: VMState) -> None:
    raise DexTraceNotImplementedError(
        f"{insn.mnemonic} not implemented (pc={insn.uoff:#06x})"
    )


def _field_sig(insn: DecodedInsn) -> str:
    sig = insn.param
    if not sig:
        raise DexTraceVMError(
            f"{insn.mnemonic} at pc={insn.uoff:#06x}: missing field signature"
        )
    return sig


def register(
    eval_table: dict,
    heap: ObjectHeap,
    static_fields: Dict[str, Any],
) -> None:
    """Register all 28 field handlers, capturing heap + static-fields map."""

    # ------------------------------------------------------------------
    # Instance fields (iget / iput families)
    # iget vA, vB, field@CCCC      → A = receiver_in_B.field
    # iput vA, vB, field@CCCC      → receiver_in_B.field = A
    # ------------------------------------------------------------------

    def _iget(insn: DecodedInsn, state: VMState) -> None:
        receiver = state.registers.get(reg_index(insn.regs[1]))
        if receiver == 0:
            raise _ThrowSignal("Ljava/lang/NullPointerException;", 0)
        val = heap.get_instance_field(receiver, _field_sig(insn), default=0)
        state.registers.set(reg_index(insn.regs[0]), int(val))

    def _iget_wide(insn: DecodedInsn, state: VMState) -> None:
        receiver = state.registers.get(reg_index(insn.regs[1]))
        if receiver == 0:
            raise _ThrowSignal("Ljava/lang/NullPointerException;", 0)
        val = heap.get_instance_field(receiver, _field_sig(insn), default=0)
        state.registers.set_wide(reg_index(insn.regs[0]), int(val))

    def _iput(insn: DecodedInsn, state: VMState) -> None:
        receiver = state.registers.get(reg_index(insn.regs[1]))
        if receiver == 0:
            raise _ThrowSignal("Ljava/lang/NullPointerException;", 0)
        val = state.registers.get(reg_index(insn.regs[0]))
        heap.set_instance_field(receiver, _field_sig(insn), val)

    def _iput_wide(insn: DecodedInsn, state: VMState) -> None:
        receiver = state.registers.get(reg_index(insn.regs[1]))
        if receiver == 0:
            raise _ThrowSignal("Ljava/lang/NullPointerException;", 0)
        val = state.registers.get_wide(reg_index(insn.regs[0]))
        heap.set_instance_field(receiver, _field_sig(insn), val)

    def _make_iget(width):
        """Build a typed iget that narrows the loaded field value to `width`."""

        def _h(insn: DecodedInsn, state: VMState) -> None:
            receiver = state.registers.get(reg_index(insn.regs[1]))
            if receiver == 0:
                raise _ThrowSignal("Ljava/lang/NullPointerException;", 0)
            val = heap.get_instance_field(receiver, _field_sig(insn), default=0)
            state.registers.set(reg_index(insn.regs[0]), width(int(val)))

        return _h

    # ------------------------------------------------------------------
    # Static fields (sget / sput families)
    # sget vAA, field@BBBB         → AA = static[field]
    # sput vAA, field@BBBB         → static[field] = AA
    # ------------------------------------------------------------------

    def _sget(insn: DecodedInsn, state: VMState) -> None:
        val = static_fields.get(_field_sig(insn), 0)
        state.registers.set(reg_index(insn.regs[0]), int(val))

    def _sget_wide(insn: DecodedInsn, state: VMState) -> None:
        val = static_fields.get(_field_sig(insn), 0)
        state.registers.set_wide(reg_index(insn.regs[0]), int(val))

    def _sput(insn: DecodedInsn, state: VMState) -> None:
        val = state.registers.get(reg_index(insn.regs[0]))
        static_fields[_field_sig(insn)] = val

    def _sput_wide(insn: DecodedInsn, state: VMState) -> None:
        val = state.registers.get_wide(reg_index(insn.regs[0]))
        static_fields[_field_sig(insn)] = val

    def _make_sget(width):
        """Build a typed sget that narrows the loaded static value to `width`."""

        def _h(insn: DecodedInsn, state: VMState) -> None:
            val = static_fields.get(_field_sig(insn), 0)
            state.registers.set(reg_index(insn.regs[0]), width(int(val)))

        return _h

    # iget*: narrow / object variants share _iget; typed widths narrow on read
    # (byte/short sign-extend, char zero-extends, boolean 0/1); -wide is its own.
    eval_table["iget"] = _iget
    eval_table["iget-object"] = _iget
    eval_table["iget-boolean"] = _make_iget(u1)
    eval_table["iget-byte"] = _make_iget(i8)
    eval_table["iget-char"] = _make_iget(u16)
    eval_table["iget-short"] = _make_iget(i16)
    eval_table["iget-wide"] = _iget_wide

    eval_table["iput"] = _iput
    eval_table["iput-object"] = _iput
    eval_table["iput-boolean"] = _iput
    eval_table["iput-byte"] = _iput
    eval_table["iput-char"] = _iput
    eval_table["iput-short"] = _iput
    eval_table["iput-wide"] = _iput_wide

    eval_table["sget"] = _sget
    eval_table["sget-object"] = _sget
    eval_table["sget-boolean"] = _make_sget(u1)
    eval_table["sget-byte"] = _make_sget(i8)
    eval_table["sget-char"] = _make_sget(u16)
    eval_table["sget-short"] = _make_sget(i16)
    eval_table["sget-wide"] = _sget_wide

    eval_table["sput"] = _sput
    eval_table["sput-object"] = _sput
    eval_table["sput-boolean"] = _sput
    eval_table["sput-byte"] = _sput
    eval_table["sput-char"] = _sput
    eval_table["sput-short"] = _sput
    eval_table["sput-wide"] = _sput_wide
