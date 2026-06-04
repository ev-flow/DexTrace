# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
Regression tests for width-specific typed array/field handlers (PR #7 review #4).

Dalvik defines the visible element width on the typed *get* opcode, not on the
register or the producing instruction. A valid 32-bit int such as 255 is not a
valid byte, so storing it through aput-byte/iput-byte and reading it back through
aget-byte/iget-byte must sign-extend to -1. char zero-extends; boolean
normalizes to 0/1; byte/short sign-extend.
"""

from __future__ import annotations

from dextrace.dalvik.types import DecodedInsn
from dextrace.vm.handlers import array as array_handlers
from dextrace.vm.handlers import field as field_handlers
from dextrace.vm.heap import ObjectHeap
from dextrace.vm.register_file import RegisterFile
from dextrace.vm.state import VMState


def _insn(regs, param=None):
    return DecodedInsn(
        uoff=0,
        byte_off=0,
        opcode=0x00,
        mnemonic="test",
        fmt="23x",
        size_units=2,
        regs=list(regs),
        param=param,
    )


def _array_table():
    table: dict = {}
    heap = ObjectHeap()
    array_handlers.register(table, heap)
    return table, heap


def _field_table():
    table: dict = {}
    heap = ObjectHeap()
    statics: dict = {}
    field_handlers.register(table, heap, statics)
    return table, heap


def _array_roundtrip(desc, put_op, get_op, value):
    """Store `value` via put_op into a fresh `desc[]`, read it back via get_op."""
    table, heap = _array_table()
    handle = heap.allocate_array(desc, 1)
    state = VMState(registers=RegisterFile(4), pc=0)
    state.registers.set(0, value)  # value
    state.registers.set(1, handle)  # array
    state.registers.set(2, 0)  # index
    table[put_op](_insn(["v0", "v1", "v2"]), state)
    table[get_op](_insn(["v3", "v1", "v2"]), state)
    return state.registers.get(3)


def _ifield_roundtrip(put_op, get_op, value, sig):
    table, heap = _field_table()
    recv = heap.allocate("LFoo;")
    state = VMState(registers=RegisterFile(4), pc=0)
    state.registers.set(0, value)  # value
    state.registers.set(1, recv)  # receiver
    table[put_op](_insn(["v0", "v1"], param=sig), state)
    table[get_op](_insn(["v2", "v1"], param=sig), state)
    return state.registers.get(2)


class TestTypedArrayWidths:
    def test_byte_sign_extends(self):
        assert _array_roundtrip("[B", "aput-byte", "aget-byte", 255) == -1

    def test_short_sign_extends(self):
        assert _array_roundtrip("[S", "aput-short", "aget-short", 0xFFFF) == -1

    def test_char_zero_extends(self):
        assert _array_roundtrip("[C", "aput-char", "aget-char", -1) == 65535

    def test_boolean_low_bit_set(self):
        # 3 & 1 == 1; also catches the "stored raw, read back as 3" bug.
        assert _array_roundtrip("[Z", "aput-boolean", "aget-boolean", 3) == 1

    def test_boolean_even_is_zero(self):
        # JVMS bastore: boolean narrows by AND with 1, so 2 -> 0.
        assert _array_roundtrip("[Z", "aput-boolean", "aget-boolean", 2) == 0

    def test_boolean_zero(self):
        assert _array_roundtrip("[Z", "aput-boolean", "aget-boolean", 0) == 0

    def test_plain_aget_roundtrips_unchanged(self):
        # Generic (untyped) aget/aput must not narrow.
        assert _array_roundtrip("[I", "aput", "aget", 0x1234_5678) == 0x1234_5678


class TestTypedInstanceFieldWidths:
    def test_byte_sign_extends(self):
        assert _ifield_roundtrip("iput-byte", "iget-byte", 255, "LFoo;->b:B") == -1

    def test_short_sign_extends(self):
        assert (
            _ifield_roundtrip("iput-short", "iget-short", 0xFFFF, "LFoo;->s:S") == -1
        )

    def test_char_zero_extends(self):
        assert (
            _ifield_roundtrip("iput-char", "iget-char", -1, "LFoo;->c:C") == 65535
        )

    def test_boolean_low_bit_set(self):
        assert _ifield_roundtrip("iput-boolean", "iget-boolean", 3, "LFoo;->z:Z") == 1

    def test_boolean_even_is_zero(self):
        assert _ifield_roundtrip("iput-boolean", "iget-boolean", 2, "LFoo;->z:Z") == 0

    def test_plain_iget_roundtrips_unchanged(self):
        assert (
            _ifield_roundtrip("iput", "iget", 0x1234_5678, "LFoo;->i:I")
            == 0x1234_5678
        )
