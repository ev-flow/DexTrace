# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""Unit tests for vm/handlers/type_conv.py — int↔long/float/double conversions."""

from __future__ import annotations

import struct

from dextrace.vm.handlers import type_conv

from .conftest import double_bits, float_bits, make_insn, make_state


class TestTypeConv:
    def test_int_to_byte_positive(self):
        state = make_state(0, 0x12F)  # 303 → byte = 0x2F = 47
        type_conv.handle_int_to_byte(make_insn(["v0", "v1"]), state)
        assert state.registers.get(0) == 47

    def test_int_to_byte_negative(self):
        state = make_state(0, 0xFF)  # 255 → signed byte = -1
        type_conv.handle_int_to_byte(make_insn(["v0", "v1"]), state)
        assert state.registers.get(0) == -1

    def test_int_to_char(self):
        state = make_state(0, 0x1_0041)  # 'A' = 0x41 after masking 16 bits
        type_conv.handle_int_to_char(make_insn(["v0", "v1"]), state)
        assert state.registers.get(0) == 0x41

    def test_int_to_short_positive(self):
        state = make_state(0, 0x7FFF)
        type_conv.handle_int_to_short(make_insn(["v0", "v1"]), state)
        assert state.registers.get(0) == 0x7FFF

    def test_int_to_short_negative(self):
        state = make_state(0, 0x8000)  # → -32768
        type_conv.handle_int_to_short(make_insn(["v0", "v1"]), state)
        assert state.registers.get(0) == -32768

    def test_int_to_long(self):
        state = make_state(0, -1, size=4)
        type_conv.handle_int_to_long(make_insn(["v0", "v1"]), state)
        # -1 sign-extended to 64-bit stored as unsigned = 0xFFFF_FFFF_FFFF_FFFF
        wide = state.registers.get_wide(0)
        assert wide == 0xFFFF_FFFF_FFFF_FFFF

    def test_long_to_int(self):
        state = make_state(size=4)
        state.registers.set_wide(1, 0x1_0000_0042)
        type_conv.handle_long_to_int(make_insn(["v0", "v1"]), state)
        assert state.registers.get(0) == 0x42

    def test_int_to_float(self):
        state = make_state(0, 3)
        type_conv.handle_int_to_float(make_insn(["v0", "v1"]), state)
        bits = state.registers.get(0)
        val = struct.unpack(">f", struct.pack(">I", bits & 0xFFFF_FFFF))[0]
        assert abs(val - 3.0) < 1e-6

    def test_float_to_int(self):
        state = make_state(0, float_bits(3.9))
        type_conv.handle_float_to_int(make_insn(["v0", "v1"]), state)
        assert state.registers.get(0) == 3  # truncate toward zero

    def test_int_to_double(self):
        state = make_state(0, 7, size=4)
        type_conv.handle_int_to_double(make_insn(["v0", "v1"]), state)
        bits = state.registers.get_wide(0)
        val = struct.unpack(">d", struct.pack(">Q", bits))[0]
        assert abs(val - 7.0) < 1e-10

    def test_double_to_int(self):
        state = make_state(size=4)
        state.registers.set_wide(1, double_bits(-2.9))
        type_conv.handle_double_to_int(make_insn(["v0", "v1"]), state)
        assert state.registers.get(0) == -2  # truncate toward zero

    def test_long_to_float(self):
        state = make_state(size=4)
        state.registers.set_wide(1, 1000)
        type_conv.handle_long_to_float(make_insn(["v0", "v1"]), state)
        bits = state.registers.get(0)
        val = struct.unpack(">f", struct.pack(">I", bits & 0xFFFF_FFFF))[0]
        assert abs(val - 1000.0) < 1.0

    def test_float_to_long(self):
        state = make_state(0, float_bits(1e6))
        type_conv.handle_float_to_long(make_insn(["v0", "v1"]), state)
        wide = state.registers.get_wide(0)
        assert wide == 1_000_000

    def test_long_to_double(self):
        state = make_state(size=4)
        state.registers.set_wide(1, 12345)
        type_conv.handle_long_to_double(make_insn(["v0", "v1"]), state)
        bits = state.registers.get_wide(0)
        val = struct.unpack(">d", struct.pack(">Q", bits))[0]
        assert abs(val - 12345.0) < 1e-6

    def test_double_to_long(self):
        state = make_state(size=4)
        state.registers.set_wide(1, double_bits(9.9))
        type_conv.handle_double_to_long(make_insn(["v0", "v1"]), state)
        wide = state.registers.get_wide(0)
        assert wide == 9  # truncate toward zero

    def test_float_to_double(self):
        state = make_state(0, float_bits(1.5), size=4)
        type_conv.handle_float_to_double(make_insn(["v0", "v1"]), state)
        bits = state.registers.get_wide(0)
        val = struct.unpack(">d", struct.pack(">Q", bits))[0]
        assert abs(val - 1.5) < 1e-10

    def test_double_to_float(self):
        state = make_state(size=4)
        state.registers.set_wide(1, double_bits(2.5))
        type_conv.handle_double_to_float(make_insn(["v0", "v1"]), state)
        bits = state.registers.get(0)
        val = struct.unpack(">f", struct.pack(">I", bits & 0xFFFF_FFFF))[0]
        assert abs(val - 2.5) < 1e-6
