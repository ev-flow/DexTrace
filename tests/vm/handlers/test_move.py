# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""Unit tests for vm/handlers/move.py — move / const / move-result variants."""

from __future__ import annotations

import pytest

from dextrace.vm.errors import DexTraceVMError
from dextrace.vm.handlers import move

from .conftest import make_insn, make_state


class TestMoveHandlers:
    def test_nop(self):
        state = make_state(42)
        move.handle_nop(make_insn([]), state)
        assert state.registers.get(0) == 42  # unchanged

    def test_const(self):
        state = make_state(0)
        move.handle_const(make_insn(["v0"], param="99"), state)
        assert state.registers.get(0) == 99

    def test_const_high16(self):
        state = make_state(0)
        move.handle_const_high16(make_insn(["v0"], param="1"), state)
        assert state.registers.get(0) == 0x1_0000

    def test_const_wide16(self):
        state = make_state(0, 0, size=4)
        move.handle_const_wide16(make_insn(["v0"], param="7"), state)
        assert state.registers.get_wide(0) == 7

    def test_const_wide32(self):
        state = make_state(0, 0, size=4)
        move.handle_const_wide32(make_insn(["v0"], param="123456"), state)
        assert state.registers.get_wide(0) == 123456

    def test_const_wide(self):
        state = make_state(0, 0, size=4)
        move.handle_const_wide(make_insn(["v0"], param="1000000"), state)
        assert state.registers.get_wide(0) == 1_000_000

    def test_const_wide_high16(self):
        state = make_state(0, 0, size=4)
        move.handle_const_wide_high16(make_insn(["v0"], param="1"), state)
        assert state.registers.get_wide(0) == (1 << 48)

    def test_move_from16(self):
        state = make_state(0, 77)
        move.handle_move_from16(make_insn(["v0", "v1"]), state)
        assert state.registers.get(0) == 77

    def test_move_16(self):
        state = make_state(0, 55)
        move.handle_move_16(make_insn(["v0", "v1"]), state)
        assert state.registers.get(0) == 55

    def test_move_wide(self):
        state = make_state(0, 0, 0, 0, size=4)
        state.registers.set_wide(2, 0xDEAD_BEEF_1234_5678)
        move.handle_move_wide(make_insn(["v0", "v2"]), state)
        assert state.registers.get_wide(0) == 0xDEAD_BEEF_1234_5678

    def test_move_wide_from16(self):
        state = make_state(0, 0, 0, 0, size=4)
        state.registers.set_wide(2, 42)
        move.handle_move_wide_from16(make_insn(["v0", "v2"]), state)
        assert state.registers.get_wide(0) == 42

    def test_move_object(self):
        state = make_state(0, 33)
        move.handle_move_object(make_insn(["v0", "v1"]), state)
        assert state.registers.get(0) == 33

    def test_move_result_no_pending_raises(self):
        state = make_state(0)
        state.pending_result = None
        with pytest.raises(DexTraceVMError, match="no pending result"):
            move.handle_move_result(make_insn(["v0"]), state)

    def test_move_result_wide_not_wide_raises(self):
        state = make_state(0, 0, size=4)
        state.pending_result = 42
        state.pending_result_is_wide = False
        with pytest.raises(DexTraceVMError, match="not wide"):
            move.handle_move_result_wide(make_insn(["v0"]), state)

    def test_move_result_consumes_pending(self):
        state = make_state(0)
        state.pending_result = 99
        state.pending_result_is_wide = False
        move.handle_move_result(make_insn(["v0"]), state)
        assert state.registers.get(0) == 99
        assert state.pending_result is None

    def test_move_result_object_no_pending_raises(self):
        state = make_state(0)
        state.pending_result = None
        with pytest.raises(DexTraceVMError):
            move.handle_move_result_object(make_insn(["v0"]), state)

    def test_move_result_wide_consumes_pending(self):
        state = make_state(0, 0, size=4)
        state.pending_result = 0xDEAD_BEEF_CAFE_1234
        state.pending_result_is_wide = True
        move.handle_move_result_wide(make_insn(["v0"]), state)
        assert state.registers.get_wide(0) == 0xDEAD_BEEF_CAFE_1234
        assert state.pending_result is None
