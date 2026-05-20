# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""Unit tests for vm/handlers/compare.py — cmp-long / cmpl-* / cmpg-*."""

from __future__ import annotations

from dextrace.vm.handlers import compare

from .conftest import double_bits, float_bits, make_insn, make_state


class TestCompareOps:
    def test_cmp_long_greater(self):
        state = make_state(size=6)
        state.registers.set_wide(1, 100)
        state.registers.set_wide(3, 50)
        compare.handle_cmp_long(make_insn(["v0", "v1", "v3"]), state)
        assert state.registers.get(0) == 1

    def test_cmp_long_less(self):
        state = make_state(size=6)
        state.registers.set_wide(1, 10)
        state.registers.set_wide(3, 20)
        compare.handle_cmp_long(make_insn(["v0", "v1", "v3"]), state)
        assert state.registers.get(0) == -1

    def test_cmp_long_equal(self):
        state = make_state(size=6)
        state.registers.set_wide(1, 42)
        state.registers.set_wide(3, 42)
        compare.handle_cmp_long(make_insn(["v0", "v1", "v3"]), state)
        assert state.registers.get(0) == 0

    def test_cmpl_float_greater(self):
        state = make_state(size=4)
        state.registers.set(1, float_bits(2.0))
        state.registers.set(2, float_bits(1.0))
        compare.handle_cmpl_float(make_insn(["v0", "v1", "v2"]), state)
        assert state.registers.get(0) == 1

    def test_cmpl_float_nan_gives_minus1(self):
        state = make_state(size=4)
        state.registers.set(1, float_bits(float("nan")))
        state.registers.set(2, float_bits(1.0))
        compare.handle_cmpl_float(make_insn(["v0", "v1", "v2"]), state)
        assert state.registers.get(0) == -1

    def test_cmpg_float_nan_gives_plus1(self):
        state = make_state(size=4)
        state.registers.set(1, float_bits(float("nan")))
        state.registers.set(2, float_bits(1.0))
        compare.handle_cmpg_float(make_insn(["v0", "v1", "v2"]), state)
        assert state.registers.get(0) == 1

    def test_cmpl_double_less(self):
        state = make_state(size=6)
        state.registers.set_wide(1, double_bits(1.0))
        state.registers.set_wide(3, double_bits(2.0))
        compare.handle_cmpl_double(make_insn(["v0", "v1", "v3"]), state)
        assert state.registers.get(0) == -1

    def test_cmpg_double_nan_gives_plus1(self):
        state = make_state(size=6)
        state.registers.set_wide(1, double_bits(float("nan")))
        state.registers.set_wide(3, double_bits(0.0))
        compare.handle_cmpg_double(make_insn(["v0", "v1", "v3"]), state)
        assert state.registers.get(0) == 1

    def test_cmpl_double_nan_gives_minus1(self):
        state = make_state(size=6)
        state.registers.set_wide(1, double_bits(float("nan")))
        state.registers.set_wide(3, double_bits(0.0))
        compare.handle_cmpl_double(make_insn(["v0", "v1", "v3"]), state)
        assert state.registers.get(0) == -1
