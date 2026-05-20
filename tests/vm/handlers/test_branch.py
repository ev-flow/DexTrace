# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""Unit tests for vm/handlers/branch.py — conditional + unconditional branches.

Note: packed-switch / sparse-switch are dispatched inline by the engine
(not via the eval table), so their coverage lives in
tests/dalvik/test_payload.py (decoder) and tests/integrations/
test_vm_run_packed_switch.py (end-to-end).
"""

from __future__ import annotations

from dextrace.vm.handlers import branch

from .conftest import make_insn, make_state


class TestBranchConditionals:
    TARGET = 20

    def _branch_insn(self, regs, uoff=0):
        return make_insn(regs, uoff=uoff, target_uoff=self.TARGET)

    def test_if_eq_taken(self):
        state = make_state(5, 5)
        branch.handle_if_eq(self._branch_insn(["v0", "v1"]), state)
        assert state.pc == self.TARGET

    def test_if_eq_not_taken(self):
        state = make_state(5, 6)
        state.pc = 0
        branch.handle_if_eq(self._branch_insn(["v0", "v1"], uoff=0), state)
        # engine will advance pc; handler left it unchanged
        assert state.pc == 0

    def test_if_ne_taken(self):
        state = make_state(1, 2)
        branch.handle_if_ne(self._branch_insn(["v0", "v1"]), state)
        assert state.pc == self.TARGET

    def test_if_lt_taken(self):
        state = make_state(1, 2)
        branch.handle_if_lt(self._branch_insn(["v0", "v1"]), state)
        assert state.pc == self.TARGET

    def test_if_lt_not_taken_equal(self):
        state = make_state(2, 2)
        state.pc = 0
        branch.handle_if_lt(self._branch_insn(["v0", "v1"], uoff=0), state)
        assert state.pc == 0

    def test_if_ge_taken(self):
        state = make_state(3, 3)
        branch.handle_if_ge(self._branch_insn(["v0", "v1"]), state)
        assert state.pc == self.TARGET

    def test_if_gt_taken(self):
        state = make_state(5, 3)
        branch.handle_if_gt(self._branch_insn(["v0", "v1"]), state)
        assert state.pc == self.TARGET

    def test_if_le_taken(self):
        state = make_state(3, 3)
        branch.handle_if_le(self._branch_insn(["v0", "v1"]), state)
        assert state.pc == self.TARGET

    def test_if_eqz_taken(self):
        state = make_state(0)
        branch.handle_if_eqz(self._branch_insn(["v0"]), state)
        assert state.pc == self.TARGET

    def test_if_nez_taken(self):
        state = make_state(7)
        branch.handle_if_nez(self._branch_insn(["v0"]), state)
        assert state.pc == self.TARGET

    def test_if_ltz_taken(self):
        state = make_state(-1)
        branch.handle_if_ltz(self._branch_insn(["v0"]), state)
        assert state.pc == self.TARGET

    def test_if_gez_taken(self):
        state = make_state(0)
        branch.handle_if_gez(self._branch_insn(["v0"]), state)
        assert state.pc == self.TARGET

    def test_if_gtz_taken(self):
        state = make_state(1)
        branch.handle_if_gtz(self._branch_insn(["v0"]), state)
        assert state.pc == self.TARGET

    def test_if_lez_taken(self):
        state = make_state(0)
        branch.handle_if_lez(self._branch_insn(["v0"]), state)
        assert state.pc == self.TARGET

    def test_goto(self):
        state = make_state(0)
        branch.handle_goto(self._branch_insn([]), state)
        assert state.pc == self.TARGET

    def test_goto_16(self):
        state = make_state(0)
        branch.handle_goto_16(self._branch_insn([]), state)
        assert state.pc == self.TARGET

    def test_goto_32(self):
        state = make_state(0)
        branch.handle_goto_32(self._branch_insn([]), state)
        assert state.pc == self.TARGET
