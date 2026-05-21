# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

import pytest
from dextrace.vm.register_file import RegisterFile
from dextrace.vm.errors import DexTraceVMError


class TestRegisterFileBounds:
    def test_get_in_range(self):
        rf = RegisterFile(4)
        assert rf.get(0) == 0
        assert rf.get(3) == 0

    def test_set_get_roundtrip(self):
        rf = RegisterFile(4)
        rf.set(2, 42)
        assert rf.get(2) == 42

    def test_get_out_of_range_raises(self):
        rf = RegisterFile(4)
        with pytest.raises(DexTraceVMError):
            rf.get(4)

    def test_get_negative_raises(self):
        rf = RegisterFile(4)
        with pytest.raises(DexTraceVMError):
            rf.get(-1)

    def test_set_out_of_range_raises(self):
        rf = RegisterFile(4)
        with pytest.raises(DexTraceVMError):
            rf.set(4, 99)


class TestWideOperations:
    def test_wide_pair_ordering(self):
        """Low 32 bits in vN, high 32 bits in vN+1."""
        rf = RegisterFile(4)
        # Store 0xDEAD_BEEF_1234_5678
        rf.set_wide(0, 0xDEAD_BEEF_1234_5678)
        assert rf.get(0) == 0x1234_5678  # lo in v0
        assert rf.get(1) == 0xDEAD_BEEF  # hi in v1
        assert rf.get_wide(0) == 0xDEAD_BEEF_1234_5678

    def test_wide_zero(self):
        rf = RegisterFile(4)
        rf.set_wide(2, 0)
        assert rf.get_wide(2) == 0

    def test_wide_out_of_range_raises(self):
        rf = RegisterFile(3)
        with pytest.raises(DexTraceVMError):
            rf.set_wide(2, 123)  # would need v3 which doesn't exist


class TestSnapshot:
    def test_snapshot_isolation(self):
        """Mutating original after snapshot must not affect snapshot."""
        rf = RegisterFile(4)
        rf.set(0, 10)
        rf.set(1, 20)

        snap = rf.snapshot()
        assert snap.get(0) == 10
        assert snap.get(1) == 20

        rf.set(0, 999)  # mutate original
        assert snap.get(0) == 10  # snapshot unchanged

    def test_snapshot_does_not_alias(self):
        """Mutating snapshot must not affect original."""
        rf = RegisterFile(4)
        rf.set(0, 10)
        snap = rf.snapshot()
        snap.set(0, 999)
        assert rf.get(0) == 10

    def test_snapshot_same_size(self):
        rf = RegisterFile(8)
        snap = rf.snapshot()
        assert len(snap) == 8
