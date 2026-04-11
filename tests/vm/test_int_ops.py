# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

from dextrace.vm.int_ops import i32, u32, reg_index


class TestI32:
    def test_zero(self):
        assert i32(0) == 0

    def test_positive_in_range(self):
        assert i32(42) == 42
        assert i32(0x7FFF_FFFF) == 0x7FFF_FFFF

    def test_i32_boundaries(self):
        # 0x80000000 wraps to -2147483648
        assert i32(0x8000_0000) == -2_147_483_648
        # 0xFFFFFFFF wraps to -1
        assert i32(0xFFFF_FFFF) == -1

    def test_large_positive_wraps(self):
        # 0x1_0000_0000 = 2^32 -> wraps to 0
        assert i32(0x1_0000_0000) == 0

    def test_negative_python_int_stays_signed(self):
        # Already-negative ints: mask then sign-extend
        assert i32(-1) == -1
        assert i32(-2_147_483_648) == -2_147_483_648

    def test_add_overflow(self):
        # 0x7FFFFFFF + 1 = 0x80000000 = -2147483648
        assert i32(0x7FFF_FFFF + 1) == -2_147_483_648


class TestU32:
    def test_zero(self):
        assert u32(0) == 0

    def test_positive(self):
        assert u32(42) == 42

    def test_u32(self):
        assert u32(0xFFFF_FFFF) == 0xFFFF_FFFF
        assert u32(0x1_0000_0000) == 0  # strips high bits

    def test_negative_python_becomes_unsigned(self):
        assert u32(-1) == 0xFFFF_FFFF
        assert u32(-2_147_483_648) == 0x8000_0000


class TestRegIndex:
    def test_v0(self):
        assert reg_index("v0") == 0

    def test_v12(self):
        assert reg_index("v12") == 12

    def test_v255(self):
        assert reg_index("v255") == 255
