# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


import pytest

from dextrace.dalvik.operand_decoder import decode_by_format


def _mk_read_u16(units):
    def read_u16(uoff: int) -> int:
        return units[uoff]

    return read_u16


def _w0(op=0x00, high8=0x00):
    return ((high8 & 0xFF) << 8) | (op & 0xFF)


# -------------------------
# common formats
# -------------------------


def test_decode_10x():
    units = [_w0()]
    ins = decode_by_format("10x", 0, _mk_read_u16(units))
    assert ins.regs == []
    assert (
        ins.index is None and ins.literal is None and ins.target_uoff is None
    )


def test_decode_11x():
    # op vAA, AA in high8
    units = [_w0(high8=0x7F)]
    ins = decode_by_format("11x", 0, _mk_read_u16(units))
    assert ins.regs == ["v127"]


def test_decode_12x_low_high_nibbles():
    # YOUR impl: A=low nibble, B=high nibble of high8
    # hi = (B<<4)|A
    A, B = 0x3, 0xA
    units = [_w0(high8=((B << 4) | A))]
    ins = decode_by_format("12x", 0, _mk_read_u16(units))
    assert ins.regs == ["v3", "v10"]


def test_decode_22x():
    units = [_w0(high8=0x11), 0x0203]
    ins = decode_by_format("22x", 0, _mk_read_u16(units))
    assert ins.regs == ["v17", "v515"]


def test_decode_32x():
    units = [_w0(), 0x0123, 0xABCD]
    ins = decode_by_format("32x", 0, _mk_read_u16(units))
    assert ins.regs == ["v291", "v43981"]


def test_decode_11n_signed4():
    # YOUR impl: A=low nibble, B=high nibble
    # choose A=2, B=0xF => -1
    A, B = 0x2, 0xF
    units = [_w0(high8=((B << 4) | A))]
    ins = decode_by_format("11n", 0, _mk_read_u16(units))
    assert ins.regs == ["v2"]
    assert ins.literal == -1


def test_decode_21s_signed16():
    units = [_w0(high8=0x02), 0xFFFE]  # -2
    ins = decode_by_format("21s", 0, _mk_read_u16(units))
    assert ins.regs == ["v2"]
    assert ins.literal == -2


def test_decode_31i_signed32():
    units = [_w0(high8=0x01), 0xFFFF, 0xFFFF]  # -1
    ins = decode_by_format("31i", 0, _mk_read_u16(units))
    assert ins.regs == ["v1"]
    assert ins.literal == -1


def test_decode_21c_index16():
    units = [_w0(high8=0x03), 0x1337]
    ins = decode_by_format("21c", 0, _mk_read_u16(units))
    assert ins.regs == ["v3"]
    assert ins.index == 0x1337


def test_decode_31c_index32():
    units = [_w0(high8=0x03), 0x5678, 0x1234]  # 0x12345678
    ins = decode_by_format("31c", 0, _mk_read_u16(units))
    assert ins.regs == ["v3"]
    assert ins.index == 0x12345678


def test_decode_22c_low_high_nibbles():
    # YOUR impl: A=low nibble, B=high nibble
    A, B = 0x4, 0x9
    units = [_w0(high8=((B << 4) | A)), 0xBEEF]
    ins = decode_by_format("22c", 0, _mk_read_u16(units))
    assert ins.regs == ["v4", "v9"]
    assert ins.index == 0xBEEF


def test_decode_23x():
    units = [_w0(high8=0x05), 0x0709]  # bb=0x09, cc=0x07
    ins = decode_by_format("23x", 0, _mk_read_u16(units))
    assert ins.regs == ["v5", "v9", "v7"]


# -------------------------
# literals / const extensions
# -------------------------


def test_decode_22b_signed8():
    # w1 low8=BB, high8=CC
    units = [_w0(high8=0x01), 0x80_02]  # BB=2, CC=0x80 => -128
    ins = decode_by_format("22b", 0, _mk_read_u16(units))
    assert ins.regs == ["v1", "v2"]
    assert ins.literal == -128


def test_decode_22s_signed16_low_high_nibbles():
    # YOUR impl: A=low nibble, B=high nibble
    A, B = 0x1, 0x2
    units = [_w0(high8=((B << 4) | A)), 0x8000]  # -32768
    ins = decode_by_format("22s", 0, _mk_read_u16(units))
    assert ins.regs == ["v1", "v2"]
    assert ins.literal == -32768


def test_decode_21h_high16_best_effort():
    units = [_w0(high8=0x01), 0x1234]
    ins = decode_by_format("21h", 0, _mk_read_u16(units))
    assert ins.regs == ["v1"]
    assert ins.literal == 0x12340000


def test_decode_51l_signed64_minus1():
    units = [_w0(high8=0x01), 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF]
    ins = decode_by_format("51l", 0, _mk_read_u16(units))
    assert ins.regs == ["v1"]
    assert ins.literal == -1


# -------------------------
# control-flow targets
# -------------------------


def test_decode_10t_target():
    # uoff=10, off=-2 => target=8
    units = [0] * 11
    units[10] = _w0(high8=0xFE)  # -2
    ins = decode_by_format("10t", 10, _mk_read_u16(units))
    assert ins.regs == []
    assert ins.target_uoff == 8


def test_decode_20t_target():
    # uoff=10, off=+3 => target=13
    units = [0] * 12
    units[10] = _w0()
    units[11] = 0x0003
    ins = decode_by_format("20t", 10, _mk_read_u16(units))
    assert ins.target_uoff == 13


def test_decode_30t_target():
    # uoff=10, off=-1
    units = [0] * 13
    units[10] = _w0()
    units[11] = 0xFFFF
    units[12] = 0xFFFF
    ins = decode_by_format("30t", 10, _mk_read_u16(units))
    assert ins.target_uoff == 9


def test_decode_21t_target_with_reg():
    # uoff=10, AA=2, off=+4 => target=14
    units = [0] * 12
    units[10] = _w0(high8=0x02)
    units[11] = 0x0004
    ins = decode_by_format("21t", 10, _mk_read_u16(units))
    assert ins.regs == ["v2"]
    assert ins.target_uoff == 14


def test_decode_22t_target_with_regs_low_high_nibbles():
    # YOUR impl: A=low nibble, B=high nibble
    # uoff=10, A=1,B=2 => hi=(B<<4)|A=0x21, off=-3 => target=7
    units = [0] * 12
    units[10] = _w0(high8=0x21)
    units[11] = 0xFFFD
    ins = decode_by_format("22t", 10, _mk_read_u16(units))
    assert ins.regs == ["v1", "v2"]
    assert ins.target_uoff == 7


def test_decode_31t_target_with_reg():
    # uoff=10, AA=1, off=+2 => target=12
    units = [0] * 13
    units[10] = _w0(high8=0x01)
    units[11] = 0x0002
    units[12] = 0x0000
    ins = decode_by_format("31t", 10, _mk_read_u16(units))
    assert ins.regs == ["v1"]
    assert ins.target_uoff == 12


# -------------------------
# invoke-kind
# -------------------------


def test_decode_35c_ag_nibbles_high_low():
    # YOUR impl:
    # w0 high8: A=HIGH nibble (arg count), G=LOW nibble (5th reg)
    # w2 nibbles: C(low) D E F(high)
    A = 3
    G = 9
    C, D, E, F = 1, 2, 3, 4
    w0 = _w0(high8=((A << 4) | G))
    w1 = 0x1337
    w2 = (C & 0xF) | ((D & 0xF) << 4) | ((E & 0xF) << 8) | ((F & 0xF) << 12)
    ins = decode_by_format("35c", 0, _mk_read_u16([w0, w1, w2]))
    assert ins.index == 0x1337
    assert ins.regs == ["v1", "v2", "v3"]


def test_decode_3rc_invoke_range():
    units = [_w0(high8=0x04), 0x2000, 0x0010]  # count=4, start=v16
    ins = decode_by_format("3rc", 0, _mk_read_u16(units))
    assert ins.index == 0x2000
    assert ins.regs == ["v16", "v17", "v18", "v19"]
