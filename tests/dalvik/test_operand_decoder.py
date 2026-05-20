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


# ---------------------------------------------------------------------------
# Generated vectors — exercise every supported format end-to-end via the
# AOSP opcode table (bytecode.txt → format → real opcode → synthetic units).
# ---------------------------------------------------------------------------

from typing import Callable, Dict, List

from dextrace.dalvik.bytecode_source import load_bytecode_lines
from dextrace.dalvik.opcode_table_builder import build_opcode_info_table


def _pick_opcode_for_format(fmt: str, fmt_to_opcode: Dict[str, int]) -> int:
    return int(fmt_to_opcode.get(fmt, 0)) & 0xFF


def _read_u16_from_units(units: List[int]) -> Callable[[int], int]:
    def read_u16(uoff: int) -> int:
        if uoff < 0 or uoff >= len(units):
            return 0
        return int(units[uoff]) & 0xFFFF

    return read_u16


# Minimal code-unit builders per format (only for formats we support).


def _units_10x(op):
    return [op]


def _units_11x(op, aa=1):
    return [op | ((aa & 0xFF) << 8)]


def _units_12x(op, a=1, b=2):
    hi = ((b & 0xF) << 4) | (a & 0xF)
    return [op | ((hi & 0xFF) << 8)]


def _units_22x(op, aa=1, bbbb=0x1234):
    return [op | ((aa & 0xFF) << 8), bbbb & 0xFFFF]


def _units_32x(op, aaaa=0x0001, bbbb=0x0002):
    return [op, aaaa & 0xFFFF, bbbb & 0xFFFF]


def _units_21s(op, aa=1, lit_s16=-2):
    return [op | ((aa & 0xFF) << 8), lit_s16 & 0xFFFF]


def _units_31i(op, aa=1, lit_s32=-3):
    v = lit_s32 & 0xFFFFFFFF
    return [op | ((aa & 0xFF) << 8), v & 0xFFFF, (v >> 16) & 0xFFFF]


def _units_11n(op, a=1, b_s4=-1):
    b = (b_s4 + 16) & 0xF if b_s4 < 0 else (b_s4 & 0xF)
    hi = ((b & 0xF) << 4) | (a & 0xF)
    return [op | ((hi & 0xFF) << 8)]


def _units_21c(op, aa=1, idx=0x0001):
    return [op | ((aa & 0xFF) << 8), idx & 0xFFFF]


def _units_31c(op, aa=1, idx=0x00010002):
    return [op | ((aa & 0xFF) << 8), idx & 0xFFFF, (idx >> 16) & 0xFFFF]


def _units_22c(op, a=1, b=2, idx=0x0001):
    hi = ((b & 0xF) << 4) | (a & 0xF)
    return [op | ((hi & 0xFF) << 8), idx & 0xFFFF]


def _units_23x(op, aa=1, bb=2, cc=3):
    w0 = op | ((aa & 0xFF) << 8)
    w1 = (bb & 0xFF) | ((cc & 0xFF) << 8)
    return [w0, w1]


def _units_22b(op, aa=1, bb=2, cc_s8=-4):
    w0 = op | ((aa & 0xFF) << 8)
    cc = cc_s8 & 0xFF
    w1 = (bb & 0xFF) | ((cc & 0xFF) << 8)
    return [w0, w1]


def _units_22s(op, a=1, b=2, lit_s16=-5):
    hi = ((b & 0xF) << 4) | (a & 0xF)
    return [op | ((hi & 0xFF) << 8), lit_s16 & 0xFFFF]


def _units_21h(op, aa=1, bbbb=0x1234):
    return [op | ((aa & 0xFF) << 8), bbbb & 0xFFFF]


def _units_51l(op, aa=1, lit_s64=-1):
    v = lit_s64 & 0xFFFFFFFFFFFFFFFF
    return [
        op | ((aa & 0xFF) << 8),
        v & 0xFFFF,
        (v >> 16) & 0xFFFF,
        (v >> 32) & 0xFFFF,
        (v >> 48) & 0xFFFF,
    ]


def _units_10t(op, off_s8=1):
    return [op | ((off_s8 & 0xFF) << 8)]


def _units_20t(op, off_s16=2):
    return [op, off_s16 & 0xFFFF]


def _units_30t(op, off_s32=3):
    v = off_s32 & 0xFFFFFFFF
    return [op, v & 0xFFFF, (v >> 16) & 0xFFFF]


def _units_21t(op, aa=1, off_s16=4):
    return [op | ((aa & 0xFF) << 8), off_s16 & 0xFFFF]


def _units_22t(op, a=1, b=2, off_s16=5):
    hi = ((b & 0xF) << 4) | (a & 0xF)
    return [op | ((hi & 0xFF) << 8), off_s16 & 0xFFFF]


def _units_31t(op, aa=1, off_s32=6):
    v = off_s32 & 0xFFFFFFFF
    return [op | ((aa & 0xFF) << 8), v & 0xFFFF, (v >> 16) & 0xFFFF]


def _units_35c(op, method_idx=1):
    A, G = 2, 0
    ag = ((A & 0xF) << 4) | (G & 0xF)
    w0 = op | ((ag & 0xFF) << 8)
    w1 = method_idx & 0xFFFF
    C, D, E, F = 2, 1, 0, 0
    w2 = (C & 0xF) | ((D & 0xF) << 4) | ((E & 0xF) << 8) | ((F & 0xF) << 12)
    return [w0, w1, w2]


def _units_3rc(op, method_idx=1):
    aa = 2
    cccc = 3
    return [op | ((aa & 0xFF) << 8), method_idx & 0xFFFF, cccc & 0xFFFF]


_FMT_BUILDERS = {
    "10x": _units_10x,
    "11x": _units_11x,
    "12x": _units_12x,
    "22x": _units_22x,
    "32x": _units_32x,
    "21s": _units_21s,
    "31i": _units_31i,
    "11n": _units_11n,
    "21c": _units_21c,
    "31c": _units_31c,
    "22c": _units_22c,
    "23x": _units_23x,
    "22b": _units_22b,
    "22s": _units_22s,
    "21h": _units_21h,
    "51l": _units_51l,
    "10t": _units_10t,
    "20t": _units_20t,
    "30t": _units_30t,
    "21t": _units_21t,
    "22t": _units_22t,
    "31t": _units_31t,
    "35c": _units_35c,
    "3rc": _units_3rc,
}


def test_generated_vectors_decode_supported_formats():
    info = build_opcode_info_table(load_bytecode_lines())
    fmt_to_opcode: Dict[str, int] = {}
    for op, oi in info.items():
        if oi.fmt and oi.fmt not in fmt_to_opcode:
            fmt_to_opcode[oi.fmt] = op

    supported = sorted(_FMT_BUILDERS.keys())
    assert supported, "No format builders? test is useless."

    for fmt in supported:
        op = _pick_opcode_for_format(fmt, fmt_to_opcode)
        units = _FMT_BUILDERS[fmt](op)
        ops = decode_by_format(fmt=fmt, uoff=0, read_u16=_read_u16_from_units(units))
        assert ops is not None, f"format {fmt} should be decodable but got None"
        for r in ops.regs:
            assert r.startswith("v")


def test_generated_vectors_specific_expectations_for_35c_and_3rc():
    op = 0x6E  # invoke-virtual in AOSP
    units = _units_35c(op, method_idx=1)
    ops = decode_by_format("35c", 0, _read_u16_from_units(units))
    assert ops is not None
    assert ops.regs[:2] == ["v2", "v1"]
    assert ops.index == 1

    op = 0x74  # invoke-virtual/range in AOSP
    units = _units_3rc(op, method_idx=2)
    ops = decode_by_format("3rc", 0, _read_u16_from_units(units))
    assert ops is not None
    assert ops.regs == ["v3", "v4"]
    assert ops.index == 2
