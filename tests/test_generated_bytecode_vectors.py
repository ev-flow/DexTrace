# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from __future__ import annotations

from typing import Callable, Dict, List

from dextrace.dalvik.bytecode_source import load_bytecode_lines
from dextrace.dalvik.opcode_table_builder import build_opcode_info_table
from dextrace.dalvik.operand_decoder import decode_by_format


def _pick_opcode_for_format(fmt: str, fmt_to_opcode: Dict[str, int]) -> int:
    # Prefer real opcode from AOSP table; fallback to 0 if missing.
    return int(fmt_to_opcode.get(fmt, 0)) & 0xFF


def _read_u16_from_units(units: List[int]) -> Callable[[int], int]:
    def read_u16(uoff: int) -> int:
        if uoff < 0 or uoff >= len(units):
            return 0
        return int(units[uoff]) & 0xFFFF

    return read_u16


# ---- Minimal code-unit builders per format (only for formats you support) ----
def _units_10x(op: int) -> List[int]:
    return [op]  # w0: opcode only


def _units_11x(op: int, aa: int = 1) -> List[int]:
    return [op | ((aa & 0xFF) << 8)]


def _units_12x(op: int, a: int = 1, b: int = 2) -> List[int]:
    # high8: A=low nibble, B=high nibble
    hi = ((b & 0xF) << 4) | (a & 0xF)
    return [op | ((hi & 0xFF) << 8)]


def _units_22x(op: int, aa: int = 1, bbbb: int = 0x1234) -> List[int]:
    return [op | ((aa & 0xFF) << 8), bbbb & 0xFFFF]


def _units_32x(op: int, aaaa: int = 0x0001, bbbb: int = 0x0002) -> List[int]:
    return [op, aaaa & 0xFFFF, bbbb & 0xFFFF]


def _units_21s(op: int, aa: int = 1, lit_s16: int = -2) -> List[int]:
    return [op | ((aa & 0xFF) << 8), lit_s16 & 0xFFFF]


def _units_31i(op: int, aa: int = 1, lit_s32: int = -3) -> List[int]:
    v = lit_s32 & 0xFFFFFFFF
    lo = v & 0xFFFF
    hi = (v >> 16) & 0xFFFF
    return [op | ((aa & 0xFF) << 8), lo, hi]


def _units_11n(op: int, a: int = 1, b_s4: int = -1) -> List[int]:
    # b is high nibble signed4
    b = (b_s4 + 16) & 0xF if b_s4 < 0 else (b_s4 & 0xF)
    hi = ((b & 0xF) << 4) | (a & 0xF)
    return [op | ((hi & 0xFF) << 8)]


def _units_21c(op: int, aa: int = 1, idx: int = 0x0001) -> List[int]:
    return [op | ((aa & 0xFF) << 8), idx & 0xFFFF]


def _units_31c(op: int, aa: int = 1, idx: int = 0x00010002) -> List[int]:
    lo = idx & 0xFFFF
    hi = (idx >> 16) & 0xFFFF
    return [op | ((aa & 0xFF) << 8), lo, hi]


def _units_22c(
    op: int, a: int = 1, b: int = 2, idx: int = 0x0001
) -> List[int]:
    hi = ((b & 0xF) << 4) | (a & 0xF)
    return [op | ((hi & 0xFF) << 8), idx & 0xFFFF]


def _units_23x(op: int, aa: int = 1, bb: int = 2, cc: int = 3) -> List[int]:
    w0 = op | ((aa & 0xFF) << 8)
    w1 = (bb & 0xFF) | ((cc & 0xFF) << 8)
    return [w0, w1]


def _units_22b(
    op: int, aa: int = 1, bb: int = 2, cc_s8: int = -4
) -> List[int]:
    w0 = op | ((aa & 0xFF) << 8)
    cc = cc_s8 & 0xFF
    w1 = (bb & 0xFF) | ((cc & 0xFF) << 8)
    return [w0, w1]


def _units_22s(
    op: int, a: int = 1, b: int = 2, lit_s16: int = -5
) -> List[int]:
    hi = ((b & 0xF) << 4) | (a & 0xF)
    return [op | ((hi & 0xFF) << 8), lit_s16 & 0xFFFF]


def _units_21h(op: int, aa: int = 1, bbbb: int = 0x1234) -> List[int]:
    return [op | ((aa & 0xFF) << 8), bbbb & 0xFFFF]


def _units_51l(op: int, aa: int = 1, lit_s64: int = -1) -> List[int]:
    v = lit_s64 & 0xFFFFFFFFFFFFFFFF
    w1 = v & 0xFFFF
    w2 = (v >> 16) & 0xFFFF
    w3 = (v >> 32) & 0xFFFF
    w4 = (v >> 48) & 0xFFFF
    return [op | ((aa & 0xFF) << 8), w1, w2, w3, w4]


def _units_10t(op: int, off_s8: int = 1) -> List[int]:
    # signed8 lives in high8 of w0
    return [op | ((off_s8 & 0xFF) << 8)]


def _units_20t(op: int, off_s16: int = 2) -> List[int]:
    return [op, off_s16 & 0xFFFF]


def _units_30t(op: int, off_s32: int = 3) -> List[int]:
    v = off_s32 & 0xFFFFFFFF
    return [op, v & 0xFFFF, (v >> 16) & 0xFFFF]


def _units_21t(op: int, aa: int = 1, off_s16: int = 4) -> List[int]:
    return [op | ((aa & 0xFF) << 8), off_s16 & 0xFFFF]


def _units_22t(op: int, a: int = 1, b: int = 2, off_s16: int = 5) -> List[int]:
    hi = ((b & 0xF) << 4) | (a & 0xF)
    return [op | ((hi & 0xFF) << 8), off_s16 & 0xFFFF]


def _units_31t(op: int, aa: int = 1, off_s32: int = 6) -> List[int]:
    v = off_s32 & 0xFFFFFFFF
    return [op | ((aa & 0xFF) << 8), v & 0xFFFF, (v >> 16) & 0xFFFF]


def _units_35c(op: int, method_idx: int = 1) -> List[int]:
    # make A=2 args: {v2, v1}  -> C=2, D=1
    A = 2
    G = 0
    ag = ((A & 0xF) << 4) | (G & 0xF)
    w0 = op | ((ag & 0xFF) << 8)
    w1 = method_idx & 0xFFFF
    # w2 nibbles: C low, D, E, F high
    C, D, E, F = 2, 1, 0, 0
    w2 = (C & 0xF) | ((D & 0xF) << 4) | ((E & 0xF) << 8) | ((F & 0xF) << 12)
    return [w0, w1, w2]


def _units_3rc(op: int, method_idx: int = 1) -> List[int]:
    # range {v3..v4} count=2 start=3
    aa = 2
    cccc = 3
    w0 = op | ((aa & 0xFF) << 8)
    w1 = method_idx & 0xFFFF
    w2 = cccc & 0xFFFF
    return [w0, w1, w2]


# Update this map as you implement more formats.
FMT_BUILDERS = {
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
    # Build fmt->opcode from official table
    info = build_opcode_info_table(load_bytecode_lines())
    fmt_to_opcode: Dict[str, int] = {}
    for op, oi in info.items():
        # pick first opcode per format (skip optimized if you want)
        if oi.fmt and oi.fmt not in fmt_to_opcode:
            fmt_to_opcode[oi.fmt] = op

    supported = sorted(FMT_BUILDERS.keys())
    assert supported, "No format builders? test is useless."

    for fmt in supported:
        op = _pick_opcode_for_format(fmt, fmt_to_opcode)
        units = FMT_BUILDERS[fmt](op)

        read_u16 = _read_u16_from_units(units)
        ops = decode_by_format(fmt=fmt, uoff=0, read_u16=read_u16)

        assert (
            ops is not None
        ), f"format {fmt} should be decodable but got None"
        # basic sanity: regs strings begin with v
        for r in ops.regs:
            assert r.startswith("v")


def test_generated_vectors_specific_expectations_for_35c_and_3rc():
    # 35c expects {v2, v1}
    op = 0x6E  # invoke-virtual in AOSP, but any low8 works for decoder
    units = _units_35c(op, method_idx=1)
    ops = decode_by_format("35c", 0, _read_u16_from_units(units))
    assert ops is not None
    assert ops.regs[:2] == ["v2", "v1"]
    assert ops.index == 1

    # 3rc expects range v3..v4
    op = 0x74  # invoke-virtual/range in AOSP
    units = _units_3rc(op, method_idx=2)
    ops = decode_by_format("3rc", 0, _read_u16_from_units(units))
    assert ops is not None
    assert ops.regs == ["v3", "v4"]
    assert ops.index == 2
