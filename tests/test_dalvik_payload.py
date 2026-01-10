# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


import struct
from dextrace.dalvik.payload import payload_size_units
from dextrace.core.dex_parser import DexCode


def test_packed_switch_payload_units():
    # packed-switch payload with size=2
    # ident=0x0100, size=2, first_key (2 units), targets[2] (4 units)
    # total units = 4 + 2*2 = 8
    units = [
        0x0100, 0x0002,
        0x0000, 0x0000,  # first_key = 0
        0x0001, 0x0000,  # target0 = 1
        0x0002, 0x0000,  # target1 = 2
    ]
    insns = struct.pack("<" + "H"*len(units), *units)
    code = DexCode(0,0,0,0,0,len(units), insns)

    def r16(i): return units[i]
    def r32(i):
        # read from units
        b = insns[i*2:i*2+4]
        return struct.unpack("<I", b)[0]

    p = payload_size_units(0, r16, r32, len(units))
    assert p is not None
    assert p.size_units == 8


def test_fill_array_data_payload_units():
    # fill-array-data payload: ident=0x0300, elem_width=1, size=3 => 3 bytes data => ceil(3/2)=2 units
    # total units = 4 + 2 = 6
    units = [
        0x0300, 0x0001,
        0x0003, 0x0000,  # size u32 = 3
        0x1122,          # data bytes: 0x22 0x11
        0x0033,          # data bytes: 0x33 0x00 (padding)
    ]
    insns = struct.pack("<" + "H"*len(units), *units)
    code = DexCode(0,0,0,0,0,len(units), insns)

    def r16(i): return units[i]
    def r32(i):
        b = insns[i*2:i*2+4]
        return struct.unpack("<I", b)[0]

    p = payload_size_units(0, r16, r32, len(units))
    assert p is not None
    assert p.size_units == 6
