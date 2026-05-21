#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pylint: disable=duplicate-code  # fixture scripts share DEX builder boilerplate intentionally
"""
Build tests/fixtures/samples/packed_switch.dex programmatically.

Method:
  LPackedSwitchTest;->switchCast(I)I  (static)
    switch (n) {
      case 0: return 100;
      case 1: return 150;
      case 2: return 200;
      case 3: return 250;
      default: return -1;
    }

Verification:
  dextrace run tests/fixtures/samples/packed_switch.dex \\
      --entry 'LPackedSwitchTest;->switchCast(I)I' --arg 2
  # -> return: 200
"""

import hashlib
import struct
import zlib
from pathlib import Path


def _uleb128(n: int) -> bytes:
    buf = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            buf.append(b | 0x80)
        else:
            buf.append(b)
            break
    return bytes(buf)


def _align4(off: int) -> int:
    return (off + 3) & ~3


def _string_data_item(s: str) -> bytes:
    b = s.encode("utf-8")
    return _uleb128(len(s)) + b + b"\x00"


def build_packed_switch_dex() -> bytes:  # pylint: disable=too-many-locals,too-many-statements
    # Strings sorted by MUTF-8 (prefix-shorter comes first).
    strings = [
        "I",                  # 0
        "II",                 # 1 — shorty for (I)I
        "Ljava/lang/Object;", # 2
        "LPackedSwitchTest;",              # 3
        "switchCast",         # 4
    ]
    type_string_ids = [0, 2, 3]  # type 0=I, 1=Object, 2=LPackedSwitchTest;
    protos = [(1, 0)]  # proto 0: shorty=str1 "II", return=type0 "I"
    method_ids = [(2, 0, 4)]  # LPackedSwitchTest;->switchCast(I)I

    # Insns (30 code units total):
    #
    # pc layout (each digit = 1 code unit):
    #   00-02  packed-switch v1, +0x12       (31t, 3 units) — payload at uoff 0x12
    #   03     const/4 v0, #-1               (11n, 1 unit)  — default
    #   04     return v0                     (11x, 1 unit)
    #   05-06  const/16 v0, #100             (21s, 2 units) — case 0
    #   07     return v0
    #   08-09  const/16 v0, #150             — case 1
    #   0a     return v0
    #   0b-0c  const/16 v0, #200             — case 2
    #   0d     return v0
    #   0e-0f  const/16 v0, #250             — case 3
    #   10     return v0
    #   11     nop                           (10x, 1 unit) — align next uoff to 4-byte
    #   12-1d  packed-switch-payload         (12 units = 24 bytes)
    #
    # Payload-target offsets are RELATIVE to the switch instruction's uoff (0).
    insns = [
        # packed-switch v1, +0x12
        0x012B, 0x0012, 0x0000,
        # default: const/4 v0, #-1; return v0
        0xF012, 0x000F,
        # case 0: const/16 v0, #100; return v0
        0x0013, 0x0064, 0x000F,
        # case 1: const/16 v0, #150
        0x0013, 0x0096, 0x000F,
        # case 2: const/16 v0, #200
        0x0013, 0x00C8, 0x000F,
        # case 3: const/16 v0, #250
        0x0013, 0x00FA, 0x000F,
        # alignment pad (uoff 0x11 is odd; payload must start at even uoff)
        0x0000,
        # packed-switch-payload @ uoff 0x12
        #   u16 ident = 0x0100
        #   u16 size  = 4
        #   s32 first_key = 0
        #   s32 targets[4] = [5, 8, 0xb, 0xe]
        0x0100, 0x0004,
        0x0000, 0x0000,    # first_key = 0 (s32 little-endian = 2 u16)
        0x0005, 0x0000,    # target[0] = 5  → case 0 body
        0x0008, 0x0000,    # target[1] = 8
        0x000B, 0x0000,    # target[2] = 0xb
        0x000E, 0x0000,    # target[3] = 0xe
    ]
    assert len(insns) == 30, f"expected 30 code units, got {len(insns)}"

    # Layout
    header_size = 0x70
    off = header_size

    string_ids_off = off
    off += len(strings) * 4

    type_ids_off = off
    off += len(type_string_ids) * 4

    proto_ids_off = off
    off += len(protos) * 12

    method_ids_off = off
    off += len(method_ids) * 8

    class_defs_off = off
    off += 1 * 32

    data_off = _align4(off)

    data = bytearray()
    string_data_offs: list[int] = []
    for s in strings:
        string_data_offs.append(data_off + len(data))
        data.extend(_string_data_item(s))

    while (data_off + len(data)) % 4 != 0:
        data.append(0)

    # type_list for proto 0's params = (I): u4 size + u2 list[size] (+ pad)
    type_list_off = data_off + len(data)
    data.extend(struct.pack("<IHH", 1, 0, 0))  # 1 entry: type_idx=0 (I)

    while (data_off + len(data)) % 4 != 0:
        data.append(0)

    code_off = data_off + len(data)
    # regs=2 (v0=result, v1=param), ins=1, outs=0, tries=0, insns_size=30
    data.extend(struct.pack("<HHHHII", 2, 1, 0, 0, 0, len(insns)))
    data.extend(struct.pack("<" + "H" * len(insns), *insns))

    ACC_PUBLIC = 0x1
    ACC_STATIC = 0x8
    class_data_off = data_off + len(data)
    data.extend(
        _uleb128(0)
        + _uleb128(0)
        + _uleb128(1)
        + _uleb128(0)
        + _uleb128(0)
        + _uleb128(ACC_PUBLIC | ACC_STATIC)
        + _uleb128(code_off)
    )

    while (data_off + len(data)) % 4 != 0:
        data.append(0)

    map_off = data_off + len(data)

    def _map_item(type_code, count, offset):
        return struct.pack("<HHII", type_code, 0, count, offset)

    map_items = [
        _map_item(0x0000, 1, 0),
        _map_item(0x0001, len(strings), string_ids_off),
        _map_item(0x0002, len(type_string_ids), type_ids_off),
        _map_item(0x0003, len(protos), proto_ids_off),
        _map_item(0x0005, len(method_ids), method_ids_off),
        _map_item(0x0006, 1, class_defs_off),
        _map_item(0x1001, 1, type_list_off),
        _map_item(0x2000, 1, class_data_off),
        _map_item(0x2001, 1, code_off),
        _map_item(0x2002, len(strings), string_data_offs[0]),
        _map_item(0x1000, 1, map_off),
    ]
    data.extend(struct.pack("<I", len(map_items)) + b"".join(map_items))

    data_size = len(data)
    file_size = data_off + data_size

    # ID sections
    string_id_items = b"".join(struct.pack("<I", o) for o in string_data_offs)
    type_id_items = b"".join(struct.pack("<I", idx) for idx in type_string_ids)
    proto_id_items = b"".join(
        struct.pack("<III", shorty_idx, return_type_idx, type_list_off)
        for shorty_idx, return_type_idx in protos
    )
    method_id_items = b"".join(
        struct.pack("<HHI", cls_idx, proto_idx, name_idx)
        for cls_idx, proto_idx, name_idx in method_ids
    )
    class_def_items = struct.pack(
        "<IIIIIIII",
        2, ACC_PUBLIC, 1, 0, 0xFFFFFFFF, 0, class_data_off, 0,
    )

    header = bytearray(header_size)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 32, file_size)
    struct.pack_into("<I", header, 36, header_size)
    struct.pack_into("<I", header, 40, 0x12345678)
    struct.pack_into("<I", header, 44, 0)
    struct.pack_into("<I", header, 48, 0)
    struct.pack_into("<I", header, 52, map_off)
    struct.pack_into("<I", header, 56, len(strings))
    struct.pack_into("<I", header, 60, string_ids_off)
    struct.pack_into("<I", header, 64, len(type_string_ids))
    struct.pack_into("<I", header, 68, type_ids_off)
    struct.pack_into("<I", header, 72, len(protos))
    struct.pack_into("<I", header, 76, proto_ids_off)
    struct.pack_into("<I", header, 80, 0)
    struct.pack_into("<I", header, 84, 0)
    struct.pack_into("<I", header, 88, len(method_ids))
    struct.pack_into("<I", header, 92, method_ids_off)
    struct.pack_into("<I", header, 96, 1)
    struct.pack_into("<I", header, 100, class_defs_off)
    struct.pack_into("<I", header, 104, data_size)
    struct.pack_into("<I", header, 108, data_off)

    blob = (
        bytes(header)
        + string_id_items
        + type_id_items
        + proto_id_items
        + method_id_items
        + class_def_items
    )
    assert len(blob) <= data_off
    blob += b"\x00" * (data_off - len(blob))
    blob += bytes(data)
    assert len(blob) == file_size

    buf = bytearray(blob)
    sig = hashlib.sha1(buf[32:], usedforsecurity=False).digest()
    buf[12:32] = sig
    checksum = zlib.adler32(buf[12:]) & 0xFFFFFFFF
    struct.pack_into("<I", buf, 8, checksum)

    return bytes(buf)


if __name__ == "__main__":
    dex = build_packed_switch_dex()
    out = (
        Path(__file__).parent.parent
        / "tests"
        / "fixtures"
        / "samples"
        / "packed_switch.dex"
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(dex)
    print(f"wrote {out} ({len(dex)} bytes)")
