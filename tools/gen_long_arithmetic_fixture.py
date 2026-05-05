#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pylint: disable=duplicate-code  # gen_pNN scripts share DEX builder boilerplate intentionally
"""
Build tests/fixtures/samples/long_arith.dex programmatically.

Method:
  Lp5b;->longSum(I)J  (static)
    long a = (long) n;
    long b = a + a;        // 2n
    long c = b * 150L;     // 300n
    return c;
  -> 100 * 300 = 30000

Verification:
  dextrace run tests/fixtures/samples/long_arith.dex \\
      --entry 'Lp5b;->longSum(I)J' --arg 100
  # -> return: 30000
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


def build_long_arithmetic_dex() -> bytes:  # pylint: disable=too-many-locals,too-many-statements
    # Strings (sorted by MUTF-8)
    strings = [
        "I",                  # 0
        "J",                  # 1
        "JI",                 # 2 — shorty for (I)J
        "Ljava/lang/Object;", # 3
        "Lp5b;",              # 4
        "longSum",            # 5
    ]
    type_string_ids = [0, 1, 3, 4]  # type 0=I, 1=J, 2=Object, 3=Lp5b;
    protos = [(2, 1)]  # proto 0: shorty=str2 "JI", return=type1 "J", params=type_list_for_I
    method_ids = [(3, 0, 5)]  # Lp5b;->longSum(I)J: class=type3, proto=0, name=str5

    # Insns (8 code units):
    #   pc=0  int-to-long v0, v7        (op 0x81, fmt 12x)
    #   pc=1  add-long v2, v0, v0       (op 0x9b, fmt 23x — 2 units)
    #   pc=3  const-wide/16 v4, #150    (op 0x16, fmt 21s — 2 units)
    #   pc=5  mul-long v2, v2, v4       (op 0x9d, fmt 23x — 2 units)
    #   pc=7  return-wide v2            (op 0x10, fmt 11x)
    insns = [
        0x7081,            # int-to-long v0, v7  (B=7, A=0, op=0x81)
        0x029B, 0x0000,    # add-long v2, v0, v0
        0x0416, 0x0096,    # const-wide/16 v4, #150 (0x96 = 150)
        0x029D, 0x0402,    # mul-long v2, v2, v4
        0x0210,            # return-wide v2
    ]

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
    # regs=8, ins=1, outs=0, tries=0, insns_size=8
    data.extend(struct.pack("<HHHHII", 8, 1, 0, 0, 0, len(insns)))
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
        3, ACC_PUBLIC, 2, 0, 0xFFFFFFFF, 0, class_data_off, 0,
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
    dex = build_long_arithmetic_dex()
    out = (
        Path(__file__).parent.parent
        / "tests"
        / "fixtures"
        / "samples"
        / "long_arith.dex"
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(dex)
    print(f"wrote {out} ({len(dex)} bytes)")
