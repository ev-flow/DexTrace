#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pylint: disable=duplicate-code  # gen_pNN scripts share DEX builder boilerplate intentionally
"""
Build tests/fixtures/samples/p5e_arrays.dex programmatically.

Method:
  Lp5e;->arraySum()I  (static, no args)
    int[] arr = new int[3];     // new-array
    fill-array-data arr, [10,20,30]
    int n = arr.length;         // array-length
    int sum = 0;
    for (int i = 0; i < n; i++) sum += arr[i];   // aget
    return sum;
  -> 60

Verification:
  python -m dextrace run tests/fixtures/samples/p5e_arrays.dex \\
      --entry 'Lp5e;->arraySum()I'
  # → return: 60
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


def _string_data_item(s: str) -> bytes:
    b = s.encode("utf-8")
    return _uleb128(len(s)) + b + b"\x00"


def build_dex() -> bytes:  # pylint: disable=too-many-locals,too-many-statements
    # Strings (sorted by MUTF-8 byte order: 'I'=0x49, 'L'=0x4C, '['=0x5B, 'a'=0x61).
    strings = [
        "I",                  # 0  (also serves as shorty for ()I)
        "Ljava/lang/Object;", # 1
        "Lp5e;",              # 2
        "[I",                 # 3  (array descriptor for int[])
        "arraySum",           # 4
    ]
    # type_string_ids[i] = string_idx for type i, sorted by string_idx.
    type_string_ids = [0, 1, 2, 3]  # 0=I, 1=Object, 2=Lp5e;, 3=[I
    protos = [(0, 0)]               # proto 0: shorty=str0 "I", return=type0 "I", no params
    method_ids = [(2, 0, 4)]        # Lp5e;->arraySum()I

    # Insns layout (30 code units; 4-byte aligned for the payload):
    #   pc=0   const/4 v0, #3                          11n  1u
    #   pc=1   new-array v1, v0, type@3 ([I)            22c  2u
    #   pc=3   fill-array-data v1, +17                  31t  3u  → payload at pc=20
    #   pc=6   array-length v0, v1                      12x  1u
    #   pc=7   const/4 v2, #0                            11n  1u
    #   pc=8   const/4 v3, #0                            11n  1u
    #   pc=9   if-ge v2, v0, +9                          22t  2u  → branch to pc=18
    #   pc=11  aget v4, v1, v2                           23x  2u
    #   pc=13  add-int v3, v3, v4                        23x  2u
    #   pc=15  add-int/lit8 v2, v2, #1                   22b  2u
    #   pc=17  goto -8                                   10t  1u  → branch to pc=9
    #   pc=18  return v3                                 11x  1u
    #   pc=19  nop (pad to 4-byte boundary)              10x  1u
    #   pc=20  fill-array-data-payload                          10u
    insns = [
        0x3012,           # const/4 v0, #3
        0x0123, 0x0003,   # new-array v1, v0, type@3
        0x0126, 0x0011, 0x0000,  # fill-array-data v1, +17
        0x1021,           # array-length v0, v1
        0x0212,           # const/4 v2, #0
        0x0312,           # const/4 v3, #0
        0x0235, 0x0009,   # if-ge v2, v0, +9
        0x0444, 0x0201,   # aget v4, v1, v2
        0x0390, 0x0403,   # add-int v3, v3, v4
        0x02D8, 0x0102,   # add-int/lit8 v2, v2, #1
        0xF828,           # goto -8
        0x030F,           # return v3
        0x0000,           # nop (alignment pad)
        # fill-array-data-payload: ident=0x0300, width=4, size=3, data=[10,20,30]
        0x0300,           # ident
        0x0004,           # element_width = 4
        0x0003, 0x0000,   # size = 3 (u32 LE)
        0x000A, 0x0000,   # 10
        0x0014, 0x0000,   # 20
        0x001E, 0x0000,   # 30
    ]
    assert len(insns) == 30

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

    data_off = (off + 3) & ~3

    data = bytearray()
    string_data_offs: list[int] = []
    for s in strings:
        string_data_offs.append(data_off + len(data))
        data.extend(_string_data_item(s))

    while (data_off + len(data)) % 4 != 0:
        data.append(0)

    code_off = data_off + len(data)
    # regs=5 (v0..v4), ins=0, outs=0, tries=0
    data.extend(struct.pack("<HHHHII", 5, 0, 0, 0, 0, len(insns)))
    data.extend(struct.pack("<" + "H" * len(insns), *insns))

    ACC_PUBLIC = 0x1
    ACC_STATIC = 0x8
    class_data_off = data_off + len(data)
    data.extend(
        _uleb128(0)                          # static_fields_size
        + _uleb128(0)                        # instance_fields_size
        + _uleb128(1)                        # direct_methods_size
        + _uleb128(0)                        # virtual_methods_size
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
        _map_item(0x2000, 1, class_data_off),
        _map_item(0x2001, 1, code_off),
        _map_item(0x2002, len(strings), string_data_offs[0]),
        _map_item(0x1000, 1, map_off),
    ]
    data.extend(struct.pack("<I", len(map_items)) + b"".join(map_items))

    data_size = len(data)
    file_size = data_off + data_size

    string_id_items = b"".join(struct.pack("<I", o) for o in string_data_offs)
    type_id_items = b"".join(struct.pack("<I", idx) for idx in type_string_ids)
    proto_id_items = b"".join(
        struct.pack("<III", shorty_idx, return_type_idx, 0)
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
    dex = build_dex()
    out = (
        Path(__file__).parent.parent
        / "tests"
        / "fixtures"
        / "samples"
        / "p5e_arrays.dex"
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(dex)
    print(f"wrote {out} ({len(dex)} bytes)")
