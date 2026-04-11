#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Build tests/fixtures/samples/p2_fib_recursive.dex programmatically.

DEX contains one class and one method:
  class:  Lp2/Fib;  (extends Ljava/lang/Object;)
  method: public static int fib(int n)
  body:
    // if n <= 1, return n
    const/4   v0, #1
    if-le     v2, v0, :base
    // fib(n-1)
    add-int/lit8  v1, v2, #-1
    invoke-static {v1}, Lp2/Fib;->fib(I)I
    move-result   v0
    // fib(n-2)
    add-int/lit8  v1, v2, #-2
    invoke-static {v1}, Lp2/Fib;->fib(I)I
    move-result   v1
    // return sum
    add-int   v0, v0, v1
    return    v0
    :base
    return    v2

Register layout:
  registers_size=3, ins_size=1
  v0 = accumulator / literal 1
  v1 = second accumulator
  v2 = n (input param, tail register)
"""

import hashlib
import struct
import zlib
from pathlib import Path


def _uleb128(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def _align4(off: int) -> int:
    return (off + 3) & ~3


def _string_data_item(s: str) -> bytes:
    b = s.encode("utf-8")
    return _uleb128(len(s)) + b + b"\x00"


def build_p2_dex() -> bytes:
    # -----------------------------------------------------------------------
    # String table (sorted by Unicode code point — DEX requirement)
    # "I" < "II" < "Ljava/lang/Object;" < "Lp2/Fib;" < "fib"
    # -----------------------------------------------------------------------
    strings = ["I", "II", "Ljava/lang/Object;", "Lp2/Fib;", "fib"]
    # indices:   0    1          2                    3         4

    # -----------------------------------------------------------------------
    # Type IDs (sorted by string index)
    # type 0 -> string 0  "I"
    # type 1 -> string 2  "Ljava/lang/Object;"
    # type 2 -> string 3  "Lp2/Fib;"
    # -----------------------------------------------------------------------
    type_string_ids = [0, 2, 3]

    # -----------------------------------------------------------------------
    # Proto IDs
    # proto 0: fib(I)I  — shorty="II"(1), return=type"I"(0), params=type_list{I}
    # parameters_off is filled in after we know the data layout.
    # -----------------------------------------------------------------------
    # (shorty_string_idx, return_type_idx)   <- params_off patched later
    proto_shorty_idx = 1  # "II"
    proto_return_idx = 0  # type "I"

    # -----------------------------------------------------------------------
    # Method IDs
    # method 0: Lp2/Fib;->fib(I)I
    #   class_type_idx=2  proto_idx=0  name_string_idx=4 ("fib")
    # -----------------------------------------------------------------------
    # (class_type_idx, proto_idx, name_string_idx)
    method_ids = [(2, 0, 4)]

    # -----------------------------------------------------------------------
    # Instruction encoding for fib(int n):
    #
    # uoff  insns                       mnemonic
    #  0    0x1012                      const/4 v0, #1         (1 unit)
    #  1    0x0236, 0x0011              if-le v2, v0, +17      (2 units, target=18)
    #  3    0x01D8, 0xFF02              add-int/lit8 v1,v2,#-1 (2 units)
    #  5    0x1071, 0x0000, 0x0001      invoke-static {v1},fib (3 units, method_idx=0)
    #  8    0x000A                      move-result v0         (1 unit)
    #  9    0x01D8, 0xFE02              add-int/lit8 v1,v2,#-2 (2 units)
    # 11    0x1071, 0x0000, 0x0001      invoke-static {v1},fib (3 units, method_idx=0)
    # 14    0x010A                      move-result v1         (1 unit)
    # 15    0x0090, 0x0100              add-int v0, v0, v1     (2 units)
    # 17    0x000F                      return v0              (1 unit)
    # 18    0x020F                      return v2  :base       (1 unit)
    # -----------------------------------------------------------------------
    insns = [
        0x1012,  # const/4 v0, #1
        0x0237,
        0x0011,  # if-le v2, v0, +17 (target uoff 18; opcode 0x37=if-le)
        0x01D8,
        0xFF02,  # add-int/lit8 v1, v2, #-1
        0x1071,
        0x0000,
        0x0001,  # invoke-static {v1}, method_idx=0
        0x000A,  # move-result v0
        0x01D8,
        0xFE02,  # add-int/lit8 v1, v2, #-2
        0x1071,
        0x0000,
        0x0001,  # invoke-static {v1}, method_idx=0
        0x010A,  # move-result v1
        0x0090,
        0x0100,  # add-int v0, v0, v1
        0x000F,  # return v0
        0x020F,  # return v2 (base case)
    ]
    assert len(insns) == 19, f"expected 19 code units, got {len(insns)}"

    HEADER_SIZE = 0x70

    # ---- lay out fixed sections ----
    off = HEADER_SIZE

    string_ids_off = off
    off += len(strings) * 4

    type_ids_off = off
    off += len(type_string_ids) * 4

    proto_ids_off = off
    off += 1 * 12  # one proto_id_item = 12 bytes

    field_ids_size = 0
    field_ids_off = 0

    method_ids_off = off
    off += len(method_ids) * 8

    class_defs_off = off
    off += 1 * 32  # one class_def_item = 32 bytes

    data_off = _align4(off)

    # ---- build data section ----
    data = bytearray()

    # string data items
    string_data_offs: list[int] = []
    for s in strings:
        string_data_offs.append(data_off + len(data))
        data.extend(_string_data_item(s))

    # 4-byte align for type_list
    while (data_off + len(data)) % 4 != 0:
        data.append(0)

    # type_list for proto parameters: {count=1, type_item[0]={type_idx=0}}
    type_list_off = data_off + len(data)
    # type_list: u32 size, then u16 type_idx per entry
    data.extend(struct.pack("<IH", 1, 0))  # size=1, type_idx=0 ("I")

    # 4-byte align for code_item
    while (data_off + len(data)) % 4 != 0:
        data.append(0)

    code_item_off = data_off + len(data)
    # code_item header: registers_size, ins_size, outs_size, tries_size, debug_info_off, insns_size
    code_item = struct.pack(
        "<HHHHII", 3, 1, 1, 0, 0, len(insns)
    ) + struct.pack("<" + "H" * len(insns), *insns)
    data.extend(code_item)

    class_data_off_val = data_off + len(data)
    # class_data_item:
    #   static_fields=0, instance_fields=0, direct_methods=1, virtual_methods=0
    #   encoded_method: method_idx_diff=0, access_flags=0x9 (public|static), code_off
    class_data = (
        _uleb128(0)
        + _uleb128(0)
        + _uleb128(1)
        + _uleb128(0)
        + _uleb128(0)
        + _uleb128(0x9)
        + _uleb128(code_item_off)
    )
    data.extend(class_data)

    # 4-byte align for map_list
    while (data_off + len(data)) % 4 != 0:
        data.append(0)

    map_off = data_off + len(data)

    def map_item(t: int, size: int, offset: int) -> bytes:
        return struct.pack("<HHII", t, 0, size, offset)

    map_items = [
        map_item(0x0000, 1, 0),  # header_item
        map_item(0x0001, len(strings), string_ids_off),  # string_id_item
        map_item(0x0002, len(type_string_ids), type_ids_off),  # type_id_item
        map_item(0x0003, 1, proto_ids_off),  # proto_id_item
        map_item(0x0005, len(method_ids), method_ids_off),  # method_id_item
        map_item(0x0006, 1, class_defs_off),  # class_def_item
        map_item(0x2001, 1, code_item_off),  # code_item
        map_item(0x2000, 1, class_data_off_val),  # class_data_item
        map_item(0x1001, 1, type_list_off),  # type_list
        map_item(
            0x2002, len(strings), string_data_offs[0]
        ),  # string_data_item
        map_item(0x1000, 1, map_off),  # map_list
    ]
    data.extend(struct.pack("<I", len(map_items)) + b"".join(map_items))

    data_size = len(data)
    file_size = data_off + data_size

    # ---- fixed ID sections ----
    string_id_items = b"".join(struct.pack("<I", o) for o in string_data_offs)
    type_id_items = b"".join(struct.pack("<I", idx) for idx in type_string_ids)

    # proto_id_item: shorty_string_idx, return_type_idx, parameters_off
    proto_id_items = struct.pack(
        "<III", proto_shorty_idx, proto_return_idx, type_list_off
    )

    method_id_items = b"".join(
        struct.pack("<HHI", cls_idx, proto_idx, name_idx)
        for cls_idx, proto_idx, name_idx in method_ids
    )

    # class_def_item (32 bytes)
    class_def_item = struct.pack(
        "<IIIIIIII",
        2,  # class_idx -> "Lp2/Fib;"
        0x1,  # access_flags: public
        1,  # superclass_idx -> "Ljava/lang/Object;"
        0,  # interfaces_off
        0xFFFFFFFF,  # source_file_idx: NO_INDEX
        0,  # annotations_off
        class_data_off_val,
        0,  # static_values_off
    )

    # ---- header ----
    header = bytearray(HEADER_SIZE)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 32, file_size)
    struct.pack_into("<I", header, 36, HEADER_SIZE)
    struct.pack_into("<I", header, 40, 0x12345678)  # endian_tag
    struct.pack_into("<I", header, 44, 0)  # link_size
    struct.pack_into("<I", header, 48, 0)  # link_off
    struct.pack_into("<I", header, 52, map_off)
    struct.pack_into("<I", header, 56, len(strings))
    struct.pack_into("<I", header, 60, string_ids_off)
    struct.pack_into("<I", header, 64, len(type_string_ids))
    struct.pack_into("<I", header, 68, type_ids_off)
    struct.pack_into("<I", header, 72, 1)  # protos_size
    struct.pack_into("<I", header, 76, proto_ids_off)
    struct.pack_into("<I", header, 80, field_ids_size)
    struct.pack_into("<I", header, 84, field_ids_off)
    struct.pack_into("<I", header, 88, len(method_ids))
    struct.pack_into("<I", header, 92, method_ids_off)
    struct.pack_into("<I", header, 96, 1)  # class_defs_size
    struct.pack_into("<I", header, 100, class_defs_off)
    struct.pack_into("<I", header, 104, data_size)
    struct.pack_into("<I", header, 108, data_off)

    # ---- assemble ----
    blob = (
        bytes(header)
        + string_id_items
        + type_id_items
        + proto_id_items
        + method_id_items
        + class_def_item
    )
    assert len(blob) <= data_off, f"layout overrun: {len(blob)} > {data_off}"
    blob += b"\x00" * (data_off - len(blob))
    blob += bytes(data)
    assert (
        len(blob) == file_size
    ), f"file_size mismatch: {len(blob)} != {file_size}"

    buf = bytearray(blob)
    sig = hashlib.sha1(buf[32:], usedforsecurity=False).digest()
    buf[12:32] = sig
    checksum = zlib.adler32(buf[12:]) & 0xFFFFFFFF
    struct.pack_into("<I", buf, 8, checksum)

    return bytes(buf)


if __name__ == "__main__":
    dex = build_p2_dex()
    out = (
        Path(__file__).parent.parent
        / "tests"
        / "fixtures"
        / "samples"
        / "p2_fib_recursive.dex"
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(dex)
    print(f"wrote {out} ({len(dex)} bytes)")
