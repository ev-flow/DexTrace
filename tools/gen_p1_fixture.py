#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pylint: disable=duplicate-code  # gen_p1/p2 share DEX builder boilerplate intentionally
"""
Build tests/fixtures/samples/p1_const_return.dex programmatically.

DEX contains one class and one method:
  class:  Lp1;  (extends Ljava/lang/Object;)
  method: public static void main()
  body:   const/16 v0, 42
          return-void
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


def build_p1_dex() -> (
    bytes
):  # pylint: disable=too-many-locals,too-many-statements
    # -----------------------------------------------------------------------
    # String table (must be sorted by Unicode code point — DEX requirement)
    # "Ljava/lang/Object;" < "Lp1;" < "V" < "main"
    # -----------------------------------------------------------------------
    strings = ["Ljava/lang/Object;", "Lp1;", "V", "main"]
    # indices:        0                  1      2     3

    # -----------------------------------------------------------------------
    # Type IDs (sorted by string index)
    # type_idx 0 -> string_idx 0  = "Ljava/lang/Object;"
    # type_idx 1 -> string_idx 1  = "Lp1;"
    # type_idx 2 -> string_idx 2  = "V"
    # -----------------------------------------------------------------------
    type_string_ids = [0, 1, 2]

    # -----------------------------------------------------------------------
    # Proto IDs
    # proto 0: ()V  — shorty="V"(2), return_type=type"V"(2), params_off=0
    # -----------------------------------------------------------------------
    # (shorty_string_idx, return_type_idx, parameters_off)
    proto_ids = [(2, 2, 0)]

    # -----------------------------------------------------------------------
    # Method IDs
    # method 0: Lp1;->main()V
    #   class_idx=1  proto_idx=0  name_string_idx=3
    # -----------------------------------------------------------------------
    # (class_type_idx, proto_idx, name_string_idx)
    method_ids = [(1, 0, 3)]

    # -----------------------------------------------------------------------
    # Instructions:  const/16 v0, #42 ; return-void
    #   const/16   opcode=0x13 fmt=21s: (vA<<8)|op  BBBB
    #              v0: (0<<8)|0x13 = 0x0013, literal = 42 = 0x002A
    #   return-void opcode=0x0E fmt=10x: (0<<8)|op
    #              0x000E
    # -----------------------------------------------------------------------
    insns = [0x0013, 0x002A, 0x000E]

    header_size = 0x70  # pylint: disable=invalid-name

    # ---- lay out fixed sections ----
    off = header_size

    string_ids_off = off
    off += len(strings) * 4

    type_ids_off = off
    off += len(type_string_ids) * 4

    proto_ids_off = off
    off += len(proto_ids) * 12

    field_ids_size = 0
    field_ids_off = 0

    method_ids_off = off
    off += len(method_ids) * 8

    class_defs_off = off
    off += 1 * 32  # one class_def_item = 32 bytes

    data_off = _align4(off)

    # ---- build data section ----
    data = bytearray()

    string_data_offs: list[int] = []
    for s in strings:
        string_data_offs.append(data_off + len(data))
        data.extend(_string_data_item(s))

    # 4-byte align for code_item
    while (data_off + len(data)) % 4 != 0:
        data.append(0)

    code_item_off = data_off + len(data)
    # code_item: registers=1, ins=0, outs=0, tries=0, debug_info_off=0, insns_size=3
    code_item = struct.pack(
        "<HHHHII", 1, 0, 0, 0, 0, len(insns)
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
        map_item(0x0003, len(proto_ids), proto_ids_off),  # proto_id_item
        map_item(0x0005, len(method_ids), method_ids_off),  # method_id_item
        map_item(0x0006, 1, class_defs_off),  # class_def_item
        map_item(0x2001, 1, code_item_off),  # code_item
        map_item(0x2000, 1, class_data_off_val),  # class_data_item
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
    proto_id_items = b"".join(
        struct.pack("<III", shorty, ret, params)
        for shorty, ret, params in proto_ids
    )
    method_id_items = b"".join(
        struct.pack("<HHI", cls_idx, proto_idx, name_idx)
        for cls_idx, proto_idx, name_idx in method_ids
    )

    # class_def_item (32 bytes)
    class_def_item = struct.pack(
        "<IIIIIIII",
        1,  # class_idx -> "Lp1;"
        0x1,  # access_flags: public
        0,  # superclass_idx -> "Ljava/lang/Object;"
        0,  # interfaces_off
        0xFFFFFFFF,  # source_file_idx: NO_INDEX
        0,  # annotations_off
        class_data_off_val,
        0,  # static_values_off
    )

    # ---- header ----
    header = bytearray(header_size)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 32, file_size)
    struct.pack_into("<I", header, 36, header_size)
    struct.pack_into("<I", header, 40, 0x12345678)  # endian_tag
    struct.pack_into("<I", header, 44, 0)  # link_size
    struct.pack_into("<I", header, 48, 0)  # link_off
    struct.pack_into("<I", header, 52, map_off)
    struct.pack_into("<I", header, 56, len(strings))
    struct.pack_into("<I", header, 60, string_ids_off)
    struct.pack_into("<I", header, 64, len(type_string_ids))
    struct.pack_into("<I", header, 68, type_ids_off)
    struct.pack_into("<I", header, 72, len(proto_ids))
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
    dex = build_p1_dex()
    out = (
        Path(__file__).parent.parent
        / "tests"
        / "fixtures"
        / "samples"
        / "p1_const_return.dex"
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(dex)
    print(f"wrote {out} ({len(dex)} bytes)")
