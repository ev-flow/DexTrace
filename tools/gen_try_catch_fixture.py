#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pylint: disable=duplicate-code  # fixture generators share DEX builder boilerplate intentionally
"""
Build tests/fixtures/samples/try_catch.dex programmatically.

Method:
  LTryCatchTest;->divCatch(II)I  (static)
    try   { return v2 / v3 }
    catch (Ljava/lang/ArithmeticException;) { return -1 }

Verification:
  python -m dextrace run tests/fixtures/samples/try_catch.dex \\
      --entry 'LTryCatchTest;->divCatch(II)I' --arg 10 --arg 0
  # → return: -1
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


def _sleb128(n: int) -> bytes:
    buf = bytearray()
    more = True
    while more:
        b = n & 0x7F
        n >>= 7
        sign_bit = b & 0x40
        if (n == 0 and sign_bit == 0) or (n == -1 and sign_bit):
            more = False
            buf.append(b)
        else:
            buf.append(b | 0x80)
    return bytes(buf)


def _align4(off: int) -> int:
    return (off + 3) & ~3


def _string_data_item(s: str) -> bytes:
    b = s.encode("utf-8")
    return _uleb128(len(s)) + b + b"\x00"


def build_try_catch_dex() -> bytes:  # pylint: disable=too-many-locals,too-many-statements
    # -----------------------------------------------------------------------
    # Strings (sorted by MUTF-8 code point)
    #  0: "I"
    #  1: "III"                            (shorty for (II)I)
    #  2: "LTryCatchTest;"
    #  3: "Ljava/lang/ArithmeticException;"
    #  4: "Ljava/lang/Object;"
    #  5: "divCatch"
    # -----------------------------------------------------------------------
    strings = [
        "I",
        "III",
        "LTryCatchTest;",
        "Ljava/lang/ArithmeticException;",
        "Ljava/lang/Object;",
        "divCatch",
    ]

    # type_ids (sorted by string_idx)
    #  type 0 → str 0  "I"
    #  type 1 → str 2  "LTryCatchTest;"
    #  type 2 → str 3  "Ljava/lang/ArithmeticException;"
    #  type 3 → str 4  "Ljava/lang/Object;"
    type_string_ids = [0, 2, 3, 4]

    # proto_ids
    #  proto 0: (II)I  shorty=str1, return_type=type0, params=type_list_for_II
    # The single proto's params_off is patched to type_list_off after we lay out data.
    protos = [(1, 0)]  # (shorty_idx, return_type_idx)

    # method_ids (sorted by class_idx, then name_idx, then proto_idx)
    #  method 0: LTryCatchTest;->divCatch(II)I  class=type1, name=str5, proto=0
    method_ids = [(1, 0, 5)]

    # -----------------------------------------------------------------------
    # divCatch insns (6 code units)
    #
    #   pc=0x0000  div-int v0, v2, v3   (op 0x93, fmt 23x, 2 units)
    #   pc=0x0002  return v0            (op 0x0f, fmt 11x, 1 unit)
    #   pc=0x0003  move-exception v1    (op 0x0d, fmt 11x, 1 unit)
    #   pc=0x0004  const/4 v0, -1       (op 0x12, fmt 11n, 1 unit; B=0xF=-1)
    #   pc=0x0005  return v0            (op 0x0f, fmt 11x, 1 unit)
    # -----------------------------------------------------------------------
    insns = [
        0x0093,  # div-int, AA=v0
        0x0302,  # CC=v3, BB=v2
        0x000F,  # return v0
        0x010D,  # move-exception v1
        0xF012,  # const/4 v0, -1  (B nibble = 0xF for signed -1, A nibble = 0)
        0x000F,  # return v0
    ]

    # Try table: covers pc 0..2 inclusive (div-int + return).
    #
    # encoded_catch_handler_list layout:
    #   uleb128 size=1                 ← 1 byte
    #   encoded_catch_handler at +1:
    #     sleb128 typed_size=1         ← one typed catch, no catch-all
    #     uleb128 type_idx=2           ← Ljava/lang/ArithmeticException;
    #     uleb128 addr=3               ← move-exception at pc=0x0003
    # try_item.handler_off is the BYTE offset from the start of the list to
    # the encoded_catch_handler — so 1, not 0 (offset 0 is the size byte).
    handlers_size_uleb = _uleb128(1)
    encoded_handler_off = len(handlers_size_uleb)  # = 1
    handlers_list = bytes(
        handlers_size_uleb
        + _sleb128(1)
        + _uleb128(2)
        + _uleb128(3)
    )

    # try_item: <I H H> = start_addr, insn_count, handler_off
    try_item = struct.pack("<IHH", 0, 3, encoded_handler_off)

    # -----------------------------------------------------------------------
    # Layout: header → IDs → class_defs → data
    # -----------------------------------------------------------------------
    header_size = 0x70
    off = header_size

    string_ids_off = off
    off += len(strings) * 4

    type_ids_off = off
    off += len(type_string_ids) * 4

    proto_ids_off = off
    off += len(protos) * 12

    field_ids_size = 0
    field_ids_off = 0

    method_ids_off = off
    off += len(method_ids) * 8

    class_defs_off = off
    off += 1 * 32

    data_off = _align4(off)

    # -----------------------------------------------------------------------
    # Build data section
    # -----------------------------------------------------------------------
    data = bytearray()

    string_data_offs: list[int] = []
    for s in strings:
        string_data_offs.append(data_off + len(data))
        data.extend(_string_data_item(s))

    # 4-byte align before type_list
    while (data_off + len(data)) % 4 != 0:
        data.append(0)

    type_list_off = data_off + len(data)
    # type_list for proto 0's params: (I, I)
    # u4 size + u2 list[size] (+ padding to 4-byte alignment if needed)
    data.extend(struct.pack("<IHH", 2, 0, 0))  # 2 entries: type_idx=0, type_idx=0

    # 4-byte align before code_item
    while (data_off + len(data)) % 4 != 0:
        data.append(0)

    divcatch_code_off = data_off + len(data)
    # code_item header: regs=4, ins=2, outs=0, tries=1
    data.extend(struct.pack("<HHHHII", 4, 2, 0, 1, 0, len(insns)))
    data.extend(struct.pack("<" + "H" * len(insns), *insns))
    # insns_size=6 is even — no padding before tries
    data.extend(try_item)
    data.extend(handlers_list)

    # class_data for LTryCatchTest;
    #   direct: method 0 (divCatch)  diff=0, acc=ACC_PUBLIC|ACC_STATIC
    ACC_PUBLIC = 0x1
    ACC_STATIC = 0x8
    class_data_off = data_off + len(data)
    data.extend(
        _uleb128(0)             # static_fields_size
        + _uleb128(0)           # instance_fields_size
        + _uleb128(1)           # direct_methods_size
        + _uleb128(0)           # virtual_methods_size
        + _uleb128(0)           # method_idx_diff
        + _uleb128(ACC_PUBLIC | ACC_STATIC)
        + _uleb128(divcatch_code_off)
    )

    # 4-byte align before map_list
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
        _map_item(0x2001, 1, divcatch_code_off),
        _map_item(0x2002, len(strings), string_data_offs[0]),
        _map_item(0x1000, 1, map_off),
    ]
    data.extend(struct.pack("<I", len(map_items)) + b"".join(map_items))

    data_size = len(data)
    file_size = data_off + data_size

    # -----------------------------------------------------------------------
    # ID sections
    # -----------------------------------------------------------------------
    string_id_items = b"".join(struct.pack("<I", o) for o in string_data_offs)
    type_id_items = b"".join(struct.pack("<I", idx) for idx in type_string_ids)

    # proto 0 params point at type_list_off
    proto_id_items = b"".join(
        struct.pack("<III", shorty_idx, return_type_idx, type_list_off)
        for shorty_idx, return_type_idx in protos
    )

    method_id_items = b"".join(
        struct.pack("<HHI", cls_idx, proto_idx, name_idx)
        for cls_idx, proto_idx, name_idx in method_ids
    )

    # class_def for LTryCatchTest;: class=type1, super=type3 (Object), data=class_data_off
    class_def_items = struct.pack(
        "<IIIIIIII",
        1,                # class_idx (LTryCatchTest)
        ACC_PUBLIC,       # access_flags
        3,                # superclass_idx (Object)
        0,                # interfaces_off
        0xFFFFFFFF,       # source_file_idx
        0,                # annotations_off
        class_data_off,   # class_data_off
        0,                # static_values_off
    )

    # -----------------------------------------------------------------------
    # Header
    # -----------------------------------------------------------------------
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
    struct.pack_into("<I", header, 80, field_ids_size)
    struct.pack_into("<I", header, 84, field_ids_off)
    struct.pack_into("<I", header, 88, len(method_ids))
    struct.pack_into("<I", header, 92, method_ids_off)
    struct.pack_into("<I", header, 96, 1)
    struct.pack_into("<I", header, 100, class_defs_off)
    struct.pack_into("<I", header, 104, data_size)
    struct.pack_into("<I", header, 108, data_off)

    # -----------------------------------------------------------------------
    # Assemble
    # -----------------------------------------------------------------------
    blob = (
        bytes(header)
        + string_id_items
        + type_id_items
        + proto_id_items
        + method_id_items
        + class_def_items
    )
    assert len(blob) <= data_off, f"layout overrun: {len(blob)} > {data_off}"
    blob += b"\x00" * (data_off - len(blob))
    blob += bytes(data)
    assert len(blob) == file_size, f"file_size mismatch: {len(blob)} != {file_size}"

    buf = bytearray(blob)
    sig = hashlib.sha1(buf[32:], usedforsecurity=False).digest()
    buf[12:32] = sig
    checksum = zlib.adler32(buf[12:]) & 0xFFFFFFFF
    struct.pack_into("<I", buf, 8, checksum)

    return bytes(buf)


if __name__ == "__main__":
    dex = build_try_catch_dex()
    out = (
        Path(__file__).parent.parent
        / "tests"
        / "fixtures"
        / "samples" / "try_catch.dex"
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(dex)
    print(f"wrote {out} ({len(dex)} bytes)")
