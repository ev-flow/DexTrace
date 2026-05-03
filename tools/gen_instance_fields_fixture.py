#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pylint: disable=duplicate-code  # gen_pNN scripts share DEX builder boilerplate intentionally
"""
Build tests/fixtures/samples/p5d_fields.dex programmatically.

Method:
  Lp5d;->fieldRoundtrip(I)I  (static)
    Box box = new Box();    // new-instance, no <init> — iget defaults to 0
    box.n = arg;            // iput v9, v0, Lp5d;->n:I
    int t = box.n;          // iget v1, v0, Lp5d;->n:I
    t = t * 2;              // mul-int/lit8 v1, v1, #2
    Lp5d.total = t;         // sput v1, Lp5d;->total:I
    return Lp5d.total;      // sget v2, Lp5d;->total:I; return v2
  -> 21 -> 42

Verification:
  dextrace run tests/fixtures/samples/p5d_fields.dex \\
      --entry 'Lp5d;->fieldRoundtrip(I)I' --arg 21
  # -> return: 42
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


def build_p5d_dex() -> bytes:  # pylint: disable=too-many-locals,too-many-statements
    # Strings (sorted by MUTF-8 byte order)
    strings = [
        "I",                   # 0
        "II",                  # 1 — shorty for (I)I
        "Ljava/lang/Object;",  # 2
        "Lp5d;",               # 3
        "fieldRoundtrip",      # 4
        "n",                   # 5
        "total",               # 6
    ]
    # type_string_ids[i] = string_idx of the i-th type descriptor.
    # Order matters: indexes here are referenced by everything downstream.
    type_string_ids = [0, 2, 3]  # type 0=I, 1=Object, 2=Lp5d;
    protos = [(1, 0)]  # proto 0: shorty=str1 "II", return=type0 "I"

    # Field IDs must be sorted by (class_idx, name_idx, type_idx).
    # Both fields belong to Lp5d; (type 2). "n" (str5) < "total" (str6).
    field_ids = [
        (2, 0, 5),  # field 0: Lp5d;->n:I
        (2, 0, 6),  # field 1: Lp5d;->total:I
    ]

    method_ids = [(2, 0, 4)]  # Lp5d;->fieldRoundtrip(I)I: cls=type2, proto=0, name=str4

    # Insns (13 code units):
    #   pc=0   new-instance v0, type@2 (Lp5d;)         (21c, op 0x22, 2 units)
    #   pc=2   iput v9, v0, field@0 (Lp5d;->n:I)        (22c, op 0x59, 2 units)
    #   pc=4   iget v1, v0, field@0                     (22c, op 0x52, 2 units)
    #   pc=6   mul-int/lit8 v1, v1, #2                  (22b, op 0xda, 2 units)
    #   pc=8   sput v1, field@1 (Lp5d;->total:I)        (21c, op 0x67, 2 units)
    #   pc=10  sget v2, field@1                         (21c, op 0x60, 2 units)
    #   pc=12  return v2                                (11x, op 0x0f, 1 unit)
    #
    # 22c high-byte packing: (B<<4)|A, where A,B are 4-bit registers.
    # 21c high-byte packing: AA (8-bit register).
    # 22b: byte0=op, byte1=AA, byte2=BB, byte3=CC — laid out as little-endian
    # u16 pairs that's (CC<<8)|BB in unit1, AA<<8|op in unit0.
    insns = [
        0x0022, 0x0002,   # new-instance v0, type@2
        0x0959, 0x0000,   # iput v9, v0, field@0  (B=0,A=9 → 0x09 high byte)
        0x0152, 0x0000,   # iget v1, v0, field@0  (B=0,A=1 → 0x01 high byte)
        0x01DA, 0x0201,   # mul-int/lit8 v1, v1, #2  (AA=1, BB=1, CC=2)
        0x0167, 0x0001,   # sput v1, field@1
        0x0260, 0x0001,   # sget v2, field@1
        0x020F,           # return v2
    ]

    # Layout: header → id sections → class_defs → data → map_list.
    header_size = 0x70
    off = header_size

    string_ids_off = off
    off += len(strings) * 4

    type_ids_off = off
    off += len(type_string_ids) * 4

    proto_ids_off = off
    off += len(protos) * 12

    field_ids_off = off
    off += len(field_ids) * 8

    method_ids_off = off
    off += len(method_ids) * 8

    class_defs_off = off
    off += 1 * 32

    data_off = (off + 3) & ~3  # align 4

    data = bytearray()
    string_data_offs: list[int] = []
    for s in strings:
        string_data_offs.append(data_off + len(data))
        data.extend(_string_data_item(s))

    while (data_off + len(data)) % 4 != 0:
        data.append(0)

    # type_list for proto 0's params = (I,): u4 size + u2 list[size] (+ pad)
    type_list_off = data_off + len(data)
    data.extend(struct.pack("<IHH", 1, 0, 0))  # 1 entry: type_idx=0 (I)

    while (data_off + len(data)) % 4 != 0:
        data.append(0)

    code_off = data_off + len(data)
    # regs=10, ins=1 (one int arg lands in v9), outs=0, tries=0
    data.extend(struct.pack("<HHHHII", 10, 1, 0, 0, 0, len(insns)))
    data.extend(struct.pack("<" + "H" * len(insns), *insns))

    # class_data_item: declare one static field (total), one instance field (n),
    # and one direct method (fieldRoundtrip). The disassembler doesn't depend
    # on the static/instance split, but build_sig_to_codeoff_map walks
    # encoded methods here to find code_off for the entry.
    ACC_PUBLIC = 0x1
    ACC_STATIC = 0x8
    class_data_off = data_off + len(data)

    # encoded_field deltas: index into field_ids, MONOTONIC delta-encoded.
    # static[0]: field@1 (total) — delta 1 from base 0
    # instance[0]: field@0 (n) — delta 0 from base 0 (instance fields restart)
    data.extend(
        _uleb128(1)                     # static_fields_size
        + _uleb128(1)                   # instance_fields_size
        + _uleb128(1)                   # direct_methods_size
        + _uleb128(0)                   # virtual_methods_size
        # static field: delta=1 (total = field_ids[1])
        + _uleb128(1) + _uleb128(ACC_PUBLIC | ACC_STATIC)
        # instance field: delta=0 (n = field_ids[0])
        + _uleb128(0) + _uleb128(ACC_PUBLIC)
        # direct method: delta=0 (only method)
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
        _map_item(0x0000, 1, 0),                                  # header
        _map_item(0x0001, len(strings), string_ids_off),          # string_id_item
        _map_item(0x0002, len(type_string_ids), type_ids_off),    # type_id_item
        _map_item(0x0003, len(protos), proto_ids_off),            # proto_id_item
        _map_item(0x0004, len(field_ids), field_ids_off),         # field_id_item
        _map_item(0x0005, len(method_ids), method_ids_off),       # method_id_item
        _map_item(0x0006, 1, class_defs_off),                     # class_def_item
        _map_item(0x1001, 1, type_list_off),                      # type_list
        _map_item(0x2000, 1, class_data_off),                     # class_data_item
        _map_item(0x2001, 1, code_off),                           # code_item
        _map_item(0x2002, len(strings), string_data_offs[0]),     # string_data_item
        _map_item(0x1000, 1, map_off),                            # map_list
    ]
    data.extend(struct.pack("<I", len(map_items)) + b"".join(map_items))

    data_size = len(data)
    file_size = data_off + data_size

    # ---- ID sections ----
    string_id_items = b"".join(struct.pack("<I", o) for o in string_data_offs)
    type_id_items = b"".join(struct.pack("<I", idx) for idx in type_string_ids)
    proto_id_items = b"".join(
        struct.pack("<III", shorty_idx, return_type_idx, type_list_off)
        for shorty_idx, return_type_idx in protos
    )
    # field_id_item: u2 class_idx, u2 type_idx, u4 name_idx
    field_id_items = b"".join(
        struct.pack("<HHI", cls_idx, type_idx, name_idx)
        for cls_idx, type_idx, name_idx in field_ids
    )
    method_id_items = b"".join(
        struct.pack("<HHI", cls_idx, proto_idx, name_idx)
        for cls_idx, proto_idx, name_idx in method_ids
    )
    # class_def_item: 8 u4 fields. class_idx=2 (Lp5d;), super=type1 (Object).
    class_def_items = struct.pack(
        "<IIIIIIII",
        2,            # class_idx: Lp5d;
        ACC_PUBLIC,   # access_flags
        1,            # superclass_idx: Object
        0,            # interfaces_off
        0xFFFFFFFF,   # source_file_idx (none)
        0,            # annotations_off
        class_data_off,
        0,            # static_values_off
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
    struct.pack_into("<I", header, 80, len(field_ids))
    struct.pack_into("<I", header, 84, field_ids_off)
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
        + field_id_items
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
    dex = build_p5d_dex()
    out = (
        Path(__file__).parent.parent
        / "tests"
        / "fixtures"
        / "samples"
        / "p5d_fields.dex"
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(dex)
    print(f"wrote {out} ({len(dex)} bytes)")
