# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from __future__ import annotations

import hashlib
import struct
import zlib
from typing import List


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


def _align(off: int, a: int) -> int:
    return (off + (a - 1)) & ~(a - 1)


def build_minimal_test_dex() -> bytes:
    """
    Build a minimal, valid DEX (dex\\n035) for deterministic unit tests.

    What this DEX contains (enough to exercise resolver + disasm pipeline):
      - class:   public class LTest; extends Ljava/lang/Object;
      - method:  LTest;-><init>()V  with code:
            invoke-direct {v0}, Ljava/lang/Object;-><init>()V
            const-string v1, "HELLO"
            invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
            return-void

    Notes:
      - Types/register semantics are NOT meant to be VM-correct; this is a static fixture.
      - We include a proto with params_off -> type_list to test proto resolver path.
    """

    # ----------------------------
    # Strings / types / protos
    # ----------------------------
    strings: List[str] = [
        "LTest;",
        "Ljava/lang/Object;",
        "Ljava/lang/String;",
        "Ljava/lang/StringBuilder;",
        "<init>",
        "append",
        "V",
        "LL",      # shorty for (L) -> L
        "HELLO",   # const-string payload
    ]

    def string_data_item(s: str) -> bytes:
        # string_data_item:
        #   uleb128 utf16_size
        #   u1 data[] (MUTF-8), terminated by 0x00
        b = s.encode("utf-8")
        return _uleb128(len(s)) + b + b"\x00"

    string_datas = [string_data_item(s) for s in strings]
    string_ids_size = len(strings)

    type_descs = [
        "LTest;",
        "Ljava/lang/Object;",
        "Ljava/lang/String;",
        "Ljava/lang/StringBuilder;",
        "V",
    ]
    type_ids = [strings.index(d) for d in type_descs]  # descriptor string index
    type_ids_size = len(type_ids)

    # protos:
    #   proto0: ()V
    #   proto1: (Ljava/lang/String;)Ljava/lang/StringBuilder;
    proto_ids_size = 2

    # We'll fill proto_id_items AFTER we build data section (so we know parameters_off)
    proto0_shorty_idx = strings.index("V")
    proto0_return_type_idx = type_descs.index("V")
    proto0_parameters_off = 0

    proto1_shorty_idx = strings.index("LL")
    proto1_return_type_idx = type_descs.index("Ljava/lang/StringBuilder;")
    proto1_parameters_off = 0  # placeholder, set later

    # method_ids:
    #   0: Ljava/lang/Object;-><init>()V
    #   1: LTest;-><init>()V
    #   2: Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    method_ids = [
        (type_descs.index("Ljava/lang/Object;"), 0, strings.index("<init>")),
        (type_descs.index("LTest;"), 0, strings.index("<init>")),
        (type_descs.index("Ljava/lang/StringBuilder;"), 1, strings.index("append")),
    ]
    method_ids_size = len(method_ids)

    class_defs_size = 1

    # ----------------------------
    # Layout fixed-size sections
    # ----------------------------
    header_size = 0x70
    off = header_size

    string_ids_off = off
    off += string_ids_size * 4

    type_ids_off = off
    off += type_ids_size * 4

    proto_ids_off = off
    off += proto_ids_size * 12

    field_ids_size = 0
    field_ids_off = 0

    method_ids_off = off
    off += method_ids_size * 8

    class_defs_off = off
    off += class_defs_size * 32

    data_off = _align(off, 4)
    off = data_off

    # ----------------------------
    # Build data section
    # ----------------------------
    data = bytearray()

    # string_data_items
    string_data_offs: List[int] = []
    for sd in string_datas:
        string_data_offs.append(data_off + len(data))
        data.extend(sd)

    # align for type_list (must be 4-byte aligned)
    while (data_off + len(data)) % 4 != 0:
        data.append(0)

    # type_list for proto1 params: [Ljava/lang/String;]
    type_list_off = data_off + len(data)
    param_type_idx = type_descs.index("Ljava/lang/String;")
    # type_list:
    #   u4 size = 1
    #   u2 list[0] = param_type_idx
    #   u2 padding (keep 4-byte aligned end)
    data.extend(struct.pack("<IHH", 1, param_type_idx, 0))

    # align for code_item (4-byte)
    while (data_off + len(data)) % 4 != 0:
        data.append(0)

    # code_item
    code_off = data_off + len(data)

    hello_idx = strings.index("HELLO")
    append_mid = 2  # method_idx for StringBuilder.append (3rd in method_ids)

    # insns (16-bit code units):
    # 1) invoke-direct {v0}, method@0000  (35c, opcode 0x70)
    #    A=1, G=0 => high8=0x10 => w0=0x1070, w1=0x0000, w2 regs = v0 in C
    # 2) const-string v1, string@HELLO (21c, opcode 0x1a) => w0=0x011a, w1=hello_idx
    # 3) invoke-virtual {v0, v1}, method@append_mid (35c, opcode 0x6e)
    #    A=2, G=0 => high8=0x20 => w0=0x206e, w1=append_mid, w2 C=v0(0), D=v1(1) => 0x0010
    # 4) return-void (10x, opcode 0x0e) => 0x000e
    insns = [
        0x1070, 0x0000, 0x0000,
        0x011A, int(hello_idx) & 0xFFFF,
        0x206E, int(append_mid) & 0xFFFF, 0x0010,
        0x000E,
    ]

    # code_item header:
    # registers_size=2 (v0=this, v1=local)
    # ins_size=1 (this)
    # outs_size=2 (invoke-virtual uses 2 args)
    # tries_size=0
    # debug_info_off=0
    # insns_size=len(insns)
    code_item = (
        struct.pack("<HHHHII", 2, 1, 2, 0, 0, len(insns))
        + struct.pack("<" + "H" * len(insns), *insns)
    )
    data.extend(code_item)

    # class_data_item (no strict alignment required)
    class_data_off = data_off + len(data)

    # class_data:
    # static_fields_size=0
    # instance_fields_size=0
    # direct_methods_size=1
    # virtual_methods_size=0
    #
    # encoded_method for LTest;-><init> (method_idx = 1):
    #   method_idx_diff = 1
    #   access_flags = ACC_PUBLIC | ACC_CONSTRUCTOR = 0x1 | 0x10000 = 0x10001
    #   code_off = code_off
    class_data = (
        _uleb128(0)
        + _uleb128(0)
        + _uleb128(1)
        + _uleb128(0)
        + _uleb128(1)
        + _uleb128(0x10001)
        + _uleb128(code_off)
    )
    data.extend(class_data)

    # align for map_list
    while (data_off + len(data)) % 4 != 0:
        data.append(0)

    map_off = data_off + len(data)

    def map_item(t: int, size: int, offset: int) -> bytes:
        return struct.pack("<HHII", t, 0, size, offset)

    # map_list: include only what we actually laid out
    items = [
        map_item(0x0000, 1, 0),  # header_item
        map_item(0x0001, string_ids_size, string_ids_off),  # string_id_item
        map_item(0x0002, type_ids_size, type_ids_off),      # type_id_item
        map_item(0x0003, proto_ids_size, proto_ids_off),    # proto_id_item
        map_item(0x0005, method_ids_size, method_ids_off),  # method_id_item
        map_item(0x0006, class_defs_size, class_defs_off),  # class_def_item
        map_item(0x1001, 1, type_list_off),                 # type_list
        map_item(0x2001, 1, code_off),                       # code_item
        map_item(0x2000, 1, class_data_off),                 # class_data_item
        map_item(0x2002, string_ids_size, string_data_offs[0]),  # string_data_item (offset to first)
        map_item(0x1000, 1, map_off),                         # map_list
    ]
    data.extend(struct.pack("<I", len(items)) + b"".join(items))

    data_size = len(data)
    file_size = data_off + data_size

    # ----------------------------
    # Build ID sections
    # ----------------------------
    string_id_items = b"".join(struct.pack("<I", o) for o in string_data_offs)
    type_id_items = b"".join(struct.pack("<I", idx) for idx in type_ids)

    # now that we know type_list_off, fill proto1_parameters_off
    proto1_parameters_off = type_list_off

    proto_id_items = b"".join(
        [
            struct.pack("<III", proto0_shorty_idx, proto0_return_type_idx, proto0_parameters_off),
            struct.pack("<III", proto1_shorty_idx, proto1_return_type_idx, proto1_parameters_off),
        ]
    )

    method_id_items = b"".join(struct.pack("<HHI", cls, proto, name) for cls, proto, name in method_ids)

    # class_def_item
    class_def_item = struct.pack(
        "<IIIIIIII",
        type_descs.index("LTest;"),                 # class_idx
        0x1,                                        # access_flags (public)
        type_descs.index("Ljava/lang/Object;"),     # superclass_idx
        0,                                          # interfaces_off
        0xFFFFFFFF,                                 # source_file_idx (NO_INDEX)
        0,                                          # annotations_off
        class_data_off,                             # class_data_off
        0,                                          # static_values_off
    )

    # ----------------------------
    # Header (checksum/signature later)
    # ----------------------------
    header = bytearray(header_size)
    header[0:8] = b"dex\n035\x00"

    struct.pack_into("<I", header, 32, file_size)
    struct.pack_into("<I", header, 36, header_size)
    struct.pack_into("<I", header, 40, 0x12345678)  # endian_tag
    struct.pack_into("<I", header, 44, 0)  # link_size
    struct.pack_into("<I", header, 48, 0)  # link_off
    struct.pack_into("<I", header, 52, map_off)

    struct.pack_into("<I", header, 56, string_ids_size)
    struct.pack_into("<I", header, 60, string_ids_off)

    struct.pack_into("<I", header, 64, type_ids_size)
    struct.pack_into("<I", header, 68, type_ids_off)

    struct.pack_into("<I", header, 72, proto_ids_size)
    struct.pack_into("<I", header, 76, proto_ids_off)

    struct.pack_into("<I", header, 80, field_ids_size)
    struct.pack_into("<I", header, 84, field_ids_off)

    struct.pack_into("<I", header, 88, method_ids_size)
    struct.pack_into("<I", header, 92, method_ids_off)

    struct.pack_into("<I", header, 96, class_defs_size)
    struct.pack_into("<I", header, 100, class_defs_off)

    struct.pack_into("<I", header, 104, data_size)
    struct.pack_into("<I", header, 108, data_off)

    # ----------------------------
    # Assemble file
    # ----------------------------
    blob = (
        bytes(header)
        + string_id_items
        + type_id_items
        + proto_id_items
        + method_id_items
        + class_def_item
    )
    if len(blob) > data_off:
        raise RuntimeError("layout bug: fixed sections exceed data_off")

    blob += b"\x00" * (data_off - len(blob))
    blob += bytes(data)

    if len(blob) != file_size:
        raise RuntimeError(f"layout bug: file_size mismatch {len(blob)} != {file_size}")

    # signature (SHA1 over bytes[32:])
    sig = hashlib.sha1(blob[32:]).digest()
    blob = bytearray(blob)
    blob[12:32] = sig

    # checksum (adler32 over bytes[12:])
    checksum = zlib.adler32(blob[12:]) & 0xFFFFFFFF
    struct.pack_into("<I", blob, 8, checksum)

    return bytes(blob)
