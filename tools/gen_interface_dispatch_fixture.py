#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pylint: disable=duplicate-code  # gen_pNN scripts share DEX builder boilerplate intentionally
"""
Build tests/fixtures/samples/p5f_interface.dex programmatically.

Class layout:
  Lp5f;
    direct  static callIFace()I    — entry point
    virtual         value()I       — returns 7

Method:
  Lp5f;->callIFace()I  (static)
    Lp5f obj = new Lp5f();
    return obj.value();             // invoke-interface dispatch on runtime class
  -> 7

Why this exercises invoke-interface:
  Dalvik's invoke-interface opcode resolves the callee at runtime via the
  receiver's actual class vtable. The static target descriptor in the insn
  doesn't have to be an interface — the engine treats invoke-interface and
  invoke-virtual identically (vtable lookup by name/proto). That's the
  correct behavior because in real DEX both forms reach the same dispatch.

Verification:
  dextrace run tests/fixtures/samples/p5f_interface.dex \\
      --entry 'Lp5f;->callIFace()I'
  # → return: 7
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
    # Strings (sorted by MUTF-8 byte order):
    # 'I'=0x49, 'L'=0x4C, 'c'=0x63, 'v'=0x76; within L, 'j' < 'p'.
    strings = [
        "I",                   # 0  (also serves as shorty for ()I)
        "Ljava/lang/Object;",  # 1
        "Lp5f;",               # 2
        "callIFace",           # 3
        "value",               # 4
    ]
    # type_string_ids[i] = string_idx for type i.
    type_string_ids = [0, 1, 2]  # 0=I, 1=Object, 2=Lp5f;
    protos = [(0, 0)]  # proto 0: shorty=str0 "I", return=type0 I, no params

    # Method IDs sorted by (class_idx, name_idx, proto_idx).
    # Both belong to Lp5f; (cls 2). "callIFace" (str3) < "value" (str4).
    method_ids = [
        (2, 0, 3),  # method 0: Lp5f;->callIFace()I
        (2, 0, 4),  # method 1: Lp5f;->value()I
    ]

    # ------------------------------------------------------------------
    # callIFace insns (7 code units)
    #   pc=0   new-instance v0, type@2 (Lp5f;)             21c, 2u
    #   pc=2   invoke-interface {v0}, method@1 (value()I)  35c, 3u
    #   pc=5   move-result v1                              11x, 1u
    #   pc=6   return v1                                   11x, 1u
    # ------------------------------------------------------------------
    callIFace_insns = [
        0x0022, 0x0002,           # new-instance v0, type@2
        0x1072, 0x0001, 0x0000,   # invoke-interface {v0}, method@1
        0x010A,                   # move-result v1
        0x010F,                   # return v1
    ]

    # ------------------------------------------------------------------
    # value insns (2 code units) — instance method, ins=1 (this in v0)
    # We never read this; const/4 v0 clobbers it before the return.
    #   pc=0   const/4 v0, #7    11n, 1u  (byte0=0x12, byte1=(7<<4)|0=0x70)
    #   pc=1   return v0         11x, 1u
    # ------------------------------------------------------------------
    value_insns = [
        0x7012,
        0x000F,
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

    data_off = (off + 3) & ~3

    data = bytearray()
    string_data_offs: list[int] = []
    for s in strings:
        string_data_offs.append(data_off + len(data))
        data.extend(_string_data_item(s))

    while (data_off + len(data)) % 4 != 0:
        data.append(0)

    # code_item callIFace
    callIFace_code_off = data_off + len(data)
    # regs=2 (v0,v1), ins=0, outs=1 (one-arg call to value), tries=0
    data.extend(struct.pack(
        "<HHHHII", 2, 0, 1, 0, 0, len(callIFace_insns)
    ))
    data.extend(struct.pack(
        "<" + "H" * len(callIFace_insns), *callIFace_insns
    ))

    while (data_off + len(data)) % 4 != 0:
        data.append(0)

    # code_item value
    value_code_off = data_off + len(data)
    # regs=1 (v0=this; clobbered by const/4), ins=1, outs=0, tries=0
    data.extend(struct.pack(
        "<HHHHII", 1, 1, 0, 0, 0, len(value_insns)
    ))
    data.extend(struct.pack(
        "<" + "H" * len(value_insns), *value_insns
    ))

    ACC_PUBLIC = 0x1
    ACC_STATIC = 0x8
    class_data_off = data_off + len(data)
    # encoded_method delta: direct list starts at 0; virtual list restarts at 0.
    # direct[0]: method@0 (callIFace) — delta 0
    # virtual[0]: method@1 (value)    — delta 1 from base 0
    data.extend(
        _uleb128(0)                          # static_fields_size
        + _uleb128(0)                        # instance_fields_size
        + _uleb128(1)                        # direct_methods_size
        + _uleb128(1)                        # virtual_methods_size
        # direct method: callIFace
        + _uleb128(0)
        + _uleb128(ACC_PUBLIC | ACC_STATIC)
        + _uleb128(callIFace_code_off)
        # virtual method: value
        + _uleb128(1)
        + _uleb128(ACC_PUBLIC)
        + _uleb128(value_code_off)
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
        _map_item(0x2001, 2, callIFace_code_off),
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
        / "p5f_interface.dex"
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(dex)
    print(f"wrote {out} ({len(dex)} bytes)")
