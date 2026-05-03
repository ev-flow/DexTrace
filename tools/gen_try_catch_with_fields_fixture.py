#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pylint: disable=duplicate-code  # gen_pNN scripts share DEX builder boilerplate intentionally
"""
Build tests/fixtures/samples/p5a_x_p5d_npe.dex programmatically.

Cross-phase combo: P5d's null-receiver iget-object throws NPE, P5a's catch
walker resolves it via the seeded Java exception hierarchy, and the in-method
catch handler returns the sentinel 99.

Method:
  Lp5ad;->igetNpe()I  (static, no args)
    Object o = null;
    try {
      return o.ref;          // iget-object on null → NPE
    } catch (NullPointerException) {
      return 99;
    }

Verification:
  python -m dextrace run tests/fixtures/samples/p5a_x_p5d_npe.dex \\
      --entry 'Lp5ad;->igetNpe()I'
  # → return: 99
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


def _string_data_item(s: str) -> bytes:
    b = s.encode("utf-8")
    return _uleb128(len(s)) + b + b"\x00"


def build_dex() -> bytes:  # pylint: disable=too-many-locals,too-many-statements
    # Strings (sorted by MUTF-8 byte order — uppercase 'I'/'L' < lowercase 'i'/'r')
    strings = [
        "I",                                # 0  (also serves as shorty for ()I)
        "Ljava/lang/NullPointerException;", # 1
        "Ljava/lang/Object;",               # 2
        "Lp5ad;",                           # 3
        "igetNpe",                          # 4
        "ref",                              # 5
    ]
    # Types (sorted by string_idx).
    type_string_ids = [0, 1, 2, 3]  # 0=I, 1=NPE, 2=Object, 3=Lp5ad;
    protos = [(0, 0)]               # proto 0: shorty=str0 "I", return=type0 "I", no params

    # Field IDs.
    field_ids = [
        (3, 2, 5),  # field 0: Lp5ad;->ref:Ljava/lang/Object;
    ]

    method_ids = [(3, 0, 4)]        # Lp5ad;->igetNpe()I

    # Insns (10 code units — even, no pad before tries):
    #   pc=0  const/4 v0, #0                       (op 0x12, 11n,  1 unit)
    #   pc=1  iget-object v1, v0, field@0           (op 0x54, 22c,  2 units)  ← throws NPE
    #   pc=3  const/16 v0, #-1                     (op 0x13, 21s,  2 units)  ← unreachable
    #   pc=5  return v0                            (op 0x0f, 11x,  1 unit)
    #   pc=6  move-exception v1                    (op 0x0d, 11x,  1 unit)   ← catch entry
    #   pc=7  const/16 v0, #99                     (op 0x13, 21s,  2 units)
    #   pc=9  return v0                            (op 0x0f, 11x,  1 unit)
    insns = [
        0x0012,          # const/4 v0, #0  (B=0, A=0 → high byte 0x00; opcode 0x12)
        0x0154, 0x0000,  # iget-object v1, v0, field@0  (B=0,A=1 packed)
        0x0013, 0xFFFF,  # const/16 v0, #-1
        0x000F,          # return v0
        0x010D,          # move-exception v1
        0x0013, 0x0063,  # const/16 v0, #99
        0x000F,          # return v0
    ]
    assert len(insns) == 10

    # Try block: covers iget-object only (start=1, count=2).
    # encoded_catch_handler: typed_size=1, type=NPE (type_idx=1), addr=6.
    handlers_size_uleb = _uleb128(1)
    encoded_handler_off = len(handlers_size_uleb)  # = 1
    handlers_list = bytes(
        handlers_size_uleb
        + _sleb128(1)        # one typed catch, no catch-all
        + _uleb128(1)        # type_idx 1 = NPE
        + _uleb128(6)        # handler addr = move-exception at pc=6
    )
    try_item = struct.pack("<IHH", 1, 2, encoded_handler_off)

    # Layout
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

    data_off = (off + 3) & ~3

    data = bytearray()
    string_data_offs: list[int] = []
    for s in strings:
        string_data_offs.append(data_off + len(data))
        data.extend(_string_data_item(s))

    while (data_off + len(data)) % 4 != 0:
        data.append(0)

    code_off = data_off + len(data)
    # regs=2 (v0, v1), ins=0, outs=0, tries=1
    data.extend(struct.pack("<HHHHII", 2, 0, 0, 1, 0, len(insns)))
    data.extend(struct.pack("<" + "H" * len(insns), *insns))
    # insns_size=10 is even — no padding before tries.
    data.extend(try_item)
    data.extend(handlers_list)

    ACC_PUBLIC = 0x1
    ACC_STATIC = 0x8
    class_data_off = data_off + len(data)
    data.extend(
        _uleb128(0)                          # static_fields_size
        + _uleb128(1)                        # instance_fields_size (declares ref)
        + _uleb128(1)                        # direct_methods_size
        + _uleb128(0)                        # virtual_methods_size
        # instance field: delta=0 (ref = field_ids[0])
        + _uleb128(0) + _uleb128(ACC_PUBLIC)
        # direct method: delta=0
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
        _map_item(0x0004, len(field_ids), field_ids_off),
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
    # proto with no params: parameters_off = 0.
    proto_id_items = b"".join(
        struct.pack("<III", shorty_idx, return_type_idx, 0)
        for shorty_idx, return_type_idx in protos
    )
    field_id_items = b"".join(
        struct.pack("<HHI", cls_idx, type_idx, name_idx)
        for cls_idx, type_idx, name_idx in field_ids
    )
    method_id_items = b"".join(
        struct.pack("<HHI", cls_idx, proto_idx, name_idx)
        for cls_idx, proto_idx, name_idx in method_ids
    )
    class_def_items = struct.pack(
        "<IIIIIIII",
        3,            # class_idx: Lp5ad;
        ACC_PUBLIC,
        2,            # super: Object
        0,
        0xFFFFFFFF,
        0,
        class_data_off,
        0,
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
    dex = build_dex()
    out = (
        Path(__file__).parent.parent
        / "tests"
        / "fixtures"
        / "samples"
        / "p5a_x_p5d_npe.dex"
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(dex)
    print(f"wrote {out} ({len(dex)} bytes)")
