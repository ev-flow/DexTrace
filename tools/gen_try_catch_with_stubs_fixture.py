#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pylint: disable=duplicate-code  # gen_pNN scripts share DEX builder boilerplate intentionally
"""
Build tests/fixtures/samples/try_catch_with_stubs.dex programmatically.

This is a P5a × stub-throws cross-phase combo: a stub raises
_ThrowSignal(IOException) and the in-method catch block recovers it. Verifies
the engine's `_invoke_stub` allowlist correctly lets _ThrowSignal pass through
instead of wrapping it as a generic stub-failed VM error.

Method:
  Lp5x;->openCatch()I  (static)
    try   { Ldemo/Net;->openConnection(); return 0 }
    catch (Ljava/io/IOException;) { return 1 }
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


def build_try_catch_with_stubs_dex() -> bytes:  # pylint: disable=too-many-locals,too-many-statements
    # Strings (sorted by MUTF-8)
    #  0: "I"
    #  1: "Ldemo/Net;"
    #  2: "Ljava/io/IOException;"
    #  3: "Ljava/lang/Object;"
    #  4: "Lp5x;"
    #  5: "V"
    #  6: "openCatch"
    #  7: "openConnection"
    strings = [
        "I",
        "Ldemo/Net;",
        "Ljava/io/IOException;",
        "Ljava/lang/Object;",
        "Lp5x;",
        "V",
        "openCatch",
        "openConnection",
    ]

    # type_ids (sorted by string_idx)
    type_string_ids = [0, 1, 2, 3, 4, 5]

    # protos
    #  proto 0: ()I  shorty=str0, return_type=type0
    #  proto 1: ()V  shorty=str5, return_type=type5
    protos = [(0, 0), (5, 5)]

    # method_ids (sorted by class_idx, then name_idx, then proto_idx)
    #  method 0: Ldemo/Net;->openConnection()V    class=1, name=7, proto=1
    #  method 1: Lp5x;->openCatch()I              class=4, name=6, proto=0
    method_ids = [(1, 1, 7), (4, 0, 6)]

    # ----------------------------------------------------------------------
    # openCatch() insns (8 code units)
    #
    #   pc=0x0000  invoke-static {}, method@0  (op 0x71 fmt 35c, 3 units)
    #              A=0 args, G=0 → word0 = 0x0071
    #              word1 = method_idx (0)
    #              word2 = 0 (no regs)
    #   pc=0x0003  const/4 v0, #0              (op 0x12, A=0, B=0)
    #   pc=0x0004  return v0                   (op 0x0f, AA=0)
    #   pc=0x0005  move-exception v1           (op 0x0d, AA=1)
    #   pc=0x0006  const/4 v0, #1              (op 0x12, A=0, B=1)
    #   pc=0x0007  return v0                   (op 0x0f, AA=0)
    # ----------------------------------------------------------------------
    insns = [
        0x0071,  # invoke-static, A=0
        0x0000,  # method_idx = 0
        0x0000,  # no regs
        0x0012,  # const/4 v0, #0
        0x000F,  # return v0
        0x010D,  # move-exception v1
        0x1012,  # const/4 v0, #1
        0x000F,  # return v0
    ]

    # try region: pc 0..4 inclusive (invoke-static (3 units) + const/4 + return)
    handlers_size_uleb = _uleb128(1)
    encoded_handler_off = len(handlers_size_uleb)  # = 1
    handlers_list = bytes(
        handlers_size_uleb
        + _sleb128(1)            # one typed catch
        + _uleb128(2)            # type_idx for Ljava/io/IOException;
        + _uleb128(5)            # handler addr (move-exception at pc=5)
    )
    try_item = struct.pack("<IHH", 0, 5, encoded_handler_off)

    # ----------------------------------------------------------------------
    # Layout
    # ----------------------------------------------------------------------
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

    code_off = data_off + len(data)
    # regs=2, ins=0, outs=0 (invoke-static {} has 0 outs), tries=1
    data.extend(struct.pack("<HHHHII", 2, 0, 0, 1, 0, len(insns)))
    data.extend(struct.pack("<" + "H" * len(insns), *insns))
    # insns_size=8 even — no padding
    data.extend(try_item)
    data.extend(handlers_list)

    ACC_PUBLIC = 0x1
    ACC_STATIC = 0x8
    class_data_off = data_off + len(data)
    data.extend(
        _uleb128(0)
        + _uleb128(0)
        + _uleb128(1)            # one direct method
        + _uleb128(0)
        + _uleb128(1)            # method_idx_diff = 1 (Lp5x;->openCatch is method_id 1)
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

    # ----------------------------------------------------------------------
    # ID sections
    # ----------------------------------------------------------------------
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

    # class_def for Lp5x; (class=4, super=type3 Object)
    class_def_items = struct.pack(
        "<IIIIIIII",
        4,
        ACC_PUBLIC,
        3,                # superclass = Ljava/lang/Object; (type 3)
        0,
        0xFFFFFFFF,
        0,
        class_data_off,
        0,
    )

    # ----------------------------------------------------------------------
    # Header
    # ----------------------------------------------------------------------
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
    dex = build_try_catch_with_stubs_dex()
    out = (
        Path(__file__).parent.parent
        / "tests"
        / "fixtures"
        / "samples"
        / "try_catch_with_stubs.dex"
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(dex)
    print(f"wrote {out} ({len(dex)} bytes)")
