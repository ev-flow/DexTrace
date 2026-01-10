# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from __future__ import annotations

import struct

from dextrace.core.dex_resolver import DexResolver
from dextrace.dalvik.disassembler import DalvikDisassembler
from tests.fixtures.dex_factory import build_minimal_test_dex


def _u16(buf: bytes, off: int) -> int:
    return struct.unpack_from("<H", buf, off)[0]


def _u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def _find_code_item_off_via_map_list(dex_bytes: bytes) -> int:
    """
    Find first code_item offset using map_list (type=0x2001).
    This avoids relying on DexParser private APIs and keeps the test deterministic.
    """
    # DEX header: map_off at 0x34 (52)
    map_off = _u32(dex_bytes, 0x34)
    if map_off <= 0 or map_off + 4 > len(dex_bytes):
        raise AssertionError(f"invalid map_off={map_off}")

    size = _u32(dex_bytes, map_off)
    p = map_off + 4

    # map_item: type(u2), unused(u2), size(u4), offset(u4)  => 12 bytes
    for _ in range(size):
        if p + 12 > len(dex_bytes):
            raise AssertionError("truncated map_list")
        typ = _u16(dex_bytes, p)
        # unused = _u16(dex_bytes, p + 2)
        # item_size = _u32(dex_bytes, p + 4)
        item_off = _u32(dex_bytes, p + 8)
        p += 12

        if typ == 0x2001:  # code_item
            if item_off <= 0 or item_off >= len(dex_bytes):
                raise AssertionError(f"invalid code_item off={item_off}")
            return int(item_off)

    raise AssertionError("code_item not found in map_list")


def test_disassemble_dummy_dex_minimal_sequence():
    dex_bytes = build_minimal_test_dex()

    resolver = DexResolver(dex_bytes)
    dis = DalvikDisassembler(dex_bytes=dex_bytes, resolver=resolver, accept_optimized=False)

    code_off = _find_code_item_off_via_map_list(dex_bytes)
    md = dis.disassemble_method(code_off)

    # We expect exactly these 4 insns in order (no payload in this minimal dex)
    got_mnemonics = [ins.mnemonic for ins in md.instructions]
    assert got_mnemonics[:4] == [
        "invoke-direct",
        "const-string",
        "invoke-virtual",
        "return-void",
    ]

    ins0, ins1, ins2, ins3 = md.instructions[:4]

    # ---- invoke-direct {v0}, Object.<init>()V ----
    assert ins0.index_type == "method-ref"
    assert ins0.param == "Ljava/lang/Object;-><init>()V"
    assert ins0.regs == ["v0"]

    # ---- const-string v1, "HELLO" ----
    assert ins1.index_type == "string-ref"
    assert ins1.param == "\"HELLO\""
    assert ins1.regs == ["v1"]

    # ---- invoke-virtual {v2,v1}, StringBuilder.append(String)StringBuilder ----
    assert ins2.index_type == "method-ref"
    assert ins2.param == "Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;"
    # regs order for 35c should keep {this, arg} => v2 then v1
    assert ins2.regs[:2] == ["v0", "v1"]

    # ---- return-void ----
    assert ins3.index_type is None
    assert ins3.param is None
    assert ins3.regs == []
