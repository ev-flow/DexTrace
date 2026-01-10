# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


import re
import struct

from dextrace.core.dex_resolver import DexResolver
from dextrace.dalvik.disassembler import DalvikDisassembler
from tests.fixtures.dex_factory import build_minimal_test_dex


def _find_code_item_off_via_map_list(dex_bytes: bytes) -> int:
    # header.map_off is at file offset 52 (0x34)
    map_off = struct.unpack_from("<I", dex_bytes, 52)[0]
    if map_off <= 0:
        raise RuntimeError("map_off=0")

    size = struct.unpack_from("<I", dex_bytes, map_off)[0]
    p = map_off + 4

    # map_item: u2 type, u2 unused, u4 size, u4 offset  => 12 bytes
    code_item_type = 0x2001

    for _ in range(size):
        t, _unused, _sz, off = struct.unpack_from("<HHII", dex_bytes, p)
        p += 12
        if t == code_item_type:
            return int(off)

    raise RuntimeError("code_item not found in map_list")


def test_disassembler_outputs_smali_hex_and_context_prev_next_1():
    dex_bytes = build_minimal_test_dex()
    resolver = DexResolver(dex_bytes)
    dis = DalvikDisassembler(dex_bytes=dex_bytes, resolver=resolver, accept_optimized=False)

    code_off = _find_code_item_off_via_map_list(dex_bytes)
    md = dis.disassemble_method(code_off)

    insns = md.instructions
    assert len(insns) >= 4

    ins0, ins1, ins2, ins3 = insns[:4]

    # --- mnemonics expected (same as your e2e) ---
    assert [x.mnemonic for x in insns[:4]] == [
        "invoke-direct",
        "const-string",
        "invoke-virtual",
        "return-void",
    ]

    # --- smali must be resolved (method/string) ---
    assert ins0.smali == "invoke-direct {v0}, Ljava/lang/Object;-><init>()V"
    assert ins1.smali == 'const-string v1, "HELLO"'
    assert ins2.smali == "invoke-virtual {v0,v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;"
    assert ins3.smali == "return-void"

    # --- hex formatting: space-separated pairs ---
    hex_re = re.compile(r"^[0-9a-f]{2}( [0-9a-f]{2})*$")
    assert hex_re.match(ins0.raw_hex)
    assert hex_re.match(ins1.raw_hex)
    assert hex_re.match(ins2.raw_hex)
    assert hex_re.match(ins3.raw_hex)

    # strong checks for two well-known instructions
    assert ins0.raw_hex == "70 10 00 00 00 00"   # invoke-direct 35c (3 units => 6 bytes)
    assert ins3.raw_hex == "0e 00"               # return-void 10x (1 unit => 2 bytes)

    # --- context prev/next 1 ---
    # ins0 has only next
    assert ins0.ctx_smali == [f"{ins1.uoff:04x}: {ins1.smali}"]

    # ins3 has only prev
    assert ins3.ctx_smali == [f"{ins2.uoff:04x}: {ins2.smali}"]

    # middle ones have both
    assert ins1.ctx_smali == [
        f"{ins0.uoff:04x}: {ins0.smali}",
        f"{ins2.uoff:04x}: {ins2.smali}",
    ]
    assert ins2.ctx_smali == [
        f"{ins1.uoff:04x}: {ins1.smali}",
        f"{ins3.uoff:04x}: {ins3.smali}",
    ]
