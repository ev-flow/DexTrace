# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/decoder.py — Week 1 static-walk adapter.

Thin wrapper over DalvikDisassembler + build_sig_to_codeoff_map.
cmd_trace.py imports only this module from vm/.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from dextrace.core.dex_resolver import DexResolver
from dextrace.core.dex_code_map import build_sig_to_codeoff_map
from dextrace.dalvik.disassembler import DalvikDisassembler
from dextrace.dalvik.opcode_table_builder import OpcodeInfo
from dextrace.dalvik.types import DecodedInsn


# DecoderTables: opcode -> OpcodeInfo, built once per DalvikVM instance (P1+).
# cmd_trace.py does not use this directly; it is here for the engine (P1).
DecoderTables = Dict[int, OpcodeInfo]


class MethodNotFound(Exception):
    """Raised when entry_sig is not present in the given DEX bytes."""


def walk_method(
    dex_bytes: bytes,
    entry_sig: str,
    resolver: Optional[DexResolver] = None,
) -> List[DecodedInsn]:
    """
    Static walk: decode every instruction in entry_sig without executing.

    Returns the list of DecodedInsn with indices resolved (method sigs,
    string literals, type names, field sigs).

    Raises MethodNotFound if entry_sig is not found in dex_bytes.
    """
    if resolver is None:
        resolver = DexResolver(dex_bytes)

    sig_to_codeoff = build_sig_to_codeoff_map(dex_bytes, resolver)
    code_off = sig_to_codeoff.get(entry_sig)

    if code_off is None:
        raise MethodNotFound(f"method not found: {entry_sig}")

    dis = DalvikDisassembler(dex_bytes=dex_bytes, resolver=resolver)
    method = dis.disassemble_method(code_off)
    return method.instructions
