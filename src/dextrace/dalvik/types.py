# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, FrozenSet, List


@dataclass(frozen=True)
class WalkItem:
    uoff: int                 # code-unit offset
    opcode: int               # low byte
    u16: int                  # raw first code unit
    mnemonic: str             # OpcodeInfo.name or placeholder
    fmt: Optional[str]        # OpcodeInfo.fmt
    size_units: int
    flags: FrozenSet[str]
    kind: str                 # "insn" | "payload" | "unknown" | "error"
    note: str = ""
    raw_hex: str = ""         # bytes of this instruction/payload region (optional)


@dataclass(frozen=True)
class DecodedInsn:
    uoff: int
    byte_off: int
    opcode: int
    mnemonic: str
    fmt: str
    size_units: int
    regs: List[str]
    param: Optional[str] = None     # resolved string/method/type/field OR literal as str
    index: Optional[int] = None     # raw index (before resolving)
    index_type: Optional[str] = None
    flags: FrozenSet[str] = frozenset()
    raw_hex: str = ""               # hex bytes for this instruction (space-separated)
    smali: str = ""                 # one-line smali (rendered)
    ctx_smali: List[str] = field(default_factory=list)  # prev/next context lines "0000: ..."

    note: str = ""
    target_uoff: Optional[int] = None
