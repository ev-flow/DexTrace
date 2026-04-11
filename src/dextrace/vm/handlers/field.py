# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/handlers/field.py — Field access stubs (P3+).

iget/iput/sget/sput families are not required for P1 or P2.
All handlers raise DexTraceNotImplementedError so the engine surfaces a
clear message instead of a KeyError on the dispatch table.
"""

from __future__ import annotations

from dextrace.dalvik.types import DecodedInsn
from dextrace.vm.errors import DexTraceNotImplementedError
from dextrace.vm.state import VMState

_FIELD_OPS = [
    "iget",
    "iget-wide",
    "iget-object",
    "iget-boolean",
    "iget-byte",
    "iget-char",
    "iget-short",
    "iput",
    "iput-wide",
    "iput-object",
    "iput-boolean",
    "iput-byte",
    "iput-char",
    "iput-short",
    "sget",
    "sget-wide",
    "sget-object",
    "sget-boolean",
    "sget-byte",
    "sget-char",
    "sget-short",
    "sput",
    "sput-wide",
    "sput-object",
    "sput-boolean",
    "sput-byte",
    "sput-char",
    "sput-short",
]


def _stub(insn: DecodedInsn, state: VMState) -> None:
    raise DexTraceNotImplementedError(
        f"{insn.mnemonic} not implemented (pc={insn.uoff:#06x})"
    )


def register(eval_table: dict) -> None:
    for name in _FIELD_OPS:
        eval_table[name] = _stub
