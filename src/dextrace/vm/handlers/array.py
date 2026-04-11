# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/handlers/array.py — Array operation stubs (P3+).

new-array, array-length, aget/aput families are not required for P1 or P2.
"""

from __future__ import annotations

from dextrace.dalvik.types import DecodedInsn
from dextrace.vm.errors import DexTraceNotImplementedError
from dextrace.vm.state import VMState

_ARRAY_OPS = [
    "new-array",
    "filled-new-array",
    "filled-new-array/range",
    "fill-array-data",
    "array-length",
    "aget",
    "aget-wide",
    "aget-object",
    "aget-boolean",
    "aget-byte",
    "aget-char",
    "aget-short",
    "aput",
    "aput-wide",
    "aput-object",
    "aput-boolean",
    "aput-byte",
    "aput-char",
    "aput-short",
]


def _stub(insn: DecodedInsn, state: VMState) -> None:
    raise DexTraceNotImplementedError(
        f"{insn.mnemonic} not implemented (pc={insn.uoff:#06x})"
    )


def register(eval_table: dict) -> None:
    for name in _ARRAY_OPS:
        eval_table[name] = _stub
