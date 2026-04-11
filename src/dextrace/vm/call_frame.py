# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/call_frame.py — Call frame saved at invoke time.

caller_registers is ALWAYS a snapshot (never a live reference).
caller_code_off is used by the engine to restore instruction lookup on return.
"""

from __future__ import annotations

from dataclasses import dataclass

from dextrace.vm.register_file import RegisterFile


@dataclass
class CallFrame:
    return_pc: int
    method_desc: str
    caller_registers: RegisterFile  # always a snapshot
    caller_code_off: int  # engine uses this to restore insn lookup
