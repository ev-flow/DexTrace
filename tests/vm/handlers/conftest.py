# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""Shared helpers for vm/handlers/ unit tests."""

from __future__ import annotations

import struct

from dextrace.dalvik.types import DecodedInsn
from dextrace.vm.register_file import RegisterFile
from dextrace.vm.state import VMState


def make_insn(regs, param=None, uoff=0, target_uoff=None, fmt="23x"):
    return DecodedInsn(
        uoff=uoff,
        byte_off=uoff * 2,
        opcode=0x00,
        mnemonic="test",
        fmt=fmt,
        size_units=2,
        regs=list(regs),
        param=param,
        target_uoff=target_uoff,
    )


def make_state(*values, size=None):
    # Default to 8 so wide-register tests (which write v4:v5 pairs) work
    # without each test needing to pass size=. Tests that need more must
    # pass size= explicitly.
    n = size if size is not None else max(len(values), 8)
    rf = RegisterFile(n)
    for i, v in enumerate(values):
        rf.set(i, v)
    return VMState(registers=rf, pc=0)


def float_bits(f: float) -> int:
    return struct.unpack(">I", struct.pack(">f", f))[0]


def double_bits(f: float) -> int:
    return struct.unpack(">Q", struct.pack(">d", f))[0]
