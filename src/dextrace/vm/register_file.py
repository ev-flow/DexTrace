# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/register_file.py — Dalvik register file.

Registers are 32-bit slots. Wide values (long/double) occupy a pair vN:vN+1
where vN holds the low 32 bits and vN+1 holds the high 32 bits.

Bounds: get/set raise DexTraceVMError on out-of-range index.
"""

from __future__ import annotations

from typing import List

from dextrace.vm.errors import DexTraceVMError


class RegisterFile:
    def __init__(self, size: int) -> None:
        self._regs: List[int] = [0] * size

    def __len__(self) -> int:
        return len(self._regs)

    def _check(self, n: int) -> None:
        if n < 0 or n >= len(self._regs):
            raise DexTraceVMError(
                f"register v{n} out of range (frame size={len(self._regs)})"
            )

    def get(self, n: int) -> int:
        self._check(n)
        return self._regs[n]

    def set(self, n: int, v: int) -> None:
        self._check(n)
        self._regs[n] = v

    def get_wide(self, n: int) -> int:
        """Return 64-bit value: low 32 in vN, high 32 in vN+1."""
        self._check(n)
        self._check(n + 1)
        lo = self._regs[n] & 0xFFFF_FFFF
        hi = self._regs[n + 1] & 0xFFFF_FFFF
        return (hi << 32) | lo

    def set_wide(self, n: int, v: int) -> None:
        """Store 64-bit value: low 32 in vN, high 32 in vN+1."""
        self._check(n)
        self._check(n + 1)
        self._regs[n] = v & 0xFFFF_FFFF
        self._regs[n + 1] = (v >> 32) & 0xFFFF_FFFF

    def snapshot(self) -> "RegisterFile":
        """Return a new RegisterFile with copied register values (shallow int copy)."""
        snap = RegisterFile(len(self._regs))
        snap._regs = list(self._regs)  # pylint: disable=protected-access
        return snap
