# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/int_ops.py — 32-bit integer helpers used by arithmetic handlers.

Shift contracts:
  shl-int:  i32(u32(a) << (b & 0x1F))
  shr-int:  i32(a) >> (b & 0x1F)          — arithmetic (sign-extends)
  ushr-int: u32(a) >> (b & 0x1F)          — logical (zero-fills), result always >= 0
"""

from __future__ import annotations


def i32(v: int) -> int:
    """Truncate to 32 bits then sign-extend to Python int."""
    v &= 0xFFFF_FFFF
    if v >= 0x8000_0000:
        v -= 0x1_0000_0000
    return v


def u32(v: int) -> int:
    """Truncate to unsigned 32 bits."""
    return v & 0xFFFF_FFFF


def reg_index(r: str) -> int:
    """Convert Dalvik register name 'v0', 'v12', 'p0' to integer index."""
    return int(r[1:])
