# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/int_ops.py — 32/64-bit integer + IEEE 754 helpers used by arithmetic handlers.

Shift contracts:
  shl-int:   i32(u32(a) << (b & 0x1F))
  shr-int:   i32(a) >> (b & 0x1F)          — arithmetic (sign-extends)
  ushr-int:  u32(a) >> (b & 0x1F)          — logical (zero-fills), result always >= 0
  shl-long:  i64(a << (b & 0x3F))           — long shift count is 6 bits
  shr-long:  i64(a) >> (b & 0x3F)
  ushr-long: u64(a) >> (b & 0x3F)

Float helpers convert between IEEE 754 bit patterns (as stored in registers)
and Python floats (used inside the handler) via the struct module.
"""

from __future__ import annotations

import struct


def i32(v: int) -> int:
    """Truncate to 32 bits then sign-extend to Python int."""
    v &= 0xFFFF_FFFF
    if v >= 0x8000_0000:
        v -= 0x1_0000_0000
    return v


def u32(v: int) -> int:
    """Truncate to unsigned 32 bits."""
    return v & 0xFFFF_FFFF


def i64(v: int) -> int:
    """Truncate to 64 bits then sign-extend."""
    v &= 0xFFFF_FFFF_FFFF_FFFF
    if v >= 0x8000_0000_0000_0000:
        v -= 0x1_0000_0000_0000_0000
    return v


def u64(v: int) -> int:
    """Truncate to unsigned 64 bits."""
    return v & 0xFFFF_FFFF_FFFF_FFFF


def f32_to_bits(f: float) -> int:
    """Encode a Python float as a 32-bit IEEE 754 bit pattern (uint32)."""
    return struct.unpack("<I", struct.pack("<f", f))[0]


def bits_to_f32(bits: int) -> float:
    """Decode a 32-bit IEEE 754 bit pattern (uint32) to a Python float."""
    return struct.unpack("<f", struct.pack("<I", bits & 0xFFFF_FFFF))[0]


def f64_to_bits(f: float) -> int:
    """Encode a Python float as a 64-bit IEEE 754 bit pattern (uint64)."""
    return struct.unpack("<Q", struct.pack("<d", f))[0]


def bits_to_f64(bits: int) -> float:
    """Decode a 64-bit IEEE 754 bit pattern (uint64) to a Python float."""
    return struct.unpack("<d", struct.pack("<Q", bits & 0xFFFF_FFFF_FFFF_FFFF))[0]


def reg_index(r: str) -> int:
    """Convert Dalvik register name 'v0', 'v12', 'p0' to integer index."""
    return int(r[1:])
