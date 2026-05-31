# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
core/dex_class_iter.py — Shared class_def and encoded_method iteration.

Used by class_hierarchy.py (vtable builder) and any code that needs to walk
class defs without going through the full DexCodeMap pipeline.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterable, Optional, Tuple

NO_SUPERCLASS: int = 0xFFFFFFFF


@dataclass(frozen=True)
class ClassDefItem:
    class_idx: int
    superclass_idx: int  # NO_SUPERCLASS if no explicit superclass
    class_data_off: int  # 0 if class has no body (interface/abstract stub)


@dataclass(frozen=True)
class EncodedMethod:
    method_idx: int
    access_flags: int
    code_off: int  # 0 = abstract (no implementation)
    is_virtual: bool


def iter_class_defs(dex_bytes: bytes) -> Iterable[ClassDefItem]:
    """
    Yield ClassDefItem for every class_def_item in the DEX.

    class_def_item layout (32 bytes, little-endian u32 each field):
      [0]  class_idx
      [4]  access_flags
      [8]  superclass_idx       (NO_INDEX = 0xFFFFFFFF means no superclass)
      [12] interfaces_off
      [16] source_file_idx
      [20] annotations_off
      [24] class_data_off       (0 means no class_data_item)
      [28] static_values_off
    """
    size = len(dex_bytes)
    if size < 0x70:
        return

    class_defs_size = _u32(dex_bytes, size, 96)   # header offset 0x60
    class_defs_off = _u32(dex_bytes, size, 100)   # header offset 0x64
    if class_defs_size is None or class_defs_off is None:
        return

    for i in range(int(class_defs_size)):
        off = int(class_defs_off) + i * 32
        if off + 32 > size:
            break

        class_idx = _u32(dex_bytes, size, off)
        superclass_idx = _u32(dex_bytes, size, off + 8)
        class_data_off = _u32(dex_bytes, size, off + 24)

        if class_idx is None or superclass_idx is None or class_data_off is None:
            break

        yield ClassDefItem(
            class_idx=int(class_idx),
            superclass_idx=int(superclass_idx),
            class_data_off=int(class_data_off),
        )


def iter_class_data_methods(
    dex_bytes: bytes, class_data_off: int
) -> Iterable[EncodedMethod]:
    """
    Parse a class_data_item and yield EncodedMethod for every direct and
    virtual method in order.

    class_data_item:
      uleb128 static_fields_size
      uleb128 instance_fields_size
      uleb128 direct_methods_size
      uleb128 virtual_methods_size
      encoded_field[static_fields_size]
      encoded_field[instance_fields_size]
      encoded_method[direct_methods_size]    -- is_virtual=False
      encoded_method[virtual_methods_size]   -- is_virtual=True

    Each encoded_method:
      uleb128 method_idx_diff   (accumulated; virtual section resets to 0)
      uleb128 access_flags
      uleb128 code_off          (0 = abstract)
    """
    size = len(dex_bytes)
    p = class_data_off
    if p <= 0 or p >= size:
        return

    static_fields_size, p = _read_uleb128(dex_bytes, size, p)
    instance_fields_size, p = _read_uleb128(dex_bytes, size, p)
    direct_methods_size, p = _read_uleb128(dex_bytes, size, p)
    virtual_methods_size, p = _read_uleb128(dex_bytes, size, p)
    if p is None:
        return

    # Skip encoded_field entries (2 uleb128s each)
    for _ in range(
        int(static_fields_size or 0) + int(instance_fields_size or 0)
    ):
        _, p = _read_uleb128(dex_bytes, size, p)
        if p is None:
            return
        _, p = _read_uleb128(dex_bytes, size, p)
        if p is None:
            return

    # Direct methods
    method_idx = 0
    for _ in range(int(direct_methods_size or 0)):
        diff, p = _read_uleb128(dex_bytes, size, p)
        if p is None:
            return
        method_idx += int(diff or 0)

        access_flags, p = _read_uleb128(dex_bytes, size, p)
        if p is None:
            return

        code_off, p = _read_uleb128(dex_bytes, size, p)
        if p is None:
            return

        yield EncodedMethod(
            method_idx=method_idx,
            access_flags=int(access_flags or 0),
            code_off=int(code_off or 0),
            is_virtual=False,
        )

    # Virtual methods (accumulator resets)
    method_idx = 0
    for _ in range(int(virtual_methods_size or 0)):
        diff, p = _read_uleb128(dex_bytes, size, p)
        if p is None:
            return
        method_idx += int(diff or 0)

        access_flags, p = _read_uleb128(dex_bytes, size, p)
        if p is None:
            return

        code_off, p = _read_uleb128(dex_bytes, size, p)
        if p is None:
            return

        yield EncodedMethod(
            method_idx=method_idx,
            access_flags=int(access_flags or 0),
            code_off=int(code_off or 0),
            is_virtual=True,
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _u32(data: bytes, size: int, off: int) -> Optional[int]:
    if off < 0 or off + 4 > size:
        return None
    return struct.unpack_from("<I", data, off)[0]


def _read_uleb128(
    data: bytes, size: int, off: int
) -> Tuple[Optional[int], Optional[int]]:
    """Return (value, next_offset). On truncation returns (None, None)."""
    if off < 0 or off >= size:
        return None, None

    value = 0
    shift = 0
    p = off

    for _ in range(5):
        if p >= size:
            return None, None
        b = data[p]
        p += 1
        value |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return value, p
        shift += 7

    return None, None
