# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Callable, Optional, Tuple


# u16 idents (little-endian code units)
PACKED_SWITCH_PAYLOAD = 0x0100
SPARSE_SWITCH_PAYLOAD = 0x0200
FILL_ARRAY_DATA_PAYLOAD = 0x0300


@dataclass(frozen=True)
class PayloadInfo:
    kind: str
    start_uoff: int
    size_units: int  # total payload length in 16-bit units (including header)


@dataclass(frozen=True)
class PackedSwitchTable:
    """Decoded packed-switch payload.

    `first_key` is the key for `targets[0]`. `targets` are *relative* code-unit
    offsets from the switch instruction's pc — to compute the absolute branch
    target, the engine adds `targets[i]` to `switch_insn.uoff`.
    """

    first_key: int
    targets: Tuple[int, ...]


@dataclass(frozen=True)
class SparseSwitchTable:
    """Decoded sparse-switch payload.

    `keys` is sorted ascending. `targets[i]` is the relative offset for `keys[i]`.
    """

    keys: Tuple[int, ...]
    targets: Tuple[int, ...]


@dataclass(frozen=True)
class FillArrayDataTable:
    """Decoded fill-array-data payload.

    `element_width` is the per-element byte width (1, 2, 4, or 8). `elements`
    are decoded as Python ints (signed for widths 1/2/4/8 — the engine
    forwards them to the array list as-is; aput-style narrowing happens
    at read-time if the array's element width demands it).
    """

    element_width: int
    elements: Tuple[int, ...]


# ---------------------------------------------------------------------------
# Helpers used by decoders below
# ---------------------------------------------------------------------------


def _u16_at(insns_bytes: bytes, uoff: int) -> int:
    """Read u16 at code-unit offset uoff from raw insns bytes."""
    import struct as _s
    return _s.unpack_from("<H", insns_bytes, uoff * 2)[0]


def _s32_at(insns_bytes: bytes, uoff: int) -> int:
    """Read signed 32-bit value at code-unit offset uoff (= 2 u16 units)."""
    import struct as _s
    return _s.unpack_from("<i", insns_bytes, uoff * 2)[0]


# ---------------------------------------------------------------------------
# Decoders
# ---------------------------------------------------------------------------


def decode_packed_switch(insns_bytes: bytes, payload_uoff: int) -> PackedSwitchTable:
    """
    packed-switch-payload (4-byte aligned):
      ushort ident      = 0x0100
      ushort size       (number of targets)
      int    first_key
      int    targets[size]   (relative code-unit offsets from the switch insn)

    Raises ValueError if the ident byte doesn't match (defensive against
    miscalculated payload_uoff).
    """
    ident = _u16_at(insns_bytes, payload_uoff)
    if ident != PACKED_SWITCH_PAYLOAD:
        raise ValueError(
            f"packed-switch payload at uoff={payload_uoff:#x}: "
            f"expected ident 0x{PACKED_SWITCH_PAYLOAD:04x}, got 0x{ident:04x}"
        )
    size = _u16_at(insns_bytes, payload_uoff + 1)
    first_key = _s32_at(insns_bytes, payload_uoff + 2)
    targets = tuple(
        _s32_at(insns_bytes, payload_uoff + 4 + 2 * i) for i in range(size)
    )
    return PackedSwitchTable(first_key=first_key, targets=targets)


def decode_fill_array_data(
    insns_bytes: bytes, payload_uoff: int
) -> FillArrayDataTable:
    """
    fill-array-data-payload (4-byte aligned):
      ushort ident         = 0x0300
      ushort element_width (1, 2, 4, or 8 bytes per element)
      uint   size          (number of elements)
      ubyte  data[]        (element_width * size bytes; padded to even)

    Elements are decoded as signed Python ints. The engine writes them
    into a heap-backed list; aget-byte/short/char already store these as
    sign-extended 32-bit (or unsigned for char) so no further masking is
    needed here.
    """
    import struct as _s

    ident = _u16_at(insns_bytes, payload_uoff)
    if ident != FILL_ARRAY_DATA_PAYLOAD:
        raise ValueError(
            f"fill-array-data payload at uoff={payload_uoff:#x}: "
            f"expected ident 0x{FILL_ARRAY_DATA_PAYLOAD:04x}, got 0x{ident:04x}"
        )
    element_width = _u16_at(insns_bytes, payload_uoff + 1)
    size = _s.unpack_from("<I", insns_bytes, (payload_uoff + 2) * 2)[0]
    data_off_bytes = (payload_uoff + 4) * 2

    if element_width == 1:
        fmt = "<b"
    elif element_width == 2:
        fmt = "<h"
    elif element_width == 4:
        fmt = "<i"
    elif element_width == 8:
        fmt = "<q"
    else:
        raise ValueError(
            f"fill-array-data: unsupported element_width {element_width}"
        )
    elements = tuple(
        _s.unpack_from(fmt, insns_bytes, data_off_bytes + i * element_width)[0]
        for i in range(size)
    )
    return FillArrayDataTable(element_width=element_width, elements=elements)


def decode_sparse_switch(insns_bytes: bytes, payload_uoff: int) -> SparseSwitchTable:
    """
    sparse-switch-payload (4-byte aligned):
      ushort ident      = 0x0200
      ushort size
      int    keys[size]      (sorted ascending)
      int    targets[size]   (relative offsets — same indexing as keys)
    """
    ident = _u16_at(insns_bytes, payload_uoff)
    if ident != SPARSE_SWITCH_PAYLOAD:
        raise ValueError(
            f"sparse-switch payload at uoff={payload_uoff:#x}: "
            f"expected ident 0x{SPARSE_SWITCH_PAYLOAD:04x}, got 0x{ident:04x}"
        )
    size = _u16_at(insns_bytes, payload_uoff + 1)
    keys = tuple(
        _s32_at(insns_bytes, payload_uoff + 2 + 2 * i) for i in range(size)
    )
    targets = tuple(
        _s32_at(insns_bytes, payload_uoff + 2 + 2 * size + 2 * i)
        for i in range(size)
    )
    return SparseSwitchTable(keys=keys, targets=targets)


def detect_payload_ident(u16: int) -> Optional[str]:
    if u16 == PACKED_SWITCH_PAYLOAD:
        return "packed-switch-payload"
    if u16 == SPARSE_SWITCH_PAYLOAD:
        return "sparse-switch-payload"
    if u16 == FILL_ARRAY_DATA_PAYLOAD:
        return "fill-array-data-payload"
    return None


def payload_size_units(start_uoff, read_u16, read_u32, total_units):
    if start_uoff < 0 or start_uoff >= total_units:
        return None

    ident = read_u16(start_uoff)
    kind = detect_payload_ident(ident)
    if kind is None:
        return None

    # 4-byte alignment: payload should start at even uoff (each uoff=2 bytes)
    if (start_uoff % 2) != 0:
        return None

    if kind in ("packed-switch-payload", "sparse-switch-payload"):
        if start_uoff + 2 > total_units:
            return None

        size = int(read_u16(start_uoff + 1))
        if size < 0 or size > total_units:
            return None

        if kind == "packed-switch-payload":
            units = 4 + 2 * size
        else:
            units = 2 + 4 * size

        if start_uoff + units > total_units:
            return None
        return PayloadInfo(kind=kind, start_uoff=start_uoff, size_units=units)

    if kind == "fill-array-data-payload":
        if start_uoff + 4 > total_units:
            return None

        elem_width = int(read_u16(start_uoff + 1))
        size = int(read_u32(start_uoff + 2))

        if elem_width <= 0 or elem_width > 8:
            return None
        if size < 0 or size > (total_units * 2):  # 粗略上限（bytes）
            return None

        data_bytes = elem_width * size
        data_units = (data_bytes + 1) // 2
        units = 4 + data_units

        if start_uoff + units > total_units:
            return None
        return PayloadInfo(kind=kind, start_uoff=start_uoff, size_units=units)

    return None
