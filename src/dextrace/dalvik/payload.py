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
