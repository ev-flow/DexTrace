# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""Unit tests for dalvik/payload.py — payload size + switch decoders."""

from __future__ import annotations

import struct

import pytest

from dextrace.core.dex_parser import DexCode
from dextrace.dalvik.payload import (
    PACKED_SWITCH_PAYLOAD,
    SPARSE_SWITCH_PAYLOAD,
    decode_packed_switch,
    decode_sparse_switch,
    payload_size_units,
)


# ---------------------------------------------------------------------------
# payload_size_units — packed-switch / fill-array-data
# ---------------------------------------------------------------------------


def test_packed_switch_payload_units():
    # packed-switch payload with size=2
    # ident=0x0100, size=2, first_key (2 units), targets[2] (4 units)
    # total units = 4 + 2*2 = 8
    units = [
        0x0100,
        0x0002,
        0x0000,
        0x0000,  # first_key = 0
        0x0001,
        0x0000,  # target0 = 1
        0x0002,
        0x0000,  # target1 = 2
    ]
    insns = struct.pack("<" + "H" * len(units), *units)
    DexCode(0, 0, 0, 0, 0, len(units), insns)

    def r16(i):
        return units[i]

    def r32(i):
        b = insns[i * 2 : i * 2 + 4]
        return struct.unpack("<I", b)[0]

    p = payload_size_units(0, r16, r32, len(units))
    assert p is not None
    assert p.size_units == 8


def test_fill_array_data_payload_units():
    # fill-array-data payload: ident=0x0300, elem_width=1, size=3
    # → 3 bytes data → ceil(3/2)=2 units → total units = 4 + 2 = 6
    units = [
        0x0300,
        0x0001,
        0x0003,
        0x0000,  # size u32 = 3
        0x1122,  # data bytes: 0x22 0x11
        0x0033,  # data bytes: 0x33 0x00 (padding)
    ]
    insns = struct.pack("<" + "H" * len(units), *units)
    DexCode(0, 0, 0, 0, 0, len(units), insns)

    def r16(i):
        return units[i]

    def r32(i):
        b = insns[i * 2 : i * 2 + 4]
        return struct.unpack("<I", b)[0]

    p = payload_size_units(0, r16, r32, len(units))
    assert p is not None
    assert p.size_units == 6


# ---------------------------------------------------------------------------
# Packed / sparse switch payload decoders
#
# Layout of code units in insns_bytes (each u16 = 2 bytes, little-endian):
#
#   packed-switch-payload:
#     [0]  ushort ident = 0x0100
#     [1]  ushort size
#     [2..3] int  first_key
#     [4..3+2*size] int targets[size]   (relative code-unit offsets)
#
#   sparse-switch-payload:
#     [0]  ushort ident = 0x0200
#     [1]  ushort size
#     [2..1+2*size]      int keys[size]      (sorted ascending)
#     [2+2*size..]       int targets[size]
# ---------------------------------------------------------------------------


def _pack_packed(first_key: int, targets: list[int]) -> bytes:
    return (
        struct.pack("<HH", PACKED_SWITCH_PAYLOAD, len(targets))
        + struct.pack("<i", first_key)
        + b"".join(struct.pack("<i", t) for t in targets)
    )


def _pack_sparse(keys: list[int], targets: list[int]) -> bytes:
    assert len(keys) == len(targets)
    return (
        struct.pack("<HH", SPARSE_SWITCH_PAYLOAD, len(keys))
        + b"".join(struct.pack("<i", k) for k in keys)
        + b"".join(struct.pack("<i", t) for t in targets)
    )


class TestPackedSwitchDecoder:
    def test_basic_four_entry_table(self):
        bytes_ = _pack_packed(first_key=0, targets=[5, 8, 11, 14])
        table = decode_packed_switch(bytes_, payload_uoff=0)
        assert table.first_key == 0
        assert table.targets == (5, 8, 11, 14)

    def test_negative_first_key(self):
        bytes_ = _pack_packed(first_key=-3, targets=[10, 20, 30])
        table = decode_packed_switch(bytes_, payload_uoff=0)
        assert table.first_key == -3
        assert table.targets == (10, 20, 30)

    def test_negative_targets_decode_signed(self):
        # targets are RELATIVE — they routinely point backwards (loops).
        bytes_ = _pack_packed(first_key=0, targets=[-4, -2])
        table = decode_packed_switch(bytes_, payload_uoff=0)
        assert table.targets == (-4, -2)

    def test_empty_payload(self):
        bytes_ = _pack_packed(first_key=42, targets=[])
        table = decode_packed_switch(bytes_, payload_uoff=0)
        assert table.first_key == 42
        assert table.targets == ()

    def test_wrong_ident_raises(self):
        # Plant a sparse ident where we ask for packed.
        bytes_ = _pack_sparse(keys=[1], targets=[10])
        with pytest.raises(ValueError, match="packed-switch payload"):
            decode_packed_switch(bytes_, payload_uoff=0)


class TestSparseSwitchDecoder:
    def test_basic_three_entry_table(self):
        bytes_ = _pack_sparse(keys=[1, 5, 100], targets=[10, 20, 30])
        table = decode_sparse_switch(bytes_, payload_uoff=0)
        assert table.keys == (1, 5, 100)
        assert table.targets == (10, 20, 30)

    def test_negative_keys_and_targets(self):
        bytes_ = _pack_sparse(keys=[-100, -1, 0, 7], targets=[2, 4, -8, -16])
        table = decode_sparse_switch(bytes_, payload_uoff=0)
        assert table.keys == (-100, -1, 0, 7)
        assert table.targets == (2, 4, -8, -16)

    def test_empty_payload(self):
        bytes_ = _pack_sparse(keys=[], targets=[])
        table = decode_sparse_switch(bytes_, payload_uoff=0)
        assert table.keys == ()
        assert table.targets == ()

    def test_wrong_ident_raises(self):
        bytes_ = _pack_packed(first_key=0, targets=[1])
        with pytest.raises(ValueError, match="sparse-switch payload"):
            decode_sparse_switch(bytes_, payload_uoff=0)


class TestPayloadOffset:
    def test_decoder_respects_nonzero_payload_uoff(self):
        # Pad with one u16 in front so payload starts at uoff=1.
        prefix = b"\x42\x42"  # one u16 of garbage
        body = _pack_packed(first_key=10, targets=[100, 200])
        bytes_ = prefix + body
        table = decode_packed_switch(bytes_, payload_uoff=1)
        assert table.first_key == 10
        assert table.targets == (100, 200)
