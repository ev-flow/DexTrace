# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterable, List, Tuple, Iterator


# ----------------------------------------------------------------------
# Exceptions
# ----------------------------------------------------------------------
class DexFormatError(ValueError):
    """Raised when DEX bytecode format is invalid."""


@dataclass(frozen=True)
class DexCode:
    """DEX code_item structure (no try/catch decoding yet)."""

    registers_size: int
    ins_size: int
    outs_size: int
    tries_size: int
    debug_info_off: int
    insns_size: int              # in 16-bit code units
    insns: bytes                 # raw instruction bytes


# ----------------------------------------------------------------------
# Parser
# ----------------------------------------------------------------------
class DexParser:
    """
    DEX bytecode parser focused on code_item.
    Disassembly/format decoding is handled in dextrace.dalvik.
    """

    def __init__(self, dex_data: bytes) -> None:
        self._data = dex_data
        self._size = len(dex_data)

    # ------------------------------------------------------------------
    # code_item parsing
    # ------------------------------------------------------------------
    def parse_code_item(self, offset: int) -> DexCode:
        """
        Parse a code_item at given offset.

        code_item format:
            ushort registers_size
            ushort ins_size
            ushort outs_size
            ushort tries_size
            uint   debug_info_off
            uint   insns_size
            ushort insns[insns_size]
        """

        if offset < 0 or offset + 16 > self._size:
            raise DexFormatError("Invalid code_item offset")

        try:
            (
                registers_size,
                ins_size,
                outs_size,
                tries_size,
                debug_info_off,
                insns_size,
            ) = struct.unpack_from("<HHHHII", self._data, offset)
        except struct.error as err:
            raise DexFormatError("Failed to unpack code_item header") from err

        insns_off = offset + 16
        insns_bytes = int(insns_size) * 2

        if insns_off + insns_bytes > self._size:
            raise DexFormatError("code_item instruction area truncated")

        insns = self._data[insns_off: insns_off + insns_bytes]

        return DexCode(
            registers_size=int(registers_size),
            ins_size=int(ins_size),
            outs_size=int(outs_size),
            tries_size=int(tries_size),
            debug_info_off=int(debug_info_off),
            insns_size=int(insns_size),
            insns=insns,
        )

    def read_code_units(self, code: DexCode) -> List[int]:
        """
        Return all 16-bit code units as a list (little-endian).
        Length == code.insns_size.
        """
        expected = code.insns_size * 2
        if len(code.insns) != expected:
            raise DexFormatError(
                f"insns length mismatch: got={len(code.insns)} expected={expected}"
            )

        if code.insns_size == 0:
            return []

        # struct unpack expects an int count
        return list(struct.unpack_from(f"<{int(code.insns_size)}H", code.insns, 0))

    def iter_code_units(self, code: DexCode) -> Iterable[Tuple[int, int]]:
        """
        Yield (uoff, u16) where uoff is offset in 16-bit code units.
        """
        for i, u in enumerate(self.read_code_units(code)):
            yield i, u

    def iter_code_units_fast(self, code: DexCode) -> Iterator[Tuple[int, int]]:
        """
        Yield (uoff, u16) without allocating a list.
        Prefer this for very large methods.
        """
        expected = code.insns_size * 2
        if len(code.insns) != expected:
            raise DexFormatError(
                f"insns length mismatch: got={len(code.insns)} expected={expected}"
            )

        for i in range(int(code.insns_size)):
            yield i, struct.unpack_from("<H", code.insns, i * 2)[0]


    def parse_code_item_at(self, offset: int) -> Tuple[DexCode, int]:
        """Return (code, insns_off) where insns_off == offset + 16."""
        code = self.parse_code_item(offset)
        return code, offset + 16
