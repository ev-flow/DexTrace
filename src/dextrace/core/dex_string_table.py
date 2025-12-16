# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from __future__ import annotations

import functools
import struct
from dataclasses import dataclass
from typing import Iterator, List, Optional, Tuple

from .dex_header import DexHeader


class DexFormatError(ValueError):
    """Raised when DEX format is invalid or truncated."""


@dataclass(frozen=True)
class DexStringId:
    """string_id_item { uint string_data_off; }"""
    string_data_off: int


class DexStringTable:
    """
    DEX string table reader.

    Reads:
      - string_ids section (array of string_id_item)
      - string_data_item at string_data_off:
          uleb128 utf16_size
          ubyte   data[]  (MUTF-8 / Modified UTF-8), null-terminated
    """

    def __init__(self, dex_data: bytes, header: DexHeader) -> None:
        self._data = dex_data
        self._size = len(dex_data)
        self._header = header

        self._string_ids: List[DexStringId] = []
        self._parse_string_ids()

    def __len__(self) -> int:
        return len(self._string_ids)

    def __iter__(self) -> Iterator[str]:
        for i in range(len(self)):
            s = self.get(i)
            yield s if s is not None else ""

    def _parse_string_ids(self) -> None:
        count = int(self._header.string_ids_size)
        offset = int(self._header.string_ids_off)

        if count == 0:
            self._string_ids = []
            return

        needed = offset + count * 4
        if offset < 0 or needed > self._size:
            raise DexFormatError("string_ids section out of range")

        string_ids: List[DexStringId] = []
        for i in range(count):
            (string_data_off,) = struct.unpack_from("<I", self._data, offset + i * 4)
            string_ids.append(DexStringId(string_data_off=string_data_off))

        self._string_ids = string_ids

    @functools.lru_cache(maxsize=4096)
    def get(self, index: int) -> Optional[str]:
        """Get decoded string by string_idx."""
        if index < 0 or index >= len(self._string_ids):
            return None

        off = self._string_ids[index].string_data_off
        if off <= 0 or off >= self._size:
            return None

        try:
            _utf16_size, adv = self._read_uleb128(off)
        except DexFormatError:
            return None

        data_off = off + adv
        raw = self._read_cstring(data_off)
        if raw is None:
            return None

        return self._decode_mutf8(raw)

    def _read_cstring(self, offset: int) -> Optional[bytes]:
        """Read null-terminated byte string starting at offset."""
        if offset < 0 or offset >= self._size:
            return None

        end = self._data.find(b"\x00", offset)
        if end == -1:
            return None
        return self._data[offset:end]

    def _decode_mutf8(self, raw: bytes) -> str:
        """
        Decode DEX "modified UTF-8" (MUTF-8).

        Practical handling:
          - DEX uses MUTF-8 for strings, where null may appear as 0xC0 0x80.
          - For API/class/method names this is almost always plain ASCII/UTF-8.
          - We still normalize 0xC0 0x80 -> 0x00 for correctness.
        """
        if not raw:
            return ""

        normalized = raw.replace(b"\xC0\x80", b"\x00")
        try:
            return normalized.decode("utf-8", errors="replace")
        except UnicodeDecodeError:
            # last resort: keep it best-effort
            return normalized.decode("latin-1", errors="replace")

    def _read_uleb128(self, offset: int) -> Tuple[int, int]:
        """
        Read unsigned LEB128 at offset.
        Returns: (value, bytes_consumed)
        """
        if offset < 0 or offset >= self._size:
            raise DexFormatError("uleb128 offset out of range")

        value = 0
        shift = 0
        consumed = 0

        # uleb128 in DEX is at most 5 bytes for 32-bit values
        for _ in range(5):
            if offset + consumed >= self._size:
                raise DexFormatError("uleb128 truncated")

            b = self._data[offset + consumed]
            consumed += 1

            value |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                return value, consumed

            shift += 7

        raise DexFormatError("uleb128 too long or malformed")
