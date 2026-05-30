# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Tuple, Iterator


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


@dataclass(frozen=True)
class CatchHandler:
    """One catch entry inside an encoded_catch_handler.

    `class_desc` is None for the catch-all (`catch_all_addr`) entry.
    `handler_addr` is the instruction-unit offset of the handler block.
    """

    class_desc: Optional[str]
    handler_addr: int


@dataclass(frozen=True)
class TryItem:
    """One try region with its resolved catch handlers.

    Inclusive: `start_addr <= pc < end_addr` (both in 16-bit code units).
    """

    start_addr: int
    end_addr: int
    handlers: Tuple[CatchHandler, ...]


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

    # ------------------------------------------------------------------
    # try_item / encoded_catch_handler parsing  (P5a — additive)
    # ------------------------------------------------------------------
    def parse_tries(self, code_off: int, resolver) -> List[TryItem]:
        """
        Parse the try_item array and encoded_catch_handler_list that follow
        the instruction stream of a code_item.

        Returns an empty list when `tries_size == 0`. `resolver` must expose
        `get_type(type_idx) -> str` to translate catch type indices to Dalvik
        descriptors (catch-all entries get class_desc=None).

        Layout (after `insns[insns_size]`):
          ushort padding             (only if insns_size is odd, to 4-byte align tries)
          try_item tries[tries_size] (8 bytes each)
          uleb128 handlers_size
          encoded_catch_handler[handlers_size]

        try_item:
          uint   start_addr      (16-bit code-unit offset into insns)
          ushort insn_count      (length in code units; end = start_addr + insn_count)
          ushort handler_off     (BYTES from the start of encoded_catch_handler_list)
        """
        code = self.parse_code_item(code_off)
        if code.tries_size == 0:
            return []

        insns_off = code_off + 16
        tries_off = insns_off + code.insns_size * 2
        if code.insns_size % 2 == 1:
            tries_off += 2  # 4-byte alignment padding

        tries_bytes_end = tries_off + code.tries_size * 8
        if tries_bytes_end > self._size:
            raise DexFormatError("try_item array runs past end of file")

        # Pass 1: read the raw try_items (deferring handler resolution).
        raw_tries: List[Tuple[int, int, int]] = []
        for i in range(code.tries_size):
            tr_off = tries_off + i * 8
            start_addr, insn_count, handler_off = struct.unpack_from(
                "<IHH", self._data, tr_off
            )
            raw_tries.append((int(start_addr), int(insn_count), int(handler_off)))

        # Pass 2: parse encoded_catch_handler_list. handler_off in each try_item
        # is BYTES relative to handlers_list_start.
        handlers_list_start = tries_bytes_end
        handlers_size, after_size = self._read_uleb128(handlers_list_start)
        # Map handler_off -> parsed CatchHandler tuple
        handler_at: dict[int, Tuple[CatchHandler, ...] ] = {}

        cursor = after_size
        for _ in range(handlers_size):
            relative_off = cursor - handlers_list_start
            entries, cursor = self._parse_encoded_catch_handler(cursor, resolver)
            handler_at[relative_off] = entries

        # Pass 3: assemble TryItems.
        out: List[TryItem] = []
        for start_addr, insn_count, handler_off in raw_tries:
            entries = handler_at.get(handler_off)
            if entries is None:
                raise DexFormatError(
                    f"try_item handler_off=0x{handler_off:x} not found in "
                    f"encoded_catch_handler_list"
                )
            out.append(
                TryItem(
                    start_addr=start_addr,
                    end_addr=start_addr + insn_count,
                    handlers=entries,
                )
            )
        return out

    # ------------------------------------------------------------------
    # uleb128 / sleb128 helpers  (private, for try parsing)
    # ------------------------------------------------------------------
    def _read_uleb128(self, off: int) -> Tuple[int, int]:
        """Return (value, new_off)."""
        result = 0
        shift = 0
        while True:
            if off >= self._size:
                raise DexFormatError("uleb128 ran past end of file")
            b = self._data[off]
            off += 1
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                break
            shift += 7
            if shift > 35:
                raise DexFormatError("uleb128 too long")
        return result, off

    def _read_sleb128(self, off: int) -> Tuple[int, int]:
        """Return (value, new_off). Sign-extends from the last byte."""
        result = 0
        shift = 0
        b = 0
        while True:
            if off >= self._size:
                raise DexFormatError("sleb128 ran past end of file")
            b = self._data[off]
            off += 1
            result |= (b & 0x7F) << shift
            shift += 7
            if (b & 0x80) == 0:
                break
            if shift > 35:
                raise DexFormatError("sleb128 too long")
        if (b & 0x40) and shift < 64:
            result |= -(1 << shift)
        return result, off

    def _parse_encoded_catch_handler(
        self, off: int, resolver
    ) -> Tuple[Tuple[CatchHandler, ...], int]:
        """
        encoded_catch_handler:
          sleb128 size
            > 0: `size` typed catches, no catch-all
            <=0: abs(size) typed catches, then a uleb128 catch_all_addr
            = 0: only catch_all_addr
          encoded_type_addr_pair handlers[abs(size)]
          uleb128 catch_all_addr   (only when size <= 0)

        encoded_type_addr_pair:
          uleb128 type_idx
          uleb128 addr
        """
        size, off = self._read_sleb128(off)
        n_typed = abs(size)
        has_catch_all = size <= 0

        out: List[CatchHandler] = []
        for _ in range(n_typed):
            type_idx, off = self._read_uleb128(off)
            addr, off = self._read_uleb128(off)
            try:
                cd = resolver.get_type(int(type_idx))
            except Exception:  # pylint: disable=broad-exception-caught
                cd = "Ljava/lang/Throwable;"
            out.append(CatchHandler(class_desc=cd, handler_addr=int(addr)))

        if has_catch_all:
            catch_all_addr, off = self._read_uleb128(off)
            out.append(
                CatchHandler(class_desc=None, handler_addr=int(catch_all_addr))
            )
        return tuple(out), off
