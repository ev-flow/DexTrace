# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, Iterable, List


# ----------------------------------------------------------------------
# Exceptions
# ----------------------------------------------------------------------
class DexFormatError(ValueError):
    """Raised when DEX bytecode format is invalid."""


# ----------------------------------------------------------------------
# Data structures
# ----------------------------------------------------------------------
@dataclass
class DexInstruction:
    """Single Dalvik instruction (raw)."""

    offset: int          # offset from code_item.insns
    opcode: int
    raw: bytes


@dataclass
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
# Opcode table (minimal – extensible)
# ----------------------------------------------------------------------
DALVIK_OPCODES: Dict[int, str] = {
    0x00: "nop",
    0x01: "move",
    0x02: "move/from16",
    0x03: "move/16",
    0x04: "move-wide",
    0x0e: "return-void",
    0x0f: "return",
    0x10: "return-wide",
    0x11: "return-object",
    0x12: "const/4",
    0x13: "const/16",
    0x14: "const",
    0x28: "goto",
    0x29: "goto/16",
    0x2a: "goto/32",
}


# ----------------------------------------------------------------------
# Parser
# ----------------------------------------------------------------------
class DexParser:
    """
    DEX bytecode parser focused on code_item.

    This parser assumes:
    - DEX header & method resolution is handled elsewhere
    - caller provides code_item offset
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
        insns_bytes = insns_size * 2

        if insns_off + insns_bytes > self._size:
            raise DexFormatError("code_item instruction area truncated")

        insns = self._data[insns_off: insns_off + insns_bytes]

        return DexCode(
            registers_size=registers_size,
            ins_size=ins_size,
            outs_size=outs_size,
            tries_size=tries_size,
            debug_info_off=debug_info_off,
            insns_size=insns_size,
            insns=insns,
        )

    # ------------------------------------------------------------------
    # Instruction decoding
    # ------------------------------------------------------------------
    def iter_instructions(self, code: DexCode) -> Iterable[DexInstruction]:
        """
        Iterate raw Dalvik instructions.

        NOTE:
        - This is a *lightweight* decoder
        - No format-based operand decoding yet
        """

        insns = code.insns
        off = 0
        size = len(insns)

        while off + 2 <= size:
            opcode = insns[off]
            raw = insns[off: off + 2]

            yield DexInstruction(
                offset=off,
                opcode=opcode,
                raw=raw,
            )

            off += 2

    # ------------------------------------------------------------------
    # Disassembly
    # ------------------------------------------------------------------
    def disassemble(self, code: DexCode) -> str:
        """
        Return simple text disassembly of code_item.
        """

        lines: List[str] = []

        for ins in self.iter_instructions(code):
            name = DALVIK_OPCODES.get(ins.opcode, f"op_{ins.opcode:02x}")
            raw_hex = ins.raw.hex()
            lines.append(f"{ins.offset:04x}: {name:<15} ; {raw_hex}")

        return "\n".join(lines)
