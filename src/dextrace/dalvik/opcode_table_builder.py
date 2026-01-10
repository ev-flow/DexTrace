# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, Optional, List


@dataclass(frozen=True)
class OpcodeInfo:
    opcode: int                 # 0..255
    name: str                   # e.g. "invoke-virtual"
    fmt: str                    # e.g. "35c"
    has_result: bool            # y/n
    index_type: Optional[str]   # e.g. "method-ref"
    flags: FrozenSet[str]       # e.g. {"continue","throw","invoke"}
    raw_line: str               # original (comment-stripped) line for debugging

    @property
    def optimized(self) -> bool:
        return "optimized" in self.flags


def _strip_comment(line: str) -> str:
    # bytecode.txt uses '#' for comments
    if "#" in line:
        line = line.split("#", 1)[0]
    return line.strip()


def _parse_op_line(line: str) -> Optional[OpcodeInfo]:
    """
    Parse one opcode line like:
      op   6e invoke-virtual              35c  n method-ref    continue|throw|invoke
    """
    s = _strip_comment(line)
    if not s:
        return None
    if not s.startswith("op"):
        return None

    parts = s.split()
    # Expect at least:
    # 0:op 1:hex 2:name 3:fmt 4:y/n 5:index_type [6:flags]
    if len(parts) < 6:
        return None

    _, hex_str, name, fmt, yn, index_type, *rest = parts

    try:
        opcode = int(hex_str, 16)
    except ValueError:
        return None
    
    # Normalize index_type: "none" -> None
    it = index_type.strip().lower()
    norm_index_type = None if it in ("none", "-", "na", "n/a") else index_type

    flags_str = rest[0] if rest else ""
    flags = frozenset(filter(None, flags_str.split("|"))) if flags_str else frozenset()

    has_result = (yn.lower() == "y")

    return OpcodeInfo(
        opcode=opcode,
        name=name,
        fmt=fmt,
        has_result=has_result,
        index_type=norm_index_type if norm_index_type is not None else "none",
        flags=flags,
        raw_line=s,
    )


def build_opcode_info_table(lines: Iterable[str]) -> Dict[int, OpcodeInfo]:
    """
    Build opcode->OpcodeInfo from bytecode.txt content (iterable of lines).
    If duplicate opcode appears, later one wins (should not happen in AOSP file).
    """
    table: Dict[int, OpcodeInfo] = {}
    for line in lines:
        info = _parse_op_line(line)
        if info is None:
            continue
        if not (0 <= info.opcode <= 0xFF):
            continue
        table[info.opcode] = info
    return table


def build_opcode_format_map(lines: Iterable[str]) -> Dict[int, str]:
    """
    Build opcode->format (e.g. 0x6e -> "35c").
    """
    info_table = build_opcode_info_table(lines)
    return {op: info.fmt for op, info in info_table.items()}


def build_opcode_name_map(lines: Iterable[str]) -> Dict[int, str]:
    info_table = build_opcode_info_table(lines)
    return {op: info.name for op, info in info_table.items()}


def load_from_file(path: str | Path) -> Dict[int, OpcodeInfo]:
    """
    Convenience loader for bytecode.txt on disk.
    """
    p = Path(path)
    text = p.read_text(encoding="utf-8", errors="replace")
    return build_opcode_info_table(text.splitlines())


def build_opcode_format_map_from_bytecode_lines(lines: List[str]) -> Dict[int, str]:
    """
    Compatibility wrapper expected by tests:
      tests import build_opcode_format_map_from_bytecode_lines()
    """
    return build_opcode_format_map(lines)


def build_opcode_info_table_from_bytecode_lines(lines: List[str]) -> Dict[int, OpcodeInfo]:
    """
    Optional companion wrapper (handy if tests/other modules need it later).
    """
    return build_opcode_info_table(lines)
