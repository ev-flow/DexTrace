# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


"""
DEX header parsing.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, asdict
from typing import Dict, Any


DEX_HEADER_STRUCT = "<8sI20s20I"
DEX_HEADER_SIZE = 0x70


class DexFormatError(ValueError):
    """Raised when DEX header format is invalid."""


@dataclass(frozen=True)
class DexHeader:
    magic: str
    checksum: int
    signature: str
    file_size: int
    header_size: int
    endian_tag: int
    link_size: int
    link_off: int
    map_off: int
    string_ids_size: int
    string_ids_off: int
    type_ids_size: int
    type_ids_off: int
    proto_ids_size: int
    proto_ids_off: int
    field_ids_size: int
    field_ids_off: int
    method_ids_size: int
    method_ids_off: int
    class_defs_size: int
    class_defs_off: int
    data_size: int
    data_off: int

    def version(self) -> str:
        # dex\n035\0 → 035
        return self.magic[4:7]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["version"] = self.version()
        return d

    @classmethod
    def from_bytes(cls, data: bytes) -> "DexHeader":
        return parse_dex_header_bytes(data)


# ----------------------------------------------------------------------
# Parsers
# ----------------------------------------------------------------------
def parse_dex_header_bytes(data: bytes) -> DexHeader:
    """
    Parse DEX header from raw bytes.
    """
    if len(data) < DEX_HEADER_SIZE:
        raise DexFormatError("File too small to contain a valid DEX header")

    try:
        unpacked = struct.unpack(DEX_HEADER_STRUCT, data[:DEX_HEADER_SIZE])
    except struct.error as exc:
        raise DexFormatError("Failed to unpack DEX header") from exc

    magic = unpacked[0].decode("ascii", "replace")

    if not (magic.startswith("dex\n") or magic.startswith("cdex\n")):
        raise DexFormatError(f"Invalid DEX magic: {magic!r}")

    return DexHeader(
        magic=magic,
        checksum=unpacked[1],
        signature=unpacked[2].hex(),
        file_size=unpacked[3],
        header_size=unpacked[4],
        endian_tag=unpacked[5],
        link_size=unpacked[6],
        link_off=unpacked[7],
        map_off=unpacked[8],
        string_ids_size=unpacked[9],
        string_ids_off=unpacked[10],
        type_ids_size=unpacked[11],
        type_ids_off=unpacked[12],
        proto_ids_size=unpacked[13],
        proto_ids_off=unpacked[14],
        field_ids_size=unpacked[15],
        field_ids_off=unpacked[16],
        method_ids_size=unpacked[17],
        method_ids_off=unpacked[18],
        class_defs_size=unpacked[19],
        class_defs_off=unpacked[20],
        data_size=unpacked[21],
        data_off=unpacked[22],
    )


def parse_dex_header_file(path: str) -> DexHeader:
    """
    Parse DEX header from a file path.
    """
    with open(path, "rb") as f:
        return parse_dex_header_bytes(f.read())


# ----------------------------------------------------------------------
# Backward compatibility
# ----------------------------------------------------------------------
def parse_dex_header(file_path=None, data=None) -> DexHeader:
    """
    Backward-compatible wrapper.

    - parse_dex_header(file_path="classes.dex")
    - parse_dex_header(data=b"...")
    """
    if data is not None:
        return parse_dex_header_bytes(data)

    if file_path is not None:
        return parse_dex_header_file(file_path)

    raise TypeError("parse_dex_header requires file_path or data")
