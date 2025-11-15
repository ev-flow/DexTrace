# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


"""
DEX Header Parser
-----------------
Parse the header section of a .dex (Dalvik Executable) file.

Reference:
https://source.android.com/docs/core/runtime/dex-format#header-item
"""

import struct
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional, Dict, Union


@dataclass
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

    @property
    def version(self) -> str:
        """Extract version (e.g. dex\\n039\\0 → 039)."""
        if self.magic.startswith("dex\n") and len(self.magic) >= 7:
            return self.magic[4:7]
        elif self.magic.startswith("cdex\n"):
            return self.magic[5:8]
        return "unknown"

    def to_dict(self) -> Dict[str, Union[str, int]]:
        data = asdict(self)
        data["version"] = self.version
        return data


DEX_HEADER_STRUCT = "<8sI20s20I"  # little-endian
DEX_HEADER_SIZE = 0x70


def parse_dex_header(file_path: Optional[str] = None, data: Optional[bytes] = None) -> DexHeader:
    """
    Parse a DEX file header from a file or raw bytes.

    Args:
        file_path: Path to the .dex file.
        data: Raw bytes (if reading from APK zip entry).

    Returns:
        DexHeader: parsed header object.

    Raises:
        FileNotFoundError: if file_path not found.
        ValueError: for invalid file or magic bytes.
    """
    if data is None:
        if not file_path:
            raise ValueError("Either 'file_path' or 'data' must be provided.")
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"DEX file not found: {file_path}")
        data = path.read_bytes()

    if len(data) < DEX_HEADER_SIZE:
        raise ValueError("File too small to contain a valid DEX header")

    header_bytes = data[:DEX_HEADER_SIZE]
    unpacked = struct.unpack(DEX_HEADER_STRUCT, header_bytes)

    fields = [
        "magic", "checksum", "signature", "file_size", "header_size",
        "endian_tag", "link_size", "link_off", "map_off",
        "string_ids_size", "string_ids_off",
        "type_ids_size", "type_ids_off",
        "proto_ids_size", "proto_ids_off",
        "field_ids_size", "field_ids_off",
        "method_ids_size", "method_ids_off",
        "class_defs_size", "class_defs_off",
        "data_size", "data_off"
    ]

    header_dict = dict(zip(fields, unpacked))
    magic = header_dict["magic"].decode("ascii", errors="replace")

    # Validate magic bytes
    if not (magic.startswith("dex\n") or magic.startswith("cdex\n")):
        raise ValueError(f"Invalid DEX magic: {magic!r}")

    return DexHeader(
        magic=magic,
        checksum=header_dict["checksum"],
        signature=header_dict["signature"].hex(),
        file_size=header_dict["file_size"],
        header_size=header_dict["header_size"],
        endian_tag=header_dict["endian_tag"],
        link_size=header_dict["link_size"],
        link_off=header_dict["link_off"],
        map_off=header_dict["map_off"],
        string_ids_size=header_dict["string_ids_size"],
        string_ids_off=header_dict["string_ids_off"],
        type_ids_size=header_dict["type_ids_size"],
        type_ids_off=header_dict["type_ids_off"],
        proto_ids_size=header_dict["proto_ids_size"],
        proto_ids_off=header_dict["proto_ids_off"],
        field_ids_size=header_dict["field_ids_size"],
        field_ids_off=header_dict["field_ids_off"],
        method_ids_size=header_dict["method_ids_size"],
        method_ids_off=header_dict["method_ids_off"],
        class_defs_size=header_dict["class_defs_size"],
        class_defs_off=header_dict["class_defs_off"],
        data_size=header_dict["data_size"],
        data_off=header_dict["data_off"],
    )


if __name__ == "__main__":
    import json, sys
    if len(sys.argv) < 2:
        print("Usage: python -m dextrace.core.dex_header <classes.dex>")
        sys.exit(1)
    path = sys.argv[1]
    try:
        header = parse_dex_header(file_path=path)
        print(json.dumps(header.to_dict(), indent=2))
    except Exception as e:
        print(f"Error: {e}")
    