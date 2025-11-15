# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


import io
import struct
import tempfile
from pathlib import Path
import pytest

from dextrace.dex.dex_header import parse_dex_header, DEX_HEADER_SIZE


def make_fake_dex(version: str = "039") -> bytes:
    """
    Construct a minimal fake DEX header for testing.
    """
    magic = f"dex\n{version}\0".encode("ascii")
    checksum = 0x12345678
    signature = bytes.fromhex("aabbcc" * 6 + "aabbcc" * 2)[:20]  # 20 bytes
    fields = [
        magic,
        checksum,
        signature,
        512000,  # file_size
        112,     # header_size
        0x12345678,  # endian_tag
        0, 0, 0,     # link_size/off/map_off
        100, 0x70,   # string_ids
        200, 0x170,  # type_ids
        300, 0x270,  # proto_ids
        400, 0x370,  # field_ids
        500, 0x470,  # method_ids
        600, 0x570,  # class_defs
        700, 0x670   # data
    ]
    packed = struct.pack("<8sI20s20I", *fields)
    # pad to DEX_HEADER_SIZE
    return packed + b"\x00" * max(0, DEX_HEADER_SIZE - len(packed))


def test_parse_dex_header_from_file(tmp_path: Path):
    """
    Verify that parse_dex_header can correctly read a valid DEX file.
    """
    fake_dex = make_fake_dex("039")
    dex_path = tmp_path / "classes.dex"
    dex_path.write_bytes(fake_dex)

    header = parse_dex_header(file_path=str(dex_path))

    assert header.magic.startswith("dex\n")
    assert header.version == "039"
    assert header.file_size == 512000
    assert isinstance(header.to_dict(), dict)
    assert "class_defs_size" in header.to_dict()


def test_parse_dex_header_from_bytes():
    """
    Verify that parse_dex_header supports raw byte input.
    """
    fake_dex = make_fake_dex("037")
    header = parse_dex_header(data=fake_dex)

    assert header.magic.startswith("dex\n")
    assert header.version == "037"
    assert header.header_size == 112
    assert header.class_defs_size == 600


def test_invalid_magic_raises(tmp_path: Path):
    """
    Invalid magic should raise ValueError.
    """
    bad_dex = b"notadex" + b"\x00" * (DEX_HEADER_SIZE - 7)
    dex_path = tmp_path / "bad.dex"
    dex_path.write_bytes(bad_dex)

    with pytest.raises(ValueError, match="Invalid DEX magic"):
        parse_dex_header(file_path=str(dex_path))


def test_file_too_small_raises(tmp_path: Path):
    """
    File smaller than header size should raise ValueError.
    """
    tiny_path = tmp_path / "tiny.dex"
    tiny_path.write_bytes(b"short")

    with pytest.raises(ValueError, match="too small"):
        parse_dex_header(file_path=str(tiny_path))
