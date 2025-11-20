# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


import struct
from dextrace.core.dex_header import parse_dex_header, DEX_HEADER_SIZE


def make_fake_dex(version="039"):
    magic = f"dex\n{version}\0".encode("ascii")
    checksum = 0x12345678
    signature = b"\xAA" * 20

    fields = [
        magic, checksum, signature,
        50000, 112, 0x12345678, 0, 0, 0,
        10, 0x70,
        20, 0x170,
        30, 0x270,
        40, 0x370,
        50, 0x470,
        60, 0x570,
        70, 0x670,
    ]

    hdr = struct.pack("<8sI20s20I", *fields)
    return hdr + b"\x00" * (DEX_HEADER_SIZE - len(hdr))


def test_parse_valid_dex_header():
    fake = make_fake_dex()
    header = parse_dex_header(data=fake)

    assert header.magic.startswith("dex\n")
    assert header.version() == "039"
    assert header.file_size == 50000


def test_parse_invalid_magic():
    fake = b"BADMAGIC" + b"\x00" * (DEX_HEADER_SIZE - 8)

    try:
        parse_dex_header(data=fake)
    except ValueError:
        assert True
    else:
        assert False, "Expected ValueError for invalid magic"
