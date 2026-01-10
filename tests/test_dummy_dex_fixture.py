# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from __future__ import annotations

import struct


def test_dummy_dex_has_valid_header(dummy_dex_path):
    b = dummy_dex_path.read_bytes()
    assert b[:8] == b"dex\n035\x00"

    file_size = struct.unpack_from("<I", b, 32)[0]
    header_size = struct.unpack_from("<I", b, 36)[0]
    endian_tag = struct.unpack_from("<I", b, 40)[0]
    map_off = struct.unpack_from("<I", b, 52)[0]

    assert file_size == len(b)
    assert header_size == 0x70
    assert endian_tag == 0x12345678
    assert 0 < map_off < len(b)

    # map_list sanity
    map_size = struct.unpack_from("<I", b, map_off)[0]
    assert map_size >= 5
