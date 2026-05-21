# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


import pytest
from dextrace.core.dex_parser import DexParser, DexFormatError


def test_dex_parser_init():
    parser = DexParser(b"\x00" * 100)
    assert parser is not None


def test_parse_code_item_invalid_offset():
    parser = DexParser(b"\x00" * 64)

    with pytest.raises(DexFormatError):
        parser.parse_code_item(9999)
