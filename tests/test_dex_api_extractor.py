# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


import pytest
from dextrace.core.dex_api_extractor import DexApiExtractor
from dextrace.core.dex_header import DexFormatError


def test_api_extractor_invalid_dex_raises():
    """
    DexApiExtractor should reject invalid DEX input.
    """
    with pytest.raises(DexFormatError):
        DexApiExtractor(b"\x00" * 256)
