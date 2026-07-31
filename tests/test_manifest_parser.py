# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

import pytest

from dextrace.core.manifest_parser import ManifestParser
from dextrace.manifest.axml_parser import _ANDROID_RES_ATTR_NAMES


def test_manifest_parser_returns_error_on_invalid_axml():
    result = ManifestParser.parse(b"not-axml")

    assert "error" in result
    assert result["error"] == "Bad AXML format"


# ---------------------------------------------------------------------------
# Resource ID fallback table
# ---------------------------------------------------------------------------

class TestAndroidResAttrNames:
    """The fallback table must contain the entries critical for manifest parsing."""

    def test_android_name_0x01010003_present(self):
        assert _ANDROID_RES_ATTR_NAMES[0x01010003] == "name"

    def test_android_name_0x0101021b_present(self):
        assert _ANDROID_RES_ATTR_NAMES[0x0101021b] == "name"

    def test_no_false_entries(self):
        """All values must be non-empty strings."""
        for res_id, attr_name in _ANDROID_RES_ATTR_NAMES.items():
            assert isinstance(attr_name, str) and attr_name, (
                f"Blank or non-string value for res_id 0x{res_id:08x}"
            )
