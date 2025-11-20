# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from dextrace.core.manifest_parser import ManifestParser


def test_manifest_parser_returns_error_on_invalid_axml():
    result = ManifestParser.parse(b"not-axml")

    assert "error" in result
    assert result["error"] == "Bad AXML format"
