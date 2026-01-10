# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from dextrace.dalvik.size_resolver import resolve_size_units


def test_resolver_fallback_to_1_for_unknown():
    res = resolve_size_units("99z")  # nonsense
    assert res.size_units == 1
    assert res.source == "fallback_1"
