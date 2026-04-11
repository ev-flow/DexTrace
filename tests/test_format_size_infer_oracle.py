# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from dextrace.dalvik.bytecode_source import load_bytecode_lines
from dextrace.dalvik.opcode_table_builder import (
    build_opcode_format_map_from_bytecode_lines,
)
from dextrace.dalvik.format_size_infer import (
    infer_format_size_units,
)  # 依你專案實際 import


def test_infer_matches_spec_table_for_known_formats():
    lines = load_bytecode_lines()
    fmt_map = build_opcode_format_map_from_bytecode_lines(lines)

    # 這段照你原本 oracle 的表/expected 走
    # 假設你原本有 expected = {"10x":1, "11x":1, ...}
    expected = {
        "00x": 1,
        "10x": 1,
        "11x": 1,
        "12x": 1,
        "21c": 2,
        # ...
    }

    for fmt, size in expected.items():
        assert infer_format_size_units(fmt) == size
