# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from dextrace.dalvik.bytecode_source import load_bytecode_lines
from dextrace.dalvik.opcode_table_builder import build_opcode_format_map_from_bytecode_lines
from dextrace.dalvik.format_size_infer import infer_format_size_units  # 依你專案實際 import

def test_all_formats_in_bytecode_txt_are_inferable():
    lines = load_bytecode_lines()
    fmt_map = build_opcode_format_map_from_bytecode_lines(lines)

    # 逐一確認 format 都能 infer（依你原測試邏輯調整）
    for opcode, fmt in fmt_map.items():
        if fmt is None:
            continue
        assert infer_format_size_units(fmt) is not None
