# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from dextrace.dalvik.bytecode_source import load_bytecode_lines
from dextrace.dalvik.opcode_table_builder import (
    build_opcode_format_map_from_bytecode_lines,
    build_opcode_info_table_from_bytecode_lines,
)


def test_build_opcode_format_map_from_bytecode_txt():
    lines = load_bytecode_lines()
    fmt_map = build_opcode_format_map_from_bytecode_lines(lines)
    assert isinstance(fmt_map, dict)
    assert fmt_map  # not empty


def test_build_opcode_info_table_flags_and_fields():
    lines = load_bytecode_lines()
    info = build_opcode_info_table_from_bytecode_lines(lines)
    assert isinstance(info, dict)
    assert info  # not empty
