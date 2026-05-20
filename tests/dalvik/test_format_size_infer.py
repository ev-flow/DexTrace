# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""Unit tests for dalvik/format_size_infer.py — spec table + full coverage."""

from dextrace.dalvik.bytecode_source import load_bytecode_lines
from dextrace.dalvik.format_size_infer import infer_format_size_units
from dextrace.dalvik.opcode_table_builder import (
    build_opcode_format_map_from_bytecode_lines,
)


def test_infer_matches_spec_table_for_known_formats():
    """Oracle: known format → expected size_units per the Dalvik spec."""
    lines = load_bytecode_lines()
    fmt_map = build_opcode_format_map_from_bytecode_lines(lines)

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


def test_all_formats_in_bytecode_txt_are_inferable():
    """Coverage: every format mentioned in bytecode.txt must be inferable."""
    lines = load_bytecode_lines()
    fmt_map = build_opcode_format_map_from_bytecode_lines(lines)

    for opcode, fmt in fmt_map.items():
        if fmt is None:
            continue
        assert infer_format_size_units(fmt) is not None
