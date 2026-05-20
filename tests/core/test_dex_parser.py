# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""Unit tests for core/dex_parser.py — DexParser, TryItem, CatchHandler."""

from __future__ import annotations

from pathlib import Path

import pytest

from dextrace.core.dex_code_map import build_sig_to_codeoff_map
from dextrace.core.dex_parser import (
    CatchHandler,
    DexFormatError,
    DexParser,
    TryItem,
)
from dextrace.core.dex_resolver import DexResolver


# ---------------------------------------------------------------------------
# Smoke + invalid offset
# ---------------------------------------------------------------------------


def test_dex_parser_init():
    parser = DexParser(b"\x00" * 100)
    assert parser is not None


def test_parse_code_item_invalid_offset():
    parser = DexParser(b"\x00" * 64)
    with pytest.raises(DexFormatError):
        parser.parse_code_item(9999)


# ---------------------------------------------------------------------------
# try_item + encoded_catch_handler parsing (P5a fixture as ground truth)
# ---------------------------------------------------------------------------

_TRY_CATCH_FIXTURE = (
    Path(__file__).parent.parent / "fixtures" / "samples" / "try_catch.dex"
)
_ENTRY = "Lp5a;->divCatch(II)I"


@pytest.fixture(scope="module")
def _context():
    dex = _TRY_CATCH_FIXTURE.read_bytes()
    resolver = DexResolver(dex)
    sig_map = build_sig_to_codeoff_map(dex, resolver)
    parser = DexParser(dex)
    return parser, resolver, sig_map


def test_parse_tries_returns_one_region(_context):
    parser, resolver, sig_map = _context
    tries = parser.parse_tries(sig_map[_ENTRY], resolver)
    assert len(tries) == 1


def test_try_region_covers_div_and_return(_context):
    parser, resolver, sig_map = _context
    tries = parser.parse_tries(sig_map[_ENTRY], resolver)
    region = tries[0]
    assert isinstance(region, TryItem)
    assert region.start_addr == 0
    assert region.end_addr == 3
    # PC 0 (div-int) and PC 2 (return v0) covered; PC 3 (handler) excluded.
    assert region.start_addr <= 0 < region.end_addr
    assert region.start_addr <= 2 < region.end_addr
    assert not (region.start_addr <= 3 < region.end_addr)


def test_catch_resolves_to_arithmetic_exception(_context):
    parser, resolver, sig_map = _context
    tries = parser.parse_tries(sig_map[_ENTRY], resolver)
    handlers = tries[0].handlers
    assert len(handlers) == 1
    h = handlers[0]
    assert isinstance(h, CatchHandler)
    assert h.class_desc == "Ljava/lang/ArithmeticException;"
    assert h.handler_addr == 3


def test_method_without_tries_returns_empty_list():
    """A code_item with tries_size=0 must return [] without touching post-insns bytes."""
    p3 = Path(__file__).parent.parent / "fixtures" / "samples" / "inheritance.dex"
    if not p3.exists():
        pytest.skip("inheritance fixture not present")
    dex = p3.read_bytes()
    resolver = DexResolver(dex)
    sig_map = build_sig_to_codeoff_map(dex, resolver)
    parser = DexParser(dex)
    for sig, off in sig_map.items():
        assert parser.parse_tries(off, resolver) == [], (
            f"inheritance method {sig} unexpectedly reported try regions"
        )
