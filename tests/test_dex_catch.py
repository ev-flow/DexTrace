# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
Parser-level tests for try_item + encoded_catch_handler decoding.

Uses the P5a fixture as ground truth: one method (divCatch), one try region
covering pc 0..2, one typed catch (ArithmeticException) at pc=3.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dextrace.core.dex_code_map import build_sig_to_codeoff_map
from dextrace.core.dex_parser import CatchHandler, DexParser, TryItem
from dextrace.core.dex_resolver import DexResolver

FIXTURE = (
    Path(__file__).parent / "fixtures" / "samples" / "try_catch.dex"
)
ENTRY = "Lp5a;->divCatch(II)I"


@pytest.fixture(scope="module")
def context():
    dex = FIXTURE.read_bytes()
    resolver = DexResolver(dex)
    sig_map = build_sig_to_codeoff_map(dex, resolver)
    parser = DexParser(dex)
    return parser, resolver, sig_map


def test_parse_tries_returns_one_region(context):
    parser, resolver, sig_map = context
    code_off = sig_map[ENTRY]
    tries = parser.parse_tries(code_off, resolver)
    assert len(tries) == 1


def test_try_region_covers_div_and_return(context):
    parser, resolver, sig_map = context
    tries = parser.parse_tries(sig_map[ENTRY], resolver)
    region = tries[0]
    assert isinstance(region, TryItem)
    assert region.start_addr == 0
    assert region.end_addr == 3
    # PC 0 (div-int) and PC 2 (return v0) covered; PC 3 (handler) excluded.
    assert region.start_addr <= 0 < region.end_addr
    assert region.start_addr <= 2 < region.end_addr
    assert not (region.start_addr <= 3 < region.end_addr)


def test_catch_resolves_to_arithmetic_exception(context):
    parser, resolver, sig_map = context
    tries = parser.parse_tries(sig_map[ENTRY], resolver)
    handlers = tries[0].handlers
    assert len(handlers) == 1
    h = handlers[0]
    assert isinstance(h, CatchHandler)
    assert h.class_desc == "Ljava/lang/ArithmeticException;"
    assert h.handler_addr == 3


def test_method_without_tries_returns_empty_list():
    """A code_item with tries_size=0 must return [] without touching post-insns bytes."""
    # Use the P3 inheritance fixture: every method has tries_size=0.
    p3 = Path(__file__).parent / "fixtures" / "samples" / "inheritance.dex"
    if not p3.exists():
        pytest.skip("P3 fixture not present")
    dex = p3.read_bytes()
    resolver = DexResolver(dex)
    sig_map = build_sig_to_codeoff_map(dex, resolver)
    parser = DexParser(dex)
    for sig, off in sig_map.items():
        assert parser.parse_tries(off, resolver) == [], (
            f"P3 method {sig} unexpectedly reported try regions"
        )
