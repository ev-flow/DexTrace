# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

from __future__ import annotations

from pathlib import Path

from dextrace.api import extract_class_hierarchy
from tests.fixtures.dex_factory import (
    build_minimal_test_dex,
    build_minimal_test_dex_with_interface,
    build_minimal_test_dex_with_two_interfaces,
)


def test_extract_class_hierarchy_smoke(tmp_path: Path):
    """Happy-path: minimal DEX with LTest extends Object returns correct mapping."""
    dex_file = tmp_path / "test.dex"
    dex_file.write_bytes(build_minimal_test_dex())

    result = extract_class_hierarchy(str(dex_file))

    assert isinstance(result, dict)
    assert "LTest;" in result
    assert result["LTest;"] == {"Ljava/lang/Object;"}


def test_extract_class_hierarchy_includes_interfaces(tmp_path: Path):
    """Class implementing one interface should list both superclass and interface in parent set."""
    dex_file = tmp_path / "test.dex"
    dex_file.write_bytes(build_minimal_test_dex_with_interface())

    result = extract_class_hierarchy(str(dex_file))

    assert "LTest;" in result
    assert result["LTest;"] == {"Ljava/lang/Object;", "LIFoo;"}


def test_extract_class_hierarchy_includes_two_interfaces(tmp_path: Path):
    """Class implementing two interfaces should list superclass and both interfaces."""
    dex_file = tmp_path / "test.dex"
    dex_file.write_bytes(build_minimal_test_dex_with_two_interfaces())

    result = extract_class_hierarchy(str(dex_file))

    assert "LTest;" in result
    assert result["LTest;"] == {"Ljava/lang/Object;", "LIFoo;", "LIBar;"}
