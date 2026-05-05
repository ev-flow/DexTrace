# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
Tests for ClassHierarchy.is_subtype() and the seeded Java built-in chain.
The catch-table walk relies on this for matching e.g. `ArithmeticException`
under a `catch (RuntimeException)` clause.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dextrace.core.dex_resolver import DexResolver
from dextrace.vm.class_hierarchy import ClassHierarchy

# Use the P5a fixture as a minimal DEX for hierarchy construction. is_subtype
# behavior is mostly driven by the Java built-in seed, which is independent
# of the DEX content.
FIXTURE = (
    Path(__file__).parent.parent / "fixtures" / "samples" / "try_catch.dex"
)


@pytest.fixture(scope="module")
def hierarchy():
    dex = FIXTURE.read_bytes()
    resolver = DexResolver(dex)
    return ClassHierarchy(dex, resolver)


class TestReflexivity:
    def test_class_is_subtype_of_itself(self, hierarchy):
        assert hierarchy.is_subtype(
            "Ljava/lang/Object;", "Ljava/lang/Object;"
        )
        assert hierarchy.is_subtype(
            "Ljava/lang/ArithmeticException;",
            "Ljava/lang/ArithmeticException;",
        )


class TestJavaBuiltInChain:
    def test_arithmetic_exception_under_runtime_exception(self, hierarchy):
        assert hierarchy.is_subtype(
            "Ljava/lang/ArithmeticException;",
            "Ljava/lang/RuntimeException;",
        )

    def test_arithmetic_exception_under_throwable(self, hierarchy):
        # Walks ArithmeticException → RuntimeException → Exception → Throwable
        assert hierarchy.is_subtype(
            "Ljava/lang/ArithmeticException;", "Ljava/lang/Throwable;"
        )

    def test_npe_under_runtime_exception(self, hierarchy):
        assert hierarchy.is_subtype(
            "Ljava/lang/NullPointerException;",
            "Ljava/lang/RuntimeException;",
        )

    def test_aioobe_under_index_oob(self, hierarchy):
        assert hierarchy.is_subtype(
            "Ljava/lang/ArrayIndexOutOfBoundsException;",
            "Ljava/lang/IndexOutOfBoundsException;",
        )

    def test_io_exception_under_exception(self, hierarchy):
        assert hierarchy.is_subtype(
            "Ljava/io/IOException;", "Ljava/lang/Exception;"
        )

    def test_file_not_found_under_io_exception(self, hierarchy):
        assert hierarchy.is_subtype(
            "Ljava/io/FileNotFoundException;", "Ljava/io/IOException;"
        )


class TestNonRelations:
    def test_runtime_exception_is_not_subtype_of_arithmetic(self, hierarchy):
        # Reverse direction must not match.
        assert not hierarchy.is_subtype(
            "Ljava/lang/RuntimeException;",
            "Ljava/lang/ArithmeticException;",
        )

    def test_io_exception_is_not_runtime_exception(self, hierarchy):
        assert not hierarchy.is_subtype(
            "Ljava/io/IOException;", "Ljava/lang/RuntimeException;"
        )

    def test_unknown_child_only_matches_itself(self, hierarchy):
        # A class never seen in the seed or DEX has no superclass info; only
        # the reflexive case returns True.
        assert hierarchy.is_subtype(
            "Lcom/foo/Unknown;", "Lcom/foo/Unknown;"
        )
        assert not hierarchy.is_subtype(
            "Lcom/foo/Unknown;", "Ljava/lang/Throwable;"
        )
