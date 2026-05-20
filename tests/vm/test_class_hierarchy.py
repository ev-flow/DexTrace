# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""Unit tests for vm/class_hierarchy.py — vtable resolution + is_subtype()."""

from pathlib import Path

import pytest

from dextrace.core.dex_code_map import build_sig_to_codeoff_map
from dextrace.core.dex_resolver import DexResolver
from dextrace.vm.class_hierarchy import ClassHierarchy
from dextrace.vm.errors import DexTraceVMError

_FIXTURES = Path(__file__).parent.parent / "fixtures" / "samples"


# ---------------------------------------------------------------------------
# Virtual method dispatch (vtable)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def inheritance_hierarchy():
    dex = (_FIXTURES / "inheritance.dex").read_bytes()
    resolver = DexResolver(dex)
    return ClassHierarchy(dex, resolver), build_sig_to_codeoff_map(dex, resolver)


@pytest.fixture(scope="module")
def fibonacci_hierarchy():
    dex = (_FIXTURES / "fib_recursive.dex").read_bytes()
    resolver = DexResolver(dex)
    return ClassHierarchy(dex, resolver)


class TestVtableResolution:
    def test_mid_foo_resolves_to_mid_implementation(self, inheritance_hierarchy):
        hier, sig_map = inheritance_hierarchy
        code_off = hier.resolve_virtual("Lp3/Mid;", "foo", "()I")
        assert code_off == sig_map["Lp3/Mid;->foo()I"]

    def test_base_foo_resolves_to_base_implementation(self, inheritance_hierarchy):
        hier, sig_map = inheritance_hierarchy
        code_off = hier.resolve_virtual("Lp3/Base;", "foo", "()I")
        assert code_off == sig_map["Lp3/Base;->foo()I"]

    def test_mid_foo_differs_from_base_foo(self, inheritance_hierarchy):
        hier, _ = inheritance_hierarchy
        mid_off = hier.resolve_virtual("Lp3/Mid;", "foo", "()I")
        base_off = hier.resolve_virtual("Lp3/Base;", "foo", "()I")
        assert mid_off != base_off

    def test_unknown_class_raises_vm_error(self, inheritance_hierarchy):
        hier, _ = inheritance_hierarchy
        with pytest.raises(DexTraceVMError, match="vtable miss"):
            hier.resolve_virtual("Lno/Such/Class;", "foo", "()I")

    def test_unknown_method_raises_vm_error(self, inheritance_hierarchy):
        hier, _ = inheritance_hierarchy
        with pytest.raises(DexTraceVMError, match="vtable miss"):
            hier.resolve_virtual("Lp3/Mid;", "nonexistent", "()I")

    def test_single_class_dex_no_crash(self, fibonacci_hierarchy):
        # P2 has only one class; hierarchy builds without error
        assert fibonacci_hierarchy is not None


# ---------------------------------------------------------------------------
# is_subtype() — drives catch-table matching for exception types
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def subtype_hierarchy():
    # try_catch.dex is the minimal DEX; is_subtype is mostly driven by the
    # Java built-in seed, independent of DEX content.
    dex = (_FIXTURES / "try_catch.dex").read_bytes()
    resolver = DexResolver(dex)
    return ClassHierarchy(dex, resolver)


class TestSubtypeReflexivity:
    def test_class_is_subtype_of_itself(self, subtype_hierarchy):
        assert subtype_hierarchy.is_subtype(
            "Ljava/lang/Object;", "Ljava/lang/Object;"
        )
        assert subtype_hierarchy.is_subtype(
            "Ljava/lang/ArithmeticException;",
            "Ljava/lang/ArithmeticException;",
        )


class TestSubtypeJavaBuiltInChain:
    def test_arithmetic_exception_under_runtime_exception(self, subtype_hierarchy):
        assert subtype_hierarchy.is_subtype(
            "Ljava/lang/ArithmeticException;",
            "Ljava/lang/RuntimeException;",
        )

    def test_arithmetic_exception_under_throwable(self, subtype_hierarchy):
        # Walks ArithmeticException → RuntimeException → Exception → Throwable
        assert subtype_hierarchy.is_subtype(
            "Ljava/lang/ArithmeticException;", "Ljava/lang/Throwable;"
        )

    def test_npe_under_runtime_exception(self, subtype_hierarchy):
        assert subtype_hierarchy.is_subtype(
            "Ljava/lang/NullPointerException;",
            "Ljava/lang/RuntimeException;",
        )

    def test_aioobe_under_index_oob(self, subtype_hierarchy):
        assert subtype_hierarchy.is_subtype(
            "Ljava/lang/ArrayIndexOutOfBoundsException;",
            "Ljava/lang/IndexOutOfBoundsException;",
        )

    def test_io_exception_under_exception(self, subtype_hierarchy):
        assert subtype_hierarchy.is_subtype(
            "Ljava/io/IOException;", "Ljava/lang/Exception;"
        )

    def test_file_not_found_under_io_exception(self, subtype_hierarchy):
        assert subtype_hierarchy.is_subtype(
            "Ljava/io/FileNotFoundException;", "Ljava/io/IOException;"
        )


class TestSubtypeNonRelations:
    def test_runtime_exception_is_not_subtype_of_arithmetic(self, subtype_hierarchy):
        # Reverse direction must not match.
        assert not subtype_hierarchy.is_subtype(
            "Ljava/lang/RuntimeException;",
            "Ljava/lang/ArithmeticException;",
        )

    def test_io_exception_is_not_runtime_exception(self, subtype_hierarchy):
        assert not subtype_hierarchy.is_subtype(
            "Ljava/io/IOException;", "Ljava/lang/RuntimeException;"
        )

    def test_unknown_child_only_matches_itself(self, subtype_hierarchy):
        # A class never seen in the seed or DEX has no superclass info; only
        # the reflexive case returns True.
        assert subtype_hierarchy.is_subtype("Lcom/foo/Unknown;", "Lcom/foo/Unknown;")
        assert not subtype_hierarchy.is_subtype(
            "Lcom/foo/Unknown;", "Ljava/lang/Throwable;"
        )
