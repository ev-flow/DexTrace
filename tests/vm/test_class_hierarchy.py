# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""Unit tests for vm/class_hierarchy.py — ClassHierarchy and vtable resolution."""

from pathlib import Path

import pytest

from dextrace.core.dex_code_map import build_sig_to_codeoff_map
from dextrace.core.dex_resolver import DexResolver
from dextrace.vm.class_hierarchy import ClassHierarchy
from dextrace.vm.errors import DexTraceNotImplementedError, DexTraceVMError

P3_FIXTURE = (
    Path(__file__).parent.parent / "fixtures" / "samples" / "inheritance.dex"
)
P2_FIXTURE = (
    Path(__file__).parent.parent / "fixtures" / "samples" / "fib_recursive.dex"
)


@pytest.fixture(scope="module")
def inheritance_hierarchy():
    dex = P3_FIXTURE.read_bytes()
    resolver = DexResolver(dex)
    return ClassHierarchy(dex, resolver), build_sig_to_codeoff_map(dex, resolver)


@pytest.fixture(scope="module")
def fibonacci_hierarchy():
    dex = P2_FIXTURE.read_bytes()
    resolver = DexResolver(dex)
    return ClassHierarchy(dex, resolver)


class TestClassHierarchyP3:
    def test_mid_foo_resolves_to_mid_implementation(self, inheritance_hierarchy):
        hier, sig_map = inheritance_hierarchy
        code_off = hier.resolve_virtual("Lp3/Mid;", "foo", "()I")
        assert code_off == sig_map["Lp3/Mid;->foo()I"]

    def test_base_foo_resolves_to_base_implementation(self, inheritance_hierarchy):
        hier, sig_map = inheritance_hierarchy
        code_off = hier.resolve_virtual("Lp3/Base;", "foo", "()I")
        assert code_off == sig_map["Lp3/Base;->foo()I"]

    def test_mid_foo_differs_from_base_foo(self, inheritance_hierarchy):
        hier, sig_map = inheritance_hierarchy
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


class TestClassHierarchyP2:
    def test_single_class_dex_no_crash(self, fibonacci_hierarchy):
        # P2 has only one class; hierarchy builds without error
        hier = fibonacci_hierarchy
        assert hier is not None
