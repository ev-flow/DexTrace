# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""Unit tests for vm/heap.py — ObjectHeap."""

import pytest

from dextrace.vm.errors import DexTraceVMError
from dextrace.vm.heap import ObjectHeap


class TestObjectHeap:
    def test_allocate_returns_positive_handle(self):
        heap = ObjectHeap()
        h = heap.allocate("Lp3/Mid;")
        assert h >= 1

    def test_allocate_sequential_handles(self):
        heap = ObjectHeap()
        h1 = heap.allocate("Lp3/Base;")
        h2 = heap.allocate("Lp3/Mid;")
        assert h2 == h1 + 1

    def test_get_class_returns_descriptor(self):
        heap = ObjectHeap()
        h = heap.allocate("Lp3/Mid;")
        assert heap.get_class(h) == "Lp3/Mid;"

    def test_get_class_null_handle_raises(self):
        heap = ObjectHeap()
        with pytest.raises(DexTraceVMError, match="null receiver"):
            heap.get_class(0)

    def test_get_class_invalid_handle_raises(self):
        heap = ObjectHeap()
        with pytest.raises(DexTraceVMError, match="invalid object handle"):
            heap.get_class(9999)

    def test_reset_clears_allocations(self):
        heap = ObjectHeap()
        h = heap.allocate("Lp3/Mid;")
        heap.reset()
        with pytest.raises(DexTraceVMError):
            heap.get_class(h)

    def test_reset_restarts_handles_from_one(self):
        heap = ObjectHeap()
        heap.allocate("Lp3/Mid;")
        heap.allocate("Lp3/Mid;")
        heap.reset()
        h = heap.allocate("Lp3/Base;")
        assert h == 1

    def test_multiple_objects_independent(self):
        heap = ObjectHeap()
        h1 = heap.allocate("Lp3/Base;")
        h2 = heap.allocate("Lp3/Mid;")
        assert heap.get_class(h1) == "Lp3/Base;"
        assert heap.get_class(h2) == "Lp3/Mid;"


class TestObjectHeapValueSlot:
    """P4: heap entries can carry a Python value (e.g. str for Ljava/lang/String;)."""

    def test_default_value_is_none(self):
        heap = ObjectHeap()
        h = heap.allocate("Lp3/Mid;")
        assert heap.get_value(h) is None

    def test_string_value_round_trips(self):
        heap = ObjectHeap()
        h = heap.allocate("Ljava/lang/String;", value="+10000000000")
        assert heap.get_value(h) == "+10000000000"
        assert heap.get_class(h) == "Ljava/lang/String;"

    def test_get_value_null_handle_raises(self):
        heap = ObjectHeap()
        with pytest.raises(DexTraceVMError, match="null receiver"):
            heap.get_value(0)

    def test_get_value_invalid_handle_raises(self):
        heap = ObjectHeap()
        with pytest.raises(DexTraceVMError, match="invalid object handle"):
            heap.get_value(9999)

    def test_reset_clears_value_too(self):
        heap = ObjectHeap()
        h = heap.allocate("Ljava/lang/String;", value="ping")
        heap.reset()
        with pytest.raises(DexTraceVMError):
            heap.get_value(h)
