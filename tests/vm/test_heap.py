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
