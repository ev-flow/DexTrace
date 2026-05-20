# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""Unit tests for vm/android_stubs/text.py — String/StringBuilder/etc."""

from __future__ import annotations

from dextrace.vm.android_stubs import REGISTRY, VOID
from dextrace.vm.android_stubs.text import (
    stub_string_init_bytes,
    stub_string_init_bytes_charset,
)
from dextrace.vm.heap import ObjectHeap


class TestStringInitBytes:
    def test_ascii_bytes_decoded_correctly(self):
        heap = ObjectHeap()
        str_handle = heap.allocate("Ljava/lang/String;")
        arr_handle = heap.allocate_array("[B", 7)
        arr = heap.get_array(arr_handle)
        for i, b in enumerate([0x73, 0x65, 0x74, 0x74, 0x69, 0x6E, 0x67]):
            arr[i] = b
        result = stub_string_init_bytes([str_handle, arr_handle], heap, [])
        assert result is VOID
        assert heap.get_value(str_handle) == "setting"

    def test_null_array_sets_empty_string(self):
        heap = ObjectHeap()
        str_handle = heap.allocate("Ljava/lang/String;")
        result = stub_string_init_bytes([str_handle, 0], heap, [])
        assert result is VOID
        assert heap.get_value(str_handle) == ""

    def test_high_bytes_decoded_as_latin1(self):
        heap = ObjectHeap()
        str_handle = heap.allocate("Ljava/lang/String;")
        arr_handle = heap.allocate_array("[B", 2)
        arr = heap.get_array(arr_handle)
        arr[0] = 0xC9  # É in Latin-1
        arr[1] = 0x74  # t
        result = stub_string_init_bytes([str_handle, arr_handle], heap, [])
        assert result is VOID
        assert heap.get_value(str_handle) == "\xC9t"

    def test_charset_utf8(self):
        heap = ObjectHeap()
        str_handle = heap.allocate("Ljava/lang/String;")
        arr_handle = heap.allocate_array("[B", 5)
        arr = heap.get_array(arr_handle)
        charset_handle = heap.allocate("Ljava/lang/String;", value="UTF-8")
        for i, b in enumerate([0x68, 0x65, 0x6C, 0x6C, 0x6F]):
            arr[i] = b
        result = stub_string_init_bytes_charset(
            [str_handle, arr_handle, charset_handle], heap, []
        )
        assert result is VOID
        assert heap.get_value(str_handle) == "hello"

    def test_registered_in_registry(self):
        assert "Ljava/lang/String;-><init>([B)V" in REGISTRY
        assert "Ljava/lang/String;-><init>([BLjava/lang/String;)V" in REGISTRY
