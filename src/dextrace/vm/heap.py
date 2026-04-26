# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/heap.py — Object heap: integer handle → (class descriptor, optional value).

Handles are sequential positive integers starting at 1.
Handle 0 is reserved to represent null (like null in Dalvik).

P4 added the optional `value` slot so string-bearing handles (e.g. handles for
Ljava/lang/String;) can carry their underlying Python str. Stubs use
heap.get_value(handle) to read the materialized value when capturing IoCs.
"""

from __future__ import annotations

from typing import Any, Dict, Tuple

from dextrace.vm.errors import DexTraceVMError


class ObjectHeap:
    """
    Minimal object heap for the DalvikVM interpreter.

    Tracks allocated objects as (handle → (class_descriptor, value)) pairs.
    The handle is an opaque integer stored in registers by new-instance.
    invoke-virtual reads it to look up the runtime class for vtable dispatch.
    The value slot is None for "plain" object handles and carries the Python
    payload (e.g. a str) for handles materialized from constants or stubs.
    """

    def __init__(self) -> None:
        self._objects: Dict[int, Tuple[str, Any]] = {}
        self._next_handle: int = 1

    def reset(self) -> None:
        """Clear all allocations. Called at vm.run() entry to isolate runs."""
        self._objects.clear()
        self._next_handle = 1

    def allocate(self, class_desc: str, value: Any = None) -> int:
        """Allocate a new object of class_desc. Returns its handle (>= 1)."""
        handle = self._next_handle
        self._next_handle += 1
        self._objects[handle] = (class_desc, value)
        return handle

    def get_class(self, handle: int) -> str:
        """
        Return the class descriptor for handle.

        Raises DexTraceVMError on null (handle=0) or invalid handle.
        """
        if handle == 0:
            raise DexTraceVMError(
                "null receiver: handle is 0 (null object reference)"
            )
        entry = self._objects.get(handle)
        if entry is None:
            raise DexTraceVMError(f"invalid object handle: {handle}")
        return entry[0]

    def get_value(self, handle: int) -> Any:
        """
        Return the materialized Python value for handle, or None if the handle
        was allocated without one. Raises on null/invalid handle so callers
        can distinguish "value is None" from "handle does not exist".
        """
        if handle == 0:
            raise DexTraceVMError(
                "null receiver: handle is 0 (null object reference)"
            )
        entry = self._objects.get(handle)
        if entry is None:
            raise DexTraceVMError(f"invalid object handle: {handle}")
        return entry[1]
