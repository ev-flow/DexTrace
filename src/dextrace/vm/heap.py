# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/heap.py — Object heap: integer handle → class descriptor.

Handles are sequential positive integers starting at 1.
Handle 0 is reserved to represent null (like null in Dalvik).
"""

from __future__ import annotations

from typing import Dict

from dextrace.vm.errors import DexTraceVMError


class ObjectHeap:
    """
    Minimal object heap for the DalvikVM interpreter.

    Tracks allocated objects as (handle → class_descriptor) pairs.
    The handle is an opaque integer stored in registers by new-instance.
    invoke-virtual reads it to look up the runtime class for vtable dispatch.
    """

    def __init__(self) -> None:
        self._objects: Dict[int, str] = {}
        self._next_handle: int = 1

    def reset(self) -> None:
        """Clear all allocations. Called at vm.run() entry to isolate runs."""
        self._objects.clear()
        self._next_handle = 1

    def allocate(self, class_desc: str) -> int:
        """Allocate a new object of class_desc. Returns its handle (>= 1)."""
        handle = self._next_handle
        self._next_handle += 1
        self._objects[handle] = class_desc
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
        desc = self._objects.get(handle)
        if desc is None:
            raise DexTraceVMError(f"invalid object handle: {handle}")
        return desc
