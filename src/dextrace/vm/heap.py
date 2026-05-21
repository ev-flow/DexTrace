# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/heap.py — Object heap: integer handle → HeapEntry.

Handles are sequential positive integers starting at 1. Handle 0 is reserved
to represent null (like null in Dalvik).

P4 introduced the optional `value` slot so string-bearing handles
(Ljava/lang/String;) can carry their underlying Python str. Stubs use
heap.get_value(handle) to read the materialized value when capturing IoCs.

P5d reshape:
  Replaces the (class_desc, value) tuple with a HeapEntry dataclass that
  also tracks instance fields. Instance fields are keyed by their full
  field signature ("Lcls;->name:type") so iget/iput-foo cannot collide
  across inherited classes that happen to share a field name.

  The public surface — allocate, get_class, get_value — is preserved.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict

from dextrace.vm.errors import DexTraceVMError


@dataclass
class HeapEntry:
    """One heap-allocated object."""

    class_desc: str
    value: Any = None
    # Field signature -> stored value. Object fields hold heap handles (ints);
    # primitive fields hold Python ints already masked to the appropriate
    # width by the iput-* handler.
    instance_fields: Dict[str, Any] = field(default_factory=dict)


class ObjectHeap:
    """
    Minimal object heap for the DalvikVM interpreter.

    Tracks allocated objects as HeapEntry records keyed by integer handle.
    The handle is an opaque integer stored in registers by new-instance
    (and by P5d const-string / const-class). invoke-virtual reads it to
    look up the runtime class for vtable dispatch.
    """

    def __init__(self) -> None:
        self._objects: Dict[int, HeapEntry] = {}
        self._next_handle: int = 1

    def reset(self) -> None:
        """Clear all allocations. Called at vm.run() entry to isolate runs."""
        self._objects.clear()
        self._next_handle = 1

    def allocate(self, class_desc: str, value: Any = None) -> int:
        """Allocate a new object of class_desc. Returns its handle (>= 1)."""
        handle = self._next_handle
        self._next_handle += 1
        self._objects[handle] = HeapEntry(class_desc=class_desc, value=value)
        return handle

    # ------------------------------------------------------------------
    # P5e: arrays
    # ------------------------------------------------------------------

    def allocate_array(self, array_desc: str, length: int) -> int:
        """
        Allocate an array of `length` elements, default-initialized to 0.
        `array_desc` is the full Dalvik array descriptor (e.g. "[I", "[[I",
        "[Ljava/lang/String;"). The list is stored on the HeapEntry's value
        slot so array handlers can index it directly.
        """
        if length < 0:
            raise DexTraceVMError(f"allocate_array: negative length {length}")
        handle = self._next_handle
        self._next_handle += 1
        self._objects[handle] = HeapEntry(
            class_desc=array_desc, value=[0] * length
        )
        return handle

    def get_array(self, handle: int) -> list:
        """
        Return the underlying Python list backing the array at `handle`.
        Caller is responsible for bounds checks and raising
        ArrayIndexOutOfBoundsException via _ThrowSignal — the heap stays
        signal-agnostic so it cannot circular-import vm.signals.
        """
        entry = self._entry(handle)
        if not isinstance(entry.value, list):
            raise DexTraceVMError(
                f"handle {handle} is not an array "
                f"(class_desc={entry.class_desc!r})"
            )
        return entry.value

    def get_class(self, handle: int) -> str:
        """
        Return the class descriptor for handle.

        Raises DexTraceVMError on null (handle=0) or invalid handle.
        """
        return self._entry(handle).class_desc

    def get_value(self, handle: int) -> Any:
        """
        Return the materialized Python value for handle, or None if the handle
        was allocated without one. Raises on null/invalid handle so callers
        can distinguish "value is None" from "handle does not exist".
        """
        return self._entry(handle).value

    def set_value(self, handle: int, value: Any) -> None:
        """
        Update the `value` slot of an existing heap entry. Used by stubs that
        mutate already-allocated objects (e.g. StringBuilder.<init> sets the
        initial string on a handle that new-instance created with value=None).
        """
        self._entry(handle).value = value

    # ------------------------------------------------------------------
    # P5d: instance fields
    # ------------------------------------------------------------------

    def set_instance_field(
        self, handle: int, field_sig: str, val: Any
    ) -> None:
        """
        Store `val` in the named instance field of `handle`. Field key is the
        full Dalvik signature (e.g. "Lp5d/Box;->count:I") so an inherited
        field with the same simple name on a different class cannot clash.
        """
        self._entry(handle).instance_fields[field_sig] = val

    def get_instance_field(
        self, handle: int, field_sig: str, default: Any = 0
    ) -> Any:
        """
        Read the named instance field of `handle`. Returns `default` (0 by
        default — Java's "unset int field" value) if the field has never been
        written. The default lets fixtures rely on Java's default-init rules
        without first running a constructor.
        """
        return self._entry(handle).instance_fields.get(field_sig, default)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _entry(self, handle: int) -> HeapEntry:
        if handle == 0:
            raise DexTraceVMError(
                "null receiver: handle is 0 (null object reference)"
            )
        entry = self._objects.get(handle)
        if entry is None:
            raise DexTraceVMError(f"invalid object handle: {handle}")
        return entry
