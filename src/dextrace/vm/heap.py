# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/heap.py — Object heap: integer handle → HeapEntry.

Handles are sequential positive integers starting at 1. Handle 0 is reserved
to represent null (like null in Dalvik).

Each HeapEntry carries an optional `value` slot so string-bearing handles
(Ljava/lang/String;) can carry their underlying Python str. Stubs use
heap.get_value(handle) to read the materialized value when capturing IoCs.

HeapEntry also tracks instance fields, keyed by their full field signature
("Lcls;->name:type") so iget/iput-foo cannot collide across inherited
classes that happen to share a field name.

Public surface: allocate, get_class, get_value.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

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
    The handle is an opaque integer stored in registers by new-instance,
    const-string, or const-class. invoke-virtual reads it to
    look up the runtime class for vtable dispatch.
    """

    # Approximate fixed CPython footprints (bytes) so the running total tracks
    # *actual* memory, not an abstract unit count.
    _SLOT_BYTES = 8       # one pointer slot in a list ([0]*n stores n pointers)
    _LIST_OVERHEAD = 56   # an empty CPython list object
    _ENTRY_OVERHEAD = 64  # a HeapEntry (dataclass + its instance_fields dict)

    def __init__(self, memory_limit_mb: Optional[int] = None) -> None:
        self._objects: Dict[int, HeapEntry] = {}
        self._next_handle: int = 1
        # Predictive, cumulative allocation budget in *bytes*. ``None`` or any
        # value <= 0 disables it (the default, so direct VM/heap use in tests is
        # unaffected, and 0 is a uniform "no limit" sentinel for callers). When
        # set, each allocation is charged its real byte footprint *before* it
        # happens; once the running total would pass the limit the request is
        # rejected without ever committing the memory.
        self._max_bytes: Optional[int] = (
            int(memory_limit_mb) * 1024 * 1024
            if memory_limit_mb and memory_limit_mb > 0
            else None
        )
        self._used_bytes: int = 0

    def reset(self) -> None:
        """Clear all allocations. Called at vm.run() entry to isolate runs."""
        self._objects.clear()
        self._next_handle = 1
        self._used_bytes = 0

    @staticmethod
    def _value_bytes(value: Any) -> int:
        """Real footprint of a heap value's payload (e.g. a string's length).

        Single source of "what a value costs", shared by allocate/set_value.
        """
        return sys.getsizeof(value) if value is not None else 0

    def _charge(self, nbytes: int) -> None:
        """Reserve ``nbytes`` against the running total *before* allocating.

        Pure integer arithmetic — no memory is touched — so a pathological
        request (e.g. ``new-array v, 2**40`` → ~8 TiB) is rejected up front
        instead of being allocated and then detected. The total accumulates
        across the whole run (reset per ``vm.run()``), so many small
        allocations also trip the cap. No-op when no budget is configured, so
        callers can charge unconditionally.
        """
        if self._max_bytes is None:
            return
        if self._used_bytes + nbytes > self._max_bytes:
            raise DexTraceVMError(
                f"memory budget exceeded: allocating {nbytes} bytes would pass "
                f"the limit ({self._max_bytes // (1024 * 1024)} MiB; "
                f"{self._used_bytes} already used)"
            )
        self._used_bytes += nbytes

    def allocate(self, class_desc: str, value: Any = None) -> int:
        """Allocate a new object of class_desc. Returns its handle (>= 1)."""
        self._charge(self._ENTRY_OVERHEAD + self._value_bytes(value))
        handle = self._next_handle
        self._next_handle += 1
        self._objects[handle] = HeapEntry(class_desc=class_desc, value=value)
        return handle

    # ------------------------------------------------------------------
    # arrays
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
        # Real host cost of [0]*length is the list backbone: one pointer slot
        # per element (the int 0 is shared), regardless of Dalvik element width
        # — that 8*length is what fills RAM. Charge it predictively (the int
        # math is cheap and _charge no-ops when unbounded).
        self._charge(self._LIST_OVERHEAD + self._SLOT_BYTES * length)
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

        Replacing a value with a larger one is charged its *growth* against the
        memory budget, so unbounded mutation (e.g. StringBuilder.append in a
        loop) cannot bypass the cap that allocate/allocate_array enforce. Only
        growth is charged — shrinking is free, keeping the cumulative-total
        semantics. Over-budget growth raises before the value is stored.
        """
        entry = self._entry(handle)
        delta = self._value_bytes(value) - self._value_bytes(entry.value)
        if delta > 0:  # only growth is charged; _charge no-ops when unbounded
            self._charge(delta)
        entry.value = value

    # ------------------------------------------------------------------
    # instance fields
    # ------------------------------------------------------------------

    def set_instance_field(
        self, handle: int, field_sig: str, val: Any
    ) -> None:
        """
        Store `val` in the named instance field of `handle`. Field key is the
        full Dalvik signature (e.g. "Lcom/foo/Box;->count:I") so an inherited
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
