# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/signals.py — internal exception-flow signals raised by handlers.

These are NOT part of the public error API; they are caught and resolved by
the engine's dispatch loop. They live in their own module so handler files can
raise them without circular-importing engine.py.
"""

from __future__ import annotations


class _ThrowSignal(Exception):
    """
    Raised by `throw` and by Java-faithful raises (e.g. div-by-zero)
    so the engine can walk the catch table in this frame and, if no match,
    pop frames until it finds one or exhausts the call stack.

    Attributes:
      class_desc:  Dalvik descriptor of the exception type (e.g.
                   "Ljava/lang/ArithmeticException;"). Used by
                   ClassHierarchy.is_subtype() against catch table entries.
      exc_handle:  Heap handle of the exception object. 0 means "no
                   pre-allocated object" — the engine lazy-allocates one
                   when a catch matches and stores the handle in
                   state.pending_exception for `move-exception` to pick up.
    """

    __slots__ = ("class_desc", "exc_handle")

    def __init__(self, class_desc: str, exc_handle: int = 0) -> None:
        self.class_desc = class_desc
        self.exc_handle = exc_handle
