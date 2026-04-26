# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/android_stubs/ — Registry of simulated Android/Java framework methods.

A "stub" is a Python callable that simulates the side-effect and return value
of an Android API the DalvikVM cannot execute (no real Android runtime). The
engine looks up stubs by full method signature BEFORE attempting in-DEX vtable
resolution or external-zero fallback.

Stub callable contract:
    stub(args: list[Any], heap: ObjectHeap, trace: list[dict]) -> StubResult

  args   — register values for the invoke instruction. For object args, the
           value is an object handle; call heap.get_value(h) for the underlying
           Python value (e.g. str for Ljava/lang/String;).
  heap   — the live ObjectHeap. Stubs may allocate new handles for return
           values typed as objects.
  trace  — the live api_calls list. Stubs append a dict describing the call.

Return shape: an instance of one of VOID, Value(int), Wide(int), ObjectRef(int).

Registry key: full method signature as emitted by the disassembler, e.g.
    "Landroid/telephony/SmsManager;->getDefault()Landroid/telephony/SmsManager;"
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List

# StubCallable is forward-declared after StubResult; mypy/runtime tolerate this
# via the late binding inside REGISTRY's value type.


# ---------------------------------------------------------------------------
# StubResult — tagged union for stub return shapes
# ---------------------------------------------------------------------------


class StubResult:
    """Marker base class for stub return shapes."""

    __slots__ = ()


class _Void(StubResult):
    """Stub returns void. Engine treats pending_result as a Dalvik no-op."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "VOID"


VOID: _Void = _Void()


@dataclass(frozen=True)
class Value(StubResult):
    """Stub returns a 32-bit primitive (int, boolean, char, etc.)."""

    value: int


@dataclass(frozen=True)
class Wide(StubResult):
    """Stub returns a 64-bit primitive (long, double)."""

    value: int


@dataclass(frozen=True)
class ObjectRef(StubResult):
    """Stub returns an object reference. handle must be from heap.allocate()."""

    handle: int


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

StubCallable = Callable[[List[Any], Any, List[Dict[str, Any]]], StubResult]

REGISTRY: Dict[str, StubCallable] = {}


def register(signature: str, fn: StubCallable) -> None:
    """Register a stub for a method signature. Last writer wins."""
    REGISTRY[signature] = fn


# ---------------------------------------------------------------------------
# Bootstrap: import each stub module so its register() calls populate REGISTRY
# at package import time. Adding a new stub family means importing it here.
# ---------------------------------------------------------------------------

from dextrace.vm.android_stubs import sms  # noqa: E402,F401  (side-effect import)
