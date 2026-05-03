# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/android_stubs/intent.py — Android Intent, Bundle, and Context stubs.

Covers the action-routing and extras surface used by GoldDream's zjReceiver:
  Intent.getAction, getExtras, getStringExtra, setClass, setFlags
  Bundle.get  — returns a 1-element Object[] holding a fake [B PDU array
  Context.startService, startActivity, openFileOutput
"""

from __future__ import annotations

from typing import Any, Dict, List

from dextrace.vm.android_stubs import (
    ObjectRef,
    StubResult,
    VOID,
    register,
)

_INTENT = "Landroid/content/Intent;"
_BUNDLE = "Landroid/os/Bundle;"
_COMPONENT = "Landroid/content/ComponentName;"
_FOS = "Ljava/io/FileOutputStream;"
_STR = "Ljava/lang/String;"


def _str_val(heap, handle: int) -> str:
    if handle == 0:
        return ""
    v = heap.get_value(handle)
    return str(v) if v is not None else ""


# ---------------------------------------------------------------------------
# Intent
# ---------------------------------------------------------------------------

def stub_intent_get_action(args: List[Any], heap, trace: List[Dict[str, Any]]) -> StubResult:
    """Intent.getAction()String — returns the action stored on the Intent handle.

    Callers inject the action by passing the Intent handle's stored value as the
    action string (set via heap.set_value before run(), or default empty string).
    """
    handle = args[0]
    action = heap.get_value(handle) if handle else None
    s = action if isinstance(action, str) else ""
    str_handle = heap.allocate(_STR, value=s)
    trace.append({"api": f"{_INTENT}->getAction()Ljava/lang/String;", "args": [s], "return": {"kind": "object", "value": s}})
    return ObjectRef(str_handle)


def stub_intent_get_extras(args: List[Any], heap, trace: List[Dict[str, Any]]) -> StubResult:
    """Intent.getExtras()Bundle — returns a Bundle handle."""
    bundle_handle = heap.allocate(_BUNDLE)
    trace.append({"api": f"{_INTENT}->getExtras()Landroid/os/Bundle;", "args": [], "return": {"kind": "object", "class": _BUNDLE}})
    return ObjectRef(bundle_handle)


def stub_intent_get_string_extra(args: List[Any], heap, trace: List[Dict[str, Any]]) -> StubResult:
    """Intent.getStringExtra(String)String — returns empty string."""
    key = _str_val(heap, args[1] if len(args) > 1 else 0)
    str_handle = heap.allocate(_STR, value="")
    trace.append({"api": f"{_INTENT}->getStringExtra(Ljava/lang/String;)Ljava/lang/String;", "args": [key], "return": {"kind": "object", "value": ""}})
    return ObjectRef(str_handle)


def stub_intent_set_class(args: List[Any], heap, trace: List[Dict[str, Any]]) -> StubResult:
    """Intent.setClass(Context, Class)Intent — returns self handle."""
    return ObjectRef(args[0])


def stub_intent_set_flags(args: List[Any], heap, trace: List[Dict[str, Any]]) -> StubResult:
    """Intent.setFlags(I)Intent — returns self handle."""
    return ObjectRef(args[0])


# ---------------------------------------------------------------------------
# Bundle
# ---------------------------------------------------------------------------

def stub_bundle_get(args: List[Any], heap, trace: List[Dict[str, Any]]) -> StubResult:
    """Bundle.get(String)Object — for 'pdus' key, returns a 1-element Object[] with a fake [B PDU."""
    key = _str_val(heap, args[1] if len(args) > 1 else 0)
    trace.append({"api": f"{_BUNDLE}->get(Ljava/lang/String;)Ljava/lang/Object;", "args": [key], "return": {"kind": "object"}})
    if key == "pdus":
        # Allocate a fake byte-array PDU and wrap it in an Object[] array.
        pdu_handle = heap.allocate_array("[B", 1)  # minimal non-empty byte array
        outer_handle = heap.allocate_array("[Ljava/lang/Object;", 1)
        outer = heap.get_array(outer_handle)
        outer[0] = pdu_handle
        return ObjectRef(outer_handle)
    # For other keys, return null so the code takes the null-check branch.
    return ObjectRef(0)


# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------

def stub_context_start_service(args: List[Any], heap, trace: List[Dict[str, Any]]) -> StubResult:
    """Context.startService(Intent)ComponentName — returns a ComponentName handle."""
    handle = heap.allocate(_COMPONENT)
    trace.append({"api": f"Landroid/content/Context;->startService(Landroid/content/Intent;)Landroid/content/ComponentName;", "args": [], "return": {"kind": "object", "class": _COMPONENT}})
    return ObjectRef(handle)


def stub_context_start_activity(args: List[Any], heap, trace: List[Dict[str, Any]]) -> StubResult:
    """Context.startActivity(Intent)V — void no-op."""
    trace.append({"api": "Landroid/content/Context;->startActivity(Landroid/content/Intent;)V", "args": [], "return": {"kind": "void"}})
    return VOID


def stub_context_open_file_output(args: List[Any], heap, trace: List[Dict[str, Any]]) -> StubResult:
    """Context.openFileOutput(String, int)FileOutputStream — returns a FileOutputStream handle."""
    filename = _str_val(heap, args[1] if len(args) > 1 else 0)
    handle = heap.allocate(_FOS)
    trace.append({"api": "Landroid/content/Context;->openFileOutput(Ljava/lang/String;I)Ljava/io/FileOutputStream;", "args": [filename], "return": {"kind": "object", "class": _FOS}})
    return ObjectRef(handle)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

register(f"{_INTENT}->getAction()Ljava/lang/String;", stub_intent_get_action)
register(f"{_INTENT}->getExtras()Landroid/os/Bundle;", stub_intent_get_extras)
register(
    f"{_INTENT}->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
    stub_intent_get_string_extra,
)
register(
    f"{_INTENT}->setClass(Landroid/content/Context;Ljava/lang/Class;){_INTENT}",
    stub_intent_set_class,
)
register(f"{_INTENT}->setFlags(I){_INTENT}", stub_intent_set_flags)

register(
    f"{_BUNDLE}->get(Ljava/lang/String;)Ljava/lang/Object;",
    stub_bundle_get,
)

register(
    "Landroid/content/Context;->startService(Landroid/content/Intent;)Landroid/content/ComponentName;",
    stub_context_start_service,
)
register(
    "Landroid/content/Context;->startActivity(Landroid/content/Intent;)V",
    stub_context_start_activity,
)
register(
    "Landroid/content/Context;->openFileOutput(Ljava/lang/String;I)Ljava/io/FileOutputStream;",
    stub_context_open_file_output,
)
