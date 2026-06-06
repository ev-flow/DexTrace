# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/android_stubs/text.py — Java lang/util stubs needed by GoldDream and similar.

Covers:
  StringBuilder (<init>, append, toString) — concrete string accumulation
  String (equals, valueOf, getBytes, lastIndexOf, substring)
  Long.valueOf, Boolean.booleanValue, Boolean.valueOf
  System.currentTimeMillis
  SimpleDateFormat.format (both overloads)

Design: StringBuilder state is kept in HeapEntry.value (a Python str).
  <init> sets value on the existing handle (allocated by new-instance).
  append appends and returns self-handle (for chaining).
  toString returns a fresh String handle with the accumulated value.
"""

from __future__ import annotations

from typing import Any, Dict, List

from dextrace.vm.android_stubs import (
    ObjectRef,
    StubResult,
    Value,
    Wide,
    VOID,
    register,
)

_SB = "Ljava/lang/StringBuilder;"
_STR = "Ljava/lang/String;"
_LONG_OBJ = "Ljava/lang/Long;"
_BOOL_OBJ = "Ljava/lang/Boolean;"
_SDF = "Ljava/text/SimpleDateFormat;"


def _str_val(heap, handle: int) -> str:
    if handle == 0:
        return ""
    v = heap.get_value(handle)
    return str(v) if v is not None else ""


# ---------------------------------------------------------------------------
# StringBuilder
# ---------------------------------------------------------------------------


def stub_sb_init_void(
    args: List[Any], heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """StringBuilder.<init>()V"""
    heap.set_value(args[0], "")
    return VOID


def stub_sb_init_string(
    args: List[Any], heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """StringBuilder.<init>(String)V"""
    initial = _str_val(heap, args[1] if len(args) > 1 else 0)
    heap.set_value(args[0], initial)
    return VOID


def stub_sb_append_string(
    args: List[Any], heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """StringBuilder.append(String)StringBuilder — returns self handle."""
    sb_handle = args[0]
    s = _str_val(heap, args[1] if len(args) > 1 else 0)
    cur = heap.get_value(sb_handle)
    heap.set_value(sb_handle, (cur or "") + s)
    return ObjectRef(sb_handle)


def stub_sb_append_int(
    args: List[Any], heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """StringBuilder.append(I)StringBuilder — returns self handle."""
    sb_handle = args[0]
    v = args[1] if len(args) > 1 else 0
    cur = heap.get_value(sb_handle)
    heap.set_value(sb_handle, (cur or "") + str(v))
    return ObjectRef(sb_handle)


def stub_sb_append_object(
    args: List[Any], heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """StringBuilder.append(Object)StringBuilder — stringify via get_value."""
    sb_handle = args[0]
    s = _str_val(heap, args[1] if len(args) > 1 else 0)
    cur = heap.get_value(sb_handle)
    heap.set_value(sb_handle, (cur or "") + s)
    return ObjectRef(sb_handle)


def stub_sb_tostring(
    args: List[Any], heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """StringBuilder.toString()String — allocates a new String handle."""
    cur = heap.get_value(args[0]) or ""
    handle = heap.allocate(_STR, value=cur)
    return ObjectRef(handle)


# ---------------------------------------------------------------------------
# String helpers
# ---------------------------------------------------------------------------


def _init_string_from_bytes(heap, str_handle, arr_handle, charset: str) -> StubResult:
    """Shared body for String.<init>([B...): decode a heap byte array into str_handle.

    Dalvik byte arrays hold signed values, so each element is masked to a byte
    before decoding. Falls back to Latin-1 if the charset is unknown/invalid.
    """
    if arr_handle == 0:
        heap.set_value(str_handle, "")
        return VOID
    raw = bytes(b & 0xFF for b in heap.get_array(arr_handle))
    try:
        s = raw.decode(charset)
    except (LookupError, UnicodeDecodeError):
        s = raw.decode("latin-1")
    heap.set_value(str_handle, s)
    return VOID


def stub_string_init_bytes(
    args: List[Any], heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """String.<init>([B)V — construct String from raw byte array.

    Defaults to UTF-8 to match Android's platform default charset; the shared
    decoder falls back to Latin-1 on invalid byte sequences.
    """
    arr_handle = args[1] if len(args) > 1 else 0
    return _init_string_from_bytes(heap, args[0], arr_handle, "utf-8")


def stub_string_init_bytes_charset(
    args: List[Any], heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """String.<init>([BLjava/lang/String;)V — byte array + charset name."""
    arr_handle = args[1] if len(args) > 1 else 0
    charset_handle = args[2] if len(args) > 2 else 0
    charset = _str_val(heap, charset_handle) if charset_handle else "utf-8"
    return _init_string_from_bytes(heap, args[0], arr_handle, charset)


def stub_string_equals(
    args: List[Any], heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """String.equals(Object)Z — compares the stored Python strings."""
    s1 = _str_val(heap, args[0])
    s2 = _str_val(heap, args[1] if len(args) > 1 else 0)
    return Value(1 if s1 == s2 else 0)


def stub_string_valueof_object(
    args: List[Any], heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """String.valueOf(Object)String (static) — args[0] is the object handle."""
    s = _str_val(heap, args[0])
    handle = heap.allocate(_STR, value=s)
    return ObjectRef(handle)


def stub_string_getbytes(
    args: List[Any], heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """String.getBytes()[B — returns a byte array handle."""
    s = _str_val(heap, args[0])
    encoded = s.encode("utf-8")
    arr_handle = heap.allocate_array("[B", len(encoded))
    arr = heap.get_array(arr_handle)
    for i, b in enumerate(encoded):
        arr[i] = b
    return ObjectRef(arr_handle)


def stub_string_last_index_of(
    args: List[Any], heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """String.lastIndexOf(String)I"""
    s = _str_val(heap, args[0])
    sub = _str_val(heap, args[1] if len(args) > 1 else 0)
    return Value(s.rfind(sub))


def stub_string_substring(
    args: List[Any], heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """String.substring(I)String"""
    s = _str_val(heap, args[0])
    start = args[1] if len(args) > 1 else 0
    result = s[start:] if 0 <= start <= len(s) else ""
    handle = heap.allocate(_STR, value=result)
    return ObjectRef(handle)


# ---------------------------------------------------------------------------
# Long / Boolean / System
# ---------------------------------------------------------------------------


def stub_long_valueof(
    args: List[Any], heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """Long.valueOf(J)Long (static) — args[0:1] are the two halves of a long."""
    lo = (args[0] & 0xFFFF_FFFF) if args else 0
    hi = (args[1] & 0xFFFF_FFFF) if len(args) > 1 else 0
    v = (hi << 32) | lo
    handle = heap.allocate(_LONG_OBJ, value=v)
    return ObjectRef(handle)


def stub_boolean_valueof(
    args: List[Any], heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """Boolean.valueOf(Z)Boolean (static)."""
    v = args[0] if args else 0
    handle = heap.allocate(_BOOL_OBJ, value=bool(v))
    return ObjectRef(handle)


def stub_boolean_booleanvalue(
    args: List[Any], heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """Boolean.booleanValue()Z"""
    v = heap.get_value(args[0])
    return Value(1 if v else 0)


_FAKE_TS_MS = 1_700_000_000_000  # 2023-11-14 approx, matches telephony.py


def stub_system_current_time_millis(
    _args: List[Any], _heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """System.currentTimeMillis()J (static) — returns a fake epoch ms."""
    return Wide(_FAKE_TS_MS)


def stub_sdf_format_object(
    _args: List[Any], heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """SimpleDateFormat.format(Object)String — returns a synthetic date string."""
    handle = heap.allocate(_STR, value="1970-01-01 00:00:00")
    return ObjectRef(handle)


def stub_sdf_format_date(
    _args: List[Any], heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """SimpleDateFormat.format(Date)String — returns a synthetic date string."""
    handle = heap.allocate(_STR, value="1970-01-01 00:00:00")
    return ObjectRef(handle)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

register(f"{_SB}-><init>()V", stub_sb_init_void)
register(f"{_SB}-><init>(Ljava/lang/String;)V", stub_sb_init_string)
register(
    f"{_SB}->append(Ljava/lang/String;){_SB}",
    stub_sb_append_string,
)
register(f"{_SB}->append(I){_SB}", stub_sb_append_int)
register(f"{_SB}->append(Ljava/lang/Object;){_SB}", stub_sb_append_object)
register(f"{_SB}->toString()Ljava/lang/String;", stub_sb_tostring)

register(
    "Ljava/lang/String;-><init>([B)V",
    stub_string_init_bytes,
)
register(
    "Ljava/lang/String;-><init>([BLjava/lang/String;)V",
    stub_string_init_bytes_charset,
)
register(
    "Ljava/lang/String;->equals(Ljava/lang/Object;)Z",
    stub_string_equals,
)
register(
    "Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;",
    stub_string_valueof_object,
)
register("Ljava/lang/String;->getBytes()[B", stub_string_getbytes)
register(
    "Ljava/lang/String;->lastIndexOf(Ljava/lang/String;)I",
    stub_string_last_index_of,
)
register(
    "Ljava/lang/String;->substring(I)Ljava/lang/String;",
    stub_string_substring,
)

register(
    "Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;",
    stub_long_valueof,
)
register(
    "Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;",
    stub_boolean_valueof,
)
register(
    "Ljava/lang/Boolean;->booleanValue()Z",
    stub_boolean_booleanvalue,
)
register(
    "Ljava/lang/System;->currentTimeMillis()J",
    stub_system_current_time_millis,
)
register(
    f"{_SDF}->format(Ljava/lang/Object;)Ljava/lang/String;",
    stub_sdf_format_object,
)
register(
    f"{_SDF}->format(Ljava/util/Date;)Ljava/lang/String;",
    stub_sdf_format_date,
)
