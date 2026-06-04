# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/android_stubs/content.py — Android ContentProvider and network connectivity stubs.

Covers DroidKungFu Threat 3 (Forward confidential data):
  Context.getContentResolver
  ContentResolver.query
  Cursor.moveToFirst, getColumnIndex, getString, getInt, close
  Uri.parse
  ConnectivityManager.getActiveNetworkInfo
  NetworkInfo.isConnected, getType, getExtraInfo
  Context.getSystemService (extended: 'connectivity' → ConnectivityManager,
                             'notification' → NotificationManager)
"""

from __future__ import annotations

from typing import Any, Dict, List

from dextrace.vm.android_stubs import (
    ObjectRef,
    StubResult,
    Value,
    VOID,
    register,
)

_CONTENT_RESOLVER = "Landroid/content/ContentResolver;"
_CURSOR = "Landroid/database/Cursor;"
_URI = "Landroid/net/Uri;"
_CONN_MGR = "Landroid/net/ConnectivityManager;"
_NET_INFO = "Landroid/net/NetworkInfo;"
_NOTIF_MGR = "Landroid/app/NotificationManager;"
_TEL_MGR = "Landroid/telephony/TelephonyManager;"
_STR = "Ljava/lang/String;"

# Fake SMS row returned by ContentResolver.query
_FAKE_SMS_ROW = {
    "address": "+15550001234",
    "body": "fake sms body",
    "date": "1700000000000",
    "type": "1",
}


def _str_val(heap, handle: int) -> str:
    if handle == 0:
        return ""
    v = heap.get_value(handle)
    return str(v) if v is not None else ""


# ---------------------------------------------------------------------------
# Context.getContentResolver
# ---------------------------------------------------------------------------


def stub_context_get_content_resolver(
    _args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """Context.getContentResolver()ContentResolver."""
    handle = heap.allocate(_CONTENT_RESOLVER)
    trace.append(
        {
            "api": f"Landroid/content/Context;->getContentResolver(){_CONTENT_RESOLVER}",
            "args": [],
            "return": {"kind": "object", "class": _CONTENT_RESOLVER},
        }
    )
    return ObjectRef(handle)


# ---------------------------------------------------------------------------
# ContentResolver.query
# ---------------------------------------------------------------------------


def stub_content_resolver_query(
    args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """ContentResolver.query(Uri, String[], String, String[], String)Cursor.

    Returns a Cursor handle with one fake SMS/CALLLOG row stored as value.
    """
    uri_str = _str_val(heap, args[1] if len(args) > 1 else 0)
    handle = heap.allocate(_CURSOR, value=_FAKE_SMS_ROW)
    trace.append(
        {
            "api": (
                f"{_CONTENT_RESOLVER}->query("
                f"{_URI}[Ljava/lang/String;Ljava/lang/String;"
                f"[Ljava/lang/String;Ljava/lang/String;){_CURSOR}"
            ),
            "args": [uri_str],
            "return": {"kind": "object", "class": _CURSOR},
        }
    )
    return ObjectRef(handle)


# ---------------------------------------------------------------------------
# Cursor
# ---------------------------------------------------------------------------


def stub_cursor_move_to_first(
    _args: List[Any], _heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """Cursor.moveToFirst()Z — returns true (one row available)."""
    trace.append(
        {
            "api": f"{_CURSOR}->moveToFirst()Z",
            "args": [],
            "return": {"kind": "int", "value": 1},
        }
    )
    return Value(1)


def stub_cursor_get_column_index(
    args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """Cursor.getColumnIndex(String)I — returns column index by name."""
    col = _str_val(heap, args[1] if len(args) > 1 else 0)
    # Map column names to fixed indices matching _FAKE_SMS_ROW insertion order
    _COL_INDEX = {"address": 0, "body": 1, "date": 2, "type": 3}
    idx = _COL_INDEX.get(col, 0)
    trace.append(
        {
            "api": f"{_CURSOR}->getColumnIndex(Ljava/lang/String;)I",
            "args": [col],
            "return": {"kind": "int", "value": idx},
        }
    )
    return Value(idx)


def stub_cursor_get_string(
    args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """Cursor.getString(I)String — returns fake column value."""
    idx = args[1] if len(args) > 1 else 0
    cursor_data = heap.get_value(args[0]) if args else {}
    _COLS = ["address", "body", "date", "type"]
    col = _COLS[idx] if isinstance(idx, int) and 0 <= idx < len(_COLS) else ""
    value = cursor_data.get(col, "") if isinstance(cursor_data, dict) else ""
    str_handle = heap.allocate(_STR, value=value)
    trace.append(
        {
            "api": f"{_CURSOR}->getString(I)Ljava/lang/String;",
            "args": [idx],
            "return": {"kind": "object", "value": value},
        }
    )
    return ObjectRef(str_handle)


def stub_cursor_get_int(
    args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """Cursor.getInt(I)I — returns integer column value."""
    idx = args[1] if len(args) > 1 else 0
    cursor_data = heap.get_value(args[0]) if args else {}
    _COLS = ["address", "body", "date", "type"]
    col = _COLS[idx] if isinstance(idx, int) and 0 <= idx < len(_COLS) else ""
    raw = cursor_data.get(col, "0") if isinstance(cursor_data, dict) else "0"
    try:
        value = int(raw)
    except (ValueError, TypeError):
        value = 0
    trace.append(
        {
            "api": f"{_CURSOR}->getInt(I)I",
            "args": [idx],
            "return": {"kind": "int", "value": value},
        }
    )
    return Value(value)


def stub_cursor_close(
    _args: List[Any], _heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """Cursor.close()V — no-op."""
    trace.append({"api": f"{_CURSOR}->close()V", "args": [], "return": {"kind": "void"}})
    return VOID


# ---------------------------------------------------------------------------
# Uri.parse
# ---------------------------------------------------------------------------


def stub_uri_parse(
    args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """Uri.parse(String)Uri (static)."""
    uri_str = _str_val(heap, args[0] if args else 0)
    handle = heap.allocate(_URI, value=uri_str)
    trace.append(
        {
            "api": f"{_URI}->parse(Ljava/lang/String;){_URI}",
            "args": [uri_str],
            "return": {"kind": "object", "class": _URI},
        }
    )
    return ObjectRef(handle)


# ---------------------------------------------------------------------------
# ConnectivityManager / NetworkInfo
# ---------------------------------------------------------------------------


def stub_connectivity_get_active_network_info(
    _args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """ConnectivityManager.getActiveNetworkInfo()NetworkInfo."""
    handle = heap.allocate(_NET_INFO, value={"connected": True, "type": 1})
    trace.append(
        {
            "api": f"{_CONN_MGR}->getActiveNetworkInfo(){_NET_INFO}",
            "args": [],
            "return": {"kind": "object", "class": _NET_INFO},
        }
    )
    return ObjectRef(handle)


def stub_network_info_is_connected(
    args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """NetworkInfo.isConnected()Z — returns true."""
    trace.append(
        {
            "api": f"{_NET_INFO}->isConnected()Z",
            "args": [],
            "return": {"kind": "int", "value": 1},
        }
    )
    return Value(1)


def stub_network_info_get_type(
    args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """NetworkInfo.getType()I — returns the receiver's stored 'type'.

    getActiveNetworkInfo() stores {"connected": ..., "type": N} on the
    NetworkInfo handle, so getType() must read it back instead of returning a
    fixed value — otherwise the same fake object reports a different network
    type than it was created with, which can send analysis down the wrong
    mobile-vs-WiFi branch. Defaults to 0 (TYPE_MOBILE) when unset/null.
    """
    value = 0
    # heap.get_value raises on a null/invalid handle, so guard args[0] first.
    if args and args[0]:
        info = heap.get_value(args[0])
        if isinstance(info, dict):
            value = int(info.get("type", 0))
    trace.append(
        {
            "api": f"{_NET_INFO}->getType()I",
            "args": [],
            "return": {"kind": "int", "value": value},
        }
    )
    return Value(value)


def stub_network_info_get_extra_info(
    _args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """NetworkInfo.getExtraInfo()String."""
    handle = heap.allocate(_STR, value="wifi")
    trace.append(
        {
            "api": f"{_NET_INFO}->getExtraInfo()Ljava/lang/String;",
            "args": [],
            "return": {"kind": "object", "value": "wifi"},
        }
    )
    return ObjectRef(handle)


# ---------------------------------------------------------------------------
# Context.getSystemService (extended — last-writer-wins over telephony.py)
# ---------------------------------------------------------------------------


def stub_context_get_system_service(
    args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """Context.getSystemService(String)Object.

    Routes:
      'phone'         → TelephonyManager
      'connectivity'  → ConnectivityManager
      'notification'  → NotificationManager
      other           → generic Object
    """
    svc_name = ""
    if len(args) > 1 and args[1]:
        v = heap.get_value(args[1])
        svc_name = str(v) if v else ""

    if svc_name == "phone":
        handle = heap.allocate(_TEL_MGR)
    elif svc_name == "connectivity":
        handle = heap.allocate(_CONN_MGR)
    elif svc_name == "notification":
        handle = heap.allocate(_NOTIF_MGR)
    else:
        handle = heap.allocate("Ljava/lang/Object;")

    trace.append(
        {
            "api": (
                "Landroid/content/Context;"
                "->getSystemService(Ljava/lang/String;)"
                "Ljava/lang/Object;"
            ),
            "args": [svc_name],
            "return": {"kind": "object"},
        }
    )
    return ObjectRef(handle)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

register(
    f"Landroid/content/Context;->getContentResolver(){_CONTENT_RESOLVER}",
    stub_context_get_content_resolver,
)
register(
    f"{_CONTENT_RESOLVER}->query("
    f"{_URI}[Ljava/lang/String;Ljava/lang/String;"
    f"[Ljava/lang/String;Ljava/lang/String;){_CURSOR}",
    stub_content_resolver_query,
)

register(f"{_CURSOR}->moveToFirst()Z", stub_cursor_move_to_first)
register(f"{_CURSOR}->getColumnIndex(Ljava/lang/String;)I", stub_cursor_get_column_index)
register(f"{_CURSOR}->getString(I)Ljava/lang/String;", stub_cursor_get_string)
register(f"{_CURSOR}->getInt(I)I", stub_cursor_get_int)
register(f"{_CURSOR}->close()V", stub_cursor_close)

register(f"{_URI}->parse(Ljava/lang/String;){_URI}", stub_uri_parse)

register(
    f"{_CONN_MGR}->getActiveNetworkInfo(){_NET_INFO}",
    stub_connectivity_get_active_network_info,
)
register(f"{_NET_INFO}->isConnected()Z", stub_network_info_is_connected)
register(f"{_NET_INFO}->getType()I", stub_network_info_get_type)
register(f"{_NET_INFO}->getExtraInfo()Ljava/lang/String;", stub_network_info_get_extra_info)

# Override telephony.py's getSystemService to add 'connectivity' and 'notification' routing
register(
    "Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;",
    stub_context_get_system_service,
)
# UpdateService-specific inherited methods (vtable miss routes here via engine fix)
_UPDATE_SVC = "Lcom/google/update/UpdateService;"
register(
    f"{_UPDATE_SVC}->getSystemService(Ljava/lang/String;)Ljava/lang/Object;",
    stub_context_get_system_service,
)
register(
    f"{_UPDATE_SVC}->getContentResolver(){_CONTENT_RESOLVER}",
    stub_context_get_content_resolver,
)
