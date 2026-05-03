# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/android_stubs/network.py — Java network stubs for GoldDream Threat 2.

Covers the HTTP upload path in com.sjhi.client.e.a(String, String):
  URL.openConnection, HttpURLConnection.getOutputStream, setRequestMethod
  DataOutputStream.writeBytes, flush
  FileInputStream.read
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

_URL_CONN = "Ljava/net/URLConnection;"
_HTTP_CONN = "Ljava/net/HttpURLConnection;"
_OS = "Ljava/io/OutputStream;"
_IS = "Ljava/io/InputStream;"
_DOS = "Ljava/io/DataOutputStream;"
_FIS = "Ljava/io/FileInputStream;"
_BR = "Ljava/io/BufferedReader;"
_ISR = "Ljava/io/InputStreamReader;"


def _str_val(heap, handle: int) -> str:
    if handle == 0:
        return ""
    v = heap.get_value(handle)
    return str(v) if v is not None else ""


# ---------------------------------------------------------------------------
# URL / HttpURLConnection
# ---------------------------------------------------------------------------

def stub_url_open_connection(args: List[Any], heap, trace: List[Dict[str, Any]]) -> StubResult:
    """URL.openConnection()URLConnection — allocates an HttpURLConnection handle."""
    handle = heap.allocate(_HTTP_CONN)
    url_val = _str_val(heap, args[0])
    trace.append({
        "api": "Ljava/net/URL;->openConnection()Ljava/net/URLConnection;",
        "args": [url_val],
        "return": {"kind": "object", "class": _HTTP_CONN},
    })
    return ObjectRef(handle)


def stub_http_set_request_method(args: List[Any], heap, trace: List[Dict[str, Any]]) -> StubResult:
    """HttpURLConnection.setRequestMethod(String)V."""
    method = _str_val(heap, args[1] if len(args) > 1 else 0)
    trace.append({
        "api": f"{_HTTP_CONN}->setRequestMethod(Ljava/lang/String;)V",
        "args": [method],
        "return": {"kind": "void"},
    })
    return VOID


def stub_http_get_output_stream(args: List[Any], heap, trace: List[Dict[str, Any]]) -> StubResult:
    """HttpURLConnection.getOutputStream()OutputStream."""
    handle = heap.allocate(_OS)
    trace.append({
        "api": f"{_HTTP_CONN}->getOutputStream()Ljava/io/OutputStream;",
        "args": [],
        "return": {"kind": "object", "class": _OS},
    })
    return ObjectRef(handle)


def stub_http_get_input_stream(args: List[Any], heap, trace: List[Dict[str, Any]]) -> StubResult:
    """HttpURLConnection.getInputStream()InputStream."""
    handle = heap.allocate(_IS)
    trace.append({
        "api": f"{_HTTP_CONN}->getInputStream()Ljava/io/InputStream;",
        "args": [],
        "return": {"kind": "object", "class": _IS},
    })
    return ObjectRef(handle)


# ---------------------------------------------------------------------------
# DataOutputStream
# ---------------------------------------------------------------------------

def stub_dos_write_bytes(args: List[Any], heap, trace: List[Dict[str, Any]]) -> StubResult:
    """DataOutputStream.writeBytes(String)V."""
    s = _str_val(heap, args[1] if len(args) > 1 else 0)
    trace.append({
        "api": f"{_DOS}->writeBytes(Ljava/lang/String;)V",
        "args": [s],
        "return": {"kind": "void"},
    })
    return VOID


def stub_dos_flush(args: List[Any], heap, trace: List[Dict[str, Any]]) -> StubResult:
    """DataOutputStream.flush()V."""
    return VOID


# ---------------------------------------------------------------------------
# FileInputStream
# ---------------------------------------------------------------------------

def stub_fis_read(args: List[Any], heap, trace: List[Dict[str, Any]]) -> StubResult:
    """FileInputStream.read([B)I — returns -1 (EOF) to signal no data."""
    trace.append({
        "api": f"{_FIS}->read([B)I",
        "args": [],
        "return": {"kind": "int", "value": -1},
    })
    return Value(-1)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

register("Ljava/net/URL;->openConnection()Ljava/net/URLConnection;", stub_url_open_connection)
register(
    f"{_HTTP_CONN}->setRequestMethod(Ljava/lang/String;)V",
    stub_http_set_request_method,
)
register(
    f"{_HTTP_CONN}->getOutputStream()Ljava/io/OutputStream;",
    stub_http_get_output_stream,
)
register(f"{_DOS}->writeBytes(Ljava/lang/String;)V", stub_dos_write_bytes)
register(f"{_DOS}->flush()V", stub_dos_flush)
register(f"{_FIS}->read([B)I", stub_fis_read)
register(
    f"{_HTTP_CONN}->getInputStream()Ljava/io/InputStream;",
    stub_http_get_input_stream,
)
register(
    f"{_BR}->readLine()Ljava/lang/String;",
    lambda args, heap, trace: ObjectRef(0),  # returns null → terminates read loop
)
# System.out.println — invoked after readLine(); System.out is a null static field,
# so the receiver is 0. Stubbing bypasses the null-receiver check.
register(
    "Ljava/io/PrintStream;->println(Ljava/lang/String;)V",
    lambda args, heap, trace: VOID,
)
register(
    "Ljava/io/DataOutputStream;->write([BII)V",
    lambda args, heap, trace: VOID,
)
