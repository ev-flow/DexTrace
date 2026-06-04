# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/android_stubs/filesystem.py — File I/O, Android UI, network extras, and String helpers.

Covers DroidKungFu Threat 2 (Install/Uninstall additional apps):
  File.<init>, exists, mkdir, createNewFile, delete
  FileOutputStream.<init>, write, close
  InputStream.read, close
  Intent.setAction, setDataAndType, Intent.<init> (single-arg)
  IntentFilter.<init>, addAction, addDataScheme
  Uri.fromFile
  Context.getFileStreamPath, registerReceiver
  Notification, NotificationManager, PendingIntent
  Toast.makeText, show
  Environment.getExternalStorageState
  AsyncTask.<init>
  Thread.sleep
  URL.<init>
  HttpURLConnection.setConnectTimeout, getContentLength
  Integer.parseInt, valueOf
  String.getBytes(charset), replaceAll, replaceFirst
  DecimalFormat.<init>, NumberFormat.format
"""

from __future__ import annotations

import re as _re
from typing import Any, Dict, List

from dextrace.vm.android_stubs import (
    ObjectRef,
    StubResult,
    Value,
    VOID,
    register,
)

_FILE = "Ljava/io/File;"
_CLASS = "Ljava/lang/Class;"
_CIPHER = "Ljavax/crypto/Cipher;"
_SECRET_KEY_SPEC = "Ljavax/crypto/spec/SecretKeySpec;"
_FOS = "Ljava/io/FileOutputStream;"
_IS = "Ljava/io/InputStream;"
_INTENT = "Landroid/content/Intent;"
_INTENT_FILTER = "Landroid/content/IntentFilter;"
_URI = "Landroid/net/Uri;"
_NOTIFICATION = "Landroid/app/Notification;"
_NOTIF_MGR = "Landroid/app/NotificationManager;"
_PENDING_INTENT = "Landroid/app/PendingIntent;"
_TOAST = "Landroid/widget/Toast;"
_ASYNC_TASK = "Landroid/os/AsyncTask;"
_URL = "Ljava/net/URL;"
_HTTP_CONN = "Ljava/net/HttpURLConnection;"
_STR = "Ljava/lang/String;"
_INT_OBJ = "Ljava/lang/Integer;"
_DF = "Ljava/text/DecimalFormat;"
_NF = "Ljava/text/NumberFormat;"


def _str_val(heap, handle: int) -> str:
    if handle == 0:
        return ""
    v = heap.get_value(handle)
    return str(v) if v is not None else ""


# ---------------------------------------------------------------------------
# java.io.File
# ---------------------------------------------------------------------------


def stub_file_init_string(
    args: List[Any], heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """File.<init>(String)V — stores path as value."""
    path = _str_val(heap, args[1] if len(args) > 1 else 0)
    heap.set_value(args[0], path)
    return VOID


def stub_file_init_string_string(
    args: List[Any], heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """File.<init>(String, String)V — joins parent + child as path."""
    parent = _str_val(heap, args[1] if len(args) > 1 else 0)
    child = _str_val(heap, args[2] if len(args) > 2 else 0)
    heap.set_value(args[0], f"{parent}/{child}")
    return VOID


def stub_file_exists(
    _args: List[Any], _heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """File.exists()Z — returns false (simulated absent file)."""
    trace.append({"api": f"{_FILE}->exists()Z", "args": [], "return": {"kind": "int", "value": 0}})
    return Value(0)


def stub_file_mkdir(
    _args: List[Any], _heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """File.mkdir()Z — returns true (simulated success)."""
    trace.append({"api": f"{_FILE}->mkdir()Z", "args": [], "return": {"kind": "int", "value": 1}})
    return Value(1)


def stub_file_create_new_file(
    _args: List[Any], _heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """File.createNewFile()Z — returns true."""
    trace.append({"api": f"{_FILE}->createNewFile()Z", "args": [], "return": {"kind": "int", "value": 1}})
    return Value(1)


def stub_file_delete(
    _args: List[Any], _heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """File.delete()Z — returns true."""
    trace.append({"api": f"{_FILE}->delete()Z", "args": [], "return": {"kind": "int", "value": 1}})
    return Value(1)


# ---------------------------------------------------------------------------
# java.lang.Object / Class
# ---------------------------------------------------------------------------


def stub_object_get_class(
    args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """Object.getClass()Class — returns a Class handle."""
    handle = heap.allocate(_CLASS)
    trace.append({"api": "Ljava/lang/Object;->getClass()Ljava/lang/Class;", "args": [], "return": {"kind": "object", "class": _CLASS}})
    return ObjectRef(handle)


def stub_cipher_get_instance(
    args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """Cipher.getInstance(String)Cipher (static) — returns a Cipher handle."""
    algo = _str_val(heap, args[0] if args else 0)
    handle = heap.allocate(_CIPHER)
    trace.append({"api": f"{_CIPHER}->getInstance(Ljava/lang/String;){_CIPHER}", "args": [algo], "return": {"kind": "object", "class": _CIPHER}})
    return ObjectRef(handle)


def stub_secret_key_spec_init(
    _args: List[Any], _heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """SecretKeySpec.<init>([B, String)V — no-op."""
    return VOID


def stub_cipher_init(
    _args: List[Any], _heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """Cipher.init(int, Key)V — no-op."""
    return VOID


def stub_cipher_do_final(
    args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """Cipher.doFinal([B)[B — returns the input byte array unchanged (identity)."""
    input_handle = args[1] if len(args) > 1 else 0
    trace.append({"api": f"{_CIPHER}->doFinal([B)[B", "args": [], "return": {"kind": "object"}})
    return ObjectRef(input_handle)


def stub_class_get_resource_as_stream(
    _args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """Class.getResourceAsStream(String)InputStream — returns null (no resources)."""
    trace.append({"api": f"{_CLASS}->getResourceAsStream(Ljava/lang/String;){_IS}", "args": [], "return": {"kind": "object"}})
    return ObjectRef(0)


# ---------------------------------------------------------------------------
# java.io.FileOutputStream
# ---------------------------------------------------------------------------


def stub_fos_init_string(
    _args: List[Any], _heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """FileOutputStream.<init>(String)V — no-op."""
    return VOID


def stub_fos_init_file(
    _args: List[Any], _heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """FileOutputStream.<init>(File)V — no-op."""
    return VOID


def stub_fos_write(
    _args: List[Any], _heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """FileOutputStream.write([BII)V — no-op."""
    trace.append({"api": f"{_FOS}->write([BII)V", "args": [], "return": {"kind": "void"}})
    return VOID


def stub_fos_close(
    _args: List[Any], _heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """FileOutputStream.close()V — no-op."""
    trace.append({"api": f"{_FOS}->close()V", "args": [], "return": {"kind": "void"}})
    return VOID


# ---------------------------------------------------------------------------
# java.io.InputStream
# ---------------------------------------------------------------------------


_OS_BASE = "Ljava/io/OutputStream;"


def stub_os_write(
    _args: List[Any], _heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """OutputStream.write([B)V — no-op."""
    return VOID


def stub_os_flush(
    _args: List[Any], _heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """OutputStream.flush()V — no-op."""
    return VOID


def stub_os_close(
    _args: List[Any], _heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """OutputStream.close()V — no-op."""
    return VOID


def stub_is_read(
    _args: List[Any], _heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """InputStream.read([B)I — returns -1 (EOF)."""
    trace.append({"api": f"{_IS}->read([B)I", "args": [], "return": {"kind": "int", "value": -1}})
    return Value(-1)


def stub_is_close(
    _args: List[Any], _heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """InputStream.close()V — no-op."""
    trace.append({"api": f"{_IS}->close()V", "args": [], "return": {"kind": "void"}})
    return VOID


# ---------------------------------------------------------------------------
# Android Intent extras
# ---------------------------------------------------------------------------


def stub_intent_init_string(
    args: List[Any], heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """Intent.<init>(String)V — stores action as value."""
    action = _str_val(heap, args[1] if len(args) > 1 else 0)
    heap.set_value(args[0], action)
    return VOID


def stub_intent_set_action(
    args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """Intent.setAction(String)Intent — stores action, returns self."""
    action = _str_val(heap, args[1] if len(args) > 1 else 0)
    trace.append(
        {
            "api": f"{_INTENT}->setAction(Ljava/lang/String;){_INTENT}",
            "args": [action],
            "return": {"kind": "object"},
        }
    )
    return ObjectRef(args[0])


def stub_intent_set_data_and_type(
    args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """Intent.setDataAndType(Uri, String)Intent — returns self."""
    mime = _str_val(heap, args[2] if len(args) > 2 else 0)
    trace.append(
        {
            "api": f"{_INTENT}->setDataAndType({_URI}Ljava/lang/String;){_INTENT}",
            "args": [mime],
            "return": {"kind": "object"},
        }
    )
    return ObjectRef(args[0])


# ---------------------------------------------------------------------------
# IntentFilter
# ---------------------------------------------------------------------------


def stub_intent_filter_init(
    _args: List[Any], _heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """IntentFilter.<init>()V — no-op."""
    return VOID


def stub_intent_filter_add_action(
    _args: List[Any], _heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """IntentFilter.addAction(String)V — no-op."""
    return VOID


def stub_intent_filter_add_data_scheme(
    _args: List[Any], _heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """IntentFilter.addDataScheme(String)V — no-op."""
    return VOID


# ---------------------------------------------------------------------------
# Uri.fromFile
# ---------------------------------------------------------------------------


def stub_uri_from_file(
    args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """Uri.fromFile(File)Uri (static)."""
    path = _str_val(heap, args[0]) if args else ""
    handle = heap.allocate(_URI, value=f"file://{path}")
    trace.append(
        {
            "api": f"{_URI}->fromFile({_FILE}){_URI}",
            "args": [path],
            "return": {"kind": "object", "class": _URI},
        }
    )
    return ObjectRef(handle)


# ---------------------------------------------------------------------------
# Context extras
# ---------------------------------------------------------------------------


def stub_context_get_file_stream_path(
    args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """Context.getFileStreamPath(String)File — returns a File handle."""
    name = _str_val(heap, args[1] if len(args) > 1 else 0)
    handle = heap.allocate(_FILE, value=f"/data/data/app/files/{name}")
    trace.append(
        {
            "api": f"Landroid/content/Context;->getFileStreamPath(Ljava/lang/String;){_FILE}",
            "args": [name],
            "return": {"kind": "object", "class": _FILE},
        }
    )
    return ObjectRef(handle)


def stub_context_register_receiver(
    _args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """Context.registerReceiver(BroadcastReceiver, IntentFilter)Intent — returns null Intent."""
    trace.append(
        {
            "api": (
                "Landroid/content/Context;"
                "->registerReceiver(Landroid/content/BroadcastReceiver;"
                f"{_INTENT_FILTER}){_INTENT}"
            ),
            "args": [],
            "return": {"kind": "object"},
        }
    )
    return ObjectRef(0)


# ---------------------------------------------------------------------------
# Notification / NotificationManager / PendingIntent
# ---------------------------------------------------------------------------


def stub_notification_init(
    _args: List[Any], _heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """Notification.<init>()V — no-op."""
    return VOID


def stub_notification_set_latest_event_info(
    _args: List[Any], _heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """Notification.setLatestEventInfo(...)V — no-op."""
    return VOID


def stub_notification_manager_cancel(
    _args: List[Any], _heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """NotificationManager.cancel(I)V — no-op."""
    return VOID


def stub_notification_manager_notify(
    _args: List[Any], _heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """NotificationManager.notify(I, Notification)V — no-op."""
    return VOID


def stub_pending_intent_get_activity(
    _args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """PendingIntent.getActivity(Context, int, Intent, int)PendingIntent (static)."""
    handle = heap.allocate(_PENDING_INTENT)
    trace.append(
        {
            "api": (
                f"{_PENDING_INTENT}->getActivity("
                f"Landroid/content/Context;I{_INTENT}I){_PENDING_INTENT}"
            ),
            "args": [],
            "return": {"kind": "object", "class": _PENDING_INTENT},
        }
    )
    return ObjectRef(handle)


# ---------------------------------------------------------------------------
# Toast
# ---------------------------------------------------------------------------


def stub_toast_make_text(
    _args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """Toast.makeText(Context, CharSequence, int)Toast (static)."""
    handle = heap.allocate(_TOAST)
    trace.append(
        {
            "api": (
                f"{_TOAST}->makeText("
                "Landroid/content/Context;Ljava/lang/CharSequence;I)"
                f"{_TOAST}"
            ),
            "args": [],
            "return": {"kind": "object", "class": _TOAST},
        }
    )
    return ObjectRef(handle)


def stub_toast_show(
    _args: List[Any], _heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """Toast.show()V — no-op."""
    trace.append({"api": f"{_TOAST}->show()V", "args": [], "return": {"kind": "void"}})
    return VOID


# ---------------------------------------------------------------------------
# AsyncTask / Environment
# ---------------------------------------------------------------------------


def stub_async_task_init(
    _args: List[Any], _heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """AsyncTask.<init>()V — no-op."""
    return VOID


def stub_environment_get_external_storage_state(
    _args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """Environment.getExternalStorageState()String (static) — returns 'mounted'."""
    handle = heap.allocate(_STR, value="mounted")
    trace.append(
        {
            "api": "Landroid/os/Environment;->getExternalStorageState()Ljava/lang/String;",
            "args": [],
            "return": {"kind": "object", "value": "mounted"},
        }
    )
    return ObjectRef(handle)


# ---------------------------------------------------------------------------
# Thread.sleep
# ---------------------------------------------------------------------------


def stub_thread_sleep(
    _args: List[Any], _heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """Thread.sleep(J)V — no-op."""
    trace.append({"api": "Ljava/lang/Thread;->sleep(J)V", "args": [], "return": {"kind": "void"}})
    return VOID


# ---------------------------------------------------------------------------
# java.net.URL constructor
# ---------------------------------------------------------------------------


def stub_url_init(
    args: List[Any], heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """URL.<init>(String)V — stores URL string as value."""
    url = _str_val(heap, args[1] if len(args) > 1 else 0)
    heap.set_value(args[0], url)
    return VOID


# ---------------------------------------------------------------------------
# HttpURLConnection extras
# ---------------------------------------------------------------------------


def stub_http_set_connect_timeout(
    _args: List[Any], _heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """HttpURLConnection.setConnectTimeout(I)V — no-op."""
    return VOID


def stub_http_get_content_length(
    _args: List[Any], _heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """HttpURLConnection.getContentLength()I — returns -1 (unknown)."""
    trace.append(
        {
            "api": f"{_HTTP_CONN}->getContentLength()I",
            "args": [],
            "return": {"kind": "int", "value": -1},
        }
    )
    return Value(-1)


# ---------------------------------------------------------------------------
# Integer
# ---------------------------------------------------------------------------


def stub_integer_parse_int(
    args: List[Any], heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """Integer.parseInt(String)I (static)."""
    s = _str_val(heap, args[0] if args else 0)
    try:
        v = int(s)
    except (ValueError, TypeError):
        v = 0
    return Value(v)


def stub_integer_value_of(
    args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """Integer.valueOf(I)Integer (static)."""
    v = args[0] if args else 0
    handle = heap.allocate(_INT_OBJ, value=v)
    trace.append(
        {
            "api": f"{_INT_OBJ}->valueOf(I){_INT_OBJ}",
            "args": [v],
            "return": {"kind": "object", "value": v},
        }
    )
    return ObjectRef(handle)


# ---------------------------------------------------------------------------
# String extras
# ---------------------------------------------------------------------------


def stub_string_getbytes_charset(
    args: List[Any], heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """String.getBytes(String)[B — charset-aware byte conversion."""
    s = _str_val(heap, args[0])
    charset = _str_val(heap, args[1] if len(args) > 1 else 0) or "UTF-8"
    try:
        encoded = s.encode(charset.replace("-", "").lower() if charset else "utf-8")
    except (LookupError, UnicodeEncodeError):
        encoded = s.encode("utf-8", errors="replace")
    arr_handle = heap.allocate_array("[B", len(encoded))
    arr = heap.get_array(arr_handle)
    for i, b in enumerate(encoded):
        arr[i] = b
    return ObjectRef(arr_handle)


def stub_string_replace_all(
    args: List[Any], heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """String.replaceAll(String, String)String."""
    s = _str_val(heap, args[0])
    pattern = _str_val(heap, args[1] if len(args) > 1 else 0)
    replacement = _str_val(heap, args[2] if len(args) > 2 else 0)
    try:
        result = _re.sub(pattern, replacement, s)
    except _re.error:
        result = s
    handle = heap.allocate(_STR, value=result)
    return ObjectRef(handle)


def stub_string_replace_first(
    args: List[Any], heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """String.replaceFirst(String, String)String."""
    s = _str_val(heap, args[0])
    pattern = _str_val(heap, args[1] if len(args) > 1 else 0)
    replacement = _str_val(heap, args[2] if len(args) > 2 else 0)
    try:
        result = _re.sub(pattern, replacement, s, count=1)
    except _re.error:
        result = s
    handle = heap.allocate(_STR, value=result)
    return ObjectRef(handle)


# ---------------------------------------------------------------------------
# DecimalFormat / NumberFormat
# ---------------------------------------------------------------------------


def stub_decimal_format_init(
    _args: List[Any], _heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """DecimalFormat.<init>(String)V — no-op."""
    return VOID


def stub_number_format_format_double(
    _args: List[Any], heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """NumberFormat.format(D)String — returns '0.00'."""
    handle = heap.allocate(_STR, value="0.00")
    return ObjectRef(handle)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

register(f"{_CIPHER}->getInstance(Ljava/lang/String;){_CIPHER}", stub_cipher_get_instance)
register(f"{_SECRET_KEY_SPEC}-><init>([BLjava/lang/String;)V", stub_secret_key_spec_init)
register(f"{_CIPHER}->init(ILjava/security/Key;)V", stub_cipher_init)
register(f"{_CIPHER}->doFinal([B)[B", stub_cipher_do_final)

register("Ljava/lang/Object;->getClass()Ljava/lang/Class;", stub_object_get_class)
register(f"{_CLASS}->getResourceAsStream(Ljava/lang/String;){_IS}", stub_class_get_resource_as_stream)

register(f"{_OS_BASE}->write([B)V", stub_os_write)
register(f"{_OS_BASE}->flush()V", stub_os_flush)
register(f"{_OS_BASE}->close()V", stub_os_close)

register(f"{_FILE}-><init>(Ljava/lang/String;)V", stub_file_init_string)
register(f"{_FILE}-><init>(Ljava/lang/String;Ljava/lang/String;)V", stub_file_init_string_string)
register(f"{_FILE}->exists()Z", stub_file_exists)
register(f"{_FILE}->mkdir()Z", stub_file_mkdir)
register(f"{_FILE}->createNewFile()Z", stub_file_create_new_file)
register(f"{_FILE}->delete()Z", stub_file_delete)

register(f"{_FOS}-><init>(Ljava/lang/String;)V", stub_fos_init_string)
register(f"{_FOS}-><init>({_FILE})V", stub_fos_init_file)
register(f"{_FOS}->write([BII)V", stub_fos_write)
register(f"{_FOS}->close()V", stub_fos_close)

register(f"{_IS}->read([B)I", stub_is_read)
register(f"{_IS}->close()V", stub_is_close)

register(f"{_INTENT}-><init>(Ljava/lang/String;)V", stub_intent_init_string)
register(f"{_INTENT}->setAction(Ljava/lang/String;){_INTENT}", stub_intent_set_action)
register(
    f"{_INTENT}->setDataAndType({_URI}Ljava/lang/String;){_INTENT}",
    stub_intent_set_data_and_type,
)

register(f"{_INTENT_FILTER}-><init>()V", stub_intent_filter_init)
register(f"{_INTENT_FILTER}->addAction(Ljava/lang/String;)V", stub_intent_filter_add_action)
register(f"{_INTENT_FILTER}->addDataScheme(Ljava/lang/String;)V", stub_intent_filter_add_data_scheme)

register(f"{_URI}->fromFile({_FILE}){_URI}", stub_uri_from_file)

register(
    f"Landroid/content/Context;->getFileStreamPath(Ljava/lang/String;){_FILE}",
    stub_context_get_file_stream_path,
)
register(
    f"Landroid/content/Context;->registerReceiver("
    f"Landroid/content/BroadcastReceiver;{_INTENT_FILTER}){_INTENT}",
    stub_context_register_receiver,
)

# Inherited-owner aliases: samples reference these inherited Context methods with
# the service class as owner. A virtual-resolve miss on the inherited method hits
# the external-miss policy, which raises for these non-void calls — so register
# the stubs under the known owner too (see content.py / intent.py for the pattern).
_UPDATE_SVC = "Lcom/google/update/UpdateService;"
register(
    f"{_UPDATE_SVC}->getFileStreamPath(Ljava/lang/String;){_FILE}",
    stub_context_get_file_stream_path,
)
register(
    f"{_UPDATE_SVC}->registerReceiver("
    f"Landroid/content/BroadcastReceiver;{_INTENT_FILTER}){_INTENT}",
    stub_context_register_receiver,
)

register(f"{_NOTIFICATION}-><init>()V", stub_notification_init)
register(
    f"{_NOTIFICATION}->setLatestEventInfo("
    f"Landroid/content/Context;Ljava/lang/CharSequence;"
    f"Ljava/lang/CharSequence;{_PENDING_INTENT})V",
    stub_notification_set_latest_event_info,
)
register(f"{_NOTIF_MGR}->cancel(I)V", stub_notification_manager_cancel)
register(f"{_NOTIF_MGR}->notify(I{_NOTIFICATION})V", stub_notification_manager_notify)
register(
    f"{_PENDING_INTENT}->getActivity("
    f"Landroid/content/Context;I{_INTENT}I){_PENDING_INTENT}",
    stub_pending_intent_get_activity,
)

register(
    f"{_TOAST}->makeText("
    f"Landroid/content/Context;Ljava/lang/CharSequence;I){_TOAST}",
    stub_toast_make_text,
)
register(f"{_TOAST}->show()V", stub_toast_show)

register(f"{_ASYNC_TASK}-><init>()V", stub_async_task_init)
register(
    "Landroid/os/Environment;->getExternalStorageState()Ljava/lang/String;",
    stub_environment_get_external_storage_state,
)

register("Ljava/lang/Thread;->sleep(J)V", stub_thread_sleep)

register(f"{_URL}-><init>(Ljava/lang/String;)V", stub_url_init)
register(f"{_HTTP_CONN}->setConnectTimeout(I)V", stub_http_set_connect_timeout)
register(f"{_HTTP_CONN}->getContentLength()I", stub_http_get_content_length)

register(f"{_INT_OBJ}->parseInt(Ljava/lang/String;)I", stub_integer_parse_int)
register(f"{_INT_OBJ}->valueOf(I){_INT_OBJ}", stub_integer_value_of)

register(
    f"{_STR}->getBytes(Ljava/lang/String;)[B",
    stub_string_getbytes_charset,
)
register(
    f"{_STR}->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
    stub_string_replace_all,
)
register(
    f"{_STR}->replaceFirst(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
    stub_string_replace_first,
)

register(f"{_DF}-><init>(Ljava/lang/String;)V", stub_decimal_format_init)
register(f"{_NF}->format(D)Ljava/lang/String;", stub_number_format_format_double)
