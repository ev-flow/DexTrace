# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/android_stubs/runtime.py — Java Runtime, Process, SharedPreferences, and system stubs.

Covers DroidKungFu Threat 1 (Gain unlimited access to a device):
  Runtime.getRuntime, Runtime.exec
  Process.getOutputStream, Process.waitFor
  DataOutputStream.<init>
  SharedPreferences.getInt, edit; SharedPreferences.Editor.putInt, commit
  SystemClock.sleep
  Intent.putExtra, Intent.<init>
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

_RUNTIME = "Ljava/lang/Runtime;"
_PROCESS = "Ljava/lang/Process;"
_OS = "Ljava/io/OutputStream;"
_DOS = "Ljava/io/DataOutputStream;"
_PREFS = "Landroid/content/SharedPreferences;"
_EDITOR = "Landroid/content/SharedPreferences$Editor;"
_INTENT = "Landroid/content/Intent;"
_STR = "Ljava/lang/String;"
_APP_INFO = "Landroid/content/pm/ApplicationInfo;"
_PKG_MGR = "Landroid/content/pm/PackageManager;"


def _str_val(heap, handle: int) -> str:
    if handle == 0:
        return ""
    v = heap.get_value(handle)
    return str(v) if v is not None else ""


# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------


def stub_runtime_get_runtime(
    _args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """Runtime.getRuntime()Runtime (static)."""
    handle = heap.allocate(_RUNTIME)
    trace.append(
        {
            "api": f"{_RUNTIME}->getRuntime(){_RUNTIME}",
            "args": [],
            "return": {"kind": "object", "class": _RUNTIME},
        }
    )
    return ObjectRef(handle)


def stub_runtime_exec(
    args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """Runtime.exec(String)Process — simulates shell command execution."""
    cmd = _str_val(heap, args[1] if len(args) > 1 else 0)
    handle = heap.allocate(_PROCESS)
    trace.append(
        {
            "api": f"{_RUNTIME}->exec(Ljava/lang/String;){_PROCESS}",
            "args": [cmd],
            "return": {"kind": "object", "class": _PROCESS},
        }
    )
    return ObjectRef(handle)


# ---------------------------------------------------------------------------
# Process
# ---------------------------------------------------------------------------


def stub_process_get_output_stream(
    _args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """Process.getOutputStream()OutputStream."""
    handle = heap.allocate(_OS)
    trace.append(
        {
            "api": f"{_PROCESS}->getOutputStream(){_OS}",
            "args": [],
            "return": {"kind": "object", "class": _OS},
        }
    )
    return ObjectRef(handle)


def stub_process_wait_for(
    _args: List[Any], _heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """Process.waitFor()I — returns 0 (success)."""
    trace.append(
        {
            "api": f"{_PROCESS}->waitFor()I",
            "args": [],
            "return": {"kind": "int", "value": 0},
        }
    )
    return Value(0)


# ---------------------------------------------------------------------------
# DataOutputStream constructor
# ---------------------------------------------------------------------------


def stub_dos_init(
    args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """DataOutputStream.<init>(OutputStream)V — marks the DOS as initialized."""
    trace.append(
        {
            "api": f"{_DOS}-><init>({_OS})V",
            "args": [],
            "return": {"kind": "void"},
        }
    )
    return VOID


# ---------------------------------------------------------------------------
# SharedPreferences
# ---------------------------------------------------------------------------


def stub_prefs_get_int(
    args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """SharedPreferences.getInt(String, int)I — returns default value (0)."""
    key = _str_val(heap, args[1] if len(args) > 1 else 0)
    default = args[2] if len(args) > 2 else 0
    trace.append(
        {
            "api": f"{_PREFS}->getInt(Ljava/lang/String;I)I",
            "args": [key, default],
            "return": {"kind": "int", "value": default},
        }
    )
    return Value(default)


def stub_prefs_edit(
    _args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """SharedPreferences.edit()SharedPreferences.Editor."""
    handle = heap.allocate(_EDITOR)
    trace.append(
        {
            "api": f"{_PREFS}->edit(){_EDITOR}",
            "args": [],
            "return": {"kind": "object", "class": _EDITOR},
        }
    )
    return ObjectRef(handle)


def stub_editor_put_int(
    args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """SharedPreferences.Editor.putInt(String, int)Editor — returns self."""
    key = _str_val(heap, args[1] if len(args) > 1 else 0)
    val = args[2] if len(args) > 2 else 0
    trace.append(
        {
            "api": f"{_EDITOR}->putInt(Ljava/lang/String;I){_EDITOR}",
            "args": [key, val],
            "return": {"kind": "object"},
        }
    )
    return ObjectRef(args[0])


def stub_editor_commit(
    _args: List[Any], _heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """SharedPreferences.Editor.commit()Z — returns true."""
    trace.append(
        {
            "api": f"{_EDITOR}->commit()Z",
            "args": [],
            "return": {"kind": "int", "value": 1},
        }
    )
    return Value(1)


# ---------------------------------------------------------------------------
# SystemClock
# ---------------------------------------------------------------------------


def stub_system_clock_sleep(
    _args: List[Any], _heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """SystemClock.sleep(J)V — no-op."""
    trace.append(
        {
            "api": "Landroid/os/SystemClock;->sleep(J)V",
            "args": [],
            "return": {"kind": "void"},
        }
    )
    return VOID


# ---------------------------------------------------------------------------
# Intent extras
# ---------------------------------------------------------------------------


def stub_intent_init(
    _args: List[Any], _heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """Intent.<init>()V — no-op constructor."""
    return VOID


def stub_intent_put_extra(
    args: List[Any], _heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """Intent.putExtra(String, String)Intent — returns self handle."""
    trace.append(
        {
            "api": f"{_INTENT}->putExtra(Ljava/lang/String;Ljava/lang/String;){_INTENT}",
            "args": [],
            "return": {"kind": "object"},
        }
    )
    return ObjectRef(args[0])


# ---------------------------------------------------------------------------
# Context/Service inherited stubs
#
# invoke-virtual on UpdateService uses the malware class name in the smali
# static callee_sig. The engine catches the vtable miss and routes to
# _handle_external_miss, which re-looks up the exact sig in the registry.
# These stubs are registered under the malware class name so they match.
# ---------------------------------------------------------------------------


def stub_service_get_package_name(
    _args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """android.content.Context.getPackageName()String — returns a fake package name."""
    handle = heap.allocate(_STR, value="com.google.update")
    trace.append(
        {
            "api": "Landroid/content/Context;->getPackageName()Ljava/lang/String;",
            "args": [],
            "return": {"kind": "object", "value": "com.google.update"},
        }
    )
    return ObjectRef(handle)


def stub_service_get_shared_preferences(
    args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """android.content.Context.getSharedPreferences(String, int)SharedPreferences."""
    name = _str_val(heap, args[1] if len(args) > 1 else 0)
    handle = heap.allocate(_PREFS)
    trace.append(
        {
            "api": f"Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I){_PREFS}",
            "args": [name],
            "return": {"kind": "object", "class": _PREFS},
        }
    )
    return ObjectRef(handle)


def stub_service_get_application_info(
    _args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """android.app.Service.getApplicationInfo() — returns a fake ApplicationInfo handle."""
    handle = heap.allocate(_APP_INFO)
    trace.append(
        {
            "api": f"{_APP_INFO}->getApplicationInfo()",
            "args": [],
            "return": {"kind": "object", "class": _APP_INFO},
        }
    )
    return ObjectRef(handle)


def stub_service_get_package_manager(
    _args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """android.app.Service.getPackageManager() — returns a fake PackageManager handle."""
    handle = heap.allocate(_PKG_MGR)
    trace.append(
        {
            "api": f"{_PKG_MGR}->getPackageManager()",
            "args": [],
            "return": {"kind": "object", "class": _PKG_MGR},
        }
    )
    return ObjectRef(handle)


# ---------------------------------------------------------------------------
# DroidKungFu string-obfuscation helper (LI/I;->I(I))
# ---------------------------------------------------------------------------

_I_STRINGS: Dict[int, str] = {
    1778: "connectivity",  # used by __() to get ConnectivityManager
}


def stub_obfuscated_string_decoder(
    args: List[Any], heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """LI/I;->I(I)String — return known decoded values; fall back to empty string.

    The real method XOR-decodes a compile-time string table stored in a static
    field that the VM never initialises, so calling it directly raises NPE.
    We stub it to return the strings that matter for Threat-3 tracing.
    """
    idx = args[0] if args else 0
    s = _I_STRINGS.get(idx, "")
    handle = heap.allocate(_STR, value=s)
    return ObjectRef(handle)


# ---------------------------------------------------------------------------
# ApplicationInfo stubs
# ---------------------------------------------------------------------------


def stub_charsequence_to_string(
    args: List[Any], heap, _trace: List[Dict[str, Any]]
) -> StubResult:
    """CharSequence.toString()String — returns the stored string value."""
    s = _str_val(heap, args[0]) if args else ""
    handle = heap.allocate(_STR, value=s)
    return ObjectRef(handle)


def stub_app_info_load_label(
    _args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """ApplicationInfo.loadLabel(PackageManager)CharSequence — returns fake app name."""
    handle = heap.allocate(_STR, value="DroidKungFu")
    trace.append(
        {
            "api": (
                f"{_APP_INFO}->loadLabel"
                "(Landroid/content/pm/PackageManager;)Ljava/lang/CharSequence;"
            ),
            "args": [],
            "return": {"kind": "object", "value": "DroidKungFu"},
        }
    )
    return ObjectRef(handle)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

register(f"{_RUNTIME}->getRuntime(){_RUNTIME}", stub_runtime_get_runtime)
register(f"{_RUNTIME}->exec(Ljava/lang/String;){_PROCESS}", stub_runtime_exec)

register(f"{_PROCESS}->getOutputStream(){_OS}", stub_process_get_output_stream)
register(f"{_PROCESS}->waitFor()I", stub_process_wait_for)

register(f"{_DOS}-><init>({_OS})V", stub_dos_init)

register(f"{_PREFS}->getInt(Ljava/lang/String;I)I", stub_prefs_get_int)
register(f"{_PREFS}->edit(){_EDITOR}", stub_prefs_edit)
register(f"{_EDITOR}->putInt(Ljava/lang/String;I){_EDITOR}", stub_editor_put_int)
register(f"{_EDITOR}->commit()Z", stub_editor_commit)

register("Landroid/os/SystemClock;->sleep(J)V", stub_system_clock_sleep)

register("Ljava/lang/CharSequence;->toString()Ljava/lang/String;", stub_charsequence_to_string)

register("LI/I;->I(I)Ljava/lang/String;", stub_obfuscated_string_decoder)

register(f"{_INTENT}-><init>()V", stub_intent_init)
register(
    f"{_INTENT}->putExtra(Ljava/lang/String;Ljava/lang/String;){_INTENT}",
    stub_intent_put_extra,
)

register(
    f"{_APP_INFO}->loadLabel"
    "(Landroid/content/pm/PackageManager;)Ljava/lang/CharSequence;",
    stub_app_info_load_label,
)

# UpdateService-specific inherited methods (registered under malware class name
# because that is the static callee_sig the engine looks up after a vtable miss).
# Handles: getPackageName, getSharedPreferences, getApplicationInfo,
#          getPackageManager, getSystemService (via content.py), getContentResolver (via content.py)
_UPDATE_SVC = "Lcom/google/update/UpdateService;"
register(
    f"{_UPDATE_SVC}->getPackageName(){_STR}",
    stub_service_get_package_name,
)
register(
    f"{_UPDATE_SVC}->getSharedPreferences(Ljava/lang/String;I){_PREFS}",
    stub_service_get_shared_preferences,
)
register(
    f"{_UPDATE_SVC}->getApplicationInfo(){_APP_INFO}",
    stub_service_get_application_info,
)
register(
    f"{_UPDATE_SVC}->getPackageManager(){_PKG_MGR}",
    stub_service_get_package_manager,
)
