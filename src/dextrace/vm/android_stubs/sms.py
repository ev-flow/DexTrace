# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/android_stubs/sms.py — SmsManager stubs.

Simulates two Android telephony APIs that show up in real malware:
  - Landroid/telephony/SmsManager;->getDefault()Landroid/telephony/SmsManager;
  - Landroid/telephony/SmsManager;->sendTextMessage(...)V

These cover the IoC capture path in Ahmyth's SMSManager.sendSMS() — the
phone number and message text passed to sendTextMessage are recorded in the
trace log as the captured "real IoC".
"""

from __future__ import annotations

from typing import Any, Dict, List

from dextrace.vm.android_stubs import (
    ObjectRef,
    StubResult,
    VOID,
    register,
)
from dextrace.vm.errors import DexTraceVMError

_SMS_MANAGER_CLASS = "Landroid/telephony/SmsManager;"

_GET_DEFAULT_SIG = (
    "Landroid/telephony/SmsManager;"
    "->getDefault()Landroid/telephony/SmsManager;"
)

_SEND_TEXT_MESSAGE_SIG = (
    "Landroid/telephony/SmsManager;"
    "->sendTextMessage("
    "Ljava/lang/String;"
    "Ljava/lang/String;"
    "Ljava/lang/String;"
    "Landroid/app/PendingIntent;"
    "Landroid/app/PendingIntent;"
    ")V"
)


def _resolve_string(heap, handle: int) -> Any:
    """Return the Python str for a String handle, or None for null/unknown."""
    if handle == 0:
        return None
    try:
        return heap.get_value(handle)
    except DexTraceVMError:
        return None


def stub_get_default(
    _args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """SmsManager.getDefault() → returns a SmsManager handle."""
    handle = heap.allocate(_SMS_MANAGER_CLASS)
    trace.append(
        {
            "api": _GET_DEFAULT_SIG,
            "args": [],
            "return": {
                "kind": "object",
                "class": _SMS_MANAGER_CLASS,
                "handle": handle,
            },
        }
    )
    return ObjectRef(handle)


def stub_send_text_message(
    args: List[Any], heap, trace: List[Dict[str, Any]]
) -> StubResult:
    """
    SmsManager.sendTextMessage(destinationAddress, scAddress, text,
                               sentIntent, deliveryIntent) → void.

    args layout for invoke-virtual {receiver, p0, p1, p2, p3, p4}:
      args[0] = receiver (SmsManager handle)
      args[1] = destinationAddress (phone number, String handle)
      args[2] = scAddress (often null)
      args[3] = text (message body, String handle)
      args[4] = sentIntent
      args[5] = deliveryIntent
    """
    destination = _resolve_string(heap, args[1] if len(args) > 1 else 0)
    sc_address = _resolve_string(heap, args[2] if len(args) > 2 else 0)
    text = _resolve_string(heap, args[3] if len(args) > 3 else 0)
    trace.append(
        {
            "api": _SEND_TEXT_MESSAGE_SIG,
            "args": [destination, sc_address, text],
            "return": {"kind": "void"},
        }
    )
    return VOID


# ---------------------------------------------------------------------------
# Registration (executed at package import via __init__.py)
# ---------------------------------------------------------------------------

register(_GET_DEFAULT_SIG, stub_get_default)
register(_SEND_TEXT_MESSAGE_SIG, stub_send_text_message)
