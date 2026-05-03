# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/android_stubs/telephony.py — Android telephony stubs for GoldDream.

Covers:
  SmsMessage.createFromPdu, getOriginatingAddress, getDisplayMessageBody,
  getTimestampMillis
  TelephonyManager.getCallState
  Context.getSystemService  — returns TelephonyManager handle for "phone"
"""

from __future__ import annotations

from typing import Any, Dict, List

from dextrace.vm.android_stubs import (
    ObjectRef,
    StubResult,
    Value,
    Wide,
    register,
)

_SMS_MSG = "Landroid/telephony/SmsMessage;"
_TEL_MGR = "Landroid/telephony/TelephonyManager;"
_STR = "Ljava/lang/String;"

_FAKE_PHONE = "+15550001234"
_FAKE_BODY = "test sms body"
_FAKE_TS_MS = 1_700_000_000_000  # 2023-11-14 approx


# ---------------------------------------------------------------------------
# SmsMessage
# ---------------------------------------------------------------------------

def stub_sms_create_from_pdu(args: List[Any], heap, trace: List[Dict[str, Any]]) -> StubResult:
    """SmsMessage.createFromPdu([B)SmsMessage (static)."""
    handle = heap.allocate(_SMS_MSG)
    trace.append({
        "api": f"{_SMS_MSG}->createFromPdu([B){_SMS_MSG}",
        "args": [],
        "return": {"kind": "object", "class": _SMS_MSG, "handle": handle},
    })
    return ObjectRef(handle)


def stub_sms_get_originating_address(args: List[Any], heap, trace: List[Dict[str, Any]]) -> StubResult:
    """SmsMessage.getOriginatingAddress()String."""
    str_handle = heap.allocate(_STR, value=_FAKE_PHONE)
    trace.append({
        "api": f"{_SMS_MSG}->getOriginatingAddress()Ljava/lang/String;",
        "args": [],
        "return": {"kind": "object", "value": _FAKE_PHONE},
    })
    return ObjectRef(str_handle)


def stub_sms_get_display_message_body(args: List[Any], heap, trace: List[Dict[str, Any]]) -> StubResult:
    """SmsMessage.getDisplayMessageBody()String."""
    str_handle = heap.allocate(_STR, value=_FAKE_BODY)
    trace.append({
        "api": f"{_SMS_MSG}->getDisplayMessageBody()Ljava/lang/String;",
        "args": [],
        "return": {"kind": "object", "value": _FAKE_BODY},
    })
    return ObjectRef(str_handle)


def stub_sms_get_timestamp_millis(args: List[Any], heap, trace: List[Dict[str, Any]]) -> StubResult:
    """SmsMessage.getTimestampMillis()J."""
    trace.append({
        "api": f"{_SMS_MSG}->getTimestampMillis()J",
        "args": [],
        "return": {"kind": "long", "value": _FAKE_TS_MS},
    })
    return Wide(_FAKE_TS_MS)


# ---------------------------------------------------------------------------
# TelephonyManager
# ---------------------------------------------------------------------------

def stub_telephony_get_call_state(args: List[Any], heap, trace: List[Dict[str, Any]]) -> StubResult:
    """TelephonyManager.getCallState()I — returns CALL_STATE_RINGING (1)."""
    state = 1  # CALL_STATE_RINGING
    trace.append({
        "api": f"{_TEL_MGR}->getCallState()I",
        "args": [],
        "return": {"kind": "int", "value": state},
    })
    return Value(state)


# ---------------------------------------------------------------------------
# Context.getSystemService
# ---------------------------------------------------------------------------

def stub_context_get_system_service(args: List[Any], heap, trace: List[Dict[str, Any]]) -> StubResult:
    """Context.getSystemService(String)Object — returns TelephonyManager for 'phone'."""
    svc_name = ""
    if len(args) > 1 and args[1]:
        v = heap.get_value(args[1])
        svc_name = str(v) if v else ""
    if svc_name == "phone":
        handle = heap.allocate(_TEL_MGR)
    else:
        handle = heap.allocate("Ljava/lang/Object;")
    trace.append({
        "api": "Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;",
        "args": [svc_name],
        "return": {"kind": "object"},
    })
    return ObjectRef(handle)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

register(f"{_SMS_MSG}->createFromPdu([B){_SMS_MSG}", stub_sms_create_from_pdu)
register(
    f"{_SMS_MSG}->getOriginatingAddress()Ljava/lang/String;",
    stub_sms_get_originating_address,
)
register(
    f"{_SMS_MSG}->getDisplayMessageBody()Ljava/lang/String;",
    stub_sms_get_display_message_body,
)
register(f"{_SMS_MSG}->getTimestampMillis()J", stub_sms_get_timestamp_millis)
register(f"{_TEL_MGR}->getCallState()I", stub_telephony_get_call_state)
register(
    "Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;",
    stub_context_get_system_service,
)
