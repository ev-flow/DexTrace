# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""Unit tests for vm/android_stubs/ — registry + SMS stubs."""

from __future__ import annotations

import pytest

from dextrace.vm.android_stubs import (
    REGISTRY,
    ObjectRef,
    VOID,
    Value,
    Wide,
)
from dextrace.vm.android_stubs.content import (
    stub_connectivity_get_active_network_info,
    stub_network_info_get_type,
)
from dextrace.vm.android_stubs.sms import (
    _GET_DEFAULT_SIG,
    _SEND_TEXT_MESSAGE_SIG,
    stub_get_default,
    stub_send_text_message,
)
from dextrace.vm.heap import ObjectHeap


class TestRegistryBootstrap:
    def test_sms_get_default_registered(self):
        assert _GET_DEFAULT_SIG in REGISTRY

    def test_sms_send_text_message_registered(self):
        assert _SEND_TEXT_MESSAGE_SIG in REGISTRY

    def test_registry_value_is_callable(self):
        assert callable(REGISTRY[_GET_DEFAULT_SIG])
        assert callable(REGISTRY[_SEND_TEXT_MESSAGE_SIG])


class TestStubResultShapes:
    def test_void_singleton_repr(self):
        assert repr(VOID) == "VOID"

    def test_value_carries_int(self):
        v = Value(42)
        assert v.value == 42

    def test_wide_carries_long(self):
        w = Wide(0xDEAD_BEEF_CAFE_1234)
        assert w.value == 0xDEAD_BEEF_CAFE_1234

    def test_object_ref_carries_handle(self):
        o = ObjectRef(7)
        assert o.handle == 7


class TestSmsGetDefault:
    def test_returns_object_ref_with_sms_manager_class(self):
        heap = ObjectHeap()
        trace: list = []
        result = stub_get_default([], heap, trace)
        assert isinstance(result, ObjectRef)
        assert heap.get_class(result.handle) == "Landroid/telephony/SmsManager;"

    def test_logs_trace_entry(self):
        heap = ObjectHeap()
        trace: list = []
        result = stub_get_default([], heap, trace)
        assert len(trace) == 1
        entry = trace[0]
        assert entry["api"] == _GET_DEFAULT_SIG
        assert entry["args"] == []
        assert entry["return"]["kind"] == "object"
        assert entry["return"]["handle"] == result.handle


class TestSmsSendTextMessage:
    def test_captures_phone_and_message(self):
        heap = ObjectHeap()
        receiver = heap.allocate("Landroid/telephony/SmsManager;")
        phone = heap.allocate("Ljava/lang/String;", value="+10000000000")
        sc_addr = 0  # null
        text = heap.allocate("Ljava/lang/String;", value="ping")
        trace: list = []
        result = stub_send_text_message(
            [receiver, phone, sc_addr, text, 0, 0], heap, trace
        )
        assert result is VOID
        assert len(trace) == 1
        entry = trace[0]
        assert entry["api"] == _SEND_TEXT_MESSAGE_SIG
        assert entry["args"] == ["+10000000000", None, "ping"]
        assert entry["return"]["kind"] == "void"

    def test_handles_null_sc_address(self):
        heap = ObjectHeap()
        receiver = heap.allocate("Landroid/telephony/SmsManager;")
        phone = heap.allocate("Ljava/lang/String;", value="+10000")
        text = heap.allocate("Ljava/lang/String;", value="msg")
        trace: list = []
        stub_send_text_message([receiver, phone, 0, text, 0, 0], heap, trace)
        assert trace[0]["args"][1] is None

    def test_handles_short_arg_list_gracefully(self):
        heap = ObjectHeap()
        trace: list = []
        # If someone misuses the stub with too few args, all string slots
        # resolve to None — no exception.
        result = stub_send_text_message([0], heap, trace)
        assert result is VOID
        assert trace[0]["args"] == [None, None, None]

    def test_handle_with_no_value_resolves_to_none(self):
        heap = ObjectHeap()
        receiver = heap.allocate("Landroid/telephony/SmsManager;")
        # This handle has no string payload — typical for object refs that
        # don't carry a Python value.
        bogus_handle = heap.allocate("Lcom/foo/Unknown;")
        trace: list = []
        stub_send_text_message(
            [receiver, bogus_handle, 0, bogus_handle, 0, 0], heap, trace
        )
        assert trace[0]["args"] == [None, None, None]


# UpdateService extends Service extends Context: real samples reference these
# inherited Context methods with the service class as owner. A virtual-resolve
# miss routes to the external-miss policy, which raises for these non-void calls,
# so the registry must carry the owner-qualified aliases (PR #8 review #1).
_UPDATE_SVC = "Lcom/google/update/UpdateService;"


class TestInheritedContextAliases:
    def test_update_service_start_service_registered(self):
        sig = (
            f"{_UPDATE_SVC}->startService(Landroid/content/Intent;)"
            "Landroid/content/ComponentName;"
        )
        assert sig in REGISTRY and callable(REGISTRY[sig])

    def test_update_service_open_file_output_registered(self):
        sig = (
            f"{_UPDATE_SVC}->openFileOutput(Ljava/lang/String;I)"
            "Ljava/io/FileOutputStream;"
        )
        assert sig in REGISTRY and callable(REGISTRY[sig])

    def test_update_service_get_file_stream_path_registered(self):
        sig = (
            f"{_UPDATE_SVC}->getFileStreamPath(Ljava/lang/String;)"
            "Ljava/io/File;"
        )
        assert sig in REGISTRY and callable(REGISTRY[sig])

    def test_update_service_register_receiver_registered(self):
        sig = (
            f"{_UPDATE_SVC}->registerReceiver("
            "Landroid/content/BroadcastReceiver;"
            "Landroid/content/IntentFilter;)Landroid/content/Intent;"
        )
        assert sig in REGISTRY and callable(REGISTRY[sig])

    def test_update_service_alias_shares_context_stub(self):
        # The alias must dispatch to the same callable as the Context owner so
        # behavior (and trace output) stays identical regardless of owner.
        ctx_sig = (
            "Landroid/content/Context;->startService(Landroid/content/Intent;)"
            "Landroid/content/ComponentName;"
        )
        svc_sig = (
            f"{_UPDATE_SVC}->startService(Landroid/content/Intent;)"
            "Landroid/content/ComponentName;"
        )
        assert REGISTRY[svc_sig] is REGISTRY[ctx_sig]


class TestNetworkInfoGetType:
    def test_get_type_matches_active_network_info_state(self):
        # getType() must report the same type the fake NetworkInfo was created
        # with (type=1, WiFi) rather than a hardcoded constant (PR #8 review #2).
        heap = ObjectHeap()
        trace: list = []
        info = stub_connectivity_get_active_network_info([], heap, trace)
        assert isinstance(info, ObjectRef)
        stored = heap.get_value(info.handle)
        result = stub_network_info_get_type([info.handle], heap, trace)
        assert isinstance(result, Value)
        assert result.value == stored["type"]
        assert trace[-1]["return"]["value"] == stored["type"]

    def test_get_type_defaults_to_zero_without_stored_state(self):
        # No stored dict (or null receiver) must not raise; defaults to 0.
        heap = ObjectHeap()
        bare = heap.allocate("Landroid/net/NetworkInfo;")
        assert stub_network_info_get_type([bare], heap, []).value == 0
        assert stub_network_info_get_type([0], heap, []).value == 0
        assert stub_network_info_get_type([], heap, []).value == 0
