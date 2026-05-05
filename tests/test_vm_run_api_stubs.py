# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
API stubs VM execution integration test — Android API stub dispatch on real malware.

Sample: Ahmyth (Android RAT). Specifically:
  Lahmyth/mine/king/ahmyth/SMSManager;->sendSMS(Ljava/lang/String;Ljava/lang/String;)Z

The method is `public static`, calls SmsManager.getDefault() then
sendTextMessage(), and returns 1 on the linear no-throw path. The API stubs
both APIs; the test asserts that the captured trace includes the phone +
message text the analyst passed in (the "real IoC").

Sample lookup: tests/fixtures/ahmyth_fetcher.get_apk_path()
  - $DEXTRACE_AHMYTH_APK env var → local copy
  - ~/.cache/dextrace/p4_ahmyth.apk
  - download from MalwareBazaar (SHA256-locked)
Offline contributors: pytest.skip on FetcherError so CI/local runs stay green.

One-liner verification:
  DEXTRACE_AHMYTH_APK=/path/to/Ahmyth.apk python -c "
import sys; sys.path.insert(0,'tests/fixtures')
from ahmyth_fetcher import get_apk_path
from dextrace.cli._io import load_dex_bytes
from dextrace.core.dex_resolver import DexResolver
from dextrace.core.dex_code_map import build_sig_to_codeoff_map
from dextrace.vm.engine import DalvikVM
dex,_ = load_dex_bytes(get_apk_path())
resolver = DexResolver(dex)
vm = DalvikVM(dex, resolver, build_sig_to_codeoff_map(dex, resolver))
sig = 'Lahmyth/mine/king/ahmyth/SMSManager;->sendSMS(Ljava/lang/String;Ljava/lang/String;)Z'
assert vm.run(sig, ['+15555550100','hi']) == 1
assert any('sendTextMessage' in c['api'] for c in vm.api_calls)
print('OK')"
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# tests/fixtures/ is not a package; make it importable.
_FIXTURES = Path(__file__).parent / "fixtures"
sys.path.insert(0, str(_FIXTURES))

from ahmyth_fetcher import FetcherError, get_apk_path  # noqa: E402

from dextrace.cli._io import load_dex_bytes  # noqa: E402
from dextrace.core.dex_code_map import build_sig_to_codeoff_map  # noqa: E402
from dextrace.core.dex_resolver import DexResolver  # noqa: E402
from dextrace.vm.engine import DalvikVM  # noqa: E402
from dextrace.vm.errors import DexTraceNotImplementedError  # noqa: E402

ENTRY = (
    "Lahmyth/mine/king/ahmyth/SMSManager;"
    "->sendSMS(Ljava/lang/String;Ljava/lang/String;)Z"
)
GET_DEFAULT_API = (
    "Landroid/telephony/SmsManager;"
    "->getDefault()Landroid/telephony/SmsManager;"
)
SEND_TEXT_API = (
    "Landroid/telephony/SmsManager;"
    "->sendTextMessage("
    "Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;"
    "Landroid/app/PendingIntent;Landroid/app/PendingIntent;"
    ")V"
)
PHONE = "+15555550100"
MESSAGE = "hello from dextrace"


@pytest.fixture(scope="module")
def ahmyth_dex_bytes() -> bytes:
    try:
        apk_path = get_apk_path()
    except FetcherError as exc:
        pytest.skip(f"Ahmyth sample unavailable: {exc}")
    dex_bytes, _ = load_dex_bytes(apk_path)
    return dex_bytes


@pytest.fixture(scope="module")
def vm(ahmyth_dex_bytes) -> DalvikVM:
    resolver = DexResolver(ahmyth_dex_bytes)
    sig_map = build_sig_to_codeoff_map(ahmyth_dex_bytes, resolver)
    assert ENTRY in sig_map, f"sendSMS not in method map: {ENTRY}"
    return DalvikVM(ahmyth_dex_bytes, resolver, sig_map)


@pytest.fixture()
def strict_vm(ahmyth_dex_bytes) -> DalvikVM:
    resolver = DexResolver(ahmyth_dex_bytes)
    sig_map = build_sig_to_codeoff_map(ahmyth_dex_bytes, resolver)
    return DalvikVM(ahmyth_dex_bytes, resolver, sig_map, strict_stubs=True)


class TestSendSmsHappyPath:
    """Linear no-throw execution: sendSMS returns 1 and captures both APIs."""

    def test_returns_one(self, vm):
        assert vm.run(ENTRY, [PHONE, MESSAGE]) == 1

    def test_two_api_calls_in_order(self, vm):
        vm.run(ENTRY, [PHONE, MESSAGE])
        apis = [c["api"] for c in vm.api_calls]
        assert apis == [GET_DEFAULT_API, SEND_TEXT_API]

    def test_send_text_captures_phone_and_message(self, vm):
        vm.run(ENTRY, [PHONE, MESSAGE])
        send = vm.api_calls[1]
        # sendTextMessage(destAddr, scAddr, text, sentIntent, deliveryIntent)
        # → stub records [destAddr, scAddr, text]; scAddr is null in Ahmyth.
        assert send["args"] == [PHONE, None, MESSAGE]
        assert send["return"] == {"kind": "void"}

    def test_get_default_returns_sms_manager_handle(self, vm):
        vm.run(ENTRY, [PHONE, MESSAGE])
        ret = vm.api_calls[0]["return"]
        assert ret["kind"] == "object"
        assert ret["class"] == "Landroid/telephony/SmsManager;"
        assert ret["handle"] >= 1

    def test_run_is_idempotent(self, vm):
        """api_calls and heap reset between runs — second call still works."""
        first = vm.run(ENTRY, [PHONE, MESSAGE])
        first_calls = vm.api_calls
        second = vm.run(ENTRY, ["+19998887777", "second run"])
        second_calls = vm.api_calls
        assert first == second == 1
        assert len(first_calls) == len(second_calls) == 2
        assert second_calls[1]["args"] == ["+19998887777", None, "second run"]


class TestStrictStubs:
    """--strict-stubs escalates void external misses to errors."""

    def test_strict_unknown_api_raises(self, strict_vm):
        # In strict mode, the first call to a non-stubbed external API raises.
        # We point at a method known to call into Android via invoke-static
        # paths that aren't in the SMS stub family.
        with pytest.raises(DexTraceNotImplementedError, match="unknown Android API"):
            strict_vm.run(
                "Lahmyth/mine/king/ahmyth/SMSManager;->getSMSList()Lorg/json/JSONObject;"
            )


class TestUnknownApiNonVoid:
    """Default mode: non-void external miss raises (policy C)."""

    def test_non_void_miss_raises(self, vm):
        # getSMSList() is not stubbed; first non-void Android call should
        # raise DexTraceNotImplementedError under default (non-strict) mode.
        with pytest.raises(DexTraceNotImplementedError, match="unknown Android API"):
            vm.run(
                "Lahmyth/mine/king/ahmyth/SMSManager;->getSMSList()Lorg/json/JSONObject;"
            )
