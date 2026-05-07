# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
DroidKungFu integration test — Android API stub coverage for three malware threats.

Threat 1: Gain unlimited access (root shell via Runtime.exec)
  Method: Lcom/google/update/UpdateService;->getPermission2()V
  Expected trace APIs: SharedPreferences.getInt, SharedPreferences.edit,
                       SharedPreferences.Editor.putInt, Runtime.getRuntime,
                       Runtime.exec, Process.getOutputStream

Threat 2: Install/uninstall apps silently (APK install via Intent)
  Method: Lcom/waps/l;->a(Landroid/view/View;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;)V
  Expected trace APIs: Intent.setAction, Uri.fromFile, Intent.setDataAndType,
                       Context.getSystemService (notification)

Threat 3: Forward confidential data (SMS/call-log exfiltration)
  Method: Lcom/madhouse/android/ads/_;->_(Landroid/content/Context;)Lcom/madhouse/android/ads/m;
  Expected trace APIs: Context.getSystemService (connectivity), getContentResolver,
                       ContentResolver.query, Cursor.moveToFirst, Cursor.getColumnIndex,
                       Cursor.close

One-liner verification (from DexTrace/ with venv active):
  python -c "
import sys; sys.path.insert(0,'tests/fixtures')
from droidkungfu_fetcher import get_apk_path
from dextrace.cli._io import load_dex_bytes
from dextrace.core.dex_resolver import DexResolver
from dextrace.core.dex_code_map import build_sig_to_codeoff_map
from dextrace.vm.engine import DalvikVM
dex,_ = load_dex_bytes(get_apk_path()); r = DexResolver(dex)
vm = DalvikVM(dex, r, build_sig_to_codeoff_map(dex, r))
vm.run('Lcom/google/update/UpdateService;->getPermission2()V', args=[''])
assert any('Runtime' in c['api'] for c in vm.api_calls); print('T1 OK')"
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

_GET_PERMISSION2 = (
    "Lcom/google/update/UpdateService;->getPermission2()V"
)
_INSTALL_APK = (
    "Lcom/waps/l;"
    "->a(Landroid/view/View;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;)V"
)
_FORWARD_DATA = (
    "Lcom/madhouse/android/ads/_;->_(Landroid/content/Context;)Lcom/madhouse/android/ads/m;"
)


@pytest.fixture(scope="module")
def droidkungfu_vm():
    if str(_FIXTURES) not in sys.path:
        sys.path.insert(0, str(_FIXTURES))
    from droidkungfu_fetcher import FetcherError, get_apk_path  # noqa: PLC0415

    try:
        apk_path = get_apk_path()
    except FetcherError as exc:
        pytest.skip(f"DroidKungFu APK unavailable: {exc}")
    dex, _ = load_dex_bytes(apk_path)
    resolver = DexResolver(dex)
    return DalvikVM(dex, resolver, build_sig_to_codeoff_map(dex, resolver))


class TestThreat1RootAccess:
    """Threat 1 — gain unlimited device access via root shell."""

    def test_runtime_exec_trace(self, droidkungfu_vm):
        vm = droidkungfu_vm
        vm.run(_GET_PERMISSION2, args=[""])
        apis = [c["api"] for c in vm.api_calls]
        assert any(
            "SharedPreferences" in a and "getInt" in a for a in apis
        ), "SharedPreferences.getInt not captured"
        assert any(
            "getRuntime" in a for a in apis
        ), "Runtime.getRuntime not captured"
        assert any(
            "->exec(" in a for a in apis
        ), "Runtime.exec not captured"
        assert any(
            "getOutputStream" in a for a in apis
        ), "Process.getOutputStream not captured"


class TestThreat2InstallApp:
    """Threat 2 — install/uninstall APK silently via Intent."""

    def test_apk_install_intent_trace(self, droidkungfu_vm):
        vm = droidkungfu_vm
        vm.run(_INSTALL_APK, args=["", 0, 0, 0, 0])
        apis = [c["api"] for c in vm.api_calls]
        assert any(
            "setAction" in a for a in apis
        ), "Intent.setAction not captured"
        assert any(
            "fromFile" in a for a in apis
        ), "Uri.fromFile not captured"
        assert any(
            "setDataAndType" in a for a in apis
        ), "Intent.setDataAndType not captured"
        assert any(
            "getSystemService" in a for a in apis
        ), "Context.getSystemService not captured"


class TestThreat3ForwardData:
    """Threat 3 — exfiltrate SMS/call-log via ContentResolver."""

    def test_content_resolver_query_trace(self, droidkungfu_vm):
        vm = droidkungfu_vm
        vm.run(_FORWARD_DATA, args=[""])
        apis = [c["api"] for c in vm.api_calls]
        assert any(
            "getContentResolver" in a for a in apis
        ), "Context.getContentResolver not captured"
        assert any(
            "ContentResolver" in a and "query" in a for a in apis
        ), "ContentResolver.query not captured"
        assert any(
            "moveToFirst" in a for a in apis
        ), "Cursor.moveToFirst not captured"
        assert any(
            "getColumnIndex" in a for a in apis
        ), "Cursor.getColumnIndex not captured"
        assert any(
            "->close()" in a for a in apis
        ), "Cursor.close not captured"
