# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
Try/catch + stub-throws integration test.

A custom stub raises `_ThrowSignal(IOException)` and the in-method catch
block recovers it. Verifies the engine's `_invoke_stub` allowlist passes
_ThrowSignal through instead of wrapping it as a generic stub-failed
DexTraceVMError (in which case the in-method catch would never see it).

Fixture: tests/fixtures/samples/try_catch_with_stubs.dex
  Lp5x;->openCatch()I  (static)
    try   { Ldemo/Net;->openConnection(); return 0 }
    catch (Ljava/io/IOException;) { return 1 }
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dextrace.core.dex_code_map import build_sig_to_codeoff_map
from dextrace.core.dex_resolver import DexResolver
from dextrace.vm.android_stubs import REGISTRY, VOID
from dextrace.vm.engine import DalvikVM
from dextrace.vm.errors import DexTraceVMError
from dextrace.vm.signals import _ThrowSignal

FIXTURE = (
    Path(__file__).parent.parent / "fixtures" / "samples" / "try_catch_with_stubs.dex"
)
ENTRY = "Lp5x;->openCatch()I"
EXTERNAL_SIG = "Ldemo/Net;->openConnection()V"


def _ioexception_stub(args, heap, api_calls):
    api_calls.append({"sig": EXTERNAL_SIG, "raised": "IOException"})
    raise _ThrowSignal("Ljava/io/IOException;")


def _ok_stub(args, heap, api_calls):
    api_calls.append({"sig": EXTERNAL_SIG, "raised": None})
    return VOID


@pytest.fixture(scope="module")
def dex_bytes():
    return FIXTURE.read_bytes()


@pytest.fixture(scope="module")
def resolver(dex_bytes):
    return DexResolver(dex_bytes)


@pytest.fixture(scope="module")
def sig_map(dex_bytes, resolver):
    return build_sig_to_codeoff_map(dex_bytes, resolver)


def _make_vm(dex_bytes, resolver, sig_map, stub_fn):
    """Build a fresh VM with a one-method registry; isolated from REGISTRY."""
    registry = {EXTERNAL_SIG: stub_fn}
    return DalvikVM(dex_bytes, resolver, sig_map, stub_registry=registry)


def test_stub_raising_ioexception_is_caught(dex_bytes, resolver, sig_map):
    """The headline: a stub that raises _ThrowSignal(IOException) is caught
    by the in-method catch block, returning 1 (the catch arm)."""
    vm = _make_vm(dex_bytes, resolver, sig_map, _ioexception_stub)
    assert vm.run(ENTRY) == 1


def test_stub_returning_void_falls_through_try(dex_bytes, resolver, sig_map):
    """When the stub returns normally, control flows past the try and
    returns 0 — the catch must NOT fire on a clean return."""
    vm = _make_vm(dex_bytes, resolver, sig_map, _ok_stub)
    assert vm.run(ENTRY) == 0


def test_stub_python_exception_still_wraps_as_vm_error(dex_bytes, resolver, sig_map):
    """A non-_ThrowSignal Python exception from a stub must be wrapped as
    DexTraceVMError (not as a Java exception caught by `try`). Verifies
    the allowlist is narrow: only DexTraceVMError / NotImplemented / _ThrowSignal
    pass through; everything else still gets the 'stub failed' wrap."""

    def buggy_stub(args, heap, api_calls):
        raise RuntimeError("simulated stub bug")

    vm = _make_vm(dex_bytes, resolver, sig_map, buggy_stub)
    with pytest.raises(DexTraceVMError, match="stub failed"):
        vm.run(ENTRY)
