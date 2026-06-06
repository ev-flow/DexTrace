# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
Public API test for dextrace.api.execute_method.

execute_method() is the stable wrapper Quark imports to run a single Dalvik
method without touching DalvikVM directly. These tests exercise it against
the committed DEX fixtures used by the VM integration tests.

One-liner verification:
  python -c "from dextrace.api import execute_method as e; \
    print(e('tests/fixtures/samples/const_return.dex', \
            'Lcom/example/ConstReturn;->main()I'))"
  # expect: 42
"""

from __future__ import annotations

import time
from pathlib import Path

from dextrace.api import _run_with_timeout, execute_method

SAMPLES = Path(__file__).parent / "fixtures" / "samples"
CONST_RETURN = SAMPLES / "const_return.dex"
CONST_RETURN_ENTRY = "Lcom/example/ConstReturn;->main()I"
FIB = SAMPLES / "fib_recursive.dex"
FIB_ENTRY = "LFibonacciTest;->fib(I)I"


def test_fixtures_exist():
    assert CONST_RETURN.exists(), f"fixture not found: {CONST_RETURN}"
    assert FIB.exists(), f"fixture not found: {FIB}"


class TestExecuteMethod:
    def test_returns_value(self):
        """execute_method on const_return.dex returns 42."""
        assert execute_method(CONST_RETURN, CONST_RETURN_ENTRY) == 42

    def test_with_args(self):
        """Positional args are passed through: fib(10) == 55."""
        assert execute_method(FIB, FIB_ENTRY, [10]) == 55

    def test_method_not_found_returns_none(self):
        """A signature absent from the DEX resolves to None, not an error."""
        assert execute_method(CONST_RETURN, "Lcom/example/Nope;->ghost()V") is None

    def test_missing_file_returns_none(self):
        """A bad path is swallowed and reported as None (resolve-or-None contract)."""
        assert execute_method(SAMPLES / "does_not_exist.dex", CONST_RETURN_ENTRY) is None


class TestTimeout:
    def test_timeout_returns_promptly(self):
        """The timeout honors the deadline instead of waiting for the worker.

        Regression for the original ThreadPoolExecutor-in-a-with-block, which
        called shutdown(wait=True) on timeout and blocked until the worker
        finished. The process-backed helper must return well before the 30s
        sleep would complete.
        """
        start = time.monotonic()
        result = _run_with_timeout(time.sleep, (30,), timeout_s=0.5)
        elapsed = time.monotonic() - start
        assert result is None
        assert elapsed < 10, f"timeout did not return early (took {elapsed:.1f}s)"
