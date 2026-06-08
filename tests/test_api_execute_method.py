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

import multiprocessing
import os
import signal
import tempfile
import time
from pathlib import Path

import pytest

from dextrace.api import (
    _execute_method_worker,
    _run_with_timeout,
    _taskkill_tree,
    execute_method,
)

SAMPLES = Path(__file__).parent / "fixtures" / "samples"
CONST_RETURN = SAMPLES / "const_return.dex"
CONST_RETURN_ENTRY = "Lcom/example/ConstReturn;->main()I"
FIB = SAMPLES / "fib_recursive.dex"
FIB_ENTRY = "LFibonacciTest;->fib(I)I"
ARRAYS = SAMPLES / "arrays.dex"
ARRAYS_ENTRY = "LArraysTest;->arraySum()I"


# Module-level (picklable) helpers for the spawn-based timeout worker.
def _add(a, b):
    return a + b


def _boom():
    raise ValueError("worker exploded")


def _spawn_grandchild_and_hang(pidfile):
    """Fork a long-sleeping grandchild, record its pid, then hang (force timeout)."""
    pid = os.fork()
    if pid == 0:  # grandchild
        time.sleep(300)
        os._exit(0)
    with open(pidfile, "w") as f:
        f.write(str(pid))
    time.sleep(300)


def _pid_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


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
    def test_timeout_returns_promptly_and_terminates_worker(self):
        """The timeout honors the deadline AND leaves no worker running.

        Regression for two bugs: (1) the original ThreadPoolExecutor-in-a-with-
        block called shutdown(wait=True) on timeout and blocked until the worker
        finished; (2) the ProcessPoolExecutor follow-up returned promptly but
        only abandoned the worker — shutdown(wait=False, cancel_futures=True)
        cannot cancel a task that has already started, so a pathological DEX
        left a background process running. The helper must now both return
        early and terminate the worker, so no child outlives the call.
        """
        start = time.monotonic()
        result = _run_with_timeout(time.sleep, (30,), timeout_s=0.5)
        elapsed = time.monotonic() - start

        assert result is None
        assert elapsed < 10, f"timeout did not return early (took {elapsed:.1f}s)"
        assert not multiprocessing.active_children(), "timed-out worker was left running"

    def test_success_value_crosses_process_boundary(self):
        """A normal return value survives the worker -> parent pipe round trip."""
        assert _run_with_timeout(_add, (2, 3), timeout_s=5.0) == 5

    def test_worker_exception_returns_none(self):
        """An exception inside the worker degrades to None, not a crash."""
        assert _run_with_timeout(_boom, (), timeout_s=5.0) is None

    def test_unpicklable_arg_returns_none(self):
        """Unpicklable args (spawn can't ship them) must honor the None contract.

        Regression: an earlier process-backed version called proc.start()
        outside the try, so the spawn-time pickling failure propagated to the
        caller instead of degrading to None.
        """
        unpicklable = lambda x: x  # noqa: E731 — lambdas aren't picklable
        assert _run_with_timeout(_add, (unpicklable, 1), timeout_s=5.0) is None

    @pytest.mark.skipif(
        not hasattr(os, "fork") or not hasattr(os, "setsid"),
        reason="grandchild reaping needs POSIX fork + setsid",
    )
    def test_timeout_reaps_grandchild(self):
        """A timeout takes down the worker's whole process group.

        The worker calls os.setsid() and the parent group-kills it, so a
        grandchild the worker spawned must not survive the call — killing only
        the worker pid would leak it.
        """
        pidfile = tempfile.mktemp()
        result = _run_with_timeout(_spawn_grandchild_and_hang, (pidfile,), timeout_s=1.0)
        assert result is None

        for _ in range(60):
            if os.path.exists(pidfile):
                break
            time.sleep(0.05)
        grandchild_pid = int(open(pidfile).read())

        time.sleep(1.0)  # if not reaped, it would sleep for 300s
        alive = _pid_alive(grandchild_pid)
        if alive:
            os.kill(grandchild_pid, signal.SIGKILL)  # don't leak from the test
        assert not alive, "grandchild survived the timeout (process group not reaped)"

    def test_windows_tree_kill_issues_taskkill(self, monkeypatch):
        """The Windows termination branch reaps the tree via `taskkill /F /T`.

        taskkill exists only on Windows, but capturing the subprocess command
        verifies the cross-platform path on any OS. Confirms grandchild reaping
        is wired for Windows, not just POSIX process groups.
        """
        import dextrace.api as api

        calls = []
        monkeypatch.setattr(api.subprocess, "run", lambda cmd, **k: calls.append(cmd))

        api._taskkill_tree(4321)
        assert calls == [["taskkill", "/F", "/T", "/PID", "4321"]]

        _taskkill_tree(None)  # no pid -> no command issued
        assert len(calls) == 1


class TestMemoryLimit:
    def test_limit_param_allows_normal_call(self):
        """A normal method runs fine under the (default) memory budget.

        The budget itself is enforced inside the VM heap; see
        tests/vm/test_heap_memory_budget.py for the allocation-level proof.
        """
        assert execute_method(CONST_RETURN, CONST_RETURN_ENTRY, memory_limit_mb=1024) == 42
        assert execute_method(CONST_RETURN, CONST_RETURN_ENTRY, memory_limit_mb=None) == 42
        # 0 disables the cap (consistent with the CLI), it does NOT reject all.
        assert execute_method(CONST_RETURN, CONST_RETURN_ENTRY, memory_limit_mb=0) == 42

    def test_vm_memory_abort_maps_to_none(self, monkeypatch):
        """A VM memory-budget abort surfaces to the caller as None.

        The heap raises DexTraceVMError on an over-budget allocation (proven in
        tests/vm/test_heap_memory_budget.py); here we verify the API worker's
        last link — that such a VM error becomes None, not an exception. Driven
        in-process via _execute_method_worker (monkeypatch cannot cross the
        spawn boundary that execute_method uses).
        """
        from dextrace.vm.engine import DalvikVM
        from dextrace.vm.errors import DexTraceVMError

        def _raise_budget(self, *a, **k):
            raise DexTraceVMError("memory budget exceeded (simulated)")

        monkeypatch.setattr(DalvikVM, "run", _raise_budget)
        assert _execute_method_worker(str(ARRAYS), ARRAYS_ENTRY, [], 1024) is None
