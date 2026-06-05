# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
Unit tests for check-cast / instance-of / monitor-enter / monitor-exit.

We construct DecodedInsns by hand, register the handlers against an empty
eval table, and verify register state and exception signaling. The
ClassHierarchy is built from the fixture; only its built-in Java seed
matters for these tests.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

import pytest

from dextrace.core.dex_resolver import DexResolver
from dextrace.dalvik.types import DecodedInsn
from dextrace.vm.class_hierarchy import ClassHierarchy
from dextrace.vm.handlers import type_check
from dextrace.vm.heap import ObjectHeap
from dextrace.vm.register_file import RegisterFile
from dextrace.vm.signals import _ThrowSignal
from dextrace.vm.state import VMState

FIXTURE = (
    Path(__file__).parent.parent / "fixtures" / "samples" / "packed_switch.dex"
)


def _insn(mnemonic: str, regs: List[str], param: str | None = None) -> DecodedInsn:
    return DecodedInsn(
        uoff=0,
        byte_off=0,
        opcode=0,
        mnemonic=mnemonic,
        fmt="21c" if mnemonic == "check-cast" else "22c",
        size_units=2,
        regs=regs,
        param=param,
    )


@pytest.fixture(scope="module")
def hierarchy():
    dex = FIXTURE.read_bytes()
    return ClassHierarchy(dex, DexResolver(dex))


@pytest.fixture()
def env(hierarchy):
    """Fresh heap, register file, and registered eval table per test."""
    heap = ObjectHeap()
    rf = RegisterFile(8)
    state = VMState(registers=rf, pc=0)
    trace_log: list[str] = []
    eval_table: dict = {}
    type_check.register(eval_table, heap, hierarchy, trace_log.append)
    return {
        "heap": heap,
        "state": state,
        "table": eval_table,
        "trace": trace_log,
    }


class TestCheckCast:
    def test_null_receiver_succeeds(self, env):
        env["state"].registers.set(0, 0)
        env["table"]["check-cast"](
            _insn("check-cast", ["v0"], "Ljava/lang/String;"),
            env["state"],
        )
        # No exception, register left at 0.
        assert env["state"].registers.get(0) == 0

    def test_exact_class_match_succeeds(self, env):
        h = env["heap"].allocate("Ljava/lang/ArithmeticException;")
        env["state"].registers.set(0, h)
        env["table"]["check-cast"](
            _insn(
                "check-cast", ["v0"], "Ljava/lang/ArithmeticException;"
            ),
            env["state"],
        )
        assert env["state"].registers.get(0) == h

    def test_subclass_under_seed_succeeds(self, env):
        # ArithmeticException is a RuntimeException via the seeded chain.
        h = env["heap"].allocate("Ljava/lang/ArithmeticException;")
        env["state"].registers.set(0, h)
        env["table"]["check-cast"](
            _insn("check-cast", ["v0"], "Ljava/lang/RuntimeException;"),
            env["state"],
        )
        assert env["state"].registers.get(0) == h

    def test_unrelated_class_throws_classcast(self, env):
        h = env["heap"].allocate("Ljava/lang/ArithmeticException;")
        env["state"].registers.set(0, h)
        with pytest.raises(_ThrowSignal) as exc:
            env["table"]["check-cast"](
                _insn("check-cast", ["v0"], "Ljava/io/IOException;"),
                env["state"],
            )
        assert exc.value.class_desc == "Ljava/lang/ClassCastException;"


class TestInstanceOf:
    def test_null_receiver_yields_zero(self, env):
        env["state"].registers.set(1, 0)
        env["table"]["instance-of"](
            _insn("instance-of", ["v0", "v1"], "Ljava/lang/String;"),
            env["state"],
        )
        assert env["state"].registers.get(0) == 0

    def test_exact_match_yields_one(self, env):
        h = env["heap"].allocate("Ljava/lang/ArithmeticException;")
        env["state"].registers.set(1, h)
        env["table"]["instance-of"](
            _insn(
                "instance-of",
                ["v0", "v1"],
                "Ljava/lang/ArithmeticException;",
            ),
            env["state"],
        )
        assert env["state"].registers.get(0) == 1

    def test_subclass_under_seed_yields_one(self, env):
        h = env["heap"].allocate("Ljava/lang/ArithmeticException;")
        env["state"].registers.set(1, h)
        env["table"]["instance-of"](
            _insn(
                "instance-of",
                ["v0", "v1"],
                "Ljava/lang/Throwable;",
            ),
            env["state"],
        )
        assert env["state"].registers.get(0) == 1

    def test_unrelated_class_yields_zero(self, env):
        h = env["heap"].allocate("Ljava/lang/ArithmeticException;")
        env["state"].registers.set(1, h)
        env["table"]["instance-of"](
            _insn(
                "instance-of",
                ["v0", "v1"],
                "Ljava/io/IOException;",
            ),
            env["state"],
        )
        assert env["state"].registers.get(0) == 0


class TestMonitor:
    def test_monitor_enter_traces_on_non_null(self, env):
        h = env["heap"].allocate("Ljava/lang/Object;")
        env["state"].registers.set(0, h)
        env["table"]["monitor-enter"](_insn("monitor-enter", ["v0"]), env["state"])
        assert env["trace"] == [f"monitor-enter: handle #{h}"]

    def test_monitor_exit_traces_on_non_null(self, env):
        h = env["heap"].allocate("Ljava/lang/Object;")
        env["state"].registers.set(0, h)
        env["table"]["monitor-exit"](_insn("monitor-exit", ["v0"]), env["state"])
        assert env["trace"] == [f"monitor-exit: handle #{h}"]

    def test_monitor_enter_null_throws_npe(self, env):
        env["state"].registers.set(0, 0)
        with pytest.raises(_ThrowSignal) as exc:
            env["table"]["monitor-enter"](
                _insn("monitor-enter", ["v0"]), env["state"]
            )
        assert exc.value.class_desc == "Ljava/lang/NullPointerException;"

    def test_monitor_exit_null_throws_npe(self, env):
        env["state"].registers.set(0, 0)
        with pytest.raises(_ThrowSignal) as exc:
            env["table"]["monitor-exit"](
                _insn("monitor-exit", ["v0"]), env["state"]
            )
        assert exc.value.class_desc == "Ljava/lang/NullPointerException;"
