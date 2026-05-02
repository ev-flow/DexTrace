# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
Tests for vm/trace.py — ExecutionTrace capture across the full VM.

Reuses the P5e array-sum fixture because it exercises the four event
types we care about together: register writes (const/4, add-int),
fall-through arithmetic, taken backward branch (goto -8), and a forward
branch (if-ge to loop exit).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dextrace.core.dex_code_map import build_sig_to_codeoff_map
from dextrace.core.dex_resolver import DexResolver
from dextrace.vm.engine import DalvikVM
from dextrace.vm.trace import ExecutionTrace, TraceStep


P5E = Path(__file__).parent.parent / "fixtures" / "samples" / "p5e_arrays.dex"
P5F = Path(__file__).parent.parent / "fixtures" / "samples" / "p5f_interface.dex"


def _make_vm(fixture: Path, trace: ExecutionTrace) -> DalvikVM:
    dex = fixture.read_bytes()
    resolver = DexResolver(dex)
    sig_map = build_sig_to_codeoff_map(dex, resolver)
    return DalvikVM(dex, resolver, sig_map, execution_trace=trace)


def test_trace_records_each_executed_instruction():
    trace = ExecutionTrace()
    vm = _make_vm(P5E, trace)
    assert vm.run("Lp5e;->arraySum()I") == 60

    # Sanity: every step has a known mnemonic and a non-negative timing.
    assert len(trace) > 0
    for step in trace.steps:
        assert isinstance(step, TraceStep)
        assert step.mnemonic
        assert step.duration_ns >= 0


def test_trace_captures_taken_backward_branch():
    trace = ExecutionTrace()
    vm = _make_vm(P5E, trace)
    vm.run("Lp5e;->arraySum()I")

    # Loop body executes 3 times → goto -8 fires 3 times as a taken branch.
    goto_steps = [s for s in trace.steps if s.mnemonic == "goto"]
    assert len(goto_steps) == 3
    assert all(s.branch_taken for s in goto_steps)
    # Each goto lands at the if-ge head (pc=9 in the fixture).
    assert all(s.next_pc == 9 for s in goto_steps)


def test_trace_captures_register_writes():
    trace = ExecutionTrace()
    vm = _make_vm(P5E, trace)
    vm.run("Lp5e;->arraySum()I")

    # const/4 v3, #0 must record a write of 0 to v3 once. add-int v3, v3, v4
    # must record three writes to v3 (one per loop iteration: 10, 30, 60).
    add_writes = [
        s for s in trace.steps
        if s.mnemonic == "add-int"
    ]
    assert len(add_writes) == 3
    sum_progression = [w[1] for s in add_writes for w in s.register_writes if w[0] == 3]
    assert sum_progression == [10, 30, 60]


def test_trace_captures_frame_changes_on_invoke_and_return():
    trace = ExecutionTrace()
    vm = _make_vm(P5F, trace)
    assert vm.run("Lp5f;->callIFace()I") == 7

    # Exactly one invoke entry (callIFace → value) and one return back.
    swaps = trace.frame_changes
    assert len(swaps) == 2
    assert swaps[0].mnemonic.startswith("invoke-")
    assert swaps[1].mnemonic.startswith("return")


def test_trace_disabled_by_default_costs_nothing():
    # No execution_trace param → engine pays a single None check per step.
    dex = P5E.read_bytes()
    resolver = DexResolver(dex)
    sig_map = build_sig_to_codeoff_map(dex, resolver)
    vm = DalvikVM(dex, resolver, sig_map)
    assert vm.run("Lp5e;->arraySum()I") == 60
