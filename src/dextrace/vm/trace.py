# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/trace.py — ExecutionTrace: per-instruction record of VM execution.

P5.3 deliverable. Designed for replay-debugging and coverage analysis.
Capture is opt-in: pass an ExecutionTrace instance to DalvikVM(...,
execution_trace=...) and it accumulates one TraceStep per executed
instruction. The engine pays nothing when no trace is attached (single
None check per step).

Each TraceStep records:
  - the executing frame (code_off + uoff + mnemonic)
  - what the instruction did to the program counter (next_pc + branch_taken)
  - what registers it wrote in the *current* frame
  - how long the handler took (perf_counter_ns delta)
  - whether the step swapped frames (invoke entered a callee, or return
    popped back to the caller)

Frame swaps deliberately leave register_writes empty — the writes from
the swap aren't local to the pre-step frame. Replay tooling should treat
frame_changed=True as a "frame transition" event and reconstruct the
new frame's register state from the next step's pre-state if it needs it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional, Tuple


@dataclass(frozen=True)
class TraceStep:
    """One executed instruction's worth of trace data."""

    code_off: int
    uoff: int
    mnemonic: str
    next_pc: int
    branch_taken: bool
    register_writes: Tuple[Tuple[int, int], ...]
    duration_ns: int
    frame_changed: bool


@dataclass
class ExecutionTrace:
    """Mutable accumulator for TraceStep events.

    Engine calls `record(...)` once per executed instruction. Consumers
    inspect `steps` after `vm.run()` returns. Reset by reassigning
    `steps = []` if you want to reuse the same trace across runs.
    """

    steps: List[TraceStep] = field(default_factory=list)

    def record(self, step: TraceStep) -> None:
        self.steps.append(step)

    def __len__(self) -> int:
        return len(self.steps)

    @property
    def branches(self) -> List[TraceStep]:
        """Steps where the handler set pc to something other than fall-through.

        Excludes frame swaps (invoke/return) — those are tracked via
        `frame_changes`. A `goto` always lands here; an `if-eq` lands here
        only when the predicate held.
        """
        return [
            s for s in self.steps if s.branch_taken and not s.frame_changed
        ]

    @property
    def frame_changes(self) -> List[TraceStep]:
        """Steps that crossed a frame boundary (invoke entry or return)."""
        return [s for s in self.steps if s.frame_changed]


# ---------------------------------------------------------------------------
# Call-tree tracing (android_emulator_enhance)
# ---------------------------------------------------------------------------


@dataclass
class CallNode:
    """One node in the call tree: a DEX-internal method or an Android API stub."""

    sig: str
    is_stub: bool
    args: List[Any]
    return_val: Any
    children: List["CallNode"]


class CallTreeTrace:
    """Records the full method call tree during vm.run().

    Single-use: create a new instance for each vm.run() call. Passing the
    same instance to multiple run() calls merges the trees, which is almost
    never what you want. The engine does not reset this object.

    Engine calls (all guarded by ``if self._call_tree_trace``):
      on_enter(sig)          -- every DEX-internal method entry
      on_exit(val)           -- every DEX-internal method return
      on_stub(api_call_dict) -- after a stub appends to api_calls

    Stack invariant: ``len(_stack) == len(state.call_stack) + 1`` while the
    VM is executing. The root frame (from run() entry) has no call_stack
    entry; every nested frame pushed via _do_invoke has an exact counterpart.
    All three guard with ``if not self._stack: return`` so a mistimed call
    (e.g. on a re-used instance) never raises.
    """

    def __init__(self) -> None:
        self._stack: List[CallNode] = []
        self._root: Optional[CallNode] = None

    def on_enter(self, sig: str) -> None:
        node = CallNode(sig=sig, is_stub=False, args=[], return_val=None, children=[])
        if self._stack:
            self._stack[-1].children.append(node)
        else:
            self._root = node
        self._stack.append(node)

    def on_exit(self, val: Any) -> None:
        if not self._stack:
            return
        node = self._stack.pop()
        node.return_val = val

    def on_stub(self, entry: dict) -> None:
        if not self._stack:
            return
        sig = entry.get("api") or entry.get("sig", "")
        args = entry.get("args", [])
        ret = entry.get("return", None)
        node = CallNode(sig=sig, is_stub=True, args=args, return_val=ret, children=[])
        self._stack[-1].children.append(node)

    @property
    def root(self) -> Optional[CallNode]:
        return self._root
