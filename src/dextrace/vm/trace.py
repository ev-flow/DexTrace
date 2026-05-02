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
from typing import List, Tuple


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
        return [s for s in self.steps if s.branch_taken and not s.frame_changed]

    @property
    def frame_changes(self) -> List[TraceStep]:
        """Steps that crossed a frame boundary (invoke entry or return)."""
        return [s for s in self.steps if s.frame_changed]
