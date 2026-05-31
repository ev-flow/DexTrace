# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/state.py — VM execution state.

pending_result lifecycle:
  - Only the instruction at pending_result_pc may consume pending_result.
    Any other dispatched instruction (including a branch landing on a
    non-move-result target) clears all three pending_result_* fields.
  - Void invokes / void external misses leave pending_result = None.
  - DalvikVM.run() clears pending_result_* at entry.
  - Producers (stub, return-from-internal-callee, external non-void miss)
    set pending_result_pc = uoff of the instruction that must consume it
    (i.e. the invoke's next_pc, or the caller's return_pc on internal return).
  - move-result*: reads pending_result, stores in register, clears all
    pending_result_* fields.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Union

from dextrace.vm.register_file import RegisterFile
from dextrace.vm.call_frame import CallFrame


@dataclass
class VMState:
    registers: RegisterFile
    pc: int
    call_stack: List[CallFrame] = field(default_factory=list)
    pending_result: Optional[Union[int, str]] = None
    pending_result_is_wide: bool = False
    pending_result_pc: Optional[int] = None
    # heap handle of an exception object whose catch handler is about to
    # run; consumed by `move-exception`. Set by the engine when a _ThrowSignal
    # matches a catch entry; cleared by move-exception (and by the engine on
    # frame unwind to prevent stale values leaking across catches).
    pending_exception: Optional[int] = None
