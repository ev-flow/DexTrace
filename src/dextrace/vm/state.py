# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/state.py — VM execution state.

pending_result lifecycle:
  - DalvikVM.run() clears pending_result=None at entry (stale result guard)
  - invoke path: assert pending_result is None before setting (catches
    back-to-back invokes without move-result; raises DexTraceVMError)
  - move-result: reads, stores in register, clears to None
  - move-result-wide: assert pending_result_is_wide; reads, set_wide, clears
  - return handler: sets pending_result = return_value AFTER restoring registers
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
    # heap handle of an exception object whose catch handler is about to
    # run; consumed by `move-exception`. Set by the engine when a _ThrowSignal
    # matches a catch entry; cleared by move-exception (and by the engine on
    # frame unwind to prevent stale values leaking across catches).
    pending_exception: Optional[int] = None
