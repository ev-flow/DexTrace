# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/engine.py — DalvikVM: iterative execution engine for P1+P2.

Architecture (per design doc rev 7):
  - eval_table: Dict[str, Callable[[DecodedInsn, VMState], None]]
    * invoke-* opcodes are NOT in this table (OV-1)
    * return-* opcodes ARE handled via _ReturnSignal
  - invoke-* handled inline in the main loop with access to engine private data
  - pending_result lifecycle (OV-2, OV-3):
    * cleared at run() entry
    * invoke asserts pending_result is None before setting
    * move-result* handlers consume and clear it
  - RegisterFile sized by code_item.registers_size at invoke time (OV-4)
  - Bounds check raises DexTraceVMError (OV-5)
  - Callee registers isolated via snapshot on push and restore on return (OV-6)

Execution loop invariant:
  - `code_off`, `insns`, `uoff_to_idx` always describe the CURRENT frame.
  - On invoke: outer loop reloads all three from the callee's code_off.
  - On return: outer loop restores all three from the call frame.
  - state.pc is always in terms of the current frame's code-unit offsets.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

from dextrace.core.dex_parser import DexParser
from dextrace.core.dex_resolver import DexResolver
from dextrace.dalvik.disassembler import DalvikDisassembler, MethodDisasm
from dextrace.dalvik.types import DecodedInsn
from dextrace.vm.call_frame import CallFrame
from dextrace.vm.errors import DexTraceVMError, DexTraceNotImplementedError
from dextrace.vm.int_ops import reg_index
from dextrace.vm.register_file import RegisterFile
from dextrace.vm.state import VMState

import dextrace.vm.handlers.arithmetic as _arith
import dextrace.vm.handlers.array as _array
import dextrace.vm.handlers.branch as _branch
import dextrace.vm.handlers.compare as _compare
import dextrace.vm.handlers.field as _field
import dextrace.vm.handlers.move as _move
import dextrace.vm.handlers.type_conv as _type_conv

# ---------------------------------------------------------------------------
# Internal signals
# ---------------------------------------------------------------------------


class _ReturnSignal(Exception):
    """Raised by return-* handlers to unwind one call frame."""

    __slots__ = ("value", "is_wide")

    def __init__(
        self, value: Optional[Union[int, str]], is_wide: bool = False
    ) -> None:
        self.value = value
        self.is_wide = is_wide


# ---------------------------------------------------------------------------
# Return handlers
# ---------------------------------------------------------------------------


def _handle_return_void(insn: DecodedInsn, state: VMState) -> None:
    raise _ReturnSignal(None, is_wide=False)


def _handle_return(insn: DecodedInsn, state: VMState) -> None:
    val = state.registers.get(reg_index(insn.regs[0]))
    raise _ReturnSignal(val, is_wide=False)


def _handle_return_wide(insn: DecodedInsn, state: VMState) -> None:
    val = state.registers.get_wide(reg_index(insn.regs[0]))
    raise _ReturnSignal(val, is_wide=True)


def _handle_return_object(insn: DecodedInsn, state: VMState) -> None:
    val = state.registers.get(reg_index(insn.regs[0]))
    raise _ReturnSignal(val, is_wide=False)


# ---------------------------------------------------------------------------
# DalvikVM
# ---------------------------------------------------------------------------


class DalvikVM:
    MAX_STEPS = 100_000  # guard against infinite loops

    def __init__(
        self,
        dex_bytes: bytes,
        resolver: DexResolver,
        sig_to_codeoff: Dict[str, int],
    ) -> None:
        self._parser = DexParser(dex_bytes)
        self._disasm = DalvikDisassembler(dex_bytes, resolver)
        self._sig_to_codeoff = sig_to_codeoff

        # instruction cache: code_off -> List[DecodedInsn]
        self._insn_cache: Dict[int, List[DecodedInsn]] = {}

        # eval table (invoke-* and return-* NOT here)
        self._eval: Dict[str, Any] = {}
        _move.register(self._eval)
        _arith.register(self._eval)
        _branch.register(self._eval)
        _compare.register(self._eval)
        _type_conv.register(self._eval)
        _field.register(self._eval)
        _array.register(self._eval)

        self._eval["return-void"] = _handle_return_void
        self._eval["return"] = _handle_return
        self._eval["return-wide"] = _handle_return_wide
        self._eval["return-object"] = _handle_return_object

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(
        self,
        entry_sig: str,
        args: Optional[List[int]] = None,
    ) -> Optional[Union[int, str]]:
        """
        Execute entry_sig with the given integer args.
        Returns the final return value (int, str, or None for void).
        Raises DexTraceVMError on runtime errors.
        """
        args = args or []

        code_off = self._sig_to_codeoff.get(entry_sig)
        if code_off is None:
            raise DexTraceVMError(f"method not found: {entry_sig}")

        code = self._parser.parse_code_item(code_off)
        rf = RegisterFile(code.registers_size)

        # Tail register convention: last ins_size registers hold args
        first_arg_reg = code.registers_size - code.ins_size
        for i, v in enumerate(args):
            dest = first_arg_reg + i
            if dest < code.registers_size:
                rf.set(dest, v)

        state = VMState(registers=rf, pc=0)
        state.pending_result = None  # OV-2: clear at entry

        return self._execute(code_off, state)

    # ------------------------------------------------------------------
    # Core execution loop
    # ------------------------------------------------------------------

    def _execute(
        self, code_off: int, state: VMState
    ) -> Optional[Union[int, str]]:
        insns = self._get_insns(code_off)
        uoff_to_idx: Dict[int, int] = {
            ins.uoff: i for i, ins in enumerate(insns)
        }

        steps = 0
        while True:
            if steps >= self.MAX_STEPS:
                raise DexTraceVMError(
                    f"execution limit exceeded ({self.MAX_STEPS} steps)"
                )
            steps += 1

            idx = uoff_to_idx.get(state.pc)
            if idx is None:
                raise DexTraceVMError(
                    f"invalid pc={state.pc:#06x}: no instruction at that offset "
                    f"(code_off={code_off:#010x})"
                )

            insn = insns[idx]
            next_pc = insn.uoff + insn.size_units
            mnemonic = insn.mnemonic

            # ---- invoke-* handled inline (OV-1) -------------------------
            if mnemonic.startswith("invoke-"):
                callee_code_off = self._do_invoke(
                    insn, state, caller_code_off=code_off
                )
                if callee_code_off is not None:
                    # Entered callee: switch instruction context
                    code_off = callee_code_off
                    insns = self._get_insns(code_off)
                    uoff_to_idx = {ins.uoff: i for i, ins in enumerate(insns)}
                    # state.pc was set to 0 inside _do_invoke
                else:
                    # External method stub: advance past invoke
                    state.pc = next_pc
                continue

            # ---- dispatch via eval table --------------------------------
            handler = self._eval.get(mnemonic)
            if handler is None:
                raise DexTraceNotImplementedError(
                    f"unimplemented opcode: {mnemonic!r} (pc={insn.uoff:#06x})"
                )

            try:
                handler(insn, state)
            except _ReturnSignal as ret:
                if not state.call_stack:
                    # Top-level return — execution complete
                    return ret.value

                # Restore caller frame (OV-6)
                frame = state.call_stack.pop()
                state.registers = frame.caller_registers
                state.pc = frame.return_pc

                # Restore caller instruction context
                code_off = frame.caller_code_off
                insns = self._get_insns(code_off)
                uoff_to_idx = {ins.uoff: i for i, ins in enumerate(insns)}

                # Make return value available to move-result* (OV-3)
                state.pending_result = ret.value
                state.pending_result_is_wide = ret.is_wide
                continue

            # Branch handlers write a new state.pc if taken, leave it at
            # insn.uoff (the pc we used to fetch the insn) if not taken.
            # Either way: if pc wasn't changed by the handler, advance.
            if state.pc == insn.uoff:
                state.pc = next_pc
            # else: branch was taken — use handler's target

    # ------------------------------------------------------------------
    # Invoke helper
    # ------------------------------------------------------------------

    def _do_invoke(
        self,
        insn: DecodedInsn,
        state: VMState,
        caller_code_off: int,
    ) -> Optional[int]:
        """
        Handle an invoke-* instruction.

        Returns:
          callee code_off  — if we entered a method in this DEX
          None             — if the callee is external (stubbed as 0)
        """
        mnemonic = insn.mnemonic

        if mnemonic in (
            "invoke-polymorphic",
            "invoke-polymorphic/range",
            "invoke-custom",
            "invoke-custom/range",
        ):
            raise DexTraceNotImplementedError(
                f"{mnemonic} not implemented (pc={insn.uoff:#06x})"
            )

        callee_sig = insn.param
        if not callee_sig:
            raise DexTraceVMError(
                f"invoke at pc={insn.uoff:#06x}: missing method signature"
            )

        callee_code_off = self._sig_to_codeoff.get(callee_sig)
        if callee_code_off is None:
            # External — stub with 0 result (discard any stale external result
            # since Dalvik does not require move-result for unused return values)
            state.pending_result = 0
            state.pending_result_is_wide = False
            return None

        # OV-3: stale pending_result guard — only applies to internal callees.
        # A prior external stub may have left pending_result=0 if the caller
        # chose not to use the return value (valid Dalvik); clear it silently.
        state.pending_result = None

        # OV-4: size callee RegisterFile from code_item
        callee_code = self._parser.parse_code_item(callee_code_off)
        callee_rf = RegisterFile(callee_code.registers_size)

        # Copy args into callee's tail registers
        # invoke-*: insn.regs = ["v0", "v1", ...] (explicit list)
        # invoke-*/range: insn.regs = [first_reg, last_reg] but disassembler
        #   expands them — we iterate regs directly either way.
        first_arg_slot = callee_code.registers_size - callee_code.ins_size
        for i, reg_str in enumerate(insn.regs):
            src_val = state.registers.get(reg_index(reg_str))
            dest_slot = first_arg_slot + i
            if dest_slot < callee_code.registers_size:
                callee_rf.set(dest_slot, src_val)

        # OV-6: snapshot caller registers before switching
        frame = CallFrame(
            return_pc=insn.uoff + insn.size_units,
            method_desc=callee_sig,
            caller_registers=state.registers.snapshot(),
            caller_code_off=caller_code_off,
        )
        state.call_stack.append(frame)

        # Switch to callee
        state.registers = callee_rf
        state.pc = 0

        return callee_code_off

    # ------------------------------------------------------------------
    # Instruction cache
    # ------------------------------------------------------------------

    def _get_insns(self, code_off: int) -> List[DecodedInsn]:
        if code_off not in self._insn_cache:
            md: MethodDisasm = self._disasm.disassemble_method(code_off)
            self._insn_cache[code_off] = md.instructions
        return self._insn_cache[code_off]
