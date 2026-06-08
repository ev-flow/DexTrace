# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/engine.py — DalvikVM: iterative execution engine.

Architecture:
  - eval_table: Dict[str, Callable[[DecodedInsn, VMState], None]]
    * invoke-* opcodes are NOT in this table
    * return-* opcodes ARE handled via _ReturnSignal
  - invoke-* handled inline in the main loop with access to engine private data
  - pending_result lifecycle:
    * cleared at run() entry
    * producers set pending_result_pc = uoff of the must-consume instruction
      (invoke's next_pc, or caller's return_pc on internal return)
    * dispatch loop clears pending_result_* whenever state.pc !=
      pending_result_pc, so only the immediately following move-result*
      can consume the value (Dalvik verifier semantics)
    * void invokes / void external misses leave pending_result = None
    * move-result* handlers consume and clear all pending_result_* fields
  - RegisterFile sized by code_item.registers_size at invoke time
  - Bounds check raises DexTraceVMError
  - Callee registers isolated via snapshot on push and restore on return

Execution loop invariant:
  - `code_off`, `insns`, `uoff_to_idx` always describe the CURRENT frame.
  - On invoke: outer loop reloads all three from the callee's code_off.
  - On return: outer loop restores all three from the call frame.
  - state.pc is always in terms of the current frame's code-unit offsets.
"""

from __future__ import annotations

from time import perf_counter_ns
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from dextrace.core.dex_parser import DexParser, CatchHandler, TryItem
from dextrace.core.dex_resolver import DexResolver
from dextrace.dalvik.disassembler import DalvikDisassembler, MethodDisasm
from dextrace.dalvik.payload import (
    decode_fill_array_data,
    decode_packed_switch,
    decode_sparse_switch,
)
from dextrace.dalvik.types import DecodedInsn
from dextrace.vm.android_stubs import (
    REGISTRY as DEFAULT_STUB_REGISTRY,
    ObjectRef,
    StubCallable,
    Value,
    VOID,
    Wide,
)
from dextrace.vm.call_frame import CallFrame
from dextrace.vm.class_hierarchy import ClassHierarchy
from dextrace.vm.errors import DexTraceVMError, DexTraceNotImplementedError
from dextrace.vm.heap import ObjectHeap
from dextrace.vm.int_ops import i32, i64, reg_index
from dextrace.vm.register_file import RegisterFile
from dextrace.vm.signals import _ThrowSignal
from dextrace.vm.state import VMState
from dextrace.vm.trace import CallTreeTrace, ExecutionTrace, TraceStep

import dextrace.vm.handlers.arithmetic as _arith
import dextrace.vm.handlers.array as _array
import dextrace.vm.handlers.branch as _branch
import dextrace.vm.handlers.compare as _compare
import dextrace.vm.handlers.field as _field
import dextrace.vm.handlers.move as _move
import dextrace.vm.handlers.throw as _throw
import dextrace.vm.handlers.type_check as _type_check
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
    # sign-extend so the surfaced value reflects Java's signed long
    # semantics. Without i64, a returned -1L would print as 2^64-1.
    val = i64(state.registers.get_wide(reg_index(insn.regs[0])))
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
        trace_sink: Optional[Callable[[str], None]] = None,
        stub_registry: Optional[Dict[str, StubCallable]] = None,
        strict_stubs: bool = False,
        execution_trace: Optional[ExecutionTrace] = None,
        call_tree_trace: Optional[CallTreeTrace] = None,
        memory_limit_mb: Optional[int] = None,
    ) -> None:
        self._parser = DexParser(dex_bytes)
        self._resolver = resolver
        self._disasm = DalvikDisassembler(dex_bytes, resolver)
        self._sig_to_codeoff = sig_to_codeoff

        # instruction cache: code_off -> List[DecodedInsn]
        self._insn_cache: Dict[int, List[DecodedInsn]] = {}

        # parsed try/catch table cache, populated on first throw inside
        # a method. Keyed by code_off, sibling of _insn_cache.
        self._handler_cache: Dict[int, List[TryItem]] = {}

        # Optional verbose trace sink: called with human-readable [INFO] messages
        self._trace_sink = trace_sink

        # optional structured execution trace. When set, the main
        # _execute loop records one TraceStep per instruction.
        self._execution_trace = execution_trace

        # android_emulator_enhance: optional call-tree trace. Single-use;
        # create a new instance per vm.run() call.
        self._call_tree_trace = call_tree_trace

        # Object heap and class hierarchy. memory_limit_mb caps total heap
        # allocation (predictively, at the allocation site) so untrusted DEX
        # cannot exhaust memory; None leaves it unbounded.
        self._heap = ObjectHeap(memory_limit_mb=memory_limit_mb)
        self._hierarchy = ClassHierarchy(dex_bytes, resolver)

        # Android-API stub registry (DI for tests; defaults to global REGISTRY)
        # Strict mode escalates void external misses to errors as well.
        self._stub_registry: Dict[str, StubCallable] = (
            stub_registry
            if stub_registry is not None
            else DEFAULT_STUB_REGISTRY
        )
        self._strict_stubs = strict_stubs

        # every stub call appends one dict here. Reset at run() entry so
        # consecutive vm.run() calls observe isolated trace logs.
        self._api_calls: List[Dict[str, Any]] = []

        # static-fields map keyed by full Dalvik field signature
        # ("Lcls;->name:type"). Reset at run() entry (heap.reset path) so
        # static state cannot bleed between method runs.
        self._static_fields: Dict[str, Any] = {}

        # eval table (invoke-* and return-* NOT here)
        self._eval: Dict[str, Any] = {}
        _move.register(self._eval)
        _arith.register(self._eval)
        _branch.register(self._eval)
        _compare.register(self._eval)
        _type_conv.register(self._eval)
        _field.register(self._eval, self._heap, self._static_fields)
        _array.register(self._eval, self._heap)

        self._eval["return-void"] = _handle_return_void
        self._eval["return"] = _handle_return
        self._eval["return-wide"] = _handle_return_wide
        self._eval["return-object"] = _handle_return_object

        # new-instance: closure captures heap reference and trace sink
        _heap_ref = self._heap
        _sink_ref = self._trace_sink

        def _handle_new_instance(insn: DecodedInsn, state: VMState) -> None:
            class_desc = insn.param
            if not class_desc:
                raise DexTraceVMError(
                    f"new-instance at pc={insn.uoff:#06x}: missing type descriptor"
                )
            handle = _heap_ref.allocate(class_desc)
            state.registers.set(reg_index(insn.regs[0]), handle)
            if _sink_ref is not None:
                _sink_ref(f"new-instance: {class_desc} → handle #{handle}")

        self._eval["new-instance"] = _handle_new_instance

        # const-string materializes the resolved string onto the heap
        # so downstream code (iget/iput-object, stubs that read via
        # heap.get_value) sees a proper Ljava/lang/String; handle instead of
        # an integer hash. Disassembler delivers `param` already wrapped in
        # double quotes — we strip them before allocation.
        def _handle_const_string(insn: DecodedInsn, state: VMState) -> None:
            raw = insn.param or ""
            if len(raw) >= 2 and raw.startswith('"') and raw.endswith('"'):
                raw = raw[1:-1]
            handle = _heap_ref.allocate("Ljava/lang/String;", value=raw)
            state.registers.set(reg_index(insn.regs[0]), handle)

        self._eval["const-string"] = _handle_const_string
        self._eval["const-string/jumbo"] = _handle_const_string

        # const-class materializes a Class<?> object whose value is the
        # underlying type descriptor. The minimal model is enough for code
        # that uses `Foo.class` as a reflection key or compares class
        # references for equality.
        def _handle_const_class(insn: DecodedInsn, state: VMState) -> None:
            type_desc = insn.param
            handle = _heap_ref.allocate("Ljava/lang/Class;", value=type_desc)
            state.registers.set(reg_index(insn.regs[0]), handle)

        self._eval["const-class"] = _handle_const_class

        # Throw needs the heap to resolve the exception class descriptor.
        _throw.register(self._eval, self._heap)

        # Check-cast / instance-of need heap + class hierarchy; monitor-*
        # records lock activity through the trace_sink when one is provided.
        _type_check.register(
            self._eval, self._heap, self._hierarchy, self._trace_sink
        )

        self._final_state: Optional[VMState] = None

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(
        self,
        entry_sig: str,
        args: Optional[List[Union[int, str]]] = None,
    ) -> Optional[Union[int, str]]:
        """
        Execute entry_sig with the given args.

        Each arg is either an int (placed directly into the register) or a
        str (materialized as a Ljava/lang/String; handle on the heap, with
        the string stored as the handle's value so stubs can read it back).

        Returns the final return value (int, str, or None for void).
        Raises DexTraceVMError on runtime errors.
        """
        args = args or []
        self._heap.reset()  # isolate heap state between run() calls
        self._static_fields.clear()  # same isolation for static fields
        self._api_calls.clear()

        code_off = self._sig_to_codeoff.get(entry_sig)
        if code_off is None:
            raise DexTraceVMError(f"method not found: {entry_sig}")

        code = self._parser.parse_code_item(code_off)
        rf = RegisterFile(code.registers_size)

        # Materialize string args AFTER heap.reset() so the handles survive.
        materialized: List[int] = []
        for v in args:
            if isinstance(v, str):
                materialized.append(
                    self._heap.allocate("Ljava/lang/String;", value=v)
                )
            else:
                materialized.append(v)

        # Tail register convention: last ins_size registers hold args
        first_arg_reg = code.registers_size - code.ins_size
        for i, v in enumerate(materialized):
            dest = first_arg_reg + i
            if dest < code.registers_size:
                rf.set(dest, v)

        state = VMState(registers=rf, pc=0)
        state.pending_result = None  # clear at entry
        state.pending_result_is_wide = False
        state.pending_result_pc = None

        if self._call_tree_trace:
            self._call_tree_trace.on_enter(entry_sig)
        result = self._execute(code_off, state)
        if self._call_tree_trace:
            self._call_tree_trace.on_exit(result)
        self._final_state = state
        # Resolve String heap handles to their Python str values so callers
        # receive a plain string rather than an opaque integer handle.
        if isinstance(result, int) and result > 0:
            try:
                if self._heap.get_class(result) == "Ljava/lang/String;":
                    str_val = self._heap.get_value(result)
                    if str_val is not None:
                        result = str_val
            except DexTraceVMError:
                pass
        return result

    @property
    def final_registers(self) -> Optional[RegisterFile]:
        """Register file of the top-level frame after the last run() call."""
        return self._final_state.registers if self._final_state else None

    @property
    def api_calls(self) -> List[Dict[str, Any]]:
        """Snapshot of stub-call trace entries from the last run()."""
        return list(self._api_calls)

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

        trace = self._execution_trace

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

            # Stale pending_result guard: a value produced by a prior invoke
            # is only consumable by the instruction at pending_result_pc
            # (i.e. immediately following the invoke, per Dalvik verifier).
            # Any other dispatch — including a branch landing on a
            # non-move-result target — clears it.
            if (
                state.pending_result is not None
                and state.pending_result_pc is not None
                and state.pc != state.pending_result_pc
            ):
                state.pending_result = None
                state.pending_result_is_wide = False
                state.pending_result_pc = None

            # per-instruction snapshot for trace diff. Skipped entirely
            # when no trace is attached so the hot path stays cheap.
            if trace is not None:
                pre_code_off = code_off
                pre_regs: Tuple[int, ...] = tuple(
                    state.registers.get(i) for i in range(len(state.registers))
                )
                t0 = perf_counter_ns()

            try:
                # ---- invoke-* handled inline ----------------------
                if mnemonic.startswith("invoke-"):
                    callee_code_off = self._do_invoke(
                        insn, state, caller_code_off=code_off
                    )
                    if callee_code_off is not None:
                        # Entered callee: switch instruction context
                        code_off = callee_code_off
                        insns = self._get_insns(code_off)
                        uoff_to_idx = {
                            ins.uoff: i for i, ins in enumerate(insns)
                        }
                        # state.pc was set to 0 inside _do_invoke
                    else:
                        # External method stub: advance past invoke
                        state.pc = next_pc
                    if trace is not None:
                        self._record_trace(
                            trace,
                            pre_code_off,
                            code_off,
                            insn,
                            mnemonic,
                            next_pc,
                            state,
                            pre_regs,
                            t0,
                        )
                    continue

                # ---- packed/sparse switch handled inline ------------------
                # Inline dispatch lets us reach the current frame's raw insn
                # bytes (needed to decode the payload) without leaking the
                # parser into eval-table handlers.
                if mnemonic == "packed-switch":
                    self._do_packed_switch(insn, state, code_off)
                elif mnemonic == "sparse-switch":
                    self._do_sparse_switch(insn, state, code_off)
                elif mnemonic == "fill-array-data":
                    self._do_fill_array_data(insn, state, code_off)
                else:
                    # ---- dispatch via eval table -------------------------
                    handler = self._eval.get(mnemonic)
                    if handler is None:
                        raise DexTraceNotImplementedError(
                            f"unimplemented opcode: {mnemonic!r} (pc={insn.uoff:#06x})"
                        )

                    handler(insn, state)
            except _ReturnSignal as ret:
                if not state.call_stack:
                    # Top-level return — execution complete
                    if trace is not None:
                        self._record_trace(
                            trace,
                            pre_code_off,
                            code_off,
                            insn,
                            mnemonic,
                            next_pc,
                            state,
                            pre_regs,
                            t0,
                        )
                    return ret.value

                # Restore caller frame
                frame = state.call_stack.pop()
                if self._call_tree_trace:
                    self._call_tree_trace.on_exit(ret.value)
                state.registers = frame.caller_registers
                state.pc = frame.return_pc

                # Restore caller instruction context
                code_off = frame.caller_code_off
                insns = self._get_insns(code_off)
                uoff_to_idx = {ins.uoff: i for i, ins in enumerate(insns)}

                # Make return value available to move-result*. Void returns
                # (ret.value is None) leave pending_result = None so a stray
                # move-result in the caller raises "no pending result".
                state.pending_result = ret.value
                state.pending_result_is_wide = ret.is_wide
                state.pending_result_pc = (
                    frame.return_pc if ret.value is not None else None
                )
                if trace is not None:
                    self._record_trace(
                        trace,
                        pre_code_off,
                        code_off,
                        insn,
                        mnemonic,
                        next_pc,
                        state,
                        pre_regs,
                        t0,
                    )
                continue
            except _ThrowSignal as sig:
                # walk catch tables in current frame; on miss pop frames
                # one at a time until either a matching handler is found or
                # the call stack is empty (uncaught -> top-level error).
                throw_pc = insn.uoff  # site of the instruction that threw
                while True:
                    matched = self._find_handler(
                        code_off, throw_pc, sig.class_desc
                    )
                    if matched is not None:
                        # Hand off to the catch handler. Lazy-allocate a heap
                        # object if the throw didn't carry one.
                        handle = sig.exc_handle
                        if handle == 0:
                            handle = self._heap.allocate(sig.class_desc)
                        state.pending_exception = handle
                        # Guardrail: clear stale return value so the catch
                        # block's first move-result-* (if any) can't pick up
                        # a leftover value from the throwing call.
                        state.pending_result = None
                        state.pending_result_is_wide = False
                        state.pending_result_pc = None
                        state.pc = matched.handler_addr
                        break

                    # No handler in this frame: pop one and retry.
                    if not state.call_stack:
                        raise DexTraceVMError(
                            f"uncaught: {sig.class_desc}"
                        ) from sig
                    frame = state.call_stack.pop()
                    if self._call_tree_trace:
                        self._call_tree_trace.on_exit(None)
                    state.registers = frame.caller_registers
                    # Throw site in the caller is the invoke instruction itself.
                    throw_pc = frame.invoke_pc
                    code_off = frame.caller_code_off
                    insns = self._get_insns(code_off)
                    uoff_to_idx = {ins.uoff: i for i, ins in enumerate(insns)}
                    # Stale-result guardrail also applies on cross-frame unwind.
                    state.pending_result = None
                    state.pending_result_is_wide = False
                    state.pending_result_pc = None
                if trace is not None:
                    self._record_trace(
                        trace,
                        pre_code_off,
                        code_off,
                        insn,
                        mnemonic,
                        next_pc,
                        state,
                        pre_regs,
                        t0,
                    )
                continue

            # Branch handlers write a new state.pc if taken, leave it at
            # insn.uoff (the pc we used to fetch the insn) if not taken.
            # Either way: if pc wasn't changed by the handler, advance.
            if state.pc == insn.uoff:
                state.pc = next_pc
            # else: branch was taken — use handler's target

            if trace is not None:
                self._record_trace(
                    trace,
                    pre_code_off,
                    code_off,
                    insn,
                    mnemonic,
                    next_pc,
                    state,
                    pre_regs,
                    t0,
                )

    # ------------------------------------------------------------------
    # trace recording
    # ------------------------------------------------------------------

    @staticmethod
    def _record_trace(
        trace: ExecutionTrace,
        pre_code_off: int,
        post_code_off: int,
        insn: DecodedInsn,
        mnemonic: str,
        next_pc: int,
        state: VMState,
        pre_regs: Tuple[int, ...],
        t0: int,
    ) -> None:
        duration = perf_counter_ns() - t0
        frame_changed = post_code_off != pre_code_off
        if frame_changed:
            # Register file got swapped to a different frame; writes from
            # the swap aren't local to the pre-step frame, so we skip the
            # diff. Replay tools can reconstruct the new frame from the
            # next step's pre-state if they need it.
            writes: Tuple[Tuple[int, int], ...] = ()
            taken = True
        else:
            post_regs = tuple(
                state.registers.get(i) for i in range(len(state.registers))
            )
            writes = tuple(
                (i, post_regs[i])
                for i in range(min(len(pre_regs), len(post_regs)))
                if pre_regs[i] != post_regs[i]
            )
            taken = state.pc != next_pc
        trace.record(
            TraceStep(
                code_off=pre_code_off,
                uoff=insn.uoff,
                mnemonic=mnemonic,
                next_pc=state.pc,
                branch_taken=taken,
                register_writes=writes,
                duration_ns=duration,
                frame_changed=frame_changed,
            )
        )

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

        # Receiver validation must precede stub dispatch: Dalvik/JVM semantics
        # require invoke-virtual / invoke-interface to raise NPE on a null
        # receiver before the callee is invoked, even when a stub is registered.
        is_virtual_dispatch = mnemonic in (
            "invoke-virtual",
            "invoke-virtual/range",
            "invoke-interface",
            "invoke-interface/range",
        )

        runtime_desc: Optional[str] = None
        if is_virtual_dispatch:
            receiver_handle = state.registers.get(reg_index(insn.regs[0]))
            if receiver_handle == 0:
                raise DexTraceVMError(
                    f"null receiver: {mnemonic} at pc={insn.uoff:#06x}"
                )
            runtime_desc = self._heap.get_class(receiver_handle)

        # Stub dispatch is keyed by the static (compile-time) callee signature
        # and sits in front of both vtable resolution and the external-miss
        # path — but only after receiver validation above.
        stub = self._stub_registry.get(callee_sig)
        if stub is not None:
            self._invoke_stub(stub, callee_sig, insn, state)
            return None

        # invoke-interface uses the same runtime-class vtable lookup as
        # invoke-virtual. Java semantics require the runtime class implements
        # the interface, so (name, proto) will be present in its vtable.
        if is_virtual_dispatch:
            assert runtime_desc is not None
            # invoke-virtual on an external (no-stub) class falls through
            # to the external-miss policy instead of raising a vtable miss.
            if not self._hierarchy.has_class(runtime_desc):
                self._handle_external_miss(callee_sig, insn, state)
                return None

            arrow_pos = callee_sig.index("->") + 2
            method_part = callee_sig[arrow_pos:]
            paren_pos = method_part.index("(")
            vname = method_part[:paren_pos]
            vproto = method_part[paren_pos:]
            try:
                callee_code_off: Optional[int] = self._hierarchy.resolve_virtual(
                    runtime_desc, vname, vproto
                )
            except DexTraceVMError:
                # Method is not defined in the DEX class chain (inherited from
                # Android SDK superclass). Treat it as an external API call —
                # check the stub registry or apply the external-miss policy.
                self._handle_external_miss(callee_sig, insn, state)
                return None
            if self._trace_sink is not None:
                resolved_sig = f"{runtime_desc}->{vname}{vproto}"
                if resolved_sig != callee_sig:
                    self._trace_sink(
                        f"{mnemonic}: {callee_sig} → {resolved_sig}"
                    )
        else:
            callee_code_off = self._sig_to_codeoff.get(callee_sig)
            if callee_code_off is None:
                self._handle_external_miss(callee_sig, insn, state)
                return None

        # Redundant with the dispatch-loop stale guard, but kept for clarity:
        # ensures the callee starts with no leftover pending_result_*.
        state.pending_result = None
        state.pending_result_is_wide = False
        state.pending_result_pc = None

        # size callee RegisterFile from code_item
        assert callee_code_off is not None  # resolve_virtual raises on miss
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

        # snapshot caller registers before switching
        frame = CallFrame(
            return_pc=insn.uoff + insn.size_units,
            method_desc=callee_sig,
            caller_registers=state.registers.snapshot(),
            caller_code_off=caller_code_off,
            invoke_pc=insn.uoff,  # catch-walk needs caller's call site
        )
        state.call_stack.append(frame)

        # Switch to callee
        state.registers = callee_rf
        state.pc = 0

        if self._call_tree_trace:
            self._call_tree_trace.on_enter(callee_sig)
        return callee_code_off

    # ------------------------------------------------------------------
    # stub dispatch + external-miss policy
    # ------------------------------------------------------------------

    def _invoke_stub(
        self,
        stub: StubCallable,
        callee_sig: str,
        insn: DecodedInsn,
        state: VMState,
    ) -> None:
        """Run a stub callable, capture its result into pending_result."""
        stub_args: List[Any] = [
            state.registers.get(reg_index(r)) for r in insn.regs
        ]
        _prev_len = len(self._api_calls)
        try:
            result = stub(stub_args, self._heap, self._api_calls)
        except (DexTraceVMError, DexTraceNotImplementedError, _ThrowSignal):
            # stubs can model Java-level failures (e.g. URL.openConnection
            # raising IOException) by raising _ThrowSignal directly. Without
            # listing it here, the broad `except Exception` below would wrap
            # the signal in a DexTraceVMError("stub failed ...") and the
            # in-method catch block would never see it.
            if self._call_tree_trace and len(self._api_calls) > _prev_len:
                self._call_tree_trace.on_stub(self._api_calls[-1])
            raise
        except Exception as exc:  # pylint: disable=broad-exception-caught
            raise DexTraceVMError(
                f"stub failed for {callee_sig} (pc={insn.uoff:#06x}): {exc}"
            ) from exc
        if self._call_tree_trace and len(self._api_calls) > _prev_len:
            self._call_tree_trace.on_stub(self._api_calls[-1])

        next_pc = insn.uoff + insn.size_units
        if result is VOID:
            # Void stubs produce no consumable result. A stray move-result*
            # in the caller will raise "no pending result" via the move-result
            # handlers (Dalvik verifier semantics).
            state.pending_result = None
            state.pending_result_is_wide = False
            state.pending_result_pc = None
        elif isinstance(result, Value):
            state.pending_result = result.value
            state.pending_result_is_wide = False
            state.pending_result_pc = next_pc
        elif isinstance(result, Wide):
            state.pending_result = result.value
            state.pending_result_is_wide = True
            state.pending_result_pc = next_pc
        elif isinstance(result, ObjectRef):
            state.pending_result = result.handle
            state.pending_result_is_wide = False
            state.pending_result_pc = next_pc
        else:
            raise DexTraceVMError(
                f"stub for {callee_sig} returned unsupported type "
                f"{type(result).__name__}"
            )

        if self._trace_sink is not None:
            self._trace_sink(f"stub: {callee_sig}")

    def _handle_external_miss(
        self, callee_sig: str, insn: DecodedInsn, state: VMState
    ) -> None:
        """
        Policy C: void external misses are silent no-ops; non-void misses
        raise DexTraceNotImplementedError. --strict-stubs escalates void
        misses to errors as well (option A semantics).
        """
        is_void = callee_sig.endswith(")V")
        if self._strict_stubs or not is_void:
            raise DexTraceNotImplementedError(
                f"unknown Android API: {callee_sig} (pc={insn.uoff:#06x})"
            )
        # Legacy void-miss: produce no consumable result.
        state.pending_result = None
        state.pending_result_is_wide = False
        state.pending_result_pc = None

    # ------------------------------------------------------------------
    # Instruction cache
    # ------------------------------------------------------------------

    def _get_insns(self, code_off: int) -> List[DecodedInsn]:
        if code_off not in self._insn_cache:
            md: MethodDisasm = self._disasm.disassemble_method(code_off)
            self._insn_cache[code_off] = md.instructions
        return self._insn_cache[code_off]

    # ------------------------------------------------------------------
    # switch dispatch (inline so handlers can reach raw insn bytes)
    # ------------------------------------------------------------------

    def _do_packed_switch(
        self, insn: DecodedInsn, state: VMState, code_off: int
    ) -> None:
        """
        Decode the packed-switch payload at insn.target_uoff and branch the
        dispatch loop. Falls through (no pc mutation) when the test value is
        outside [first_key, first_key + size).
        """
        test_val = i32(state.registers.get(reg_index(insn.regs[0])))
        if insn.target_uoff is None:
            raise DexTraceVMError(
                f"packed-switch at pc={insn.uoff:#06x}: missing payload offset"
            )
        insns_bytes = self._parser.parse_code_item(code_off).insns
        table = decode_packed_switch(insns_bytes, insn.target_uoff)
        size = len(table.targets)
        if size == 0:
            return
        if table.first_key <= test_val < table.first_key + size:
            rel = table.targets[test_val - table.first_key]
            state.pc = insn.uoff + rel

    def _do_sparse_switch(
        self, insn: DecodedInsn, state: VMState, code_off: int
    ) -> None:
        """
        Decode the sparse-switch payload at insn.target_uoff and branch on a
        keys[] match. Linear scan is fine for the tables we see in the wild;
        keys are guaranteed sorted ascending so we can early-exit.
        """
        test_val = i32(state.registers.get(reg_index(insn.regs[0])))
        if insn.target_uoff is None:
            raise DexTraceVMError(
                f"sparse-switch at pc={insn.uoff:#06x}: missing payload offset"
            )
        insns_bytes = self._parser.parse_code_item(code_off).insns
        table = decode_sparse_switch(insns_bytes, insn.target_uoff)
        for k, t in zip(table.keys, table.targets):
            if k == test_val:
                state.pc = insn.uoff + t
                return
            if k > test_val:
                return

    def _do_fill_array_data(
        self, insn: DecodedInsn, state: VMState, code_off: int
    ) -> None:
        """
        Decode the fill-array-data payload at insn.target_uoff and copy each
        element into the heap-backed array referenced by the instruction's
        register. Null array → NPE; payload longer than the array is a hard
        format error (would be rejected by dexopt) so it raises VMError.
        """
        handle = state.registers.get(reg_index(insn.regs[0]))
        if handle == 0:
            raise _ThrowSignal("Ljava/lang/NullPointerException;", 0)
        if insn.target_uoff is None:
            raise DexTraceVMError(
                f"fill-array-data at pc={insn.uoff:#06x}: missing payload offset"
            )
        insns_bytes = self._parser.parse_code_item(code_off).insns
        table = decode_fill_array_data(insns_bytes, insn.target_uoff)
        arr = self._heap.get_array(handle)
        if len(table.elements) > len(arr):
            raise DexTraceVMError(
                f"fill-array-data at pc={insn.uoff:#06x}: payload has "
                f"{len(table.elements)} elements but array length is {len(arr)}"
            )
        for i, v in enumerate(table.elements):
            arr[i] = int(v)

    # ------------------------------------------------------------------
    # try/catch table cache + handler lookup
    # ------------------------------------------------------------------

    def _get_tries(self, code_off: int) -> List[TryItem]:
        """Lazy-populated parsed try/catch table for `code_off`."""
        cached = self._handler_cache.get(code_off)
        if cached is not None:
            return cached
        tries = self._parser.parse_tries(code_off, self._resolver)
        self._handler_cache[code_off] = tries
        return tries

    def _find_handler(
        self, code_off: int, throw_pc: int, exc_class: str
    ) -> Optional[CatchHandler]:
        """
        Return the first CatchHandler in `code_off` whose try block covers
        `throw_pc` AND whose class matches `exc_class` (subtype-aware), or
        None if none match. Catch entries are evaluated in source order;
        a catch-all (class_desc=None) matches any exception type.

        The Dalvik spec says the FIRST matching handler in the FIRST covering
        try block wins; later try blocks are not consulted even if they also
        cover the throw site. We follow that ordering.
        """
        tries = self._get_tries(code_off)
        for tr in tries:
            if not tr.start_addr <= throw_pc < tr.end_addr:
                continue
            for h in tr.handlers:
                if h.class_desc is None:
                    return h
                if self._hierarchy.is_subtype(exc_class, h.class_desc):
                    return h
            # First covering try block wins — even if no entry matched,
            # don't fall through to a later try block. This is the standard
            # Dalvik handler-lookup rule.
            return None
        return None
