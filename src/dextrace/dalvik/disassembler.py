# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from __future__ import annotations

import struct
from dataclasses import dataclass, replace
from typing import List, Optional, Dict

from dextrace.core.dex_parser import DexParser, DexCode
from dextrace.core.dex_resolver import DexResolver

from dextrace.dalvik.bytecode_source import load_bytecode_lines
from dextrace.dalvik.opcode_table_builder import build_opcode_info_table
from dextrace.dalvik.payload import payload_size_units
from dextrace.dalvik.size_resolver import resolve_size_units
from dextrace.dalvik.types import WalkItem, DecodedInsn
from dextrace.dalvik.operand_decoder import decode_by_format


@dataclass
class MethodDisasm:
    registers_size: int
    ins_size: int
    outs_size: int
    tries_size: int
    insns_size: int
    instructions: List[DecodedInsn]


def _normalize_index_type(t: str | None) -> str | None:
    if t is None:
        return None
    s = str(t).strip()
    if not s:
        return None
    if s.lower() == "none":
        return None
    return s


def _render_smali_line(mnemonic: str, regs: List[str], param: Optional[str]) -> str:
    """
    Best-effort one-line smali renderer for evidence.

    Examples:
      - invoke-direct {v0}, Ljava/lang/Object;-><init>()V
      - const-string v1, "HELLO"
      - return-void
    """
    regs = list(regs or [])
    p = "" if param is None else str(param)

    # invoke-kind typically prints registers inside {}
    if mnemonic.startswith("invoke-") or mnemonic in ("filled-new-array", "filled-new-array/range"):
        if "/range" in mnemonic and regs:
            reg_part = f"{{{regs[0]} .. {regs[-1]}}}"
        else:
            reg_part = "{" + ",".join(regs) + "}" if regs else "{}"
        if p:
            return f"{mnemonic} {reg_part}, {p}"
        return f"{mnemonic} {reg_part}"

    # non-invoke
    if regs:
        reg_part = ", ".join(regs)
        if p:
            return f"{mnemonic} {reg_part}, {p}"
        return f"{mnemonic} {reg_part}"

    # no regs
    if p:
        return f"{mnemonic} {p}"
    return f"{mnemonic}"


def _format_ctx_line(ins: DecodedInsn) -> str:
    sm = ins.smali or _render_smali_line(ins.mnemonic, ins.regs, ins.param)
    return f"{ins.uoff:04x}: {sm}"


class DalvikDisassembler:
    def __init__(self, dex_bytes: bytes, resolver: DexResolver, accept_optimized: bool = False):
        self.dex_bytes = dex_bytes
        self.parser = DexParser(dex_bytes)
        self.resolver = resolver
        self.accept_optimized = accept_optimized

        info = build_opcode_info_table(load_bytecode_lines())

        self.opcode_to_format = {op: oi.fmt for op, oi in info.items()}
        self.opcode_to_mnemonic = {op: oi.name for op, oi in info.items()}
        self.opcode_to_flags = {op: oi.flags for op, oi in info.items()}
        self.opcode_to_index_type = {op: oi.index_type for op, oi in info.items()}

        if not accept_optimized:
            for op, oi in list(info.items()):
                if oi.optimized:
                    self.opcode_to_format.pop(op, None)
                    self.opcode_to_mnemonic.pop(op, None)
                    self.opcode_to_flags.pop(op, None)
                    self.opcode_to_index_type.pop(op, None)

    def disassemble_method(self, code_off: int, max_insns: Optional[int] = None) -> MethodDisasm:
        code = self.parser.parse_code_item(code_off)

        walker = DalvikWalker(code)
        walked = walker.walk(
            opcode_to_format=self.opcode_to_format,
            opcode_to_mnemonic=self.opcode_to_mnemonic,
            opcode_to_flags=self.opcode_to_flags,
        )

        decoded = decode_items(
            code=code,
            walked=walked,
            opcode_to_index_type=self.opcode_to_index_type,
        )

        if max_insns and max_insns > 0:
            decoded = decoded[: max_insns]

        # Resolve indices + render smali
        resolved = [self._resolve_insn(ins) for ins in decoded]

        # Attach context (prev 1 + next 1) over INSNS ONLY
        resolved = self._attach_context_prev_next_1(resolved)

        return MethodDisasm(
            registers_size=code.registers_size,
            ins_size=code.ins_size,
            outs_size=code.outs_size,
            tries_size=code.tries_size,
            insns_size=code.insns_size,
            instructions=resolved,
        )

    def _resolve_insn(self, ins: DecodedInsn) -> DecodedInsn:
        index_type = _normalize_index_type(ins.index_type)

        # no index or no index_type => just ensure smali is present
        if ins.index is None or not index_type:
            smali = ins.smali or _render_smali_line(ins.mnemonic, ins.regs, ins.param)
            return replace(ins, index_type=None, smali=smali)

        param = ins.param
        try:
            if index_type == "method-ref":
                param = self.resolver.get_method_sig(ins.index)
            elif index_type == "string-ref":
                s = self.resolver.get_string(ins.index)
                param = f"\"{s}\""
            elif index_type == "type-ref":
                param = self.resolver.get_type(ins.index)
            elif index_type == "field-ref":
                param = self.resolver.get_field_sig(ins.index)
            elif index_type == "proto-ref":
                param = self.resolver.get_proto(ins.index)
        except Exception:
            param = ins.param

        smali = _render_smali_line(ins.mnemonic, ins.regs, param)
        return replace(ins, index_type=index_type, param=param, smali=smali)

    def _attach_context_prev_next_1(self, insns: List[DecodedInsn]) -> List[DecodedInsn]:
        if not insns:
            return insns

        ctx_lines = [_format_ctx_line(x) for x in insns]
        out: List[DecodedInsn] = []
        n = len(insns)

        for i, ins in enumerate(insns):
            ctx: List[str] = []
            if i - 1 >= 0:
                ctx.append(ctx_lines[i - 1])
            if i + 1 < n:
                ctx.append(ctx_lines[i + 1])
            out.append(replace(ins, ctx_smali=ctx))

        return out


class DalvikWalker:
    def __init__(self, code: DexCode):
        self.code = code
        self.units_total = int(code.insns_size)

    def _read_u16(self, uoff: int) -> int:
        byte_off = uoff * 2
        return struct.unpack_from("<H", self.code.insns, byte_off)[0]

    def _read_u32(self, uoff: int) -> int:
        byte_off = uoff * 2
        return struct.unpack_from("<I", self.code.insns, byte_off)[0]

    def _slice_hex_units(self, uoff: int, size_units: int) -> str:
        byte_off = uoff * 2
        byte_len = max(0, size_units) * 2
        end = min(len(self.code.insns), byte_off + byte_len)
        return self.code.insns[byte_off:end].hex(" ")

    def walk(
        self,
        opcode_to_format: Dict[int, str],
        opcode_to_mnemonic: Dict[int, str] | None = None,
        opcode_to_flags: Dict[int, frozenset[str]] | None = None,
    ) -> List[WalkItem]:
        out: List[WalkItem] = []
        uoff = 0

        while uoff < self.units_total:
            pinfo = payload_size_units(
                start_uoff=uoff,
                read_u16=self._read_u16,
                read_u32=self._read_u32,
                total_units=self.units_total,
            )
            if pinfo is not None:
                raw_hex = self._slice_hex_units(uoff, pinfo.size_units)
                out.append(
                    WalkItem(
                        uoff=uoff,
                        opcode=-1,
                        u16=self._read_u16(uoff),
                        mnemonic=f"<{pinfo.kind}>",
                        fmt=None,
                        size_units=int(pinfo.size_units),
                        flags=frozenset(),
                        kind="payload",
                        note=f"units={pinfo.size_units}",
                        raw_hex=raw_hex,
                    )
                )
                uoff += int(pinfo.size_units)
                continue

            u16 = self._read_u16(uoff)
            opcode = u16 & 0xFF
            fmt = opcode_to_format.get(opcode)

            if fmt is None:
                out.append(
                    WalkItem(
                        uoff=uoff,
                        opcode=opcode,
                        u16=u16,
                        mnemonic=(opcode_to_mnemonic.get(opcode) if opcode_to_mnemonic else f"op_{opcode:02x}"),
                        fmt=None,
                        size_units=1,
                        flags=(opcode_to_flags.get(opcode, frozenset()) if opcode_to_flags else frozenset()),
                        kind="unknown",
                        note="unknown-format",
                        raw_hex=self._slice_hex_units(uoff, 1),
                    )
                )
                uoff += 1
                continue

            res = resolve_size_units(fmt)
            size_units = int(res.size_units) if int(res.size_units) > 0 else 1

            mnemonic = opcode_to_mnemonic.get(opcode) if opcode_to_mnemonic else f"op_{opcode:02x}"
            flags = opcode_to_flags.get(opcode, frozenset()) if opcode_to_flags else frozenset()
            raw_hex = self._slice_hex_units(uoff, size_units)
            note = "" if res.source == "infer" else f"size via {res.source}"

            out.append(
                WalkItem(
                    uoff=uoff,
                    opcode=opcode,
                    u16=u16,
                    mnemonic=mnemonic,
                    fmt=fmt,
                    size_units=size_units,
                    flags=flags,
                    kind="insn",
                    note=note,
                    raw_hex=raw_hex,
                )
            )
            uoff += size_units

        return out


def decode_items(
    code: DexCode,
    walked: List[WalkItem],
    opcode_to_index_type: Dict[int, str] | None = None,
) -> List[DecodedInsn]:
    walker = DalvikWalker(code)

    out: List[DecodedInsn] = []
    for wi in walked:
        if wi.kind != "insn" or not wi.fmt:
            continue

        ops = decode_by_format(wi.fmt, wi.uoff, walker._read_u16)
        if ops is None:
            index_type = _normalize_index_type(opcode_to_index_type.get(wi.opcode) if opcode_to_index_type else None)
            out.append(
                DecodedInsn(
                    uoff=wi.uoff,
                    byte_off=wi.uoff * 2,
                    opcode=wi.opcode,
                    mnemonic=wi.mnemonic,
                    fmt=wi.fmt,
                    size_units=wi.size_units,
                    regs=[],
                    param=None,
                    index=None,
                    index_type=index_type,
                    flags=wi.flags,
                    raw_hex=wi.raw_hex,
                    smali=_render_smali_line(wi.mnemonic, [], None),
                    note=(wi.note + " decode-unsupported").strip(),
                    target_uoff=None,
                )
            )
            continue

        index_type = _normalize_index_type(opcode_to_index_type.get(wi.opcode) if opcode_to_index_type else None)

        target_uoff: Optional[int] = None
        param: str | None = None

        if ops.target_uoff is not None:
            target_uoff = int(ops.target_uoff)
            param = f":L{target_uoff:04x}"
        elif ops.literal is not None:
            param = str(int(ops.literal))
        elif ops.index is not None:
            t = index_type or "index"
            param = f"<{t}:{int(ops.index)}>"
        else:
            param = None

        regs = list(ops.regs)
        smali = _render_smali_line(wi.mnemonic, regs, param)

        out.append(
            DecodedInsn(
                uoff=wi.uoff,
                byte_off=wi.uoff * 2,
                opcode=wi.opcode,
                mnemonic=wi.mnemonic,
                fmt=wi.fmt,
                size_units=wi.size_units,
                regs=regs,
                param=param,
                index=(int(ops.index) if ops.index is not None else None),
                index_type=index_type,
                flags=wi.flags,
                raw_hex=wi.raw_hex,
                smali=smali,
                note=wi.note,
                target_uoff=target_uoff,
            )
        )

    return out
