# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from .dex_header import DexHeader


class DexFormatError(ValueError):
    """Raised when DEX format is invalid or truncated."""


@dataclass(frozen=True)
class ApiCall:
    caller_class: str
    caller_method: str
    caller_proto: str
    invoke: str
    invoke_offset: int
    callee_class: str
    callee_method: str
    callee_proto: str
    registers: List[str]

    def to_dict(self) -> dict:
        return {
            "caller": {
                "class": self.caller_class,
                "method": self.caller_method,
                "proto": self.caller_proto,
            },
            "invoke": {
                "opcode": self.invoke,
                "offset": self.invoke_offset,
                "registers": self.registers,
            },
            "callee": {
                "class": self.callee_class,
                "method": self.callee_method,
                "proto": self.callee_proto,
            },
        }


@dataclass
class MethodApiTrace:
    """
    Stage 3 + 4 carrier structure.
    """
    method: str
    api_set: List[str]
    api_sequence: List[dict]


# invoke-kind opcodes (common)
INVOKE_OPCODES: Dict[int, str] = {
    0x6E: "invoke-virtual",
    0x6F: "invoke-super",
    0x70: "invoke-direct",
    0x71: "invoke-static",
    0x72: "invoke-interface",
    0x74: "invoke-virtual/range",
    0x75: "invoke-super/range",
    0x76: "invoke-direct/range",
    0x77: "invoke-static/range",
    0x78: "invoke-interface/range",
}


class DexApiExtractor:
    """
    Extract API calls by scanning code_item instructions and resolving method_id items.
    """

    def __init__(self, dex_data: bytes) -> None:
        self._data = dex_data
        self._size = len(dex_data)
        self._header = DexHeader.from_bytes(dex_data)

        # simple caches to reduce repeated table lookups
        self._string_cache: Dict[int, Optional[str]] = {}
        self._type_cache: Dict[int, Optional[str]] = {}
        self._proto_cache: Dict[int, Optional[str]] = {}
        self._method_cache: Dict[int, Optional[Tuple[str, str, str]]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def extract_api_calls(self, limit: Optional[int] = None) -> List[ApiCall]:
        calls: List[ApiCall] = []

        for method_idx, code_off in self._iter_all_methods_code_off():
            caller = self._get_method(method_idx)
            if not caller:
                continue
            caller_cls, caller_name, caller_proto = caller

            for inv_name, insn_off, callee_idx, regs in self._iter_invokes(code_off):
                callee = self._get_method(callee_idx)
                if not callee:
                    continue
                callee_cls, callee_name, callee_proto = callee

                calls.append(
                    ApiCall(
                        caller_class=caller_cls,
                        caller_method=caller_name,
                        caller_proto=caller_proto,
                        invoke=inv_name,
                        invoke_offset=insn_off,
                        callee_class=callee_cls,
                        callee_method=callee_name,
                        callee_proto=callee_proto,
                        registers=regs,
                    )
                )

                if limit and len(calls) >= limit:
                    return calls

        return calls

    # ------------------------------------------------------------------
    # Stage 3 – API sets per method
    # ------------------------------------------------------------------
    def extract_api_sets(self) -> Dict[str, List[str]]:
        result: Dict[str, set] = {}

        for method_idx, code_off in self._iter_all_methods_code_off():
            caller = self._get_method(method_idx)
            if not caller:
                continue

            method_sig = self._format_method_sig(*caller)
            result.setdefault(method_sig, set())

            for _, _, callee_idx, _ in self._iter_invokes(code_off):
                callee = self._get_method(callee_idx)
                if not callee:
                    continue
                result[method_sig].add(self._format_method_sig(*callee))

        return {k: sorted(v) for k, v in result.items()}

    # ------------------------------------------------------------------
    # Stage 4 – API call sequences per method
    # ------------------------------------------------------------------
    def extract_api_sequences(self) -> Dict[str, List[dict]]:
        result: Dict[str, List[dict]] = {}

        for method_idx, code_off in self._iter_all_methods_code_off():
            caller = self._get_method(method_idx)
            if not caller:
                continue

            method_sig = self._format_method_sig(*caller)
            result.setdefault(method_sig, [])

            for invoke, offset, callee_idx, _ in self._iter_invokes(code_off):
                callee = self._get_method(callee_idx)
                if not callee:
                    continue

                result[method_sig].append(
                    {
                        "offset": offset,
                        "invoke": invoke,
                        "callee": self._format_method_sig(*callee),
                    }
                )

        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _format_method_sig(cls: str, name: str, proto: str) -> str:
        return f"{cls}->{name}{proto}"

    # ------------------------------------------------------------------
    # Class/method iteration (class_data_item)
    # ------------------------------------------------------------------
    def _iter_all_methods_code_off(self) -> Iterable[Tuple[int, int]]:
        """
        Iterate all (method_idx, code_off) in all class_data_item.
        """
        base = self._header.class_defs_off
        count = self._header.class_defs_size

        # class_def_item is 32 bytes
        for i in range(count):
            off = base + i * 32
            if off < 0 or off + 32 > self._size:
                break

            class_data_off = self._u32(off + 24)
            if not class_data_off:
                continue

            yield from self._iter_class_data_methods(class_data_off)

    def _iter_class_data_methods(self, off: int) -> Iterable[Tuple[int, int]]:
        """
        Parse class_data_item and yield (method_idx, code_off) for direct+virtual methods.
        """
        p = off
        if p <= 0 or p >= self._size:
            return

        static_fields_size, p = self._read_uleb128_safe(p)
        instance_fields_size, p = self._read_uleb128_safe(p)
        direct_methods_size, p = self._read_uleb128_safe(p)
        virtual_methods_size, p = self._read_uleb128_safe(p)
        if p is None:
            return

        # skip encoded_field for static+instance
        for _ in range((static_fields_size or 0) + (instance_fields_size or 0)):
            _, p = self._read_uleb128_safe(p)  # field_idx_diff
            if p is None:
                return
            _, p = self._read_uleb128_safe(p)  # access_flags
            if p is None:
                return

        def _iter_methods(n: int) -> Iterable[Tuple[int, int]]:
            nonlocal p
            method_idx = 0  # IMPORTANT: reset per list (direct / virtual)
            for _ in range(int(n or 0)):
                diff, p2 = self._read_uleb128_safe(p)
                if p2 is None:
                    return
                p = p2
                method_idx += int(diff or 0)

                _, p2 = self._read_uleb128_safe(p)  # access_flags
                if p2 is None:
                    return
                p = p2

                code_off, p2 = self._read_uleb128_safe(p)
                if p2 is None:
                    return
                p = p2

                if code_off:
                    yield method_idx, int(code_off)

        # direct list
        yield from _iter_methods(direct_methods_size or 0)
        # virtual list (reset happens inside _iter_methods)
        yield from _iter_methods(virtual_methods_size or 0)

    @staticmethod
    def _payload_width_units(insns: bytes, uoff: int, total_units: int) -> int:
        """
        Handle opcode==0x00 payloads:
        packed-switch-payload (0x0100), sparse-switch-payload (0x0200),
        fill-array-data-payload (0x0300)
        Return payload size in 16-bit code units.
        """
        byte_off = uoff * 2
        if byte_off + 2 > len(insns):
            return 1

        ident = struct.unpack_from("<H", insns, byte_off)[0]

        # packed-switch-payload
        if ident == 0x0100:
            # u2 ident, u2 size, u4 first_key, u4 targets[size]
            if byte_off + 4 > len(insns):
                return 1
            size = struct.unpack_from("<H", insns, byte_off + 2)[0]
            units = 4 + (size * 2)  # 2(header) + 2(first_key) + 2*size(targets)
            return max(1, min(units, total_units - uoff))

        # sparse-switch-payload
        if ident == 0x0200:
            # u2 ident, u2 size, u4 keys[size], u4 targets[size]
            if byte_off + 4 > len(insns):
                return 1
            size = struct.unpack_from("<H", insns, byte_off + 2)[0]
            units = 2 + (size * 4)  # 2(header) + 2*size(keys) + 2*size(targets)
            return max(1, min(units, total_units - uoff))

        # fill-array-data-payload
        if ident == 0x0300:
            # u2 ident, u2 element_width, u4 size, u1 data[size*element_width], padding
            if byte_off + 8 > len(insns):
                return 1
            element_width = struct.unpack_from("<H", insns, byte_off + 2)[0]
            size = struct.unpack_from("<I", insns, byte_off + 4)[0]
            data_bytes = int(size) * int(element_width)
            data_units = (data_bytes + 1) // 2  # round up to 16-bit units
            units = 4 + data_units  # 4 units header + data
            return max(1, min(units, total_units - uoff))

        return 1

    @staticmethod
    def _insn_width_units(opcode: int, insns: bytes, uoff: int, total_units: int) -> int:
        """
        Return instruction width in 16-bit code units (not bytes).
        This is a pragmatic table covering common Dalvik opcodes.
        Unknown opcodes default to 1 to avoid infinite loops.
        """
        # payloads are encoded as opcode 0x00 (nop) with ident in high byte
        if opcode == 0x00:
            return DexApiExtractor._payload_width_units(insns, uoff, total_units)

        # 5 units
        if opcode == 0x18:  # const-wide (51l)
            return 5

        # 4 units (rare but valid: invoke-polymorphic/custom)
        if opcode in (0xFA, 0xFB, 0xFC, 0xFD):  # 45cc / 4rcc
            return 4

        # 3 units
        if opcode in (
            0x03, 0x06, 0x09,        # move/16, move-wide/16, move-object/16 (32x)
            0x14, 0x17,              # const (31i), const-wide/32 (31i)
            0x1B,                    # const-string/jumbo (31c)
            0x26,                    # fill-array-data (31t)
            0x2A,                    # goto/32 (30t)
            0x2B, 0x2C,              # packed-switch, sparse-switch (31t)
        ):
            return 3

        # invokes are always 3 units in classic formats
        if opcode in (0x6E, 0x6F, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78):
            return 3

        # 2 units (a lot of opcodes)
        if opcode in (
            0x01,                    # move (12x) actually 1, keep out
        ):
            return 1

        width2 = set()

        # move/from16, move-wide/from16, move-object/from16 (22x)
        width2.update([0x02, 0x05, 0x08])

        # move-result*, return*, throw (11x) are 1; don't add

        # const/4 is 1; const/16, const-wide/16, const/high16 etc are 2
        width2.update([0x13, 0x15, 0x16, 0x19, 0x1C, 0x1D])

        # const-string, const-class, check-cast, instance-of, new-instance (21c / 22c)
        width2.update([0x1A, 0x1C, 0x1F, 0x20, 0x22])

        # new-array, filled-new-array (22c/35c) -> new-array is 2, filled-new-array is 3 (0x24 handled by default 1; you can add if needed)
        width2.update([0x23])

        # iget/iput (22c)
        width2.update(list(range(0x52, 0x60)))

        # sget/sput (21c)
        width2.update(list(range(0x60, 0x6E)))

        # invoke-xxx are 3 already

        # if-* (22t / 21t)
        width2.update(list(range(0x32, 0x3E)))

        # goto/16 (20t)
        width2.update([0x29])

        # aget/aput (23x)
        width2.update(list(range(0x44, 0x52)))

        # arithmetic 23x / 12x mix; include common 23x comparisons
        width2.update(list(range(0x2D, 0x32)))  # cmpl/cmpg/cmp-long etc are 2

        # add-int/lit16 etc (22s) and lit8 (22b)
        width2.update(list(range(0xD0, 0xE3)))  # lit16/lit8 family are 2

        if opcode in width2:
            return 2

        # default
        return 1

    # ------------------------------------------------------------------
    # code_item + invoke scan + register extraction
    # ------------------------------------------------------------------
    def _iter_invokes(self, code_off: int) -> Iterable[Tuple[str, int, int, List[str]]]:
        """
        Yield (invoke_name, insn_byte_offset_from_code_insns, callee_method_idx, regs)
        """
        if code_off <= 0 or code_off + 16 > self._size:
            return

        insns_size = self._u32(code_off + 12)
        if insns_size is None:
            return

        insns_off = code_off + 16
        insns_bytes = int(insns_size) * 2
        if insns_off + insns_bytes > self._size:
            return

        insns = self._data[insns_off : insns_off + insns_bytes]

        uoff = 0
        total_units = int(insns_size)

        while uoff < total_units:
            byte_off = uoff * 2
            if byte_off + 2 > len(insns):
                return

            opcode = insns[byte_off]
            width = self._insn_width_units(opcode, insns, uoff, total_units)
            if width <= 0:
                width = 1

            if opcode not in INVOKE_OPCODES:
                uoff += width
                continue

            name = INVOKE_OPCODES[opcode]

            # -------------------------
            # invoke-xxx (35c) : 3 units
            # -------------------------
            if opcode <= 0x72:
                if uoff + 2 >= total_units:
                    return

                first = struct.unpack_from("<H", insns, byte_off)[0]
                A = (first >> 12) & 0xF  # reg_count
                G = (first >> 8) & 0xF   # 5th register (only if A==5)

                method_idx = struct.unpack_from("<H", insns, (uoff + 1) * 2)[0]
                regs_word = struct.unpack_from("<H", insns, (uoff + 2) * 2)[0]

                C = (regs_word >> 0) & 0xF
                D = (regs_word >> 4) & 0xF
                E = (regs_word >> 8) & 0xF
                F = (regs_word >> 12) & 0xF
                regs_all = [C, D, E, F, G]
                regs = [f"v{r}" for r in regs_all[:A]]

                # alignment guard: invalid method_idx => likely misaligned; skip as noise
                if method_idx < self._header.method_ids_size:
                    yield name, byte_off, method_idx, regs

                uoff += 3
                continue

            # -------------------------
            # invoke-xxx/range (3rc) : 3 units
            # -------------------------
            if uoff + 2 >= total_units:
                return

            reg_count = insns[byte_off + 1]
            method_idx = struct.unpack_from("<H", insns, (uoff + 1) * 2)[0]
            start_reg = struct.unpack_from("<H", insns, (uoff + 2) * 2)[0]
            regs = [f"v{start_reg + i}" for i in range(reg_count)]

            if method_idx < self._header.method_ids_size:
                yield name, byte_off, method_idx, regs

            uoff += 3

    # ------------------------------------------------------------------
    # Safe resolvers
    # ------------------------------------------------------------------
    def _get_method(self, method_idx: int) -> Optional[Tuple[str, str, str]]:
        if method_idx in self._method_cache:
            return self._method_cache[method_idx]

        if method_idx < 0 or method_idx >= self._header.method_ids_size:
            self._method_cache[method_idx] = None
            return None

        off = self._header.method_ids_off + method_idx * 8
        if off < 0 or off + 8 > self._size:
            self._method_cache[method_idx] = None
            return None

        try:
            class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", self._data, off)
        except struct.error:
            self._method_cache[method_idx] = None
            return None

        cls = self._get_type(class_idx)
        name = self._get_string(name_idx)
        proto = self._get_proto(proto_idx)

        if not cls or not name or not proto:
            self._method_cache[method_idx] = None
            return None

        self._method_cache[method_idx] = (cls, name, proto)
        return self._method_cache[method_idx]

    def _get_string(self, string_idx: int) -> Optional[str]:
        if string_idx in self._string_cache:
            return self._string_cache[string_idx]

        if string_idx < 0 or string_idx >= self._header.string_ids_size:
            self._string_cache[string_idx] = None
            return None

        off = self._header.string_ids_off + string_idx * 4
        if off < 0 or off + 4 > self._size:
            self._string_cache[string_idx] = None
            return None

        try:
            str_off = struct.unpack_from("<I", self._data, off)[0]
        except struct.error:
            self._string_cache[string_idx] = None
            return None

        if str_off <= 0 or str_off >= self._size:
            self._string_cache[string_idx] = None
            return None

        # string_data_item:
        # uleb128 utf16_size
        # u1 data[] (MUTF-8), terminated by 0x00
        utf16_size, p = self._read_uleb128_safe(str_off)
        if p is None:
            self._string_cache[string_idx] = None
            return None

        start = p
        if start >= self._size:
            self._string_cache[string_idx] = None
            return None

        # Scan until 0x00 terminator (bounded)
        end = start
        limit = min(self._size, start + 1024 * 1024)  # hard safety cap
        while end < limit and self._data[end] != 0:
            end += 1

        if end >= self._size:
            self._string_cache[string_idx] = None
            return None

        raw = self._data[start:end]
        try:
            s = raw.decode("utf-8", errors="ignore")
        except Exception:
            s = None

        self._string_cache[string_idx] = s
        return s

    def _get_type(self, type_idx: int) -> Optional[str]:
        if type_idx in self._type_cache:
            return self._type_cache[type_idx]

        if type_idx < 0 or type_idx >= self._header.type_ids_size:
            self._type_cache[type_idx] = None
            return None

        off = self._header.type_ids_off + type_idx * 4
        if off < 0 or off + 4 > self._size:
            self._type_cache[type_idx] = None
            return None

        str_idx = self._u32(off)
        if str_idx is None:
            self._type_cache[type_idx] = None
            return None

        self._type_cache[type_idx] = self._get_string(int(str_idx))
        return self._type_cache[type_idx]

    def _get_proto(self, proto_idx: int) -> Optional[str]:
        if proto_idx in self._proto_cache:
            return self._proto_cache[proto_idx]

        if proto_idx < 0 or proto_idx >= self._header.proto_ids_size:
            self._proto_cache[proto_idx] = None
            return None

        off = self._header.proto_ids_off + proto_idx * 12
        if off < 0 or off + 12 > self._size:
            self._proto_cache[proto_idx] = None
            return None

        # proto_id_item:
        # u4 shorty_idx, u4 return_type_idx, u4 parameters_off
        shorty_idx = self._u32(off)
        return_type_idx = self._u32(off + 4)
        params_off = self._u32(off + 8)

        if shorty_idx is None or return_type_idx is None or params_off is None:
            self._proto_cache[proto_idx] = None
            return None

        # Prefer human-ish proto: (params)return
        ret = self._get_type(int(return_type_idx)) or "?"
        params = self._get_type_list(int(params_off))
        proto = f"({''.join(params)}){ret}" if params is not None else (self._get_string(int(shorty_idx)) or "?")

        self._proto_cache[proto_idx] = proto
        return proto

    def _get_type_list(self, type_list_off: int) -> Optional[List[str]]:
        if type_list_off == 0:
            return []

        if type_list_off < 0 or type_list_off + 4 > self._size:
            return None

        size = self._u32(type_list_off)
        if size is None:
            return None

        p = type_list_off + 4
        out: List[str] = []
        for _ in range(int(size)):
            if p + 2 > self._size:
                return None
            t = struct.unpack_from("<H", self._data, p)[0]
            p += 2
            out.append(self._get_type(int(t)) or "?")

        return out

    # ------------------------------------------------------------------
    # Small safe readers
    # ------------------------------------------------------------------
    def _u32(self, off: int) -> Optional[int]:
        if off < 0 or off + 4 > self._size:
            return None
        try:
            return struct.unpack_from("<I", self._data, off)[0]
        except struct.error:
            return None

    def _read_uleb128_safe(self, off: int) -> Tuple[Optional[int], Optional[int]]:
        """
        Return (value, next_offset). If invalid/truncated, returns (None, None).
        """
        if off < 0 or off >= self._size:
            return None, None

        value = 0
        shift = 0
        p = off

        for _ in range(5):  # uleb128 max 5 bytes for 32-bit
            if p >= self._size:
                return None, None
            b = self._data[p]
            p += 1
            value |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                return value, p
            shift += 7

        return None, None
