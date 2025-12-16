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
            },
            "callee": {
                "class": self.callee_class,
                "method": self.callee_method,
                "proto": self.callee_proto,
            },
        }


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

    Notes:
    - This is a "best-effort" extractor: invalid indexes won't crash; they are skipped.
    - It does not require full semantic decoding; only invoke opcodes are recognized.
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

            for inv_name, insn_off, callee_idx in self._iter_invokes(code_off):
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
                    )
                )

                if limit is not None and len(calls) >= limit:
                    return calls

        return calls

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
            _, p = self._read_uleb128_safe(p)
            if p is None:
                return
            _, p = self._read_uleb128_safe(p)
            if p is None:
                return

        # encoded_method: method_idx_diff, access_flags, code_off
        method_idx = 0
        for _ in range((direct_methods_size or 0) + (virtual_methods_size or 0)):
            diff, p = self._read_uleb128_safe(p)
            if p is None:
                return
            method_idx += int(diff or 0)

            _, p = self._read_uleb128_safe(p)  # access_flags
            if p is None:
                return

            code_off, p = self._read_uleb128_safe(p)
            if p is None:
                return

            if code_off:
                yield method_idx, int(code_off)

    # ------------------------------------------------------------------
    # code_item + invoke scan
    # ------------------------------------------------------------------
    def _iter_invokes(self, code_off: int) -> Iterable[Tuple[str, int, int]]:
        """
        Yield (invoke_name, insn_byte_offset_from_code_insns, callee_method_idx)
        """
        if code_off <= 0 or code_off + 16 > self._size:
            return

        # code_item:
        # u2 registers_size, u2 ins_size, u2 outs_size, u2 tries_size,
        # u4 debug_info_off, u4 insns_size, u2 insns[insns_size]
        insns_size = self._u32(code_off + 12)
        if insns_size is None:
            return

        insns_off = code_off + 16
        insns_bytes = int(insns_size) * 2
        if insns_off + insns_bytes > self._size:
            return

        insns = self._data[insns_off : insns_off + insns_bytes]

        # iterate in 16-bit code units; decode only invoke formats
        uoff = 0
        total_units = int(insns_size)
        while uoff < total_units:
            byte_off = uoff * 2
            if byte_off + 2 > len(insns):
                return

            opcode = insns[byte_off]
            if opcode not in INVOKE_OPCODES:
                uoff += 1
                continue

            # invoke-xxx (35c) and invoke-xxx/range (3rc) are 3 code units
            if uoff + 2 >= total_units:
                return

            # method_idx is always the 2nd code unit for invoke-* (BBBB)
            method_idx = struct.unpack_from("<H", insns, (uoff + 1) * 2)[0]
            yield INVOKE_OPCODES[opcode], byte_off, int(method_idx)

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
