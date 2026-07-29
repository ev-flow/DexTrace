# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from __future__ import annotations

import struct
from typing import Dict, List, Optional, Tuple

from dextrace.core.dex_header import DexHeader


class DexFormatError(ValueError):
    """Raised when DEX format is invalid or truncated."""


class DexResolver:
    """
    Resolve DEX indices (string/type/proto/method/field) into human-readable signatures.

    This class is intentionally self-contained and "safe":
    - bounds checks everywhere
    - caches to reduce repeated lookups
    """

    def __init__(self, dex_parser_or_bytes):
        # allow DexParser or raw bytes
        if hasattr(dex_parser_or_bytes, "_data"):
            self._data = dex_parser_or_bytes._data  # DexParser internal
        elif isinstance(dex_parser_or_bytes, bytes):
            self._data = dex_parser_or_bytes  # avoid unnecessary copy
        else:
            self._data = bytes(dex_parser_or_bytes)

        self._size = len(self._data)
        self._hdr = DexHeader.from_bytes(self._data)

        self._string_cache: Dict[int, Optional[str]] = {}
        self._type_cache: Dict[int, Optional[str]] = {}
        self._proto_cache: Dict[int, Optional[str]] = {}
        self._method_cache: Dict[int, Optional[Tuple[str, str, str]]] = {}
        self._field_cache: Dict[int, Optional[Tuple[str, str, str]]] = {}

    # ----------------------------
    # Public: primitive resolvers
    # ----------------------------
    def get_string(self, string_idx: int) -> str:
        s = self._get_string(string_idx)
        if s is None:
            raise DexFormatError(f"Invalid string_idx={string_idx}")
        return s

    def get_type(self, type_idx: int) -> str:
        s = self._get_type(type_idx)
        if s is None:
            raise DexFormatError(f"Invalid type_idx={type_idx}")
        return s

    def get_proto(self, proto_idx: int) -> str:
        s = self._get_proto(proto_idx)
        if s is None:
            raise DexFormatError(f"Invalid proto_idx={proto_idx}")
        return s

    # ----------------------------
    # Public: signature helpers
    # ----------------------------
    def get_method_sig(self, method_idx: int) -> str:
        m = self._get_method(method_idx)
        if not m:
            raise DexFormatError(f"Invalid method_idx={method_idx}")
        cls, name, proto = m
        return f"{cls}->{name}{proto}"

    def get_field_sig(self, field_idx: int) -> str:
        f = self._get_field(field_idx)
        if not f:
            raise DexFormatError(f"Invalid field_idx={field_idx}")
        cls, name, ftype = f
        return f"{cls}->{name}:{ftype}"

    # ----------------------------
    # Internal: method/field
    # ----------------------------
    def _get_method(self, method_idx: int) -> Optional[Tuple[str, str, str]]:
        if method_idx in self._method_cache:
            return self._method_cache[method_idx]

        if method_idx < 0 or method_idx >= int(self._hdr.method_ids_size):
            self._method_cache[method_idx] = None
            return None

        off = int(self._hdr.method_ids_off) + int(method_idx) * 8
        if off < 0 or off + 8 > self._size:
            self._method_cache[method_idx] = None
            return None

        try:
            class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", self._data, off)
        except struct.error:
            self._method_cache[method_idx] = None
            return None

        cls = self._get_type(int(class_idx))
        name = self._get_string(int(name_idx))
        proto = self._get_proto(int(proto_idx))

        if not cls or not name or not proto:
            self._method_cache[method_idx] = None
            return None

        self._method_cache[method_idx] = (cls, name, proto)
        return self._method_cache[method_idx]

    def _get_field(self, field_idx: int) -> Optional[Tuple[str, str, str]]:
        if field_idx in self._field_cache:
            return self._field_cache[field_idx]

        if field_idx < 0 or field_idx >= int(self._hdr.field_ids_size):
            self._field_cache[field_idx] = None
            return None

        off = int(self._hdr.field_ids_off) + int(field_idx) * 8
        if off < 0 or off + 8 > self._size:
            self._field_cache[field_idx] = None
            return None

        try:
            class_idx, type_idx, name_idx = struct.unpack_from("<HHI", self._data, off)
        except struct.error:
            self._field_cache[field_idx] = None
            return None

        cls = self._get_type(int(class_idx))
        name = self._get_string(int(name_idx))
        ftype = self._get_type(int(type_idx))

        if not cls or not name or not ftype:
            self._field_cache[field_idx] = None
            return None

        self._field_cache[field_idx] = (cls, name, ftype)
        return self._field_cache[field_idx]

    # ----------------------------
    # Internal: string/type/proto
    # ----------------------------
    def _get_string(self, string_idx: int) -> Optional[str]:
        if string_idx in self._string_cache:
            return self._string_cache[string_idx]

        if string_idx < 0 or string_idx >= int(self._hdr.string_ids_size):
            self._string_cache[string_idx] = None
            return None

        off = int(self._hdr.string_ids_off) + int(string_idx) * 4
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
        _, p = self._read_uleb128_safe(int(str_off))
        if p is None or p >= self._size:
            self._string_cache[string_idx] = None
            return None

        # bounded scan until 0x00
        limit = min(self._size, p + 1024 * 1024)
        try:
            end = self._data.index(b"\x00", p, limit)
        except ValueError:
            end = limit
        if end >= self._size:
            self._string_cache[string_idx] = None
            return None

        raw = self._data[p:end]
        try:
            s = raw.decode("utf-8", errors="ignore")
        except Exception:
            s = None

        self._string_cache[string_idx] = s
        return s

    def _get_type(self, type_idx: int) -> Optional[str]:
        if type_idx in self._type_cache:
            return self._type_cache[type_idx]

        if type_idx < 0 or type_idx >= int(self._hdr.type_ids_size):
            self._type_cache[type_idx] = None
            return None

        off = int(self._hdr.type_ids_off) + int(type_idx) * 4
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

        if proto_idx < 0 or proto_idx >= int(self._hdr.proto_ids_size):
            self._proto_cache[proto_idx] = None
            return None

        off = int(self._hdr.proto_ids_off) + int(proto_idx) * 12
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

        ret = self._get_type(int(return_type_idx)) or "?"
        params = self._get_type_list(int(params_off))

        if params is None:
            # fallback to shorty if type_list parse fails
            shorty = self._get_string(int(shorty_idx)) or "?"
            self._proto_cache[proto_idx] = shorty
            return shorty

        proto = f"({''.join(params)}){ret}"
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

    # ----------------------------
    # Internal: small safe readers
    # ----------------------------
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
