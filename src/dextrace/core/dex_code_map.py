# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from __future__ import annotations

from collections import OrderedDict
from typing import Dict, Iterable, Optional, Tuple

from dextrace.core.dex_header import DexHeader


class DexFormatError(ValueError):
    """Raised when DEX format is invalid or truncated."""


# Module-level LRU cache keyed by dex_bytes[8:32] — the DEX Adler-32 checksum (4 bytes
# at offset 8) plus SHA-1 signature (20 bytes at offset 12). This 24-byte slice
# uniquely identifies a DEX file regardless of object identity, so the key is safe
# across APK boundaries and not vulnerable to id() reuse after GC.
_MAX_CACHE_ENTRIES = 256
_sig_to_codeoff_cache: OrderedDict[bytes, Dict[str, int]] = OrderedDict()


def build_sig_to_codeoff_map(dex_bytes: bytes, resolver) -> Dict[str, int]:
    """
    Build map: method_signature -> code_off
    - method_signature example: Lx/y/Z;->m(II)Ljava/lang/String;
    - resolver must provide: get_method_sig(method_idx) -> str
    """
    key = dex_bytes[8:32] if len(dex_bytes) >= 32 else dex_bytes
    cached = _sig_to_codeoff_cache.get(key)
    if cached is not None:
        _sig_to_codeoff_cache.move_to_end(key)
        return cached

    header = DexHeader.from_bytes(dex_bytes)
    size = len(dex_bytes)

    out: Dict[str, int] = {}

    for method_idx, code_off in _iter_all_methods_code_off(dex_bytes, header, size):
        if not code_off:
            continue
        try:
            sig = resolver.get_method_sig(int(method_idx))
        except Exception:
            # If resolver fails, skip (or you can store by idx)
            continue
        if sig:
            out[sig] = int(code_off)

    if len(_sig_to_codeoff_cache) >= _MAX_CACHE_ENTRIES:
        _sig_to_codeoff_cache.popitem(last=False)
    _sig_to_codeoff_cache[key] = out
    return out


# ----------------------------------------------------------------------
# class_defs -> class_data -> encoded_method iteration
# ----------------------------------------------------------------------
def _iter_all_methods_code_off(
    data: bytes, header: DexHeader, size: int
) -> Iterable[Tuple[int, int]]:
    base = int(header.class_defs_off)
    count = int(header.class_defs_size)

    # class_def_item is 32 bytes
    for i in range(count):
        off = base + i * 32
        if off < 0 or off + 32 > size:
            break

        class_data_off = _u32(data, size, off + 24)
        if not class_data_off:
            continue

        yield from _iter_class_data_methods(data, size, int(class_data_off))


def _iter_class_data_methods(
    data: bytes, size: int, off: int
) -> Iterable[Tuple[int, int]]:
    """
    Parse class_data_item and yield (method_idx, code_off) for direct+virtual methods.

    class_data_item:
      uleb128 static_fields_size
      uleb128 instance_fields_size
      uleb128 direct_methods_size
      uleb128 virtual_methods_size
      encoded_field[static_fields_size]
      encoded_field[instance_fields_size]
      encoded_method[direct_methods_size]
      encoded_method[virtual_methods_size]
    """
    p = off
    if p <= 0 or p >= size:
        return

    static_fields_size, p = _read_uleb128_safe(data, size, p)
    instance_fields_size, p = _read_uleb128_safe(data, size, p)
    direct_methods_size, p = _read_uleb128_safe(data, size, p)
    virtual_methods_size, p = _read_uleb128_safe(data, size, p)
    if p is None:
        return

    # skip encoded_field for static + instance
    for _ in range(int(static_fields_size or 0) + int(instance_fields_size or 0)):
        _, p = _read_uleb128_safe(data, size, p)  # field_idx_diff
        if p is None:
            return
        _, p = _read_uleb128_safe(data, size, p)  # access_flags
        if p is None:
            return

    # ---- direct methods ----
    method_idx_direct = 0
    for _ in range(int(direct_methods_size or 0)):
        diff, p = _read_uleb128_safe(data, size, p)
        if p is None:
            return
        method_idx_direct += int(diff or 0)

        _, p = _read_uleb128_safe(data, size, p)  # access_flags
        if p is None:
            return

        code_off, p = _read_uleb128_safe(data, size, p)
        if p is None:
            return

        yield int(method_idx_direct), int(code_off or 0)

    # ---- virtual methods (RESET method idx accumulator!) ----
    method_idx_virtual = 0
    for _ in range(int(virtual_methods_size or 0)):
        diff, p = _read_uleb128_safe(data, size, p)
        if p is None:
            return
        method_idx_virtual += int(diff or 0)

        _, p = _read_uleb128_safe(data, size, p)  # access_flags
        if p is None:
            return

        code_off, p = _read_uleb128_safe(data, size, p)
        if p is None:
            return

        yield int(method_idx_virtual), int(code_off or 0)

# ----------------------------------------------------------------------
# small safe readers
# ----------------------------------------------------------------------
def _u32(data: bytes, size: int, off: int) -> Optional[int]:
    if off < 0 or off + 4 > size:
        return None
    return int.from_bytes(data[off : off + 4], "little", signed=False)


def _read_uleb128_safe(
    data: bytes, size: int, off: int
) -> Tuple[Optional[int], Optional[int]]:
    """
    Return (value, next_offset). If invalid/truncated, returns (None, None).
    """
    if off < 0 or off >= size:
        return None, None

    value = 0
    shift = 0
    p = off

    for _ in range(5):  # uleb128 max 5 bytes for 32-bit
        if p >= size:
            return None, None
        b = data[p]
        p += 1
        value |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return value, p
        shift += 7

    return None, None
