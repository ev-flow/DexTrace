# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from __future__ import annotations


class UnknownDalvikFormat(ValueError):
    pass


def infer_format_size_units(fmt: str) -> int:
    """
    Infer instruction size in 16-bit code units from format string.

    Dalvik format naming convention: first digit is usually the size in code units.
    Examples: 10x->1, 22c->2, 35c->3, 45cc->4, 51l->5.
    """
    if not fmt or len(fmt) < 3:
        raise UnknownDalvikFormat(f"Invalid format: {fmt!r}")
    
    # 00x = reserved/unused opcode placeholder in some bytecode tables
    if fmt == "00x":
        return 1

    first = fmt[0]
    if first.isdigit():
        n = int(first)
        if 1 <= n <= 5:
            return n

    raise UnknownDalvikFormat(f"Unknown format: {fmt!r}")
