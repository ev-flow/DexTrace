# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from dextrace.dalvik.format_size_infer import infer_format_size_units, UnknownDalvikFormat
from dextrace.dalvik.format_table import FORMAT_SIZE_UNITS as SPEC_FORMAT_SIZE_UNITS


@dataclass
class SizeResolveResult:
    size_units: int
    source: str          # "infer" | "fallback_table" | "fallback_1"
    error: Optional[str] = None


def resolve_size_units(fmt: str) -> SizeResolveResult:
    # 1) prefer infer
    try:
        return SizeResolveResult(infer_format_size_units(fmt), "infer")
    except UnknownDalvikFormat as e:
        pass
    except Exception as e:
        # defensive: inference bug shouldn't break disassembly
        err = f"infer_failed: {e}"
        # try table anyway
        size = SPEC_FORMAT_SIZE_UNITS.get(fmt)
        if size is not None:
            return SizeResolveResult(size, "fallback_table", error=err)
        return SizeResolveResult(1, "fallback_1", error=err)

    # 2) fallback to spec table
    size = SPEC_FORMAT_SIZE_UNITS.get(fmt)
    if size is not None:
        return SizeResolveResult(size, "fallback_table", error=f"unknown_format: {fmt}")

    # 3) last resort
    return SizeResolveResult(1, "fallback_1", error=f"unknown_format: {fmt}")
