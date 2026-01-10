# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from __future__ import annotations

from pathlib import Path
from typing import List


def _try_read(path: Path) -> List[str] | None:
    if path.exists() and path.is_file():
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    return None


def load_bytecode_lines() -> List[str]:
    """
    Load AOSP bytecode opcode table lines.

    Search order:
      1) installed package resources:
         - dextrace/dalvik/data/bytecode.txt
         - dextrace/dalvik/bytecode.txt
      2) source tree fallback:
         - src/dextrace/dalvik/data/bytecode.txt (relative to this file)
         - repo root ./bytecode.txt
    """
    # 1) package resources (works after packaging)
    try:
        import importlib.resources as ir

        # try dextrace.dalvik.data: bytecode.txt
        try:
            pkg = "dextrace.dalvik.data"
            files = ir.files(pkg)
            text = files.joinpath("bytecode.txt").read_text(encoding="utf-8", errors="replace")
            return text.splitlines()
        except Exception:
            pass

        # try dextrace.dalvik: bytecode.txt
        try:
            pkg = "dextrace.dalvik"
            files = ir.files(pkg)
            text = files.joinpath("bytecode.txt").read_text(encoding="utf-8", errors="replace")
            return text.splitlines()
        except Exception:
            pass
    except Exception:
        pass

    # 2) source tree fallback (works in your dev workspace)
    here = Path(__file__).resolve()

    # src/dextrace/dalvik/data/bytecode.txt
    cand = here.parent / "data" / "bytecode.txt"
    got = _try_read(cand)
    if got is not None:
        return got

    # src/dextrace/dalvik/bytecode.txt
    cand = here.parent / "bytecode.txt"
    got = _try_read(cand)
    if got is not None:
        return got

    # repo root ./bytecode.txt (if user keeps it there)
    cand = Path.cwd() / "bytecode.txt"
    got = _try_read(cand)
    if got is not None:
        return got

    raise FileNotFoundError(
        "bytecode.txt not found. Tried package resources "
        "(dextrace.dalvik.data/bytecode.txt, dextrace.dalvik/bytecode.txt) "
        "and local paths (src/dextrace/dalvik/data/bytecode.txt, ./bytecode.txt)."
    )
