# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
dextrace trace — Walk a method statically; decode every instruction (no execution).

IMPORT BOUNDARY: this module must import ONLY from vm/decoder.py and
core/dalvik/* support modules.  It must NOT import vm/engine.py,
vm/state.py, or any vm/handlers/* module.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

from dextrace.core.apk_reader import ApkReader
from dextrace.vm.decoder import DexParseError, MethodNotFound, walk_method


def register(p: argparse.ArgumentParser) -> None:
    p.add_argument("input", help="APK or DEX path")
    p.add_argument(
        "--entry",
        required=True,
        metavar="SIG",
        help="Method signature to trace: Lx/y/Z;->m(...)R",
    )
    p.set_defaults(func=run)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_dex_bytes(input_path: Path) -> tuple[bytes, str]:
    if input_path.suffix.lower() == ".dex":
        return input_path.read_bytes(), input_path.name
    apk = ApkReader(str(input_path))
    dex_bytes = apk.read_file("classes.dex")
    if not dex_bytes:
        raise SystemExit("APK does not contain classes.dex")
    return dex_bytes, "classes.dex"


def _insn_to_dict(ins) -> Dict[str, Any]:
    """Serialize a DecodedInsn to a JSON-safe dict; omit None/empty fields."""
    d: Dict[str, Any] = {
        "uoff": ins.uoff,
        "mnemonic": ins.mnemonic,
    }
    if ins.regs:
        d["regs"] = list(ins.regs)
    if ins.param is not None:
        d["param"] = ins.param
    if ins.index is not None:
        d["index"] = ins.index
    if ins.index_type is not None:
        d["index_type"] = ins.index_type
    if ins.flags:
        d["flags"] = sorted(ins.flags)
    if ins.target_uoff is not None:
        d["target_uoff"] = ins.target_uoff
    return d


# ---------------------------------------------------------------------------
# Subcommand handler
# ---------------------------------------------------------------------------

def run(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[ERROR] input not found: {input_path}", file=sys.stderr)
        return 1

    try:
        dex_bytes, dex_name = _load_dex_bytes(input_path)
    except SystemExit as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 3

    try:
        instructions = walk_method(dex_bytes, args.entry)
    except MethodNotFound as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1
    except DexParseError as e:
        print(f"[ERROR] malformed DEX: {e}", file=sys.stderr)
        return 3

    out: Dict[str, Any] = {
        "version": 1,
        "format": "trace",
        "source": {"input": str(input_path), "dex": dex_name},
        "method": args.entry,
        "instructions": [_insn_to_dict(ins) for ins in instructions],
    }
    print(json.dumps(out, ensure_ascii=False))
    return 0
