# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
cli/cmd_run.py — `dextrace run` subcommand.

Usage:
  dextrace run <dex> --entry 'Lp1;->main()I'
  dextrace run <dex> --entry 'Lp2/Fib;->fib(I)I' --arg 10
  dextrace run <dex> --entry 'Lp1;->main()I' --json

Exit codes (per DESIGN.md):
  0  success
  1  user error (bad args, method not found)
  2  VM runtime error
  3  parse error
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path
from dextrace.cli._io import load_dex_bytes
from dextrace.core.dex_parser import DexParser
from dextrace.core.dex_resolver import DexResolver
from dextrace.core.dex_code_map import build_sig_to_codeoff_map
from dextrace.vm.engine import DalvikVM
from dextrace.vm.errors import DexTraceVMError, DexTraceNotImplementedError


def register(p: argparse.ArgumentParser) -> None:
    p.add_argument("input", help="DEX file path")
    p.add_argument(
        "--entry",
        "-e",
        required=True,
        metavar="SIG",
        help="Entry method signature, e.g. 'Lp1;->main()I'",
    )
    p.add_argument(
        "--arg",
        "-a",
        action="append",
        type=int,
        default=[],
        metavar="N",
        dest="args",
        help="Integer argument (may be repeated for multiple args)",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Output result as JSON to stdout",
    )
    p.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print [INFO] progress messages to stderr",
    )
    p.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    if not input_path.exists():
        _err(f"file not found: {input_path}")
        return 1
    if not input_path.is_file():
        _err(f"not a file: {input_path}")
        return 1
    if input_path.suffix.lower() not in {".dex", ".apk"}:
        _err(f"expected a .dex or .apk file, got: {input_path.suffix!r}")
        return 1

    # --- Load DEX bytes (handles both .dex and .apk) ----------------------
    try:
        dex_bytes, _dex_name = load_dex_bytes(input_path)
    except SystemExit as e:
        _err(str(e))
        return 3

    # --- Parse DEX -------------------------------------------------------
    try:
        DexParser(dex_bytes)  # validate structure
        resolver = DexResolver(dex_bytes)
    except (
        ValueError,
        struct.error,
        KeyError,
        IndexError,
        OverflowError,
    ) as exc:
        _err(f"parse error: {exc}")
        return 3

    # --- Build method map ------------------------------------------------
    try:
        sig_to_codeoff = build_sig_to_codeoff_map(dex_bytes, resolver)
    except (
        ValueError,
        struct.error,
        KeyError,
        IndexError,
        OverflowError,
    ) as exc:
        _err(f"parse error building method map: {exc}")
        return 3

    if args.verbose:
        _info(f"loaded {len(sig_to_codeoff)} methods from {input_path.name}")

    # --- Check entry exists ----------------------------------------------
    entry_sig = args.entry
    if entry_sig not in sig_to_codeoff:
        _err(f"method not found: {entry_sig}")
        _err(f"available methods ({len(sig_to_codeoff)}):")
        for sig in sorted(sig_to_codeoff)[:20]:
            _err(f"  {sig}")
        if len(sig_to_codeoff) > 20:
            _err(f"  ... and {len(sig_to_codeoff) - 20} more")
        return 1

    # --- Run -------------------------------------------------------------
    vm = DalvikVM(dex_bytes, resolver, sig_to_codeoff)

    if args.verbose:
        _info(f"executing {entry_sig} with args={args.args}")

    try:
        result = vm.run(entry_sig, args.args)
    except DexTraceNotImplementedError as exc:
        _err(f"not implemented: {exc}")
        return 2
    except DexTraceVMError as exc:
        _err(f"VM error: {exc}")
        return 2
    except Exception as exc:  # pylint: disable=broad-exception-caught
        _err(f"internal error: {exc}")
        return 2

    # --- Output ----------------------------------------------------------
    if args.json:
        _print_json(result)
    else:
        _print_text(result)

    return 0


# ---------------------------------------------------------------------------
# Output formatters (Terminal Noir, per DESIGN.md)
# ---------------------------------------------------------------------------


def _print_text(result) -> None:
    """Text output: 'return: <value>' to stdout."""
    if result is None:
        print("return: void")
    elif isinstance(result, str):
        print(f'return: "{result}"')
    else:
        print(f"return: {result}")


def _print_json(result) -> None:
    """JSON output: 2-space indent, ensure_ascii=False."""
    print(json.dumps({"return": result}, indent=2, ensure_ascii=False))


# ---------------------------------------------------------------------------
# Message helpers (stderr only, 7-char fixed-width prefix per DESIGN.md)
# ---------------------------------------------------------------------------


def _err(msg: str) -> None:
    print(f"[ERROR] {msg}", file=sys.stderr)


def _info(msg: str) -> None:
    print(f"[INFO]  {msg}", file=sys.stderr)
