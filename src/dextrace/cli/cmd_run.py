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
from dextrace.vm.trace import CallTreeTrace


def register(p: argparse.ArgumentParser) -> None:
    p.add_argument("input", help="DEX file path")
    p.add_argument(
        "--entry",
        "-e",
        required=True,
        metavar="SIG",
        help="Entry method signature, e.g. 'Lp1;->main()I'",
    )
    # P4: --arg auto-detects int (decimal/0x hex) vs string. Repeat for
    # multiple positional args. Mutually exclusive with --args.
    p.add_argument(
        "--arg",
        "-a",
        action="append",
        type=str,
        default=[],
        metavar="V",
        dest="args",
        help=(
            "Method argument (int parsed from decimal or 0x-hex; "
            "anything else is passed as a string). Repeat for multiple args."
        ),
    )
    p.add_argument(
        "--args",
        metavar="JSON",
        dest="args_json",
        help=(
            "JSON list of mixed int/string args, e.g. '[\"+10000\",\"hi\"]'. "
            "Mutually exclusive with --arg."
        ),
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Output result as JSON to stdout",
    )
    p.add_argument(
        "--trace",
        action="store_true",
        help=(
            "Print the call tree (entry method → internal nodes → API stubs) "
            "to stdout. With --json, emits flat api_calls JSON instead."
        ),
    )
    p.add_argument(
        "--strict-stubs",
        action="store_true",
        help=(
            "Treat ALL external (unstubbed) API calls as errors, including "
            "void ones. Default: void misses are silent no-ops."
        ),
    )
    p.add_argument(
        "--dump-regs",
        action="store_true",
        help="Print non-zero register values after execution",
    )
    p.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print [INFO] progress messages to stderr",
    )
    p.set_defaults(func=run)


def _parse_one_arg(raw: str):
    """
    Auto-detect: 0x-hex int, signed decimal int, or string.

    Treats anything with a leading '+' (e.g. phone numbers like '+15555550100')
    as a string — Python's int() accepts '+' but the analyst almost never does,
    so honoring it here would silently downgrade phone-number args to ints and
    lose the IoC payload. Use --args '[...]' for explicit typing.
    """
    s = raw.strip()
    if s.startswith(("0x", "0X", "-0x", "-0X")):
        try:
            return int(s, 16)
        except ValueError:
            return raw
    body = s[1:] if s.startswith("-") else s
    if body.isdigit():
        return int(s, 10)
    return raw


def run(  # pylint: disable=too-many-return-statements,too-many-branches
    args: argparse.Namespace,
) -> int:
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

    # --- Resolve args: --arg (auto-detect) XOR --args (JSON list) --------
    if args.args and args.args_json:
        _err("--arg and --args are mutually exclusive")
        return 1

    if args.args_json is not None:
        try:
            method_args = json.loads(args.args_json)
        except json.JSONDecodeError as exc:
            _err(f"--args is not valid JSON: {exc}")
            return 1
        if not isinstance(method_args, list):
            _err("--args must be a JSON list, e.g. '[1,\"hi\"]'")
            return 1
        for v in method_args:
            if not isinstance(v, (int, str)):
                _err(
                    f"--args entries must be int or string, got "
                    f"{type(v).__name__}: {v!r}"
                )
                return 1
    else:
        method_args = [_parse_one_arg(a) for a in args.args]

    # --- Run -------------------------------------------------------------
    tree = CallTreeTrace() if (args.trace and not args.json) else None
    vm = DalvikVM(
        dex_bytes,
        resolver,
        sig_to_codeoff,
        trace_sink=_info if args.verbose else None,
        strict_stubs=args.strict_stubs,
        call_tree_trace=tree,
    )

    if args.verbose:
        _info(f"executing {entry_sig} with args={method_args}")

    try:
        result = vm.run(entry_sig, method_args)
    except DexTraceNotImplementedError as exc:
        _err(str(exc))
        return 2
    except DexTraceVMError as exc:
        _err(str(exc))
        return 2
    except Exception as exc:  # pylint: disable=broad-exception-caught
        _err(f"internal error: {exc}")
        return 2

    # --- Output ----------------------------------------------------------
    if args.json:
        _print_json(result, vm.api_calls if args.trace else None)
    else:
        _print_text(result)
        if args.trace and tree is not None:
            _print_call_tree(tree)

    if args.dump_regs:
        _print_registers(vm.final_registers)

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


def _print_json(result, api_calls=None) -> None:
    """JSON output: 2-space indent, ensure_ascii=False."""
    payload = {"return": result}
    if api_calls is not None:
        payload["api_calls"] = api_calls
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def _print_call_tree(tree: CallTreeTrace) -> None:
    """Render the call tree to stdout. No-op if root is None (empty run)."""
    root = tree.root
    if root is None:
        return
    _render_node(root, prefix="", is_root=True)


def _render_node(node, prefix: str, is_root: bool) -> None:
    if is_root:
        print(node.sig)
    elif node.is_stub:
        print(f"{prefix}|- {node.sig}({_fmt_args(node)})")
    else:
        print(f"{prefix}|- {node.sig}")

    child_prefix = "" if is_root else prefix + "|  "

    for i, child in enumerate(node.children):
        _render_node(child, child_prefix, is_root=False)
        if i < len(node.children) - 1:
            print(child_prefix)

    ret = _fmt_return(node.return_val, node.is_stub)
    if ret is None and is_root:
        rv = node.return_val
        ret = "void" if rv is None else str(rv)
    if ret is None:
        return

    if is_root:
        print(f"- return: {ret}")
    elif ret.startswith("- "):
        print(f"{child_prefix}- return:")
        print(f"{child_prefix}  {ret}")
    else:
        print(f"{child_prefix}- return: {ret}")


def _fmt_args(node) -> str:
    if not node.args:
        return ""
    parts = []
    for a in node.args:
        if a is None:
            parts.append("null")
        elif isinstance(a, str):
            parts.append(f'"{a}"')
        else:
            parts.append(str(a))
    return ", ".join(parts)


def _fmt_return(val, is_stub: bool):
    if not is_stub:
        return None
    if val is None:
        return "[exception]"
    if not isinstance(val, dict):
        return str(val)
    kind = val.get("kind", "")
    if kind == "void":
        return "void"
    if kind == "int":
        return str(val.get("value", 0))
    if kind == "object":
        return "- " + val.get("class", "Ljava/lang/Object;") + " object"
    return str(val)


def _print_registers(rf) -> None:
    """Print non-zero register values to stdout."""
    if rf is None:
        return
    parts = [f"v{i}={rf.get(i)}" for i in range(len(rf)) if rf.get(i) != 0]
    if parts:
        print("registers: " + "  ".join(parts))


# ---------------------------------------------------------------------------
# Message helpers (stderr only, 7-char fixed-width prefix per DESIGN.md)
# ---------------------------------------------------------------------------


def _err(msg: str) -> None:
    print(f"[ERROR] {msg}", file=sys.stderr)


def _info(msg: str) -> None:
    print(f"[INFO]  {msg}", file=sys.stderr)
