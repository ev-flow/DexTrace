# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


import sys
import argparse
from dextrace.version import __version__

from dextrace.cli import cmd_meta
from dextrace.cli import cmd_dex
from dextrace.cli import cmd_disasm
from dextrace.cli import cmd_run


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dextrace",
        description="DexTrace — DEX/APK parsing & static metadata extraction",
    )

    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"DexTrace {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="")

    # -------------------------
    # meta subcommand
    # -------------------------

    p_meta = subparsers.add_parser(
        "meta",
        help="Show basic static metadata for an APK (hashes, manifest, DEX headers)",
    )
    cmd_meta.register(p_meta)  # <<<<< KEY: use new cmd_meta.register()

    # -------------------------
    # dex subcommand
    # -------------------------

    p_dex = subparsers.add_parser(
        "dex",
        help="Show dex info for an APK",
    )
    cmd_dex.register(p_dex)

    # -------------------------
    # disasm
    # -------------------------
    p_disasm = subparsers.add_parser(
        "disasm",
        help="Disassemble specified methods and output JSON for Quark stage-5.",
    )
    cmd_disasm.register(p_disasm)

    # -------------------------
    # run subcommand
    # -------------------------
    p_run = subparsers.add_parser(
        "run",
        help="Execute a method in the Dalvik VM interpreter",
    )
    cmd_run.register(p_run)

    return parser


def main(argv=None):
    parser = build_parser()

    if argv is None:
        argv = sys.argv[1:]

    # Catch argparse SystemExit for --help/--version
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 0

    # Dispatch subcommand
    handler = getattr(args, "func", None)

    if callable(handler):
        try:
            rc = handler(args)
        except SystemExit as e:
            return e.code if isinstance(e.code, int) else 0
        return rc if isinstance(rc, int) else 0

    # No subcommand given
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
