# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

import argparse, sys, json
from ..version import __version__
from ..apk.reader import ApkReader

def cmd_meta(args: argparse.Namespace) -> int:
    reader = ApkReader(args.apk_path)
    info = reader.get_info()
    print(json.dumps(info, indent=2))
    return 0

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dextrace",
        description="DexTrace — DEX/APK parsing & call-tracing core",
    )
    p.add_argument("-V", "--version", action="version", version=f"DexTrace {__version__}")

    sub = p.add_subparsers(dest="command", required=True)

    p_meta = sub.add_parser("meta", help="Show APK basic info")
    p_meta.add_argument("apk_path", help="Path to the APK file")
    p_meta.set_defaults(func=cmd_meta)

    return p

def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)

if __name__ == "__main__":
    sys.exit(main())
