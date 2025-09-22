import argparse, sys
from .. import __version__


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="dextrace",
        description="DexTrace — DEX/APK parsing & call-tracing core (M0 skeleton)",
    )
    parser.add_argument("-V", "--version", action="version", version=f"DexTrace {__version__}")

    sub = parser.add_subparsers(dest="command")

    # Will implement later.
    p_meta = sub.add_parser("meta", help="Show APK basic info. (Do it later.)")
    p_meta.set_defaults(func=lambda args: print("meta command not yet implemented"))

    args = parser.parse_args(argv)
    if hasattr(args, "func"):
        return args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    sys.exit(main())
