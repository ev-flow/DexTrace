# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from __future__ import annotations

import json
from argparse import ArgumentParser, Namespace
from typing import Any, Dict, List

from dextrace.core.apk_reader import ApkReader
from dextrace.core.dex_api_extractor import DexApiExtractor
from dextrace.core.dex_header import DexHeader


def register(parser: ArgumentParser) -> None:
    parser.add_argument("apk", help="Path to APK file")

    parser.add_argument("--header", action="store_true", help="Show DEX header information only")
    parser.add_argument("--summary", action="store_true", help="Show basic DEX summary (default)")
    parser.add_argument("--apis", action="store_true", help="Extract invoke-* API calls from classes.dex")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of API calls (0 = no limit)")
    parser.add_argument("--json", action="store_true", help="Output structured JSON")

    parser.set_defaults(func=run)


def run(args: Namespace) -> int:
    reader = ApkReader(args.apk)

    try:
        dex_data = reader.read_file("classes.dex")
    except KeyError as exc:
        raise SystemExit("[-] APK does not contain classes.dex") from exc

    header = DexHeader.from_bytes(dex_data)

    # default behavior
    want_summary = args.summary or (not args.header and not args.apis)

    if args.header:
        payload = {"dex": {"header": header.to_dict()}}
        return _emit(payload, as_json=args.json, fallback_print=_print_header)

    if args.apis:
        extractor = DexApiExtractor(dex_data)
        limit = args.limit if args.limit and args.limit > 0 else None
        calls = extractor.extract_api_calls(limit=limit)

        payload = {
            "dex": {
                "summary": _summary_dict(header),
                "api_calls": [c.to_dict() for c in calls],
                "api_calls_count": len(calls),
            }
        }
        return _emit(payload, as_json=args.json, fallback_print=lambda p: _print_api_calls(p["dex"]["api_calls"]))

    if want_summary:
        payload = {"dex": {"summary": _summary_dict(header)}}
        return _emit(payload, as_json=args.json, fallback_print=_print_summary)

    return 0


def _emit(payload: Dict[str, Any], as_json: bool, fallback_print) -> int:
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    fallback_print(payload)
    return 0


def _summary_dict(header: DexHeader) -> Dict[str, Any]:
    info = header.to_dict()
    return {
        "magic": info.get("magic"),
        "version": info.get("version"),
        "file_size": info.get("file_size"),
        "header_size": info.get("header_size"),
        "endian_tag": info.get("endian_tag"),
        "string_ids_size": info.get("string_ids_size"),
        "type_ids_size": info.get("type_ids_size"),
        "proto_ids_size": info.get("proto_ids_size"),
        "field_ids_size": info.get("field_ids_size"),
        "method_ids_size": info.get("method_ids_size"),
        "class_defs_size": info.get("class_defs_size"),
        "data_size": info.get("data_size"),
    }


def _print_header(payload: Dict[str, Any]) -> None:
    header = payload["dex"]["header"]
    print("DEX Header")
    print("-" * 60)
    for k, v in header.items():
        print(f"{k:20}: {v}")


def _print_summary(payload: Dict[str, Any]) -> None:
    s = payload["dex"]["summary"]
    print("DEX Summary")
    print("-" * 60)
    for k, v in s.items():
        print(f"{k:20}: {v}")


def _print_api_calls(api_calls: List[Dict[str, Any]]) -> None:
    print("DEX API Calls (invoke-*)")
    print("-" * 60)
    for item in api_calls:
        caller = item["caller"]
        callee = item["callee"]
        inv = item["invoke"]
        print(
            f'{inv["opcode"]:22} @ {inv["offset"]:>6}  '
            f'{caller["class"]}->{caller["method"]}{caller["proto"]}  ->  '
            f'{callee["class"]}->{callee["method"]}{callee["proto"]}'
        )
