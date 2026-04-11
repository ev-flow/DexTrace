# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, DefaultDict

from dextrace.core.apk_reader import ApkReader
from dextrace.core.dex_parser import DexParser
from dextrace.core.dex_resolver import DexResolver
from dextrace.core.dex_code_map import build_sig_to_codeoff_map
from dextrace.dalvik.disassembler import DalvikDisassembler
from dextrace.dalvik.smali import SmaliRenderer


def register(p: argparse.ArgumentParser) -> None:
    p.add_argument("input", help="APK or DEX path")
    p.add_argument(
        "--method",
        action="append",
        default=[],
        help="Method signature: Lx/y/Z;->m(...)R",
    )
    p.add_argument(
        "--methods-file", help="Text file: one method signature per line"
    )
    p.add_argument(
        "--format",
        choices=["smali"],
        default="smali",
        help="Output format (MVP: smali only)",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Output JSON to stdout (MVP: always JSON)",
    )
    p.add_argument(
        "--max-insns",
        type=int,
        default=0,
        help="Max instructions per method (0 = no limit)",
    )
    p.add_argument(
        "--accept-optimized",
        action="store_true",
        help="Accept optimized opcodes (default: false)",
    )
    p.set_defaults(func=run)


def _read_methods_file(path: str) -> List[str]:
    out: List[str] = []
    for line in (
        Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
    ):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        out.append(s)
    return out


def _load_dex_bytes(input_path: Path) -> tuple[bytes, str]:
    if input_path.suffix.lower() == ".dex":
        return input_path.read_bytes(), input_path.name

    apk = ApkReader(str(input_path))
    dex_bytes = apk.read_file("classes.dex")
    if not dex_bytes:
        raise SystemExit("APK does not contain classes.dex")
    return dex_bytes, "classes.dex"


def _format_label(uoff: int) -> str:
    # label format you already use: :L0017 (hex, 4 digits)
    return f":L{uoff:04x}"


def _collect_label_targets(instructions) -> List[int]:
    """
    Collect all branch targets from DecodedInsn.target_uoff (int code-unit offset).
    Return sorted unique uoffs.
    """
    targets = set()
    for ins in instructions:
        t = getattr(ins, "target_uoff", None)
        if isinstance(t, int) and t >= 0:
            targets.add(t)
    return sorted(targets)


def _build_labels_by_uoff(instructions) -> Dict[int, List[str]]:
    """
    Build mapping: target_uoff -> [":Lxxxx", ...]
    Use list so multiple labels can coexist on same uoff (no overwrite).
    """
    labels_by_uoff: DefaultDict[int, List[str]] = defaultdict(list)
    for uoff in _collect_label_targets(instructions):
        labels_by_uoff[uoff].append(_format_label(uoff))
    return dict(labels_by_uoff)


def run(args: argparse.Namespace) -> int:
    methods: List[str] = list(args.method or [])
    if args.methods_file:
        methods.extend(_read_methods_file(args.methods_file))

    if not methods:
        raise SystemExit(
            "disasm requires --method or --methods-file (to avoid huge outputs)."
        )

    input_path = Path(args.input)
    if not input_path.exists():
        raise SystemExit(f"Input not found: {input_path}")

    dex_bytes, dex_name = _load_dex_bytes(input_path)

    parser = DexParser(dex_bytes)
    resolver = DexResolver(parser)

    sig_to_codeoff = build_sig_to_codeoff_map(dex_bytes, resolver)

    dis = DalvikDisassembler(
        dex_bytes=dex_bytes,
        resolver=resolver,
        accept_optimized=bool(args.accept_optimized),
    )
    renderer = SmaliRenderer(resolver)

    out: Dict[str, Any] = {
        "version": 1,
        "format": "smali",
        "source": {"input": str(input_path), "dex": dex_name},
        "methods": {},
        "errors": {},
    }

    max_insns: Optional[int] = args.max_insns or None

    for sig in methods:
        code_off = sig_to_codeoff.get(sig)
        if not code_off:
            out["errors"][sig] = {"error": "MethodNotFound"}
            continue

        try:
            m = dis.disassemble_method(code_off, max_insns=max_insns)

            # NEW: labels come from DecodedInsn.target_uoff, not from ins.param string
            labels_by_uoff = _build_labels_by_uoff(m.instructions)

            ins_list: List[Dict[str, Any]] = []
            for ins in m.instructions:
                # insert label line(s) if needed
                for lab in labels_by_uoff.get(ins.uoff, []):
                    ins_list.append(
                        {
                            "offset": ins.uoff,
                            "byte_off": ins.byte_off,
                            "smali": lab,
                        }
                    )

                ins_list.append(
                    {
                        "offset": ins.uoff,
                        "byte_off": ins.byte_off,
                        "smali": renderer.to_smali(ins),
                    }
                )

            out["methods"][sig] = {
                "code_off": code_off,
                "registers_size": m.registers_size,
                "ins_size": m.ins_size,
                "outs_size": m.outs_size,
                "tries_size": m.tries_size,
                "insns_size": m.insns_size,
                "instructions": ins_list,
            }
        except Exception as e:
            out["errors"][sig] = {"error": type(e).__name__, "message": str(e)}

    # MVP: Always print JSON
    print(json.dumps(out, ensure_ascii=False))
    return 0
