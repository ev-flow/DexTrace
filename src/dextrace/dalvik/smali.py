# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from __future__ import annotations

from typing import Optional

from dextrace.dalvik.types import DecodedInsn


class SmaliRenderer:
    """
    Minimal Smali renderer for DecodedInsn.

    Assumptions:
    - ins.mnemonic is opcode mnemonic (e.g. "invoke-virtual")
    - ins.regs is list like ["v0","v1",...]
    - ins.param is resolved string/method/type/field/proto OR placeholder/literal as str
    - control-flow should prefer ins.target_uoff to build labels
    """

    def __init__(self, resolver=None) -> None:
        self.resolver = resolver

    @staticmethod
    def _label_of(target_uoff: Optional[int]) -> Optional[str]:
        if isinstance(target_uoff, int) and target_uoff >= 0:
            return f":L{target_uoff:04x}"
        return None

    def to_smali(self, ins: DecodedInsn) -> str:
        m = ins.mnemonic
        regs = ins.regs or []
        p = ins.param

        # payload/unknown already filtered by caller; still be defensive
        if not ins.fmt:
            return m

        # -------------------------
        # Control-flow (prefer target_uoff)
        # -------------------------
        if m.startswith("if-") or m.startswith("goto"):
            label = self._label_of(getattr(ins, "target_uoff", None))

            # fallback to existing param if label is not available
            if label is None and isinstance(p, str) and p.startswith(":L"):
                label = p

            if m.startswith("goto"):
                # goto :Lxxxx
                if label:
                    return f"{m} {label}"
                return m

            # if-xx vA, :Lxxxx  or if-xx vA, vB, :Lxxxx
            if label:
                if regs:
                    return f"{m} {', '.join(regs)}, {label}"
                return f"{m} {label}"
            # no target: keep old behavior
            if regs and p:
                return f"{m} {', '.join(regs)}, {p}"
            if p:
                return f"{m} {p}"
            if regs:
                return f"{m} {', '.join(regs)}"
            return m

        # -------------------------
        # Invoke-kind
        # -------------------------
        if m.startswith("invoke-"):
            reg_list = "{" + ",".join(regs) + "}"
            if p:
                return f"{m} {reg_list}, {p}"
            return f"{m} {reg_list}"

        # -------------------------
        # move-result-kind
        # -------------------------
        if m.startswith("move-result"):
            if regs:
                return f"{m} {regs[0]}"
            return m

        # -------------------------
        # return-kind
        # -------------------------
        if m.startswith("return"):
            if m == "return-void":
                return "return-void"
            if regs:
                return f"{m} {regs[0]}"
            return m

        # -------------------------
        # const-string / const-class / const (literal)
        # -------------------------
        if m in ("const-string", "const-string/jumbo", "const-class"):
            if regs and p is not None:
                return f"{m} {regs[0]}, {p}"
            if regs:
                return f"{m} {regs[0]}"
            return m

        if m.startswith("const"):
            if regs and p is not None:
                return f"{m} {regs[0]}, {p}"
            if regs:
                return f"{m} {regs[0]}"
            return m

        # -------------------------
        # generic fallback
        # -------------------------
        if regs and p is not None:
            return f"{m} {', '.join(regs)}, {p}"
        if regs:
            return f"{m} {', '.join(regs)}"
        if p is not None:
            return f"{m} {p}"
        return m
