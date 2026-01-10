# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List, Optional


@dataclass(frozen=True)
class DecodedOperands:
    """
    Dalvik operands decoded from code units.

    - regs: list like ["v0","v1",...]
    - index: reference index (string/type/field/method/proto) if any
    - literal: integer literal if any
    - target_uoff: branch/switch target in code units (absolute uoff), if any
    """
    regs: List[str]
    index: Optional[int] = None
    literal: Optional[int] = None
    target_uoff: Optional[int] = None


def _u16(read_u16: Callable[[int], int], uoff: int) -> int:
    return int(read_u16(uoff)) & 0xFFFF


def _low8(x: int) -> int:
    return x & 0xFF


def _high8(x: int) -> int:
    return (x >> 8) & 0xFF


def _nibble(x: int, shift: int) -> int:
    return (x >> shift) & 0xF


def _s8(x: int) -> int:
    x &= 0xFF
    return x - 0x100 if x & 0x80 else x


def _s16(x: int) -> int:
    x &= 0xFFFF
    return x - 0x10000 if x & 0x8000 else x


def _s32(lo16: int, hi16: int) -> int:
    v = (hi16 << 16) | lo16
    v &= 0xFFFFFFFF
    return v - 0x100000000 if v & 0x80000000 else v


def _u32(lo16: int, hi16: int) -> int:
    return ((hi16 & 0xFFFF) << 16) | (lo16 & 0xFFFF)


def _u64(w1: int, w2: int, w3: int, w4: int) -> int:
    # little-endian by 16-bit words: w1=lowest
    return (
        (w1 & 0xFFFF)
        | ((w2 & 0xFFFF) << 16)
        | ((w3 & 0xFFFF) << 32)
        | ((w4 & 0xFFFF) << 48)
    )


def _s64(w1: int, w2: int, w3: int, w4: int) -> int:
    v = _u64(w1, w2, w3, w4) & 0xFFFFFFFFFFFFFFFF
    return v - 0x10000000000000000 if v & 0x8000000000000000 else v


# -------------------------
# Format decoders (common)
# -------------------------

def decode_10x(read_u16: Callable[[int], int], uoff: int) -> DecodedOperands:
    # op
    return DecodedOperands(regs=[])


def decode_11x(read_u16: Callable[[int], int], uoff: int) -> DecodedOperands:
    # op vAA
    w0 = _u16(read_u16, uoff)
    aa = _high8(w0)
    return DecodedOperands(regs=[f"v{aa}"])


def decode_12x(read_u16: Callable[[int], int], uoff: int) -> DecodedOperands:
    # op vA, vB  (A=LOW nibble of high8, B=HIGH nibble of high8)
    w0 = _u16(read_u16, uoff)
    hi = _high8(w0)
    a = _nibble(hi, 0)
    b = _nibble(hi, 4)
    return DecodedOperands(regs=[f"v{a}", f"v{b}"])


def decode_22x(read_u16: Callable[[int], int], uoff: int) -> DecodedOperands:
    # op vAA, vBBBB
    w0 = _u16(read_u16, uoff)
    w1 = _u16(read_u16, uoff + 1)
    aa = _high8(w0)
    bbbb = w1
    return DecodedOperands(regs=[f"v{aa}", f"v{bbbb}"])


def decode_32x(read_u16: Callable[[int], int], uoff: int) -> DecodedOperands:
    # op vAAAA, vBBBB
    w1 = _u16(read_u16, uoff + 1)
    w2 = _u16(read_u16, uoff + 2)
    return DecodedOperands(regs=[f"v{w1}", f"v{w2}"])


def decode_21s(read_u16: Callable[[int], int], uoff: int) -> DecodedOperands:
    # op vAA, #+BBBB (signed 16)
    w0 = _u16(read_u16, uoff)
    w1 = _u16(read_u16, uoff + 1)
    aa = _high8(w0)
    lit = _s16(w1)
    return DecodedOperands(regs=[f"v{aa}"], literal=lit)


def decode_31i(read_u16: Callable[[int], int], uoff: int) -> DecodedOperands:
    # op vAA, #+BBBBBBBB (signed 32)
    w0 = _u16(read_u16, uoff)
    w1 = _u16(read_u16, uoff + 1)  # low16
    w2 = _u16(read_u16, uoff + 2)  # high16
    aa = _high8(w0)
    lit = _s32(w1, w2)
    return DecodedOperands(regs=[f"v{aa}"], literal=lit)


def decode_11n(read_u16: Callable[[int], int], uoff: int) -> DecodedOperands:
    # op vA, #+B (signed 4)
    w0 = _u16(read_u16, uoff)
    hi = _high8(w0)

    # IMPORTANT: A = low nibble, B = high nibble
    a = _nibble(hi, 0)
    b = _nibble(hi, 4)

    # 4-bit signed
    lit = b - 16 if b & 0x8 else b
    return DecodedOperands(regs=[f"v{a}"], literal=int(lit))


def decode_21c(read_u16: Callable[[int], int], uoff: int) -> DecodedOperands:
    # op vAA, thing@BBBB
    w0 = _u16(read_u16, uoff)
    w1 = _u16(read_u16, uoff + 1)
    aa = _high8(w0)
    return DecodedOperands(regs=[f"v{aa}"], index=int(w1))


def decode_31c(read_u16: Callable[[int], int], uoff: int) -> DecodedOperands:
    # op vAA, thing@BBBBBBBB
    w0 = _u16(read_u16, uoff)
    w1 = _u16(read_u16, uoff + 1)  # low16
    w2 = _u16(read_u16, uoff + 2)  # high16
    aa = _high8(w0)
    idx = _u32(w1, w2)
    return DecodedOperands(regs=[f"v{aa}"], index=int(idx))


def decode_22c(read_u16: Callable[[int], int], uoff: int) -> DecodedOperands:
    # op vA, vB, thing@CCCC  (A=LOW nibble, B=HIGH nibble)
    w0 = _u16(read_u16, uoff)
    w1 = _u16(read_u16, uoff + 1)
    hi = _high8(w0)
    a = _nibble(hi, 0)
    b = _nibble(hi, 4)
    return DecodedOperands(regs=[f"v{a}", f"v{b}"], index=int(w1))


def decode_23x(read_u16: Callable[[int], int], uoff: int) -> DecodedOperands:
    # op vAA, vBB, vCC
    w0 = _u16(read_u16, uoff)
    w1 = _u16(read_u16, uoff + 1)
    aa = _high8(w0)
    bb = _low8(w1)
    cc = _high8(w1)
    return DecodedOperands(regs=[f"v{aa}", f"v{bb}", f"v{cc}"])


# -------------------------
# Batch 2: literals / const extensions
# -------------------------

def decode_22b(read_u16: Callable[[int], int], uoff: int) -> DecodedOperands:
    """
    op vAA, vBB, #+CC (signed 8)
    w0: op | AA
    w1: BB | CC
    """
    w0 = _u16(read_u16, uoff)
    w1 = _u16(read_u16, uoff + 1)

    aa = _high8(w0)
    bb = _low8(w1)
    cc = _s8(_high8(w1))
    return DecodedOperands(regs=[f"v{aa}", f"v{bb}"], literal=int(cc))


def decode_22s(read_u16: Callable[[int], int], uoff: int) -> DecodedOperands:
    # op vA, vB, #+CCCC (signed 16)  (A=LOW nibble, B=HIGH nibble)
    w0 = _u16(read_u16, uoff)
    w1 = _u16(read_u16, uoff + 1)
    hi = _high8(w0)
    a = _nibble(hi, 0)
    b = _nibble(hi, 4)
    lit = _s16(w1)
    return DecodedOperands(regs=[f"v{a}", f"v{b}"], literal=int(lit))


def decode_21h(read_u16: Callable[[int], int], uoff: int) -> DecodedOperands:
    """
    op vAA, #+BBBB0000 (high16)

    注意：21h 的「shift 位數」其實跟 opcode 語意相關：
      - const/high16: BBBB << 16
      - const-wide/high16: BBBB << 48

    operand_decoder 不看 opcode（只看 format），因此這裡採用「常見的 <<16」
    做成 literal，至少讓輸出可讀；若要精確，可在上層依 mnemonic 修正。
    """
    w0 = _u16(read_u16, uoff)
    w1 = _u16(read_u16, uoff + 1)
    aa = _high8(w0)

    # best-effort: treat as 32-bit high16
    lit = (int(w1) & 0xFFFF) << 16
    return DecodedOperands(regs=[f"v{aa}"], literal=int(lit))


def decode_51l(read_u16: Callable[[int], int], uoff: int) -> DecodedOperands:
    """
    op vAA, #+BBBBBBBBBBBBBBBB (signed 64)
    units:
      w0: op | AA
      w1..w4: 64-bit literal (little-endian by 16-bit words)
    """
    w0 = _u16(read_u16, uoff)
    aa = _high8(w0)

    w1 = _u16(read_u16, uoff + 1)
    w2 = _u16(read_u16, uoff + 2)
    w3 = _u16(read_u16, uoff + 3)
    w4 = _u16(read_u16, uoff + 4)

    lit = _s64(w1, w2, w3, w4)
    return DecodedOperands(regs=[f"v{aa}"], literal=int(lit))


# -------------------------
# Batch 1: Control-flow (targets)
# -------------------------

def decode_10t(read_u16: Callable[[int], int], uoff: int) -> DecodedOperands:
    # op +AA (signed 8 in high8 of first unit)
    w0 = _u16(read_u16, uoff)
    off = _s8(_high8(w0))
    return DecodedOperands(regs=[], target_uoff=int(uoff + off))


def decode_20t(read_u16: Callable[[int], int], uoff: int) -> DecodedOperands:
    # op +BBBB (signed 16 in second unit)
    w1 = _u16(read_u16, uoff + 1)
    off = _s16(w1)
    return DecodedOperands(regs=[], target_uoff=int(uoff + off))


def decode_30t(read_u16: Callable[[int], int], uoff: int) -> DecodedOperands:
    # op +BBBBBBBB (signed 32 in units 1..2; low16 then high16)
    w1 = _u16(read_u16, uoff + 1)  # low16
    w2 = _u16(read_u16, uoff + 2)  # high16
    off = _s32(w1, w2)
    return DecodedOperands(regs=[], target_uoff=int(uoff + off))


def decode_21t(read_u16: Callable[[int], int], uoff: int) -> DecodedOperands:
    # op vAA, +BBBB (signed 16)
    w0 = _u16(read_u16, uoff)
    w1 = _u16(read_u16, uoff + 1)
    aa = _high8(w0)
    off = _s16(w1)
    return DecodedOperands(regs=[f"v{aa}"], target_uoff=int(uoff + off))


def decode_22t(read_u16: Callable[[int], int], uoff: int) -> DecodedOperands:
    # op vA, vB, +CCCC (signed 16) (A=LOW nibble, B=HIGH nibble)
    w0 = _u16(read_u16, uoff)
    w1 = _u16(read_u16, uoff + 1)
    hi = _high8(w0)
    a = _nibble(hi, 0)
    b = _nibble(hi, 4)
    off = _s16(w1)
    return DecodedOperands(regs=[f"v{a}", f"v{b}"], target_uoff=int(uoff + off))


def decode_31t(read_u16: Callable[[int], int], uoff: int) -> DecodedOperands:
    """
    op vAA, +BBBBBBBB  (signed 32)
    Used by:
      - packed-switch
      - sparse-switch
      - fill-array-data
    target points to payload start (uoff in code units).
    """
    w0 = _u16(read_u16, uoff)
    w1 = _u16(read_u16, uoff + 1)  # low16
    w2 = _u16(read_u16, uoff + 2)  # high16
    aa = _high8(w0)
    off = _s32(w1, w2)
    return DecodedOperands(regs=[f"v{aa}"], target_uoff=int(uoff + off))


# -------------------------
# invoke-kind
# -------------------------

def decode_35c(read_u16: Callable[[int], int], uoff: int) -> DecodedOperands:
    """
    invoke-xxx {vC,vD,vE,vF,vG}, meth@BBBB  (format 35c)

    w0: op | (A,G) in high8
        - A: argument count (HIGH nibble)
        - G: 5th register (LOW nibble)
    w1: BBBB (method index)
    w2: C|D|E|F packed in nibbles (low -> high)
    """
    w0 = _u16(read_u16, uoff)
    w1 = _u16(read_u16, uoff + 1)
    w2 = _u16(read_u16, uoff + 2)

    ag = _high8(w0)

    # IMPORTANT: A is HIGH nibble, G is LOW nibble (per your observed bytes)
    a = _nibble(ag, 4)  # arg count
    g = _nibble(ag, 0)  # 5th reg

    c = _nibble(w2, 0)
    d = _nibble(w2, 4)
    e = _nibble(w2, 8)
    f = _nibble(w2, 12)

    regs_order = [c, d, e, f, g]
    regs = [f"v{r}" for r in regs_order[: int(a)]]

    return DecodedOperands(regs=regs, index=int(w1))


def decode_3rc(read_u16: Callable[[int], int], uoff: int) -> DecodedOperands:
    """
    invoke-xxx/range {vCCCC .. vNNNN}, meth@BBBB
    w0: op | AA (count) in high8
    w1: BBBB (method index)
    w2: CCCC (first reg)
    """
    w0 = _u16(read_u16, uoff)
    w1 = _u16(read_u16, uoff + 1)
    w2 = _u16(read_u16, uoff + 2)

    aa = _high8(w0)
    cccc = int(w2)
    regs = [f"v{cccc + i}" for i in range(int(aa))]
    return DecodedOperands(regs=regs, index=int(w1))


# -------------------------
# dispatcher
# -------------------------

_SUPPORTED = {
    # common
    "10x": decode_10x,
    "11x": decode_11x,
    "12x": decode_12x,
    "22x": decode_22x,
    "32x": decode_32x,
    "11n": decode_11n,
    "21s": decode_21s,
    "31i": decode_31i,
    "21c": decode_21c,
    "31c": decode_31c,
    "22c": decode_22c,
    "23x": decode_23x,

    # invoke-kind
    "35c": decode_35c,
    "3rc": decode_3rc,

    # control-flow
    "10t": decode_10t,
    "20t": decode_20t,
    "30t": decode_30t,
    "21t": decode_21t,
    "22t": decode_22t,
    "31t": decode_31t,

    # literals / const extensions
    "22b": decode_22b,
    "22s": decode_22s,
    "21h": decode_21h,
    "51l": decode_51l,
}


def decode_by_format(
    fmt: str,
    uoff: int,
    read_u16: Callable[[int], int],
) -> Optional[DecodedOperands]:
    fn = _SUPPORTED.get(fmt)
    if fn is None:
        return None
    return fn(read_u16, uoff)
