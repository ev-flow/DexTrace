# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from __future__ import annotations

from typing import Dict


# Dalvik instruction format -> size in 16-bit code units
FORMAT_SIZE_UNITS: Dict[str, int] = {
    # 1 unit
    "10x": 1,  # nop, return-void
    "12x": 1,  # move vA, vB
    "11n": 1,  # const/4 vA, #+B
    "11x": 1,  # return vAA, move-result vAA
    "10t": 1,  # goto +AA (8-bit)

    # 2 units
    "20t": 2,   # goto/16 +AAAA
    "20bc": 2,  # throw-verification-error kind@AA, ref@BBBB (rare)
    "22x": 2,   # move/from16 vAA, vBBBB
    "21t": 2,   # if-xx vAA, +BBBB
    "21s": 2,   # const/16 vAA, #+BBBB
    "21h": 2,   # const/high16 vAA, #+BBBB0000
    "21c": 2,   # const-string vAA, string@BBBB ; const-class vAA, type@BBBB
    "23x": 2,   # aget vAA, vBB, vCC
    "22b": 2,   # add-int/lit8 vAA, vBB, #+CC
    "22t": 2,   # if-eq vA, vB, +CCCC
    "22s": 2,   # add-int/lit16 vA, vB, #+CCCC
    "22c": 2,   # iget vA, vB, field@CCCC ; new-instance vA, type@CCCC
    "22cs": 2,  # iget-quick vA, vB, fieldoff@CCCC (odex/quick)
    "21lh": 2,  # (some docs call long/ high16 variants) keep extensible

    # 3 units
    "30t": 3,  # goto/32 +AAAAAAAA
    "32x": 3,  # move/16 vAAAA, vBBBB
    "31i": 3,  # const vAA, #+BBBBBBBB
    "31t": 3,  # fill-array-data vAA, +BBBBBBBB ; packed/sparse-switch vAA, +BBBBBBBB
    "31c": 3,  # const-string/jumbo vAA, string@BBBBBBBB
    "35c": 3,  # invoke-xxx {vC..vG}, meth@BBBB ; filled-new-array {..}, type@BBBB
    "35ms": 3, # invoke-virtual-quick {..}, vtaboff@BBBB (odex)
    "35mi": 3, # invoke-super-quick {..}, vtaboff@BBBB (odex)
    "3rc": 3,  # invoke-xxx/range {vCCCC..}, meth@BBBB
    "3rms": 3, # invoke-virtual-quick/range (odex)
    "3rmi": 3, # invoke-super-quick/range (odex)

    # 4 units
    "45cc": 4, # invoke-polymorphic {..}, meth@BBBB, proto@HHHH
    "4rcc": 4, # invoke-polymorphic/range {..}, meth@BBBB, proto@HHHH

    # 5 units
    "51l": 5,  # const-wide vAA, #+BBBBBBBBBBBBBBBB
}


def format_size_units(fmt: str) -> int:
    """
    Return instruction size in 16-bit code units for a Dalvik format string.
    Raises KeyError if unknown.
    """
    return FORMAT_SIZE_UNITS[fmt]
