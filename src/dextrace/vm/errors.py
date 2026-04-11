# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/errors.py — VM exception hierarchy.
"""

from __future__ import annotations


class DexTraceVMError(Exception):
    """Raised for VM-level errors: div-by-zero, stack overflow, bad register access."""


class DexTraceNotImplementedError(DexTraceVMError):
    """Raised when an opcode has no handler (unimplemented or deferred to a later phase)."""
