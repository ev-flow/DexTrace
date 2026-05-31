# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/errors.py — VM exception hierarchy.

Two layers:
  - DexTraceVMError / DexTraceNotImplementedError: top-level, indicate the
    interpreter cannot proceed. Bubble out of run() to the CLI.
  - DexTraceJavaException + 6 subclasses: model Java-level exceptions
    that DEX code catches via try/catch tables. Carry a Dalvik class
    descriptor so catch-walk uses class_hierarchy.is_subtype() rather than
    string matching on the message.
"""

from __future__ import annotations


class DexTraceVMError(Exception):
    """Raised for VM-level errors: div-by-zero, stack overflow, bad register access."""


class DexTraceNotImplementedError(DexTraceVMError):
    """Raised when an opcode has no handler (unimplemented or deferred to a later phase)."""


class DexTraceJavaException(DexTraceVMError):
    """
    Base for VM-modeled Java exceptions that user code can catch.

    Subclasses set `class_desc` to the Dalvik descriptor of the exception
    type they model. The engine wraps these in `_ThrowSignal` and walks the
    catch table using `class_hierarchy.is_subtype(class_desc, handler_type)`.
    """

    class_desc: str = "Ljava/lang/Throwable;"


class NullPointerException(DexTraceJavaException):
    class_desc = "Ljava/lang/NullPointerException;"


class ArithmeticException(DexTraceJavaException):
    class_desc = "Ljava/lang/ArithmeticException;"


class ClassCastException(DexTraceJavaException):
    class_desc = "Ljava/lang/ClassCastException;"


class ArrayIndexOutOfBoundsException(DexTraceJavaException):
    class_desc = "Ljava/lang/ArrayIndexOutOfBoundsException;"


class NegativeArraySizeException(DexTraceJavaException):
    class_desc = "Ljava/lang/NegativeArraySizeException;"


class IOException(DexTraceJavaException):
    class_desc = "Ljava/io/IOException;"
