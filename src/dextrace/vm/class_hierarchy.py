# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
vm/class_hierarchy.py — Vtable construction and virtual method resolution.

Built once at DalvikVM init from the raw DEX bytes + resolver.
Provides O(1) dispatch: resolve_virtual(runtime_class_desc, name, proto) → code_off.

Algorithm:
  1. Collect all class_def_items from the DEX.
  2. DFS-topological sort so every superclass is processed before its subclasses.
  3. For each class: copy superclass vtable, then override/append virtual methods.
  4. Store final vtable as Dict[(name, proto) → code_off] per class_desc.

External superclasses (e.g. Ljava/lang/Object; not defined in this DEX) get an
empty vtable, which is correct — they have no Dalvik implementation to dispatch to.
"""

from __future__ import annotations

from typing import Dict, Optional, Set, Tuple

from dextrace.core.dex_class_iter import (
    NO_SUPERCLASS,
    iter_class_data_methods,
    iter_class_defs,
)
from dextrace.vm.errors import DexTraceNotImplementedError, DexTraceVMError

# vtable maps (method_name, proto_string) → code_off
_VTable = Dict[Tuple[str, str], int]


class ClassHierarchy:
    """
    Vtable table for all classes in a DEX.

    Constructed once and shared for the lifetime of a DalvikVM instance.
    """

    def __init__(self, dex_bytes: bytes, resolver) -> None:
        # class_desc → vtable
        self._vtables: Dict[str, _VTable] = {}
        # class_desc → superclass_desc (None for Object / no superclass in DEX)
        self._superclass: Dict[str, Optional[str]] = {}
        self._build(dex_bytes, resolver)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def resolve_virtual(self, class_desc: str, name: str, proto: str) -> int:
        """
        Return the code_off for the virtual method (name, proto) as inherited
        by class_desc after vtable resolution.

        Raises:
          DexTraceVMError              — class or method not found in vtable
          DexTraceNotImplementedError  — method slot exists but code_off == 0
                                         (abstract method with no implementation)
        """
        vtable = self._vtables.get(class_desc)
        if vtable is None:
            raise DexTraceVMError(
                f"vtable miss: {class_desc} is not a known class"
            )

        code_off = vtable.get((name, proto))
        if code_off is None:
            raise DexTraceVMError(
                f"vtable miss: {class_desc} has no method {name}{proto}"
            )

        if code_off == 0:
            raise DexTraceNotImplementedError(
                f"abstract method: {class_desc}->{name}{proto} has no implementation"
            )

        return code_off

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    def _build(self, dex_bytes: bytes, resolver) -> None:
        # Step 1: collect class info from class_def_items
        # Maps class_desc → (superclass_desc_or_None, class_data_off)
        class_info: Dict[str, Tuple[Optional[str], int]] = {}

        for cdef in iter_class_defs(dex_bytes):
            try:
                class_desc = resolver.get_type(cdef.class_idx)
            except Exception:
                continue

            if cdef.superclass_idx == NO_SUPERCLASS:
                super_desc: Optional[str] = None
            else:
                try:
                    super_desc = resolver.get_type(cdef.superclass_idx)
                except Exception:
                    super_desc = None

            class_info[class_desc] = (super_desc, cdef.class_data_off)
            self._superclass[class_desc] = super_desc

        # Step 2: DFS topological order — superclass processed before subclass
        visited: Set[str] = set()

        def visit(desc: str) -> None:
            if desc in visited:
                return
            visited.add(desc)

            info = class_info.get(desc)
            if info is None:
                # External class (e.g. Ljava/lang/Object; not in this DEX)
                self._vtables[desc] = {}
                return

            super_desc, class_data_off = info

            # Ensure superclass vtable is built first
            if super_desc is not None:
                visit(super_desc)

            # Start with a copy of the superclass vtable
            if super_desc is not None and super_desc in self._vtables:
                vtable: _VTable = dict(self._vtables[super_desc])
            else:
                vtable = {}

            # Override / append this class's virtual methods
            if class_data_off:
                for em in iter_class_data_methods(dex_bytes, class_data_off):
                    if not em.is_virtual:
                        continue
                    try:
                        m = resolver._get_method(em.method_idx)
                    except Exception:
                        m = None
                    if not m:
                        continue
                    _, vname, vproto = m
                    vtable[(vname, vproto)] = em.code_off

            self._vtables[desc] = vtable

        for desc in class_info:
            visit(desc)
