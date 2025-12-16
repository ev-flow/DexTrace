# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from __future__ import annotations

import functools
import struct
from dataclasses import dataclass
from typing import Iterator, List, Optional

from .dex_header import DexHeader
from .dex_string_table import DexStringTable
from .dex_type_table import DexTypeTable


class DexFormatError(ValueError):
    """Raised when DEX format is invalid or truncated."""


@dataclass(frozen=True)
class DexMethodId:
    """method_id_item"""
    class_idx: int
    proto_idx: int
    name_idx: int


class DexMethodTable:
    """
    DEX method_ids parser.

    Responsible for:
      - Reading method_id_item table
      - Resolving method name
      - Resolving declaring class
      - Formatting method signatures
    """

    def __init__(
        self,
        dex_data: bytes,
        header: DexHeader,
        strings: DexStringTable,
        types: DexTypeTable,
    ) -> None:
        self._data = dex_data
        self._size = len(dex_data)
        self._header = header
        self._strings = strings
        self._types = types

        self._methods: List[DexMethodId] = []
        self._parse_method_ids()

    def __len__(self) -> int:
        return len(self._methods)

    def __iter__(self) -> Iterator[str]:
        for i in range(len(self)):
            sig = self.get_descriptor_signature(i)
            yield sig if sig else ""

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------
    def _parse_method_ids(self) -> None:
        count = int(self._header.method_ids_size)
        offset = int(self._header.method_ids_off)

        if count == 0:
            self._methods = []
            return

        needed = offset + count * 8
        if offset < 0 or needed > self._size:
            raise DexFormatError("method_ids section out of range")

        methods: List[DexMethodId] = []
        for i in range(count):
            class_idx, proto_idx, name_idx = struct.unpack_from(
                "<HHI", self._data, offset + i * 8
            )
            methods.append(
                DexMethodId(
                    class_idx=class_idx,
                    proto_idx=proto_idx,
                    name_idx=name_idx,
                )
            )

        self._methods = methods

    # ------------------------------------------------------------------
    # Raw accessors
    # ------------------------------------------------------------------
    def get(self, method_idx: int) -> Optional[DexMethodId]:
        if method_idx < 0 or method_idx >= len(self._methods):
            return None
        return self._methods[method_idx]

    def get_name(self, method_idx: int) -> Optional[str]:
        m = self.get(method_idx)
        if not m:
            return None
        return self._strings.get(m.name_idx)

    def get_class_descriptor(self, method_idx: int) -> Optional[str]:
        m = self.get(method_idx)
        if not m:
            return None
        return self._types.get_descriptor(m.class_idx)

    def get_class_name(self, method_idx: int) -> Optional[str]:
        m = self.get(method_idx)
        if not m:
            return None
        return self._types.get_java_name(m.class_idx)

    # ------------------------------------------------------------------
    # Signature formatting
    # ------------------------------------------------------------------
    @functools.lru_cache(maxsize=8192)
    def get_descriptor_signature(self, method_idx: int) -> Optional[str]:
        """
        Return Dalvik-style descriptor signature.

        Example:
          Ljava/lang/String;->length()I
        """
        m = self.get(method_idx)
        if not m:
            return None

        class_desc = self._types.get_descriptor(m.class_idx)
        name = self._strings.get(m.name_idx)
        proto = self._get_proto_descriptor(m.proto_idx)

        if not class_desc or not name or not proto:
            return None

        return f"{class_desc}->{name}{proto}"

    @functools.lru_cache(maxsize=8192)
    def get_java_signature(self, method_idx: int) -> Optional[str]:
        """
        Return Java-like signature.

        Example:
          java.lang.String.length():int
        """
        m = self.get(method_idx)
        if not m:
            return None

        class_name = self._types.get_java_name(m.class_idx)
        name = self._strings.get(m.name_idx)
        proto = self._get_proto_java_signature(m.proto_idx)

        if not class_name or not name or not proto:
            return None

        return f"{class_name}.{name}{proto}"

    # ------------------------------------------------------------------
    # Proto helpers (minimal)
    # ------------------------------------------------------------------
    def _get_proto_descriptor(self, proto_idx: int) -> Optional[str]:
        """
        Minimal proto resolution:
        We only use shorty string for now.
        """
        proto_off = int(self._header.proto_ids_off) + proto_idx * 12
        if proto_off + 12 > self._size:
            return None

        shorty_idx, return_type_idx, _ = struct.unpack_from(
            "<III", self._data, proto_off
        )

        shorty = self._strings.get(shorty_idx)
        ret = self._types.get_descriptor(return_type_idx)

        if not shorty or not ret:
            return None

        # NOTE: parameters omitted here, API extractor will expand later
        return f"(){ret}"

    def _get_proto_java_signature(self, proto_idx: int) -> Optional[str]:
        proto = self._get_proto_descriptor(proto_idx)
        if not proto:
            return None

        # ()Ljava/lang/String; -> ():java.lang.String
        if proto.startswith("()"):
            ret_desc = proto[2:]
            ret_name = DexTypeTable.descriptor_to_java_name(ret_desc)
            return f"():{ret_name}"

        return proto
