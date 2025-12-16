# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from __future__ import annotations

import functools
import struct
from dataclasses import dataclass
from typing import Iterator, List, Optional, Sequence, Tuple

from .dex_header import DexHeader
from .dex_string_table import DexStringTable
from .dex_type_table import DexTypeTable


class DexFormatError(ValueError):
    """Raised when DEX format is invalid or truncated."""


@dataclass(frozen=True)
class DexProtoId:
    """proto_id_item"""
    shorty_idx: int
    return_type_idx: int
    parameters_off: int


class DexProtoTable:
    """
    DEX proto_ids parser.

    proto_id_item (12 bytes each):
      uint shorty_idx
      uint return_type_idx
      uint parameters_off  (0 if no params)

    parameters_off -> type_list:
      uint size
      ushort list[size]
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

        self._protos: List[DexProtoId] = []
        self._parse_proto_ids()

    def __len__(self) -> int:
        return len(self._protos)

    def get(self, proto_idx: int) -> Optional[DexProtoId]:
        if proto_idx < 0 or proto_idx >= len(self._protos):
            return None
        return self._protos[proto_idx]

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------
    def _parse_proto_ids(self) -> None:
        count = int(self._header.proto_ids_size)
        offset = int(self._header.proto_ids_off)

        if count == 0:
            self._protos = []
            return

        needed = offset + count * 12
        if offset < 0 or needed > self._size:
            raise DexFormatError("proto_ids section out of range")

        protos: List[DexProtoId] = []
        for i in range(count):
            shorty_idx, return_type_idx, parameters_off = struct.unpack_from(
                "<III", self._data, offset + i * 12
            )
            protos.append(
                DexProtoId(
                    shorty_idx=shorty_idx,
                    return_type_idx=return_type_idx,
                    parameters_off=parameters_off,
                )
            )

        self._protos = protos

    # ------------------------------------------------------------------
    # Resolution helpers
    # ------------------------------------------------------------------
    def get_return_descriptor(self, proto_idx: int) -> Optional[str]:
        proto = self.get(proto_idx)
        if not proto:
            return None
        return self._types.get_descriptor(proto.return_type_idx)

    def get_param_type_indexes(self, proto_idx: int) -> Optional[List[int]]:
        proto = self.get(proto_idx)
        if not proto:
            return None

        if proto.parameters_off == 0:
            return []

        off = proto.parameters_off
        if off < 0 or off + 4 > self._size:
            return None

        (size,) = struct.unpack_from("<I", self._data, off)
        list_off = off + 4

        # type_item = ushort, total = size * 2
        byte_len = size * 2
        if list_off + byte_len > self._size:
            return None

        result: List[int] = []
        for i in range(size):
            (type_idx,) = struct.unpack_from("<H", self._data, list_off + i * 2)
            result.append(int(type_idx))

        return result

    def get_param_descriptors(self, proto_idx: int) -> Optional[List[str]]:
        indexes = self.get_param_type_indexes(proto_idx)
        if indexes is None:
            return None
        return [self._types.get_descriptor(i) or "" for i in indexes]

    def get_param_java_names(self, proto_idx: int) -> Optional[List[str]]:
        indexes = self.get_param_type_indexes(proto_idx)
        if indexes is None:
            return None
        return [self._types.get_java_name(i) or "" for i in indexes]

    def get_shorty(self, proto_idx: int) -> Optional[str]:
        proto = self.get(proto_idx)
        if not proto:
            return None
        return self._strings.get(proto.shorty_idx)

    # ------------------------------------------------------------------
    # Canonical signatures
    # ------------------------------------------------------------------
    @functools.lru_cache(maxsize=8192)
    def get_descriptor_signature(self, proto_idx: int) -> Optional[str]:
        """
        Return descriptor-style proto signature.

        Example:
          (Ljava/lang/String;I)Z
        """
        ret = self.get_return_descriptor(proto_idx)
        params = self.get_param_descriptors(proto_idx)
        if ret is None or params is None:
            return None

        return f"({''.join(params)}){ret}"

    @functools.lru_cache(maxsize=8192)
    def get_java_signature(self, proto_idx: int) -> Optional[str]:
        """
        Return Java-like signature.

        Example:
          (java.lang.String, int):boolean
        """
        ret_desc = self.get_return_descriptor(proto_idx)
        params = self.get_param_java_names(proto_idx)
        if ret_desc is None or params is None:
            return None

        ret_java = self._descriptor_to_java_name(ret_desc)
        joined = ", ".join(params)
        return f"({joined}):{ret_java}"

    # ------------------------------------------------------------------
    # Descriptor conversion
    # ------------------------------------------------------------------
    @staticmethod
    def _descriptor_to_java_name(desc: str) -> str:
        """
        Convert type descriptor to Java-like type name.

        Examples:
          I -> int
          Ljava/lang/String; -> java.lang.String
          [I -> int[]
          [[Ljava/lang/String; -> java.lang.String[][]
        """
        if not desc:
            return ""

        array_dim = 0
        while desc.startswith("["):
            array_dim += 1
            desc = desc[1:]

        prim = {
            "V": "void",
            "Z": "boolean",
            "B": "byte",
            "S": "short",
            "C": "char",
            "I": "int",
            "J": "long",
            "F": "float",
            "D": "double",
        }

        if desc in prim:
            base = prim[desc]
        elif desc.startswith("L") and desc.endswith(";"):
            base = desc[1:-1].replace("/", ".")
        else:
            base = desc

        return base + "[]" * array_dim
