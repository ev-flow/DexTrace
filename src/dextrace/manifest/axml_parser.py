# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


import struct
import functools
from typing import Any, Dict, Iterator, List, Optional, Tuple
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from io import BytesIO

from ..errors import BadAxmlFormat

# ======== Android AXML Constants ========

RES_NULL_TYPE = 0x0000
RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_RESOURCE_MAP_TYPE = 0x0180
UTF8_FLAG = 0x00000100

# ResValue types
TYPE_STRING = 0x03
TYPE_INT_BOOLEAN = 0x12
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11


@dataclass
class ResChunkHeader:
    """Basic XML chunk header."""
    address: int
    type: int
    name: Optional[int] = None
    namespace: Optional[int] = None


@dataclass
class ResValue:
    """Representation of a single XML attribute value."""
    namespace: int
    name: int
    value: int
    type: int
    data: int


class AxmlReader:
    """
    Pure-Python AndroidManifest.xml (AXML) parser.

    Usage:
        with AxmlReader(data) as ax:
            root = ax.get_xml_tree()
            package = ax.package_name()
    """

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._size = len(data)
        self._ptr = 0
        self._file = BytesIO(data)

        # string pool
        self._sp_count = 0
        self._sp_utf8 = False
        self._sp_data_off = 0
        self._sp_offsets: List[int] = []

        # optional resource map
        self._res_ids: List[int] = []

        # initialize
        self._parse_header()
        self._parse_string_pool()
        self._parse_resource_map()

    # ---------- Context Manager ----------
    def __enter__(self) -> "AxmlReader":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def close(self) -> None:
        if self._file and not self._file.closed:
            self._file.close()

    # ---------- Header ----------
    def _parse_header(self) -> None:
        try:
            type_id, header_size, axml_size = struct.unpack_from("<HHI", self._data, 0)
        except struct.error as err:
            raise BadAxmlFormat("Invalid or truncated AXML header") from err

        if type_id != RES_XML_TYPE or header_size != 0x08:
            raise BadAxmlFormat("Invalid AXML header")

        if axml_size > self._size:
            raise BadAxmlFormat("AXML declared size exceeds file length")

        self._ptr = 8

    # ---------- String Pool ----------
    def _parse_string_pool(self) -> None:
        header_pos = self._ptr
        try:
            chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", self._data, header_pos)
        except struct.error as err:
            raise BadAxmlFormat("Missing string pool header") from err

        if chunk_type != RES_STRING_POOL_TYPE:
            raise BadAxmlFormat("String pool chunk not found")

        if header_pos + chunk_size > self._size:
            raise BadAxmlFormat("Invalid string pool chunk size")

        (self._sp_count, _style_count, flags,
         strings_start, _styles_start) = struct.unpack_from("<IIIII", self._data, header_pos + 8)

        self._sp_utf8 = bool(flags & UTF8_FLAG)
        self._sp_offsets = list(self._unpack_array("<I", header_pos + header_size, self._sp_count))
        self._sp_data_off = header_pos + strings_start

        self._ptr += chunk_size

    def _parse_resource_map(self) -> None:
        if self._ptr + 8 > self._size:
            return

        chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", self._data, self._ptr)
        if chunk_type != RES_XML_RESOURCE_MAP_TYPE:
            return

        count = (chunk_size - header_size) // 4
        self._res_ids = list(self._unpack_array("<I", self._ptr + header_size, count))
        self._ptr += chunk_size

    def _unpack_array(self, fmt: str, offset: int, count: int) -> Iterator[int]:
        """Unpack a consecutive array of values from current data."""
        size = struct.calcsize(fmt)
        for i in range(count):
            pos = offset + i * size
            if pos + size > self._size:
                break
            yield struct.unpack_from(fmt, self._data, pos)[0]

    # ---------- String Pool Access ----------
    @functools.lru_cache()
    def get_string(self, index: int) -> Optional[str]:
        if index < 0 or index >= self._sp_count:
            return None

        str_off = self._sp_data_off + self._sp_offsets[index]

        if self._sp_utf8:
            # UTF-8 模式
            _, size, adv = self._read_uleb128_pair(str_off)
            start = str_off + adv
            end = start + size
            return self._data[start:end].decode("utf-8", errors="ignore")
        else:
            # UTF-16 模式（使用固定 short 長度解析）
            (u16len,) = struct.unpack_from("<H", self._data, str_off)
            start = str_off + 2
            raw = self._data[start:start + u16len * 2]
            return raw.decode("utf-16le", errors="ignore")

    def _read_uleb128(self, pos: int) -> Tuple[int, int]:
        result = 0
        shift = 0
        length = 0
        while True:
            byte = self._data[pos + length]
            result |= (byte & 0x7F) << shift
            length += 1
            if not (byte & 0x80):
                break
            shift += 7
        return result, length

    def _read_uleb128_pair(self, pos: int) -> Tuple[int, int, int]:
        u16, a = self._read_uleb128(pos)
        u8, b = self._read_uleb128(pos + a)
        return u16, u8, a + b

    # ---------- Iterate XML Nodes ----------
    def __iter__(self) -> Iterator[ResChunkHeader]:
        ptr = self._ptr
        while ptr + 8 <= self._size:
            try:
                chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", self._data, ptr)
            except struct.error:
                break

            if chunk_size == 0 or ptr + chunk_size > self._size:
                break

            if chunk_type == RES_XML_START_ELEMENT_TYPE:
                ns, name, *_ = struct.unpack_from("<IIHHHHHH", self._data, ptr + 16)
                yield ResChunkHeader(ptr, chunk_type, name, ns)
            elif chunk_type == RES_XML_END_ELEMENT_TYPE:
                ns, name = struct.unpack_from("<II", self._data, ptr + 16)
                yield ResChunkHeader(ptr, chunk_type, name, ns)

            ptr += chunk_size

    # ---------- Attributes ----------
    def get_attributes(self, chunk: ResChunkHeader) -> List[ResValue]:
        if chunk.type != RES_XML_START_ELEMENT_TYPE:
            return []

        ext = chunk.address + 16
        _, _, attr_start, attr_size, attr_count, *_ = struct.unpack_from("<IIHHHHHH", self._data, ext)

        attrs: List[ResValue] = []
        aoff = ext + attr_start
        for _ in range(attr_count):
            a_ns, a_name, a_raw, a_sz, a_res0, a_type, a_data = struct.unpack_from("<IIIHBBI", self._data, aoff)
            aoff += 20
            attrs.append(ResValue(a_ns, a_name, a_raw, a_type, a_data))

        return attrs

    # ---------- XML Tree ----------
    def get_xml_tree(self) -> ET.Element:
        root: Optional[ET.Element] = None
        stack: List[ET.Element] = []

        for chunk in self:
            if chunk.type == RES_XML_START_ELEMENT_TYPE:
                tag = self.get_string(chunk.name) or "?"
                attrs: Dict[str, str] = {}
                for rv in self.get_attributes(chunk):
                    key = self.get_string(rv.name) or "?"
                    val = self._decode_attr_value(rv)
                    attrs[key] = val
                element = ET.Element(tag, attrs)
                if not stack:
                    root = element
                else:
                    stack[-1].append(element)
                stack.append(element)

            elif chunk.type == RES_XML_END_ELEMENT_TYPE and stack:
                stack.pop()

        if root is None:
            raise BadAxmlFormat("Manifest root not found")

        return root

    def _decode_attr_value(self, rv: ResValue) -> str:
        if rv.value != 0xFFFFFFFF:
            s = self.get_string(rv.value)
            return s or ""
        if rv.type == TYPE_STRING:
            s = self.get_string(rv.data)
            return s or ""
        if rv.type == TYPE_INT_BOOLEAN:
            return "true" if rv.data != 0 else "false"
        if rv.type in (TYPE_INT_DEC, TYPE_INT_HEX):
            return str(int(rv.data))
        return f"0x{rv.data:08x}"

    def package_name(self) -> Optional[str]:
        for chunk in self:
            if chunk.type == RES_XML_START_ELEMENT_TYPE:
                tag = self.get_string(chunk.name)
                if tag == "manifest":
                    for rv in self.get_attributes(chunk):
                        key = self.get_string(rv.name)
                        if key and "package" in key:
                            return self._decode_attr_value(rv)
        return None


# ======== High-level Wrapper ========

class ManifestInspector:
    """Extracts manifest metadata from XML or binary AXML."""

    @staticmethod
    def parse(data: bytes) -> Dict[str, Any]:
        # try plain XML first
        try:
            root = ET.fromstring(data.decode(errors="ignore"))
            return ManifestInspector._extract_from_xml(root)
        except Exception:
            pass

        # fallback to binary AXML
        with AxmlReader(data) as ax:
            pkg = ax.package_name() or "unknown"
            root = ax.get_xml_tree()
            return ManifestInspector._extract_from_xml(root, pkg_hint=pkg)

    @staticmethod
    def _extract_from_xml(root: ET.Element, pkg_hint: Optional[str] = None) -> Dict[str, Any]:
        def get_name(el: ET.Element) -> Optional[str]:
            for k, v in el.attrib.items():
                if k.endswith("}name") or k == "name":
                    return v
            return None

        def collect(path: str) -> List[str]:
            return [n for el in root.findall(path) if (n := get_name(el))]

        pkg = root.attrib.get("package", pkg_hint or "unknown")
        return {
            "package": pkg,
            "permissions": collect("uses-permission"),
            "activities": collect("application/activity"),
            "services": collect("application/service"),
            "receivers": collect("application/receiver"),
            "providers": collect("application/provider"),
        }
