# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


import json
import struct
import pytest
import zipfile
from pathlib import Path
from dextrace.manifest.axml_parser import AxmlReader, ManifestInspector


# -------------------------------------------------------------
# Fixtures
# -------------------------------------------------------------
@pytest.fixture
def plain_xml_manifest() -> bytes:
    """Simple plaintext XML manifest"""
    return b"""
    <?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android"
              package="com.example.app">
        <uses-permission android:name="android.permission.INTERNET" />
        <application>
            <activity android:name="com.example.app.MainActivity" />
        </application>
    </manifest>
    """


@pytest.fixture
def binary_axml_manifest() -> bytes:
    """Binary AXML fixture with consistent header and string pool size (for safe unit tests)."""

    # 原始 body（略過前 8 bytes 的主 header）
    body = (
        b"\x01\x00\x1c\x00\xa4\t\x00\x00"  # <-- 我們稍後會覆蓋這裡的 chunk_size
        b"4\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\xec\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x1a\x00\x00\x004\x00\x00\x00@\x00\x00\x00^\x00\x00\x00\x82\x00\x00\x00"
        b"\x9c\x00\x00\x00\xa8\x00\x00\x00\xb6\x00\x00\x00\xc4\x00\x00\x00\xdc\x00\x00"
        b"\x00\xf0\x00\x00\x00\n\x01\x00\x00\"\x01\x00\x006\x01\x00\x00H\x01\x00\x00"
        b"\xa0\x01\x00\x00\xa4\x01\x00\x00\xb6\x01\x00\x00\xca\x01\x00\x00\x02\x02\x00"
        b"\x00\x0c\x02\x00\x00.\x02\x00\x00x\x02\x00\x00\xb2\x02\x00\x00\xec\x02\x00"
        b"\x00(\x03\x00\x00h\x03\x00\x00\xa2\x03\x00\x00\xe6\x03\x00\x00<\x04\x00\x00"
        b"P\x04\x00\x00j\x04\x00\x00~\x04\x00\x00\xd0\x04\x00\x00\xee\x04\x00\x00\xfe"
        b"\x04\x00\x006\x05\x00\x00J\x05\x00\x00\x8e\x05\x00\x00\xa0\x05\x00\x00\xea"
        b"\x05\x00\x00\xfe\x05\x00\x00d\x06\x00\x00\xb0\x06\x00\x00\x00\x07\x00\x00R"
        b"\x07\x00\x00l\x07\x00\x00\xd0\x07\x00\x00\x1c\x08\x00\x002\x08\x00\x00f\x08"
        b"\x00\x00\x0b\x00v\x00e\x00r\x00s\x00i\x00o\x00n\x00C\x00o\x00d\x00e\x00\x00"
        b"\x00\x0b\x00v\x00e\x00r\x00s\x00i\x00o\x00n\x00N\x00a\x00m\x00e\x00\x00\x00"
        b"\x04\x00n\x00a\x00m\x00e\x00\x00\x00\x0b\x00a\x00p\x00p\x00l\x00i\x00c\x00a"
        b"\x00t\x00i\x00o\x00n\x00\x00\x00\x08\x00a\x00c\x00t\x00i\x00v\x00i\x00t\x00"
        b"y\x00\x00\x00\x07\x00p\x00a\x00c\x00k\x00a\x00g\x00e\x00\x00\x00\x1a\x00c"
        b"\x00o\x00m\x00.\x00e\x00x\x00a\x00m\x00p\x00l\x00e\x00.\x00a\x00p\x00p\x00"
        b"\x00\x00\x0f\x00u\x00s\x00e\x00s\x00-\x00p\x00e\x00r\x00m\x00i\x00s\x00s\x00"
        b"i\x00o\x00n\x00\x00\x00#\x00a\x00n\x00d\x00r\x00o\x00i\x00d\x00.\x00p\x00e"
        b"\x00r\x00m\x00i\x00s\x00s\x00i\x00o\x00n\x00.\x00I\x00N\x00T\x00E\x00R\x00N"
        b"\x00E\x00T\x00\x00\x00"
    )

    # 修正 string pool chunk 的大小（用實際長度代替 0x09A4）
    fixed_body = bytearray(body)
    struct.pack_into("<I", fixed_body, 4, len(body))  # offset=4 => 覆蓋 chunk_size 欄位

    # 最外層 header：type=3, header_size=8, axml_size=8 + len(fixed_body)
    header = struct.pack("<HHI", 0x0003, 0x0008, 8 + len(fixed_body))
    return header + fixed_body


# -------------------------------------------------------------
# Core Tests
# -------------------------------------------------------------
def test_manifest_parser_plain_xml(plain_xml_manifest: bytes):
    """Test normal plain-text XML manifest parsing"""
    parsed = ManifestInspector.parse(plain_xml_manifest)
    assert parsed["package"] == "com.example.app"
    assert "android.permission.INTERNET" in parsed["permissions"]
    assert parsed["activities"] == ["com.example.app.MainActivity"]
    assert parsed["services"] == []
    assert parsed["receivers"] == []


def test_manifest_parser_utf16_axml(binary_axml_manifest: bytes):
    """Test AXML UTF-16 binary parsing (if available)"""
    parsed = ManifestInspector.parse(binary_axml_manifest)
    assert "package" in parsed
    assert isinstance(parsed["permissions"], list)
    assert isinstance(parsed["activities"], list)


def test_manifest_parser_missing():
    """Handle invalid or empty manifest"""
    parsed = ManifestInspector.parse(b"")
    assert isinstance(parsed, dict)
    assert parsed["package"] == "unknown"
    assert parsed["permissions"] == []
    assert parsed["activities"] == []


# ULEB128 decode
# ---------------------------------------------------------
def test_read_uleb128_basic(binary_axml_manifest: bytes):
    reader = AxmlReader(binary_axml_manifest)
    val, size = reader._read_uleb128(0)
    assert isinstance(val, int)
    assert isinstance(size, int)
    reader.close()


def test_read_uleb128_pair(binary_axml_manifest: bytes):
    reader = AxmlReader(binary_axml_manifest)
    val1, val2, size = reader._read_uleb128_pair(0)
    assert isinstance(val1, int)
    assert isinstance(val2, int)
    assert isinstance(size, int)
    reader.close()


# -------------------------------------------------------------
# CLI-level integration test (optional)
# -------------------------------------------------------------
def test_manifest_via_zip(tmp_path: Path, plain_xml_manifest: bytes):
    """Simulate APK with embedded manifest"""
    apk_path = tmp_path / "test.apk"
    with zipfile.ZipFile(apk_path, "w") as z:
        z.writestr("AndroidManifest.xml", plain_xml_manifest)

    with zipfile.ZipFile(apk_path, "r") as z:
        data = z.read("AndroidManifest.xml")

    parsed = ManifestInspector.parse(data)
    assert parsed["package"] == "com.example.app"


# -------------------------------------------------------------
# Extended behavior verification
# -------------------------------------------------------------
def test_manifest_json_serialization(plain_xml_manifest: bytes):
    """Ensure parsed manifest is JSON serializable"""
    parsed = ManifestInspector.parse(plain_xml_manifest)
    json_data = json.dumps(parsed)
    assert "package" in json_data
    assert "permissions" in json_data
