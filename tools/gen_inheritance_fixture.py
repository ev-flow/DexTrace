#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pylint: disable=duplicate-code  # gen_const_return/fibonacci/inheritance share DEX builder boilerplate intentionally
"""
Build tests/fixtures/samples/inheritance.dex programmatically.

Class hierarchy:
  LBase;  extends Ljava/lang/Object;
    public int foo() { return 1; }
  LMid;   extends LBase;
    public int foo() { return 2; }   ← overrides Base.foo
  LMain;  extends Ljava/lang/Object;
    public static int entry() {
        Lp3/Mid obj = new Lp3/Mid();
        return obj.foo();            ← invoke-virtual dispatches to Mid.foo → 2
    }

Verification:
  python -m dextrace run tests/fixtures/samples/inheritance.dex \\
      --entry 'LMain;->entry()I'
  # → return: 2
"""

import hashlib
import struct
import zlib
from pathlib import Path


# ---------------------------------------------------------------------------
# uleb128 helpers
# ---------------------------------------------------------------------------

def _uleb128(n: int) -> bytes:
    buf = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            buf.append(b | 0x80)
        else:
            buf.append(b)
            break
    return bytes(buf)


def _align4(off: int) -> int:
    return (off + 3) & ~3


def _string_data_item(s: str) -> bytes:
    b = s.encode("utf-8")
    return _uleb128(len(s)) + b + b"\x00"


# ---------------------------------------------------------------------------
# DEX builder
# ---------------------------------------------------------------------------

def build_inheritance_dex() -> bytes:  # pylint: disable=too-many-locals,too-many-statements
    # -----------------------------------------------------------------------
    # String table (sorted by MUTF-8 code point — DEX requirement)
    #  0: "<init>"
    #  1: "I"
    #  2: "Ljava/lang/Object;"
    #  3: "LBase;"
    #  4: "LMain;"
    #  5: "LMid;"
    #  6: "V"
    #  7: "entry"
    #  8: "foo"
    # -----------------------------------------------------------------------
    strings = [
        "<init>",              # 0
        "I",                   # 1
        "Ljava/lang/Object;",  # 2
        "LBase;",           # 3
        "LMain;",           # 4
        "LMid;",            # 5
        "V",                   # 6
        "entry",               # 7
        "foo",                 # 8
    ]

    # -----------------------------------------------------------------------
    # Type IDs (sorted by string_idx)
    #  type 0 → str 1  "I"
    #  type 1 → str 2  "Ljava/lang/Object;"
    #  type 2 → str 3  "LBase;"
    #  type 3 → str 4  "LMain;"
    #  type 4 → str 5  "LMid;"
    #  type 5 → str 6  "V"
    # -----------------------------------------------------------------------
    type_string_ids = [1, 2, 3, 4, 5, 6]

    # -----------------------------------------------------------------------
    # Proto IDs (sorted by return_type_idx, then params)
    #  proto 0: ()I  shorty=str1 "I",  return_type=type0 "I",  params=none
    #  proto 1: ()V  shorty=str6 "V",  return_type=type5 "V",  params=none
    # (no type_list needed — both protos have empty parameter lists)
    # -----------------------------------------------------------------------
    # [(shorty_string_idx, return_type_idx)]  — params_off patched to 0
    protos = [
        (1, 0),  # proto 0: ()I
        (6, 5),  # proto 1: ()V
    ]

    # -----------------------------------------------------------------------
    # Method IDs (sorted by class_idx, then name_idx, then proto_idx)
    #  method 0: LBase;-><init>()V   class=2, name=0, proto=1
    #  method 1: LBase;->foo()I      class=2, name=8, proto=0
    #  method 2: LMain;-><init>()V   class=3, name=0, proto=1
    #  method 3: LMain;->entry()I    class=3, name=7, proto=0
    #  method 4: LMid;-><init>()V    class=4, name=0, proto=1
    #  method 5: LMid;->foo()I       class=4, name=8, proto=0
    # -----------------------------------------------------------------------
    # [(class_type_idx, proto_idx, name_string_idx)]
    method_ids = [
        (2, 1, 0),  # 0: Base.<init>()V
        (2, 0, 8),  # 1: Base.foo()I
        (3, 1, 0),  # 2: Main.<init>()V
        (3, 0, 7),  # 3: Main.entry()I
        (4, 1, 0),  # 4: Mid.<init>()V
        (4, 0, 8),  # 5: Mid.foo()I
    ]

    # -----------------------------------------------------------------------
    # Code items
    # -----------------------------------------------------------------------

    # Base.<init>()V:  return-void
    #   regs=1, ins=1 (this), outs=0
    insns_base_init = [0x000E]           # return-void

    # Base.foo()I:  const/4 v0, #1;  return v0
    #   regs=2, ins=1 (this), outs=0
    insns_base_foo = [0x1012, 0x000F]   # const/4 v0,#1; return v0

    # Main.<init>()V:  return-void
    #   regs=1, ins=1 (this), outs=0
    insns_main_init = [0x000E]

    # Main.entry()I (static):
    #   new-instance v0, LMid;        opcode=0x22, type_idx=4
    #   invoke-direct {v0}, Mid.<init>() opcode=0x70, method_idx=4
    #   invoke-virtual {v0}, Base.foo()  opcode=0x6e, method_idx=1
    #   move-result v0                   opcode=0x0a
    #   return v0                        opcode=0x0f
    #   regs=2, ins=0 (static), outs=1
    insns_main_entry = [
        0x0022, 0x0004,              # new-instance v0, type@4
        0x1070, 0x0004, 0x0000,      # invoke-direct {v0}, method@4
        0x106E, 0x0001, 0x0000,      # invoke-virtual {v0}, method@1
        0x000A,                      # move-result v0
        0x000F,                      # return v0
    ]

    # Mid.<init>()V:  return-void
    #   regs=1, ins=1 (this), outs=0
    insns_mid_init = [0x000E]

    # Mid.foo()I:  const/4 v0, #2;  return v0
    #   regs=2, ins=1 (this), outs=0
    insns_mid_foo = [0x2012, 0x000F]   # const/4 v0,#2; return v0

    # -----------------------------------------------------------------------
    # Layout
    # -----------------------------------------------------------------------
    header_size = 0x70

    off = header_size

    string_ids_off = off
    off += len(strings) * 4

    type_ids_off = off
    off += len(type_string_ids) * 4

    proto_ids_off = off
    off += len(protos) * 12

    field_ids_size = 0
    field_ids_off = 0

    method_ids_off = off
    off += len(method_ids) * 8

    class_defs_off = off
    off += 3 * 32  # three class_def_items

    data_off = _align4(off)

    # -----------------------------------------------------------------------
    # Build data section
    # -----------------------------------------------------------------------
    data = bytearray()

    # --- string data items ---
    string_data_offs: list[int] = []
    for s in strings:
        string_data_offs.append(data_off + len(data))
        data.extend(_string_data_item(s))

    # 4-byte align before code items
    while (data_off + len(data)) % 4 != 0:
        data.append(0)

    # --- code items (all 6) ---
    def _code_item(registers_size, ins_size, outs_size, insns):
        hdr = struct.pack(
            "<HHHHII",
            registers_size,
            ins_size,
            outs_size,
            0,    # tries_size
            0,    # debug_info_off
            len(insns),
        )
        body = struct.pack("<" + "H" * len(insns), *insns)
        return hdr + body

    def _append_code(registers_size, ins_size, outs_size, insns):
        while (data_off + len(data)) % 4 != 0:
            data.append(0)
        ci_off = data_off + len(data)
        data.extend(_code_item(registers_size, ins_size, outs_size, insns))
        return ci_off

    base_init_off = _append_code(1, 1, 0, insns_base_init)
    base_foo_off = _append_code(2, 1, 0, insns_base_foo)
    main_init_off = _append_code(1, 1, 0, insns_main_init)
    main_entry_off = _append_code(2, 0, 1, insns_main_entry)
    mid_init_off = _append_code(1, 1, 0, insns_mid_init)
    mid_foo_off = _append_code(2, 1, 0, insns_mid_foo)

    # --- class data items ---
    def _encoded_method(method_idx_diff, access_flags, code_off):
        return (
            _uleb128(method_idx_diff)
            + _uleb128(access_flags)
            + _uleb128(code_off)
        )

    ACC_PUBLIC = 0x1
    ACC_STATIC = 0x8
    ACC_CONSTRUCTOR = 0x10000
    ACC_PUB_CTOR = ACC_PUBLIC | ACC_CONSTRUCTOR

    # LBase; class data
    #   direct:  method 0 (<init>)   diff=0, acc=ACC_PUB_CTOR
    #   virtual: method 1 (foo)      diff=1 (from 0), acc=ACC_PUBLIC
    base_class_data_off = data_off + len(data)
    data.extend(
        _uleb128(0)   # static_fields_size
        + _uleb128(0)  # instance_fields_size
        + _uleb128(1)  # direct_methods_size
        + _uleb128(1)  # virtual_methods_size
        + _encoded_method(0, ACC_PUB_CTOR, base_init_off)   # method 0
        + _encoded_method(1, ACC_PUBLIC, base_foo_off)       # method 1 (diff from 0)
    )

    # LMain; class data
    #   direct:  method 2 (<init>)   diff=2, acc=ACC_PUB_CTOR
    #   direct:  method 3 (entry)    diff=1, acc=ACC_PUBLIC|ACC_STATIC
    #   virtual: (none)
    main_class_data_off = data_off + len(data)
    data.extend(
        _uleb128(0)
        + _uleb128(0)
        + _uleb128(2)  # direct_methods_size
        + _uleb128(0)  # virtual_methods_size
        + _encoded_method(2, ACC_PUB_CTOR, main_init_off)        # method 2
        + _encoded_method(1, ACC_PUBLIC | ACC_STATIC, main_entry_off)  # method 3
    )

    # LMid; class data
    #   direct:  method 4 (<init>)   diff=4, acc=ACC_PUB_CTOR
    #   virtual: method 5 (foo)      diff=5 (from 0), acc=ACC_PUBLIC
    mid_class_data_off = data_off + len(data)
    data.extend(
        _uleb128(0)
        + _uleb128(0)
        + _uleb128(1)  # direct_methods_size
        + _uleb128(1)  # virtual_methods_size
        + _encoded_method(4, ACC_PUB_CTOR, mid_init_off)   # method 4
        + _encoded_method(5, ACC_PUBLIC, mid_foo_off)       # method 5 (diff from 0)
    )

    # 4-byte align before map_list
    while (data_off + len(data)) % 4 != 0:
        data.append(0)

    map_off = data_off + len(data)

    def _map_item(type_code, count, offset):
        return struct.pack("<HHII", type_code, 0, count, offset)

    # map_list items (must be sorted by type code, ascending)
    map_items = [
        _map_item(0x0000, 1, 0),                              # header_item
        _map_item(0x0001, len(strings), string_ids_off),      # string_id_item
        _map_item(0x0002, len(type_string_ids), type_ids_off),# type_id_item
        _map_item(0x0003, len(protos), proto_ids_off),         # proto_id_item
        _map_item(0x0005, len(method_ids), method_ids_off),   # method_id_item
        _map_item(0x0006, 3, class_defs_off),                  # class_def_item
        _map_item(0x2000, 3, base_class_data_off),             # class_data_item
        _map_item(0x2001, 6, base_init_off),                   # code_item (6 total)
        _map_item(0x2002, len(strings), string_data_offs[0]), # string_data_item
        _map_item(0x1000, 1, map_off),                         # map_list
    ]
    data.extend(struct.pack("<I", len(map_items)) + b"".join(map_items))

    data_size = len(data)
    file_size = data_off + data_size

    # -----------------------------------------------------------------------
    # Build fixed ID sections
    # -----------------------------------------------------------------------
    string_id_items = b"".join(struct.pack("<I", o) for o in string_data_offs)
    type_id_items = b"".join(struct.pack("<I", idx) for idx in type_string_ids)

    # proto_id_item: shorty_string_idx, return_type_idx, parameters_off (0 = no params)
    proto_id_items = b"".join(
        struct.pack("<III", shorty_idx, return_type_idx, 0)
        for shorty_idx, return_type_idx in protos
    )

    # method_id_item: class_type_idx (u16), proto_idx (u16), name_string_idx (u32)
    method_id_items = b"".join(
        struct.pack("<HHI", cls_idx, proto_idx, name_idx)
        for cls_idx, proto_idx, name_idx in method_ids
    )

    # class_def_items (32 bytes each, 3 classes)
    #   LBase;  class_idx=2, superclass=type1 (Object), data=base_class_data_off
    #   LMain;  class_idx=3, superclass=type1 (Object), data=main_class_data_off
    #   LMid;   class_idx=4, superclass=type2 (Base),   data=mid_class_data_off
    def _class_def(class_idx, superclass_idx, class_data_off):
        return struct.pack(
            "<IIIIIIII",
            class_idx,
            ACC_PUBLIC,      # access_flags
            superclass_idx,  # superclass_idx
            0,               # interfaces_off
            0xFFFFFFFF,      # source_file_idx: NO_INDEX
            0,               # annotations_off
            class_data_off,
            0,               # static_values_off
        )

    class_def_items = (
        _class_def(2, 1, base_class_data_off)   # Base extends Object
        + _class_def(3, 1, main_class_data_off)  # Main extends Object
        + _class_def(4, 2, mid_class_data_off)   # Mid extends Base
    )

    # -----------------------------------------------------------------------
    # Header
    # -----------------------------------------------------------------------
    header = bytearray(header_size)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 32, file_size)
    struct.pack_into("<I", header, 36, header_size)
    struct.pack_into("<I", header, 40, 0x12345678)  # endian_tag
    struct.pack_into("<I", header, 44, 0)            # link_size
    struct.pack_into("<I", header, 48, 0)            # link_off
    struct.pack_into("<I", header, 52, map_off)
    struct.pack_into("<I", header, 56, len(strings))
    struct.pack_into("<I", header, 60, string_ids_off)
    struct.pack_into("<I", header, 64, len(type_string_ids))
    struct.pack_into("<I", header, 68, type_ids_off)
    struct.pack_into("<I", header, 72, len(protos))
    struct.pack_into("<I", header, 76, proto_ids_off)
    struct.pack_into("<I", header, 80, field_ids_size)
    struct.pack_into("<I", header, 84, field_ids_off)
    struct.pack_into("<I", header, 88, len(method_ids))
    struct.pack_into("<I", header, 92, method_ids_off)
    struct.pack_into("<I", header, 96, 3)             # class_defs_size
    struct.pack_into("<I", header, 100, class_defs_off)
    struct.pack_into("<I", header, 104, data_size)
    struct.pack_into("<I", header, 108, data_off)

    # -----------------------------------------------------------------------
    # Assemble
    # -----------------------------------------------------------------------
    blob = (
        bytes(header)
        + string_id_items
        + type_id_items
        + proto_id_items
        + method_id_items
        + class_def_items
    )
    assert len(blob) <= data_off, f"layout overrun: {len(blob)} > {data_off}"
    blob += b"\x00" * (data_off - len(blob))
    blob += bytes(data)
    assert len(blob) == file_size, f"file_size mismatch: {len(blob)} != {file_size}"

    buf = bytearray(blob)
    sig = hashlib.sha1(buf[32:], usedforsecurity=False).digest()
    buf[12:32] = sig
    checksum = zlib.adler32(buf[12:]) & 0xFFFFFFFF
    struct.pack_into("<I", buf, 8, checksum)

    return bytes(buf)


if __name__ == "__main__":
    dex = build_inheritance_dex()
    out = (
        Path(__file__).parent.parent
        / "tests"
        / "fixtures"
        / "samples"
        / "inheritance.dex"
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(dex)
    print(f"wrote {out} ({len(dex)} bytes)")
