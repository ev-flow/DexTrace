# DexTrace Modules Overview

## Overview

DexTrace is organized as a small public API and CLI layer on top of internal parsing and decoding modules.

At a high level, the repository is split into:

- public API and CLI entry points
- APK / DEX parsing core
- API extraction and reference resolution
- Dalvik bytecode disassembly internals
- binary manifest parsing
- pytest-based tests and fixtures

This document explains the role of each Python module currently present in the repository.

---

## 1. Public API and CLI

### `src/dextrace/api.py`
Public Python-facing entry point for programmatic use of DexTrace functionality.

Use this module when integrating DexTrace into other Python workflows instead of invoking the CLI directly.

### `src/dextrace/cli/main.py`
Top-level CLI dispatcher.

Responsible for wiring subcommands and handing control to command-specific modules.

### `src/dextrace/cli/cmd_meta.py`
CLI command for APK / manifest metadata-oriented output.

Used when inspecting package metadata, manifest-derived information, or other high-level APK facts.

### `src/dextrace/cli/cmd_disasm.py`
CLI command focused on disassembly-oriented workflows.

Used when instruction-level or smali-like output is needed for debugging and parser verification.

### `src/dextrace/cli/cmd_dex.py`
CLI command for DEX/API-oriented workflows.

Used when inspecting DEX content, extracted references, or API-level evidence from bytecode.

### `src/dextrace/cli/__init__.py`
Package marker for CLI modules.

---

## 2. Core APK / DEX parsing modules

### `src/dextrace/core/apk_reader.py`
Reads APK archive contents.

Acts as a lower-level APK access layer used by metadata extraction, manifest parsing, and DEX loading workflows.

### `src/dextrace/core/apk_metadata.py`
Extracts high-level APK metadata.

Typical outputs include package-level metadata derived from the APK and manifest.

### `src/dextrace/core/dex_parser.py`
Main DEX parsing entry point.

Coordinates reading of DEX structures and provides parsed data needed by downstream extraction and analysis.

### `src/dextrace/core/dex_header.py`
Parses and represents DEX header information.

Useful when validating offsets, section sizes, and overall structural correctness of a DEX file.

### `src/dextrace/core/dex_string_table.py`
Handles DEX string table parsing and lookup.

Provides string resolution support for other parsed tables and decoded references.

### `src/dextrace/core/dex_proto_table.py`
Handles DEX prototype table parsing.

Used for method signature and descriptor-related resolution.

### `src/dextrace/core/dex_method_table.py`
Handles DEX method table parsing.

Provides method identity and indexing information used throughout DEX analysis.

### `src/dextrace/core/dex_code_map.py`
Maps parsed methods to code items or code-related structures.

Supports downstream workflows that need to connect method definitions with instruction streams.

### `src/dextrace/core/dex_api_extractor.py`
Extracts API usage evidence from parsed DEX methods.

This is one of the most important Quark-facing modules because it turns raw method/code content into extracted invoke/API facts that can later be consumed by higher-level rule engines.

### `src/dextrace/core/dex_resolver.py`
Resolves method or API references from parsed DEX data.

Used to convert lower-level parsed indices or references into more meaningful method/API identities.

### `src/dextrace/core/manifest_parser.py`
Higher-level manifest parsing bridge.

Works with the low-level binary manifest parser to produce usable manifest information for the rest of the project.

### `src/dextrace/core/__init__.py`
Package marker for core modules.

---

## 3. Core utilities

### `src/dextrace/core/utils/file_hash.py`
Utility for file hashing.

Useful for sample tracking, reproducibility notes, or identifying analysis inputs consistently.

### `src/dextrace/core/utils/__init__.py`
Package marker for core utilities.

---

## 4. Dalvik bytecode and disassembly internals

### `src/dextrace/dalvik/bytecode_source.py`
Abstraction for bytecode input sources.

Helps unify how raw instruction bytes are supplied to decoding and disassembly logic.

### `src/dextrace/dalvik/disassembler.py`
Primary Dalvik disassembly engine.

Transforms parsed bytecode into decoded instructions or instruction-oriented output used for debugging and verification.

### `src/dextrace/dalvik/format_size_infer.py`
Infers instruction size from opcode format rules.

Important for reliable instruction boundary handling.

### `src/dextrace/dalvik/format_table.py`
Defines or exposes opcode format metadata.

Acts as a reference source for operand decoding and instruction size logic.

### `src/dextrace/dalvik/opcode_table_builder.py`
Builds opcode lookup tables from underlying opcode definitions.

Supports deterministic and testable opcode metadata construction.

### `src/dextrace/dalvik/operand_decoder.py`
Decodes instruction operands from raw Dalvik bytecode.

A critical low-level component for correct disassembly and invoke extraction.

### `src/dextrace/dalvik/payload.py`
Handles payload-style instructions.

This includes instruction forms that need specialized decoding beyond ordinary opcode handling.

### `src/dextrace/dalvik/size_resolver.py`
Resolves or normalizes instruction size behavior.

Closely related to bytecode traversal correctness.

### `src/dextrace/dalvik/smali.py`
Smali-related helpers or formatting support.

Used when rendering or reasoning about disassembled instruction output in a smali-adjacent representation.

### `src/dextrace/dalvik/types.py`
Shared type definitions or structures for Dalvik-related logic.

Provides consistency across disassembler and decoder internals.

### `src/dextrace/dalvik/__init__.py`
Package marker for Dalvik modules.

### `src/dextrace/dalvik/data/__init__.py`
Package marker for bundled data resources used by Dalvik internals.

---

## 5. Manifest parsing

### `src/dextrace/manifest/axml_parser.py`
Low-level binary AndroidManifest AXML parser.

This module is the foundation for manifest decoding and is typically used indirectly via `core/manifest_parser.py`.

### `src/dextrace/manifest/__init__.py`
Package marker for manifest modules.

---

## 6. Dalvik VM interpreter

### `src/dextrace/vm/engine.py`
Main interpreter loop and opcode dispatch for the Dalvik VM.

Takes a parsed DEX, a method signature, and optional arguments; executes the
method through a register-based frame stack; returns the final register value or
raises `DexTraceVMError`. Opcode handlers are registered as a dict keyed by
mnemonic. Invoke variants (virtual, interface, direct, static, super) each resolve
through the class hierarchy; invoke-virtual and invoke-interface share the same
runtime-class vtable path. Accepts an optional `ExecutionTrace` for instruction-level
recording.

### `src/dextrace/vm/heap.py`
Object heap with typed `HeapEntry` handles.

Allocates objects, arrays, and primitives by class descriptor. Provides a
`ClassHierarchy` for subtype checks used by check-cast, instance-of, and vtable
resolution. The heap resets between `vm.run()` calls; static fields persist for
the duration of a run.

### `src/dextrace/vm/trace.py`
Opt-in `ExecutionTrace` — records one `TraceStep` per executed instruction.

Pass `execution_trace=ExecutionTrace()` to `DalvikVM(...)` to enable. Each step
captures: mnemonic, register writes, `branch_taken`, `frame_changed`, and
`duration_ns`. Zero overhead when not attached (single `None` check per step).

### `src/dextrace/vm/int_ops.py`
Signed 32-bit and 64-bit integer arithmetic helpers (`i32`, `i64`).

Wraps Python's arbitrary-precision integers to Java's signed-overflow semantics
so arithmetic opcodes produce the correct signed results.

### `src/dextrace/vm/handlers/`
Per-family opcode handlers, each registered with `engine._eval`.

* `arithmetic.py`: add/sub/mul/div/rem/and/or/xor/shl/shr/ushr for int and long
* `array.py`: new-array, filled-new-array, fill-array-data, aget/aput, array-length
* `branch.py`: goto, if-*, packed-switch, sparse-switch
* `compare.py`: cmpl/cmpg-float, cmp-long
* `field.py`: iget/iput/sget/sput for all types including wide and object
* `move.py`: move, move-wide, move-result, move-exception
* `throw.py`: throw — raises `_ThrowSignal` for try/catch handling
* `type_check.py`: check-cast, instance-of, monitor-enter, monitor-exit
* `type_conv.py`: int-to-long, long-to-int, and related narrowing/widening

### `src/dextrace/vm/android_stubs/`
Android API stub implementations for IoC extraction.

* `sms.py`: `SmsManager.sendTextMessage` and related telephony stubs

Stubs are registered with the engine via a `trace_sink` callback; captured calls
appear in `--trace` JSON output.

### `src/dextrace/vm/errors.py`, `signals.py`, `state.py`, `call_frame.py`, `register_file.py`, `decoder.py`
Supporting modules: VM-specific exceptions, control-flow signals (`_ThrowSignal`,
`_ReturnSignal`), per-frame state (`VMState`), call frame and register file
management, and instruction decoding helpers.

---

## 8. Support modules

### `src/dextrace/errors.py`
Shared error and exception definitions.

Use this module when standardizing project-specific failure modes.

### `src/dextrace/version.py`
Package version information.

### `src/dextrace/__init__.py`
Top-level package marker and package exports.

---

## 9. Test suite overview

The test suite is organized by subsystem. Contributors should treat tests as the main executable specification for current behavior.

### Shared pytest setup

#### `tests/conftest.py`
Shared pytest fixtures and configuration.

#### `tests/fixtures/dex_factory.py`
Synthetic DEX fixture builder used by tests.

This is especially useful when adding deterministic parser or disassembler regression coverage without relying entirely on external samples.

#### `tests/fixtures/__init__.py`
Package marker for fixtures.

---

## 8. Test files by area

### CLI and smoke tests

#### `tests/test_cli_meta.py`
Covers CLI metadata behavior.

#### `tests/test_smoke.py`
Smoke coverage for basic package functionality.

### APK and metadata tests

#### `tests/test_apk_reader.py`
Coverage for APK archive reading behavior.

#### `tests/test_apk_metadata.py`
Coverage for APK metadata extraction.

### Manifest tests

#### `tests/test_manifest_parser.py`
Coverage for higher-level manifest parsing behavior.

### Core DEX parsing tests

#### `tests/test_dex_parser.py`
Coverage for DEX parser behavior.

#### `tests/test_dex_header.py`
Coverage for DEX header parsing.

#### `tests/test_dummy_dex_fixture.py`
Validates synthetic DEX fixture behavior.

### API extraction tests

#### `tests/test_dex_api_extractor.py`
Coverage for API extraction behavior and a key place to add regression tests when Quark-facing API evidence changes.

### Dalvik and disassembly tests

#### `tests/test_operand_decoder.py`
Coverage for operand decoding.

#### `tests/test_size_resolver.py`
Coverage for instruction size resolution.

#### `tests/test_opcode_table_builder.py`
Coverage for opcode lookup table construction.

#### `tests/test_format_size_infer_oracle.py`
Coverage for instruction size inference correctness.

#### `tests/test_disassembler_e2e_dummy_dex.py`
End-to-end disassembly coverage using synthetic DEX input.

#### `tests/test_disassembler_evidence_smali_hex.py`
Evidence-oriented disassembly checks tied to expected instruction representations.

#### `tests/test_dalvik_payload.py`
Coverage for payload-style instruction handling.

#### `tests/test_all_formats_inferable.py`
Checks format inference coverage.

#### `tests/test_generated_bytecode_vectors.py`
Coverage based on generated bytecode vectors.

### VM execution tests

#### `tests/test_vm_run_p5a.py` through `tests/test_vm_run_p5f.py`
End-to-end integration tests for VM execution. Each file pairs with a synthetic
DEX fixture in `tests/fixtures/samples/` and a fixture generator in `tools/`.

#### `tests/test_vm_run_p5a_x_p5d.py`
Cross-phase combo: try/catch + field access. Verifies NPE is caught when
`iget-object` receives a null receiver inside a try block.

#### `tests/vm/test_handlers.py`
Unit coverage for individual opcode handler behavior (array ops, arithmetic).

#### `tests/vm/test_heap.py`
Unit coverage for the object heap, `HeapEntry` structure, and class hierarchy.

#### `tests/vm/test_trace.py`
Unit coverage for `ExecutionTrace` / `TraceStep` recording. Verifies branch
recording, register write diffs, and frame-change detection.

#### `tests/vm/test_wide_arithmetic.py`, `test_switch_payload.py`, `test_type_check.py`
Focused unit tests for wide-operand arithmetic, switch payload decoding, and
type check opcodes respectively.

---

## 10. How to use this document during handoff

Use this document to answer three common contributor questions.

### “Where should I start reading?”
Start with:

1. `README.md`
2. `src/dextrace/api.py`
3. `src/dextrace/cli/main.py`
4. the relevant subsystem in `src/dextrace/core/`, `dalvik/`, or `manifest/`

### “Where should I change code?”
Map the problem to a subsystem first:

- metadata problem → `apk_reader.py`, `apk_metadata.py`
- manifest problem → `manifest_parser.py`, `axml_parser.py`
- DEX structure problem → `dex_parser.py`, related core tables
- API extraction problem → `dex_api_extractor.py`, `dex_resolver.py`
- instruction/disassembly problem → `dalvik/`
- VM execution problem → `vm/engine.py`, `vm/handlers/`, `vm/heap.py`
- Android API stub problem → `vm/android_stubs/`
- execution trace problem → `vm/trace.py`

### “Which tests should I run?”
Run the narrowest relevant subsystem tests first, then broaden if needed.
