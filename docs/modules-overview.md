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

### `src/dextrace/cli/cmd_run.py`
CLI command implementing `dextrace run`.

Loads a DEX (or the DEX embedded in an APK), builds the method map, and executes a
single entry method on the Dalvik VM (`src/dextrace/vm/`), printing the return value,
optional call tree, and optional registers.

### `src/dextrace/cli/_io.py`
Shared input-loading helper for CLI subcommands.

Provides `load_dex_bytes`, which loads DEX bytes from a `.dex` file or extracts
`classes.dex` from an `.apk`, so each command does not re-implement input handling.

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

### `src/dextrace/core/dex_class_iter.py`
Shared iteration over DEX `class_def` and `encoded_method` structures.

Walks class definitions without going through the full `dex_code_map.py` pipeline; used
by the VM's `class_hierarchy.py` vtable builder and other class-walking code.

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

## 5. Dalvik VM execution engine

The `src/dextrace/vm/` package executes Dalvik bytecode (dynamic analysis). This is
distinct from `src/dextrace/dalvik/`, which only decodes and disassembles instructions.
It is the subsystem behind the `dextrace run` command.

### `src/dextrace/vm/engine.py`
`DalvikVM`, the iterative execution engine. Drives the instruction loop, invoke
resolution, handler/stub dispatch, try/catch handling, and trace emission.

### `src/dextrace/vm/decoder.py`
Static-walk adapter that yields a method's decoded instructions for the engine.
Raises `MethodNotFound` / `DexParseError` (`walk_method`).

### `src/dextrace/vm/state.py`
`VMState`: the mutable execution state carried through the instruction loop.

### `src/dextrace/vm/register_file.py`
`RegisterFile`: the Dalvik register file for a frame.

### `src/dextrace/vm/call_frame.py`
`CallFrame`: caller state saved at invoke time so execution can resume after a call.

### `src/dextrace/vm/heap.py`
Object heap mapping integer handles to `HeapEntry` records (`ObjectHeap`).

### `src/dextrace/vm/class_hierarchy.py`
`ClassHierarchy`: vtable construction and virtual method resolution.

### `src/dextrace/vm/int_ops.py`
32/64-bit integer and IEEE 754 float/double helpers used by the arithmetic handlers.

### `src/dextrace/vm/signals.py`
Internal exception-flow signals raised by handlers (`_ThrowSignal`).

### `src/dextrace/vm/trace.py`
Execution tracing: per-instruction `TraceStep` / `ExecutionTrace` and the
`CallNode` / `CallTreeTrace` call-tree representation.

### `src/dextrace/vm/errors.py`
VM exception hierarchy (`DexTraceVMError`, `DexTraceNotImplementedError`, and Java-style
exceptions such as `NullPointerException`, `ArithmeticException`, `ClassCastException`).

### `src/dextrace/vm/__init__.py`
Package marker for VM modules.

### Opcode handlers — `src/dextrace/vm/handlers/`

Each handler module registers the opcodes it implements with the engine.

- `arithmetic.py`: integer/long/float/double arithmetic instructions
- `array.py`: array creation and element access
- `branch.py`: conditional branch and `goto` instructions
- `compare.py`: `cmp*` comparison instructions
- `field.py`: instance and static field access
- `move.py`: `move`, `const`, and `move-result`/`move-exception` instructions
- `throw.py`: the `throw vAA` opcode
- `type_check.py`: `check-cast`, `instance-of`, `monitor-enter`, `monitor-exit`
- `type_conv.py`: numeric type-conversion instructions
- `__init__.py`: package marker for handler modules

### Android API stubs — `src/dextrace/vm/android_stubs/`

Simulated Android/Java framework methods so framework-dependent code can run without a
device. `__init__.py` is the stub registry and shared value types (`StubResult`, `Value`,
`Wide`, `ObjectRef`).

- `content.py`: `ContentProvider` / `ContentResolver` and network connectivity stubs
- `filesystem.py`: file I/O, Android UI, network extras, and `String` helpers
- `intent.py`: `Intent`, `Bundle`, and `Context` stubs
- `network.py`: Java networking stubs (`URL`/`HttpURLConnection`/streams)
- `runtime.py`: `Runtime`, `Process`, `SharedPreferences`, and system stubs
- `sms.py`: `SmsManager` stubs
- `telephony.py`: telephony / `SmsMessage` stubs
- `text.py`: `java.lang`/`java.util` stubs (`StringBuilder`, `String`, date formatting)

---

## 6. Manifest parsing

### `src/dextrace/manifest/axml_parser.py`
Low-level binary AndroidManifest AXML parser.

This module is the foundation for manifest decoding and is typically used indirectly via `core/manifest_parser.py`.

### `src/dextrace/manifest/__init__.py`
Package marker for manifest modules.

---

## 7. Support modules

### `src/dextrace/errors.py`
Shared error and exception definitions.

Use this module when standardizing project-specific failure modes.

### `src/dextrace/version.py`
Package version information.

### `src/dextrace/__init__.py`
Top-level package marker and package exports.

---

## 8. Test suite overview

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

## 9. Test files by area

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

#### `tests/test_dex_catch.py`
Parser-level coverage for `try_item` and `encoded_catch_handler` decoding (try/catch
region and typed catch handlers).

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

End-to-end coverage for the Dalvik VM (`src/dextrace/vm/`) and `dextrace run`. Most are
named `tests/test_vm_run_*.py` and execute a small synthetic method to assert a result:

#### `tests/test_vm_run_const_return.py`, `tests/test_vm_run_fibonacci.py`, `tests/test_vm_run_long_arithmetic.py`
Arithmetic, constants, recursion, and wide (long) value handling.

#### `tests/test_vm_run_arrays.py`, `tests/test_vm_run_instance_fields.py`, `tests/test_vm_run_packed_switch.py`
Array operations, instance field access, and `packed-switch` control flow.

#### `tests/test_vm_run_inheritance.py`, `tests/test_vm_run_interface_dispatch.py`
Virtual / interface method dispatch through the class hierarchy.

#### `tests/test_vm_run_try_catch.py`, `tests/test_vm_run_try_catch_with_fields.py`, `tests/test_vm_run_try_catch_with_stubs.py`
Exception flow, including interaction with fields and Android API stubs.

#### `tests/test_vm_null_receiver.py`, `tests/test_vm_pending_result_lifecycle.py`
Null-receiver handling and the `move-result` pending-result lifecycle.

#### `tests/vm/`
Additional VM-focused tests and fixtures.

Run the VM tests with `pytest -k vm`.

---

## 10. How to use this document during handoff

Use this document to answer three common contributor questions.

### “Where should I start reading?”
Start with:

1. `README.md`
2. `src/dextrace/api.py`
3. `src/dextrace/cli/main.py`
4. the relevant subsystem in `src/dextrace/core/`, `dalvik/`, `vm/`, or `manifest/`

### “Where should I change code?”
Map the problem to a subsystem first:

- metadata problem → `apk_reader.py`, `apk_metadata.py`
- manifest problem → `manifest_parser.py`, `axml_parser.py`
- DEX structure problem → `dex_parser.py`, related core tables
- API extraction problem → `dex_api_extractor.py`, `dex_resolver.py`
- instruction/disassembly problem → `dalvik/`
- VM execution / `dextrace run` problem → `src/dextrace/vm/`, `src/dextrace/cli/cmd_run.py`

### “Which tests should I run?”
Run the narrowest relevant subsystem tests first, then broaden if needed.

- VM execution changes → `pytest -k vm`
