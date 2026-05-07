# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Setup

```bash
pip install -e .[dev]
python -c "import dextrace; print('ok')"  # verify
```

Docker alternative:
```bash
docker build -t dextrace-dev .
docker run --rm -it -v "$(pwd)":/workspace -w /workspace dextrace-dev bash
# then: pip install -e .[dev]
```

## Commands

```bash
# Run all tests
pytest

# Run a single test file
pytest tests/test_dex_api_extractor.py

# Run tests by keyword
pytest -k api_extractor

# CLI
dextrace meta sample.apk
dextrace dex --header sample.apk
dextrace dex --apis sample.apk
dextrace dex --api-sets sample.apk
dextrace dex --api-seq sample.apk
dextrace dex --api-seq --json sample.apk
```

## Architecture

DexTrace is a layered APK/DEX static analysis library. It does **not** perform malware classification — it produces structured, reproducible evidence consumed by downstream engines like Quark Engine.

### Data flow

```
APK file
  └─> ApkReader           (core/apk_reader.py)       — raw ZIP access
        ├─> ApkMetadata   (core/apk_metadata.py)      — hashes, file metadata
        ├─> ManifestParser(core/manifest_parser.py)   — bridges to axml_parser
        │     └─> AXMLParser (manifest/axml_parser.py) — binary AXML decode
        └─> DEX bytes
              └─> DexParser (core/dex_parser.py)      — coordinates table loading
                    ├─> DexHeader        (core/dex_header.py)
                    ├─> DexStringTable   (core/dex_string_table.py)
                    ├─> DexProtoTable    (core/dex_proto_table.py)
                    ├─> DexMethodTable   (core/dex_method_table.py)
                    └─> DexCodeMap       (core/dex_code_map.py)
                          └─> DexApiExtractor (core/dex_api_extractor.py)
                                └─> DexResolver (core/dex_resolver.py)
                                      └─> DalvikDisassembler (dalvik/disassembler.py)
```

### Public surface

**`src/dextrace/api.py`** is the stable programmatic entry point Quark Engine imports. Key functions:
- `build_dex_report(path)` — returns all `invoke-*` API calls as a dict (Stage 2)
- `build_disasm_report(path, method_sig)` — returns smali disassembly for a specific method
- `extract_api_calls()`, `disasm_method()` — convenience wrappers over the above
- `parse_manifest()`, `get_apk_permissions()` — manifest helpers

**`src/dextrace/cli/main.py`** dispatches to five CLI subcommands registered via `cmd_*.register(subparser)`: `meta`, `dex`, `disasm`, `trace`, and `run`.

### Quark Engine integration (API extraction stages)

The Quark-aligned detection stages are implemented in `core/dex_api_extractor.py`:
- **Stage 2** (`--apis`): all `invoke-*` instructions with caller/callee resolved
- **Stage 3** (`--api-sets`): APIs grouped per caller method (order-independent)
- **Stage 4** (`--api-seq`): static call order within each method (offset-ordered)

`dex_resolver.py` converts raw DEX indices to `class/method/proto` strings. Changes here directly affect Quark rule matching.

### Dalvik internals (`src/dextrace/dalvik/`)

The disassembly pipeline: `bytecode_source.py` → `operand_decoder.py` → `disassembler.py` → `smali.py`. Opcode metadata is built from `dalvik/data/bytecode.txt` at import time via `opcode_table_builder.py`. Instruction sizes are determined by `format_size_infer.py` + `size_resolver.py`. Payload-type instructions (switch tables, fill-array) are handled separately in `payload.py`.

### Synthetic DEX fixtures

`tests/fixtures/dex_factory.py` builds minimal valid DEX bytes for deterministic parser/disassembler tests. Use it rather than shipping binary APK files for new regression coverage.

## Subsystem → test mapping

| Area changed | Tests to run |
|---|---|
| CLI | `pytest tests/test_cli_meta.py tests/test_smoke.py` |
| APK reader / metadata | `pytest tests/test_apk_reader.py tests/test_apk_metadata.py` |
| Manifest | `pytest tests/test_manifest_parser.py` |
| DEX structure | `pytest tests/test_dex_parser.py tests/test_dex_header.py` |
| API extraction | `pytest tests/test_dex_api_extractor.py` |
| Dalvik / disassembly | `pytest -k disassembler` (or the full set in `docs/development-workflow.md`) |
| VM / execution engine | `pytest tests/vm/ tests/test_vm_run_try_catch*.py tests/test_vm_run_long_arithmetic.py tests/test_vm_run_packed_switch.py tests/test_vm_run_instance_fields.py tests/test_vm_run_arrays.py tests/test_vm_run_interface_dispatch.py` |

## Commit style

```
fix: correct invoke target extraction for dex api matching
test: add regression coverage for api extractor mismatch case
docs: update module overview for new resolver behavior
refactor: simplify dalvik operand decoding path
```

## Design System

Always read `DESIGN.md` before making any CLI output or formatting decisions.
All output format, color, spacing, and message conventions are defined there.
Do not deviate without explicit user approval.

Key rules from DESIGN.md:
- stdout is data only (JSON or return value). All messages → stderr.
- `[ERROR]`, `[WARN]`, `[INFO]` are fixed-width prefixes. `[INFO]` only with `--verbose`.
- Color is semantic-only: cyan = identifiers, amber = values, green = return/success, red = error.
- Default JSON output is never colored — must be pipe-safe.
- Exit codes: 0 = success, 1 = user error, 2 = VM error, 3 = parse error.

## Quark mismatch investigations

When a rule mismatch is observed between Quark+DexTrace and Quark+Androguard:
1. Fix APK, Quark version, and rule IDs across both runs
2. Trace the gap: APK parse failure → `apk_reader`/`dex_parser`; missing API evidence → `dex_api_extractor`/`dex_resolver`; instruction-level → `operand_decoder`/`disassembler`/`size_resolver`/`payload`
3. Use conservative wording until verified in code: "inconsistent API matching", "invoke extraction gap", "method resolution difference"
4. Preserve APK id, rule IDs, commands, both outputs, and diff in the issue
