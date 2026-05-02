# DexTrace

**DexTrace** is a lightweight core for **Android APK / DEX parsing and call-tracing**.

It **does not decide whether an APK is malicious**.  
Instead, DexTrace focuses on producing a **clean, standardized, and reproducible representation** of:

- APK metadata
- AndroidManifest structure
- DEX internal tables
- API call evidence and method-level cross-references (XREF)

These results are designed to be **consumed by higher-level engines**, such as  
👉 [Quark Engine](https://github.com/ev-flow/quark-engine) or other static / hybrid analysis frameworks.

---

## Goals

DexTrace is intended to provide:

- lightweight APK and DEX parsing without depending on a full Android analysis framework
- deterministic Dalvik bytecode disassembly and inspection
- structured API extraction from DEX bytecode
- manifest and APK metadata parsing
- a Python API and CLI for inspection, debugging, and integration
- reproducible outputs suitable for downstream rule engines


## ✨ Current Features

### APK Support
- File hashes (MD5 / SHA1 / SHA256)
- File size and ZIP entries
- APK archive reading for downstream parsing workflows

### AndroidManifest Parsing
- Supports **binary AXML** and **plain XML**
- Extracts:
  - package name
  - permissions
  - activities
  - services
  - receivers
  - providers
- Safe fallback for malformed or missing manifests

### DEX Header Parsing
- Strict DEX magic validation (`dex\n035`, `cdex`)
- Full header field decoding
- Defensive handling of truncated / invalid DEX files

### DEX Bytecode Parsing (Core)
- `code_item` parsing
- instruction iteration
- offset-aware bytecode handling
- method/code mapping support
- designed to scale toward richer control-flow or data-flow analysis later

---

## 🔍 API Call Tracing (Quark-aligned)

DexTrace implements **progressive API tracing stages** aligned with  
**Quark Engine’s 5-stage detection model**.

### Stage 2 – API Calls
- extracts all `invoke-*` instructions
- resolves:
  - caller class / method / prototype
  - callee class / method / prototype
  - opcode type and bytecode offset
- produces **structured XREF output**
- safe against malformed indices and corrupted tables

### Stage 3 – API Sets (Per Method)
- groups APIs **per caller method**
- represents *which APIs are used together*
- order-independent
- designed for **combination-based rule matching**

### Stage 4 – API Call Sequences
- preserves **static call order** within each method
- offset-aware ordering of `invoke-*` instructions
- method-local (no CFG explosion)
- designed for **sequence-based rule matching**

---

## Repository Structure

```text
src/dextrace/
  api.py                  # public Python API entry point
  cli/                    # CLI entry points (meta, dex, disasm, trace, run)
  core/                   # APK/DEX parsing and API extraction core
  dalvik/                 # Dalvik disassembly and opcode utilities
  manifest/               # binary AndroidManifest parsing
  vm/                     # Dalvik VM interpreter (engine, heap, handlers, trace)
  errors.py               # shared project exceptions
  version.py              # package version

tests/
  fixtures/               # synthetic fixtures used by tests
  vm/                     # VM-specific unit tests (handlers, trace, heap)
  test_*.py               # pytest-based test suite

tools/
  gen_p*.py               # DEX fixture generators for VM test samples

docs/
  modules-overview.md     # module-by-module handoff guide
  development-workflow.md # contributor workflow and validation notes
  current-status.md       # current state, known gaps, handoff notes
```

### Key areas

#### `src/dextrace/cli/`

Command-line entry points.

* `main.py`: top-level CLI dispatcher
* `cmd_meta.py`: metadata-oriented inspection
* `cmd_disasm.py`: disassembly-oriented inspection
* `cmd_dex.py`: DEX/API-oriented inspection

#### `src/dextrace/core/`

Core APK / DEX parsing and API extraction logic.

Includes:

* APK reading
* APK metadata extraction
* manifest parsing bridge
* DEX structure parsing
* method/code mapping
* API extraction
* method/API resolution

#### `src/dextrace/dalvik/`

Dalvik bytecode internals.

Includes:

* opcode format metadata
* operand decoding
* instruction size handling
* payload decoding
* disassembly support
* smali-oriented helpers

#### `src/dextrace/manifest/`

Low-level binary AXML parsing used by manifest-related workflows.

#### `src/dextrace/vm/`

Dalvik VM interpreter for dynamic method execution.

Includes:

* `engine.py`: main interpreter loop, opcode dispatch, frame management
* `heap.py`: object heap with typed handles and class hierarchy
* `handlers/`: per-family opcode handlers (arithmetic, array, branch, field, move, type checks)
* `trace.py`: opt-in `ExecutionTrace` — records one `TraceStep` per executed instruction
* `android_stubs/`: Android API stubs (SMS, telephony) used for IoC extraction
* supporting modules: `int_ops.py`, `register_file.py`, `call_frame.py`, `signals.py`, `state.py`

---

## 📦 Installation

### Development install (editable mode)

```bash
git clone https://github.com/ev-flow/DexTrace.git
cd DexTrace
pip install -e .
```

### Optional Pipenv workflow

```bash
pipenv install --dev
pipenv shell
```

---

## CLI Usage

DexTrace exposes a single CLI entry point:

```bash
dextrace --help
```

## APK Metadata

Show hashes, manifest summary, and DEX presence:

```bash
dextrace meta sample.apk
```

## DEX Header

Parse and display full DEX header fields:

```bash
dextrace dex --header sample.apk
```

## DEX Summary

Show a concise overview of DEX structure:

```bash
dextrace dex --summary sample.apk
```

## 🔗 API Tracing Commands

### Stage 2 – API Calls

```bash
dextrace dex --apis sample.apk
```

### Stage 3 – API Sets

```bash
dextrace dex --api-sets sample.apk
```

### Stage 4 – API Sequences

```bash
dextrace dex --api-seq sample.apk
```

### JSON Output

All commands support structured JSON output:

```bash
dextrace dex --api-seq --json sample.apk
```

## Dynamic Execution

`dextrace run` executes a single DEX method through the built-in Dalvik VM and
prints the return value. It supports the full P1–P5 opcode surface: arithmetic,
field access, arrays, try/catch, vtable dispatch, and invoke-interface.

### Run a method

```bash
dextrace run classes.dex --entry 'Lcom/example/Foo;->compute(I)I' --arg 10
```

### Capture Android API calls (IoC extraction)

```bash
dextrace run malware.dex --entry 'Lcom/evil/SMS;->sendSMS()V' --trace
```

`--trace` prints captured Android stub calls (SMS, telephony, etc.) as JSON.

### Pass multiple arguments

```bash
dextrace run classes.dex --entry 'Lcom/example/Foo;->bar(ILjava/lang/String;)I' \
  --arg 42 --arg hello
```

Or as a JSON list:

```bash
dextrace run classes.dex --entry 'Lcom/example/Foo;->bar(II)I' --args '[1, 2]'
```

### Strict stub mode

```bash
dextrace run classes.dex --entry 'Lcom/example/Foo;->bar()V' --strict-stubs
```

Exits with code 2 on any unimplemented Android API call instead of silently
continuing with a null result.

## Example Output

### Stage 2

```json
{
  "dex": {
    "summary": {
      "magic": "dex\n035\u0000",
      "version": "035",
      "file_size": 717940,
      "string_ids_size": 6285,
      "method_ids_size": 5455,
      "class_defs_size": 534
    },
    "api_calls": [
      {
        "caller": {
          "class": "Landroid/support/v4/accessibilityservice/AccessibilityServiceInfoCompat;",
          "method": "<clinit>",
          "proto": "()V"
        },
        "invoke": {
          "opcode": "invoke-direct",
          "offset": 16
        },
        "callee": {
          "class": "Landroid/support/v4/accessibilityservice/AccessibilityServiceInfoCompat$AccessibilityServiceInfoJellyBeanMr2;",
          "method": "<init>",
          "proto": "()V"
        }
      }
    ],
    "api_calls_count": 1
  }
}
```

---

## Running Tests

Run the full test suite:

```bash
pytest
```

Run a targeted test file:

```bash
pytest tests/test_dex_parser.py
```

Run tests by keyword:

```bash
pytest -k api_extractor
```
### Suggested subsystem-oriented test runs

* CLI changes:

  ```bash
  pytest tests/test_cli_meta.py tests/test_smoke.py
  ```

* APK / metadata changes:

  ```bash
  pytest tests/test_apk_reader.py tests/test_apk_metadata.py
  ```

* manifest changes:

  ```bash
  pytest tests/test_manifest_parser.py
  ```

* DEX parser changes:

  ```bash
  pytest tests/test_dex_parser.py tests/test_dex_header.py
  ```

* API extraction changes:

  ```bash
  pytest tests/test_dex_api_extractor.py
  ```

* Dalvik / disassembly changes:

  ```bash
  pytest -k disassembler
  ```

* VM / execution engine changes:

  ```bash
  pytest tests/vm/ tests/test_vm_run_p5*.py tests/test_vm_run_p5a_x_p5d.py
  ```

---

## Development Notes

DexTrace is organized by subsystem, so contributors should usually:

1. identify the affected subsystem first
2. make the smallest targeted change possible
3. run the closest subsystem tests first
4. broaden validation only if the change touches shared logic
5. update documentation when contributor-facing behavior changes

When DexTrace is used under Quark Engine, Quark-facing mismatches should be investigated conservatively and evidence-first. Preserve:

* APK identifier or sample path
* rule IDs
* exact commands used
* DexTrace output
* comparison-core output such as Androguard
* diff excerpts
* current hypothesis

Prefer wording such as:

* inconsistent API matching
* resolution difference
* invoke extraction gap

until the exact root cause is verified in code and tests.

---

## Documentation

Additional contributor documentation:

* [Contributing](CONTRIBUTING.md)
* [Modules Overview](docs/modules-overview.md)
* [Development Workflow](docs/development-workflow.md)
* [Current Status](docs/current-status.md)

---

## Samples and Build Artifacts

The repository may include:

* extracted sample APK directories for validation or reproduction
* generated build artifacts under `dist/`

These are useful for testing and packaging, but they are **not** the core implementation surface.

---

## Relationship with Quark Engine

DexTrace can be used as an analysis core under Quark Engine.
In that setup:

* **DexTrace** is responsible for parsing APK / DEX input and extracting evidence
* **Quark Engine** is responsible for higher-level rule matching and scoring

When validating Quark-facing behavior, comparisons should keep the APK, rule set, and Quark version fixed while only changing the analysis core.

---

## License

See [LICENSE](LICENSE).
