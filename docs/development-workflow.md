# DexTrace Development Workflow

## Purpose

This document describes the recommended day-to-day contributor workflow for DexTrace.

It is intended to answer practical questions such as:

- where to make a change
- which tests to run
- how to validate parser or disassembler behavior
- how to reproduce and investigate Quark-facing mismatches

---

## 1. Local setup

Install the package in editable mode:

```bash
pip install -e .
```

Install test dependencies if needed:

```bash
pip install pytest
```

Optional Pipenv workflow:

```bash
pipenv install --dev
pipenv shell
```

Verify basic import:

```bash
python -c "import dextrace; print('ok')"
```

Run the test suite once before making changes:

```bash
pytest
```

---

## 2. General contributor loop

Use this loop for most changes:

1. identify the subsystem involved
2. read the relevant module(s)
3. run the closest existing tests
4. make the smallest change that fixes the issue
5. re-run targeted tests
6. run broader tests if the change affects shared logic
7. update documentation if contributor-facing behavior changed

---

## 3. Subsystem-oriented workflow

### A. CLI changes

Relevant files:

* `src/dextrace/cli/main.py`
* `src/dextrace/cli/cmd_meta.py`
* `src/dextrace/cli/cmd_disasm.py`
* `src/dextrace/cli/cmd_dex.py`

Typical reasons to modify:

* argument parsing
* output formatting
* command routing
* exposing a new inspection path

Validate with:

```bash
pytest tests/test_cli_meta.py tests/test_smoke.py
```

If the command output semantics changed, also update `README.md`.

---

### B. APK reader or metadata changes

Relevant files:

* `src/dextrace/core/apk_reader.py`
* `src/dextrace/core/apk_metadata.py`

Typical reasons to modify:

* APK entry loading issues
* metadata extraction bugs
* package-level information mismatches

Validate with:

```bash
pytest tests/test_apk_reader.py tests/test_apk_metadata.py
```

---

### C. Manifest parsing changes

Relevant files:

* `src/dextrace/core/manifest_parser.py`
* `src/dextrace/manifest/axml_parser.py`

Typical reasons to modify:

* binary AXML decoding issues
* manifest field extraction problems
* permission/component parsing mismatches

Validate with:

```bash
pytest tests/test_manifest_parser.py
```

If the parser output format changes, update the related documentation and examples.

---

### D. DEX structure parsing changes

Relevant files:

* `src/dextrace/core/dex_parser.py`
* `src/dextrace/core/dex_header.py`
* `src/dextrace/core/dex_string_table.py`
* `src/dextrace/core/dex_proto_table.py`
* `src/dextrace/core/dex_method_table.py`
* `src/dextrace/core/dex_code_map.py`

Typical reasons to modify:

* incorrect parsing offsets
* table lookup mismatches
* DEX structural edge cases
* code item mapping problems

Validate with:

```bash
pytest tests/test_dex_parser.py tests/test_dex_header.py
```

Then broaden as needed:

```bash
pytest -k dex
```

---

### E. API extraction and resolution changes

Relevant files:

* `src/dextrace/core/dex_api_extractor.py`
* `src/dextrace/core/dex_resolver.py`

Typical reasons to modify:

* missing invoke/API extraction
* incorrect method identity resolution
* Quark-facing API evidence mismatches

Validate with:

```bash
pytest tests/test_dex_api_extractor.py
```

If the issue is reported through Quark integration, also perform a Quark comparison workflow after DexTrace-side tests pass.

---

### F. Dalvik disassembly changes

Relevant files:

* `src/dextrace/dalvik/disassembler.py`
* `src/dextrace/dalvik/operand_decoder.py`
* `src/dextrace/dalvik/format_size_infer.py`
* `src/dextrace/dalvik/format_table.py`
* `src/dextrace/dalvik/opcode_table_builder.py`
* `src/dextrace/dalvik/payload.py`
* `src/dextrace/dalvik/size_resolver.py`
* `src/dextrace/dalvik/smali.py`
* `src/dextrace/dalvik/types.py`

Typical reasons to modify:

* wrong operand decoding
* bad instruction sizes
* payload decoding bugs
* incorrect disassembly output
* bytecode traversal bugs

Validate with:

```bash
pytest \
  tests/test_operand_decoder.py \
  tests/test_size_resolver.py \
  tests/test_opcode_table_builder.py \
  tests/test_format_size_infer_oracle.py \
  tests/test_disassembler_e2e_dummy_dex.py \
  tests/test_disassembler_evidence_smali_hex.py \
  tests/test_dalvik_payload.py \
  tests/test_all_formats_inferable.py \
  tests/test_generated_bytecode_vectors.py
```

---

### G. VM interpreter changes

Relevant files:

* `src/dextrace/vm/engine.py` — interpreter loop, frame management, opcode dispatch
* `src/dextrace/vm/heap.py` — object heap, class hierarchy
* `src/dextrace/vm/handlers/*.py` — opcode handler families
* `src/dextrace/vm/trace.py` — ExecutionTrace recording
* `src/dextrace/vm/android_stubs/` — Android API stubs
* `src/dextrace/cli/cmd_run.py` — `dextrace run` subcommand

Typical reasons to modify:

* wrong return value from a method
* incorrect behavior for a specific opcode or opcode family
* missing Android API stub
* extending `--trace` output
* new fixture for a feature not yet covered

Validate with:

```bash
pytest tests/vm/ tests/test_vm_run_p5*.py tests/test_vm_run_p5a_x_p5d.py
```

When adding a new opcode family:

1. add a handler file under `src/dextrace/vm/handlers/`
2. call `register(...)` from `engine.py`
3. write a synthetic DEX fixture in `tools/gen_pNx_fixture.py`
4. add an integration test in `tests/test_vm_run_pNx.py`
5. run the full suite to confirm no regressions

---

## 4. When to add tests

Add or extend tests when:

* a parser bug was fixed
* a previous mismatch now has a known reproduction
* instruction decoding logic changed
* a regression could silently return later
* contributor-facing behavior changed

Prefer the smallest effective test:

* unit test for local deterministic logic
* fixture-based parser test for structural cases
* targeted regression test for a previously observed failure

Use `tests/fixtures/dex_factory.py` when synthetic DEX data is enough.

---

## 5. Quark comparison workflow

DexTrace may be used as a core under Quark Engine. When a problem is reported as a Quark mismatch, use a disciplined comparison process.

### Recommended process

1. choose a fixed APK sample
2. use the same Quark version
3. use the same rule(s)
4. run Quark once with DexTrace
5. run Quark once with Androguard
6. save both outputs
7. diff the outputs
8. identify which rule(s) differ
9. trace the issue back to the most likely DexTrace subsystem
10. write the issue conservatively

### Keep the evidence

For every investigated mismatch, preserve:

* APK identifier or sample path
* rule IDs
* exact commands used
* DexTrace output
* Androguard output
* diff excerpt
* current hypothesis

### How to phrase hypotheses

Prefer conservative wording such as:

* inconsistent API matching
* method resolution difference
* invoke extraction gap
* framework API handling mismatch

Avoid claiming a root cause until it has been verified in code or tests.

---

## 6. Suggested issue investigation path

When Quark says a rule differs, ask:

### Does DexTrace fail to parse the APK or DEX correctly?

Look at:

* `apk_reader.py`
* `dex_parser.py`
* `dex_header.py`

### Does DexTrace parse but miss API evidence?

Look at:

* `dex_api_extractor.py`
* `dex_resolver.py`

### Does the problem look instruction-level?

Look at:

* `operand_decoder.py`
* `disassembler.py`
* `size_resolver.py`
* `payload.py`

### Does the rule rely on manifest facts?

Look at:

* `manifest_parser.py`
* `axml_parser.py`

---

## 7. Practical validation checklist before opening a PR

Before opening a PR, verify:

* the narrowest relevant tests pass
* no unrelated subsystem was changed accidentally
* the new behavior is explained in the PR description
* documentation was updated if needed
* Quark comparison was performed when the change is Quark-facing

A minimal PR description should include:

* what changed
* why
* how it was tested
* before/after behavior if applicable

---

## 8. Handoff guidance for the next contributor

When picking up unfinished work:

1. read `docs/current-status.md`
2. identify the affected subsystem
3. run the related tests first
4. reproduce the problem before changing code
5. preserve output diffs for future documentation

This is especially important for parser and API extraction issues, where small low-level changes can affect downstream analysis behavior.
