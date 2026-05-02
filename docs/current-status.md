# DexTrace Current Status

## Purpose

This document records the current handoff state of DexTrace.

It is not a changelog. It is a practical snapshot for the next contributor: what the repository currently covers, what is known to work, what areas are still evolving, and what known gaps or investigation tracks already exist.

---

## 1. Current implementation status

At the current stage, DexTrace includes:

- APK archive reading
- APK metadata extraction
- binary AndroidManifest parsing
- DEX structure parsing
- Dalvik bytecode disassembly support
- API extraction from parsed bytecode
- CLI commands for metadata, disassembly, DEX-oriented inspection, and dynamic execution
- a Dalvik VM interpreter (`src/dextrace/vm/`) covering the full P1–P5 opcode surface:
  wide arithmetic, field access, arrays, try/catch, vtable dispatch, invoke-interface,
  switch payloads, type checks, and opt-in `ExecutionTrace` recording
- Android API stubs for IoC extraction via `dextrace run --trace`
- pytest coverage across parser, manifest, disassembly, API extraction, and VM areas
  (339 tests passing as of Phase 5f + P5.3)

The codebase is organized into distinct subsystems under:

- `src/dextrace/cli/`
- `src/dextrace/core/`
- `src/dextrace/dalvik/`
- `src/dextrace/manifest/`
- `src/dextrace/vm/`
- `tests/` (including `tests/vm/`)

This makes the repository reasonably handoff-friendly once the subsystem boundaries are understood.

---

## 2. Stable areas

The following areas appear structurally well-defined in the repository.

### CLI structure
The project has a clear CLI split:

- `cmd_meta.py`
- `cmd_disasm.py`
- `cmd_dex.py`
- `cmd_trace.py`
- `cmd_run.py` — dynamic execution via the Dalvik VM

### Core parser boundaries
APK, manifest, DEX parsing, and API extraction are separated into different modules rather than mixed together in a single file.

### Dalvik internals
Dalvik-related concerns are separated into opcode metadata, operand decoding, payload handling, size handling, and disassembly support.

### Dalvik VM interpreter
The `src/dextrace/vm/` subsystem is structurally stable. The engine, heap, and handler modules are decoupled; new opcode families can be added by creating a handler file and calling `register(eval_dict, ...)`. The `ExecutionTrace` opt-in recording adds zero overhead to normal execution paths.

### Test coverage shape
The test suite is organized by subsystem, which makes targeted regression work practical. VM tests live under `tests/vm/` (unit) and `tests/test_vm_run_p5*.py` (integration).

---

## 3. Areas that are still evolving

The following areas should be treated as active development surfaces.

### API extraction and Quark-facing behavior
`dex_api_extractor.py` and `dex_resolver.py` are especially important because their behavior can affect Quark rule matching results.

These modules are likely to remain active areas for debugging and refinement.

### Framework API matching and resolution investigations
Recent investigation work has involved rule mismatches observed when comparing Quark + DexTrace against Quark + Androguard.

This suggests that some discrepancies may still exist in how DexTrace extracts or resolves API evidence for certain rule patterns.

### Documentation maturity
The repository now has a cleaner documentation plan, but contributor-facing documentation should continue to be updated alongside code changes.

---

## 4. Known contributor guidance

### Sample APK directory
The repository currently includes a sample APK extraction directory such as:

```text
13667fe3b0ad496a0cd157f34b7e0c991d72a4db/
````

This should be treated as a reproduction or validation sample, not as part of the source implementation.

### Build artifacts

The `dist/` directory contains build outputs and should not be manually edited.

---

## 5. Known investigation context

A recent investigation compared Quark analysis results using the same APK and rules under two different cores:

* DexTrace
* Androguard

Rules previously discussed in this context included:

* `00083`
* `00092`
* `00223`

The working hypothesis was intentionally kept conservative:

* inconsistent framework API matching
* method resolution difference
* invoke extraction gap

This should remain the preferred wording until the exact root cause is verified in code and supported by tests.

---

## 6. Current documentation plan

The current repository documentation is intended to be split as follows:

* `README.md`: project overview and entry point
* `CONTRIBUTING.md`: contributor setup and contribution process
* `docs/modules-overview.md`: module-by-module handoff guide
* `docs/development-workflow.md`: practical development and validation workflows
* `docs/current-status.md`: current state, known gaps, and handoff notes

This split is deliberate. It keeps the README readable while moving contributor detail into dedicated documents.

---

## 7. Recommended next tasks for contributors

The most useful next improvements are:

### 1. keep subsystem tests aligned with code changes

When behavior changes, add or refine the nearest regression test.

### 2. improve Quark-facing regression coverage

When a mismatch is reproduced reliably, add the smallest DexTrace-side test that helps lock down the behavior.

### 3. continue documenting real workflows

If a contributor repeatedly performs the same investigation or validation steps, document them in `docs/development-workflow.md`.

### 4. avoid over-documenting hypothetical components

Documentation should only describe modules and workflows that actually exist in the repository.

---

## 8. Handoff notes

For the next contributor:

* start with `README.md`
* read `docs/modules-overview.md` before changing unfamiliar modules
* use `docs/development-workflow.md` to decide which tests to run
* keep issue writeups evidence-based and conservative
* treat Quark mismatches as cross-system evidence, then narrow down the likely DexTrace subsystem before proposing a root cause

The repository is in a workable handoff state as long as contributors preserve the current discipline: small changes, targeted tests, and careful wording when the exact cause is not yet proven.
