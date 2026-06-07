# Contributing to DexTrace

Thank you for contributing to DexTrace.

This document focuses on practical contributor workflows for the current repository state: how to set up the project, where to make changes, how to validate those changes, and what information to include when reporting or fixing issues.

## Before you start

Read these files first:

- `README.md`
- `docs/modules-overview.md`
- `docs/development-workflow.md`
- `docs/current-status.md`

These documents explain the repository layout, major subsystems, common validation workflows, and current handoff notes.

## Development setup

### Requirements

Recommended baseline:

- Python 3.10 or a project-supported compatible version
- `pip` or `pipenv`
- `pytest`

Project configuration is defined in:

- `pyproject.toml`
- `Pipfile`

### Install in editable mode

```bash
pip install -e .
```

Optional test tooling:

```bash
pip install pytest
```

If you prefer Pipenv:

```bash
pipenv install --dev
pipenv shell
```

### Verify local setup

Check that the package imports:

```bash
python -c "import dextrace; print('ok')"
```

Run the test suite:

```bash
pytest
```

## Container-based setup

DexTrace provides a container-compatible development base so both VS Code and non-VS Code contributors can use the same environment definition.

### Build the development image

```bash
docker build -t dextrace-dev .
```

## Start a development container

```bash
docker run --rm -it \
  -v "$(pwd)":/workspace \
  -w /workspace \
  dextrace-dev \
  bash
```
### Install the project and run tests

Inside the container:

```bash
pip install -e .[dev]
pytest
```

VS Code users may use devcontainer-compatible tooling, but the primary setup path should remain reproducible through standard container CLI commands.

## Repository layout

Main code lives under:

```text
src/dextrace/
```

Key areas:

* `cli/`: command-line entry points
* `core/`: APK / DEX parsing and API extraction
* `dalvik/`: bytecode decoding and disassembly internals
* `vm/`: Dalvik bytecode execution engine, opcode handlers, and Android API stubs
* `manifest/`: binary manifest parsing
* `tests/`: pytest test suite and fixtures

For more detail, see `docs/modules-overview.md`.

## Common development tasks

### 1. Modify CLI behavior

Typical files:

* `src/dextrace/cli/main.py`
* `src/dextrace/cli/cmd_meta.py`
* `src/dextrace/cli/cmd_disasm.py`
* `src/dextrace/cli/cmd_dex.py`
* `src/dextrace/cli/cmd_run.py`

Validate with:

```bash
pytest tests/test_cli_meta.py tests/test_smoke.py
```

### 2. Modify APK reading or metadata extraction

Typical files:

* `src/dextrace/core/apk_reader.py`
* `src/dextrace/core/apk_metadata.py`

Validate with:

```bash
pytest tests/test_apk_reader.py tests/test_apk_metadata.py
```

### 3. Modify manifest parsing

Typical files:

* `src/dextrace/core/manifest_parser.py`
* `src/dextrace/manifest/axml_parser.py`

Validate with:

```bash
pytest tests/test_manifest_parser.py
```

### 4. Modify DEX parsing

Typical files:

* `src/dextrace/core/dex_parser.py`
* `src/dextrace/core/dex_header.py`
* `src/dextrace/core/dex_string_table.py`
* `src/dextrace/core/dex_proto_table.py`
* `src/dextrace/core/dex_method_table.py`
* `src/dextrace/core/dex_code_map.py`

Validate with:

```bash
pytest tests/test_dex_parser.py tests/test_dex_header.py
```

Run broader related tests when needed:

```bash
pytest -k dex
```

### 5. Modify API extraction or resolution

Typical files:

* `src/dextrace/core/dex_api_extractor.py`
* `src/dextrace/core/dex_resolver.py`

Validate with:

```bash
pytest tests/test_dex_api_extractor.py
```

If the change is Quark-facing, also perform an external comparison against Quark with DexTrace and another core such as Androguard.

### 6. Modify Dalvik disassembly internals

Typical files:

* `src/dextrace/dalvik/disassembler.py`
* `src/dextrace/dalvik/operand_decoder.py`
* `src/dextrace/dalvik/format_size_infer.py`
* `src/dextrace/dalvik/format_table.py`
* `src/dextrace/dalvik/opcode_table_builder.py`
* `src/dextrace/dalvik/payload.py`
* `src/dextrace/dalvik/size_resolver.py`
* `src/dextrace/dalvik/smali.py`
* `src/dextrace/dalvik/types.py`

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

### 7. Modify VM execution (`dextrace run`)

This is bytecode **execution**, not disassembly.

Typical files:

* `src/dextrace/vm/engine.py`
* `src/dextrace/vm/handlers/` (opcode handlers)
* `src/dextrace/vm/android_stubs/` (simulated Android/Java framework methods)
* other `src/dextrace/vm/` modules (`decoder.py`, `state.py`, `register_file.py`,
  `call_frame.py`, `heap.py`, `class_hierarchy.py`, `int_ops.py`, `signals.py`,
  `trace.py`, `errors.py`)
* `src/dextrace/cli/cmd_run.py`

Validate with:

```bash
pytest -k vm
```

## Testing guidance

### Full suite

```bash
pytest
```

If you use the Pipenv workflow, run tests through Pipenv instead:

```bash
pipenv run pytest
```

### Targeted runs

Examples:

```bash
pytest tests/test_manifest_parser.py
pytest tests/test_dex_api_extractor.py
pytest -k disassembler
pytest -k vm
pytest -k smoke
```

### When adding tests

Prefer:

* focused unit tests for deterministic parsing logic
* regression tests for previously observed failures
* subsystem-local tests before broad end-to-end coverage

If a bug is reproduced through Quark integration, add or extend the closest DexTrace-side regression test if practical.

## Reproducing Quark mismatches

When validating behavior against Quark Engine:

1. Use the same APK for all comparisons.
2. Use the same Quark version.
3. Use the same rule set.
4. Compare DexTrace core against another core such as Androguard under the same conditions.
5. Save the command lines and outputs.
6. Diff the results and keep the diff in the issue or investigation notes.

Recommended issue evidence includes:

* APK sample identifier
* rule IDs
* Quark commands used
* DexTrace output
* comparison-core output
* diff excerpt
* current hypothesis, written conservatively

Do not overstate the cause unless verified. Prefer wording such as:

* inconsistent API matching
* method resolution difference
* invoke extraction gap
* framework API handling mismatch

over stronger claims that have not yet been demonstrated.

## Reporting issues

Please include:

* summary of the problem
* affected file(s) or subsystem
* exact reproduction steps
* expected behavior
* actual behavior
* test results
* logs, output snippets, or diffs
* APK / sample identifier if relevant
* Quark rule IDs if relevant

For rule mismatch issues, include the comparison context clearly:

* Quark version
* core used
* APK used
* rules used

## Pull requests

Keep pull requests focused.

A good PR should include:

* what changed
* why it changed
* how it was validated
* before/after behavior when relevant

Prefer small, reviewable PRs over mixed refactors plus behavior changes.

## Commit messages

Use short, action-oriented commit messages.

Examples:

```text
fix: correct invoke target extraction for dex api matching
test: add regression coverage for api extractor mismatch case
docs: add contributor workflow and module overview
refactor: simplify dalvik operand decoding path
```

## Documentation updates

When you change contributor-facing behavior, update the related documentation in the same PR when possible.

Typical mapping:

* module responsibilities changed → update `docs/modules-overview.md`
* validation workflow changed → update `docs/development-workflow.md`
* project state or known limitations changed → update `docs/current-status.md`

## Scope notes

The repository may contain:

* sample APK extraction directories
* generated artifacts under `dist/`

These are not primary source modules and should not be treated as the main implementation surface.

## Questions to ask before merging a change

* Which subsystem changed?
* Which tests prove the change is correct?
* Does the change alter public CLI or API behavior?
* Does Quark-facing behavior need comparison against another core?
* Does any documentation now need updating?
