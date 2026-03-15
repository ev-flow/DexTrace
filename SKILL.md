---
name: dextrace-contributor
description: understand the dextrace repository and guide contributor workflows for setup, code navigation, and test selection. use when chatgpt is asked to work on dextrace development tasks such as explaining module responsibilities, finding where to change code, setting up the development environment, or choosing validation steps. prefer container-based setup that works for both vscode and non-vscode users, and avoid vscode ui-dependent instructions.
---

# DexTrace contributor

Use this skill when helping with the DexTrace repository.

## Start here

Before answering, read these files if they exist:

- `README.md`
- `CONTRIBUTING.md`
- `docs/modules-overview.md`
- `docs/development-workflow.md`
- `docs/current-status.md`

Treat them as the source of truth for repository structure, contributor workflows, and current project scope.

## What this skill does

Use this skill to:

- explain DexTrace module responsibilities
- map a task to the correct subsystem
- guide development environment setup
- recommend the right tests for a change
- onboard contributors to the current repository state

Do not use this skill for issue drafting, PR drafting, or mismatch analysis unless the user explicitly asks.

## Repository mental model

Map requests to one of these areas first:

- `src/dextrace/cli/` for CLI behavior
- `src/dextrace/core/` for APK / DEX parsing and API extraction
- `src/dextrace/dalvik/` for bytecode decoding and disassembly internals
- `src/dextrace/manifest/` for binary manifest parsing
- `tests/` for validation and fixtures

Do not invent modules, files, or workflows that are not present in the repository.

## Setup rules

Prefer container-based setup that works for both:

- VS Code users
- non-VS Code users

Do not make VS Code UI actions the primary path.

For DexTrace, prefer this order:

1. Read `CONTRIBUTING.md` first.
2. Check whether the repository provides container-related files such as:
   - `devcontainer.json` or `.devcontainer/`
   - `Dockerfile`
   - compose files
   - setup scripts
3. If container files exist, explain setup through CLI-first container workflows.
4. Reuse the same container definition for both VS Code and non-VS Code contributors.
5. Use documented install commands inside the container.
6. Verify setup with the smallest useful checks:
   - package import
   - targeted tests
   - full test suite only when needed

If the repository provides devcontainer-compatible configuration, treat it as a shared container definition, not as a VS Code-only workflow.

Do not claim automatic setup unless the repository actually provides the required files or scripts.

## Change-to-subsystem mapping

### CLI
Files:
- `src/dextrace/cli/main.py`
- `src/dextrace/cli/cmd_meta.py`
- `src/dextrace/cli/cmd_disasm.py`
- `src/dextrace/cli/cmd_dex.py`

Tests:
- `tests/test_cli_meta.py`
- `tests/test_smoke.py`

### APK and metadata
Files:
- `src/dextrace/core/apk_reader.py`
- `src/dextrace/core/apk_metadata.py`

Tests:
- `tests/test_apk_reader.py`
- `tests/test_apk_metadata.py`

### Manifest
Files:
- `src/dextrace/core/manifest_parser.py`
- `src/dextrace/manifest/axml_parser.py`

Tests:
- `tests/test_manifest_parser.py`

### DEX structure parsing
Files:
- `src/dextrace/core/dex_parser.py`
- `src/dextrace/core/dex_header.py`
- `src/dextrace/core/dex_string_table.py`
- `src/dextrace/core/dex_proto_table.py`
- `src/dextrace/core/dex_method_table.py`
- `src/dextrace/core/dex_code_map.py`

Tests:
- `tests/test_dex_parser.py`
- `tests/test_dex_header.py`

### API extraction and resolution
Files:
- `src/dextrace/core/dex_api_extractor.py`
- `src/dextrace/core/dex_resolver.py`

Tests:
- `tests/test_dex_api_extractor.py`

### Dalvik disassembly
Files:
- `src/dextrace/dalvik/disassembler.py`
- `src/dextrace/dalvik/operand_decoder.py`
- `src/dextrace/dalvik/format_size_infer.py`
- `src/dextrace/dalvik/format_table.py`
- `src/dextrace/dalvik/opcode_table_builder.py`
- `src/dextrace/dalvik/payload.py`
- `src/dextrace/dalvik/size_resolver.py`
- `src/dextrace/dalvik/smali.py`
- `src/dextrace/dalvik/types.py`

Tests:
- `tests/test_operand_decoder.py`
- `tests/test_size_resolver.py`
- `tests/test_opcode_table_builder.py`
- `tests/test_format_size_infer_oracle.py`
- `tests/test_disassembler_e2e_dummy_dex.py`
- `tests/test_disassembler_evidence_smali_hex.py`
- `tests/test_dalvik_payload.py`
- `tests/test_all_formats_inferable.py`
- `tests/test_generated_bytecode_vectors.py`

## Testing behavior

Recommend the narrowest relevant tests first.

Use full `pytest` only when:

- shared logic changed
- the user asks for full validation
- targeted tests are not enough

When setup verification is requested, prefer:

1. package import
2. one or two targeted tests
3. full suite only after basic checks pass

## Documentation behavior

When explaining the repository:

- use `README.md` for project overview and CLI basics
- use `CONTRIBUTING.md` for setup and contribution flow
- use `docs/modules-overview.md` for module responsibilities
- use `docs/development-workflow.md` for validation steps
- use `docs/current-status.md` for current scope and handoff notes

If documents disagree, prefer the more specific contributor document and mention the inconsistency.

## Container guidance rules

When talking about container workflows:

- prefer editor-agnostic wording
- do not assume VS Code is available
- do not require GUI actions
- explain the workflow in terms of repository files, container runtime, and CLI commands
- treat devcontainer-compatible configuration as reusable by both VS Code and non-VS Code users when paired with a shared `Dockerfile`

If the repository provides both `devcontainer.json` and `Dockerfile`, prefer describing the Dockerfile-based CLI workflow first, then mention VS Code compatibility as optional.

## What not to do

Do not:

- assume nonexistent modules or future architecture
- promise automatic environment setup if the repository lacks the required files
- describe mismatch investigation workflows unless the user asks for them
- drift into issue-writing or PR-writing guidance unless requested
- make VS Code UI steps the primary setup path

## Output rules

Be concrete.

Always prefer:

- exact file paths
- exact subsystem names
- exact test files
- verified repository facts
- documented setup commands

over generic contributor advice.

When something is missing from the repo, say that it is missing instead of inferring that it exists.
