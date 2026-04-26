# Design System — DexTrace CLI

## Product Context
- **What this is:** Python CLI + library for Android APK/DEX static analysis and Dalvik bytecode inspection
- **Who it's for:** Security researchers, malware analysts; downstream engines like Quark Engine
- **Space/industry:** Mobile security / reverse engineering tooling
- **Project type:** Developer CLI tool + Python library

## Aesthetic Direction
- **Direction:** Terminal Noir
- **Decoration level:** None — pure type and whitespace
- **Mood:** Information-dense, zero ceremony. Color appears when it means something specific. Never for decoration.

## Color System — Semantic Only

Every color maps to exactly one semantic category. If a color appears, it has a fixed meaning.

| Color | Hex | Role |
|-------|-----|------|
| Cyan bold | `#22d3ee` | Identifiers — class names, method signatures, JSON keys |
| Amber | `#fbbf24` | Literal values — integers, string params, branch targets |
| Green | `#4ade80` | Return values, success |
| Red bold | `#f87171` | `[ERROR]` prefix, fatal failures |
| White bold | `#ffffff` | Mnemonics (`const/16`, `invoke-static`) |
| Dim gray | `#888888` | Offsets `[0x0000]`, registers `v0 v1` |
| Muted gray | `#444444` | `[INFO]` verbose progress (opt-in only) |

Color applies only when `--color` is explicitly passed or when output is a terminal (isatty). Plain JSON to a pipe is always uncolored.

## Output Format Conventions

### JSON output (default — `dextrace trace`, `dextrace run --json`)

- 2-space indent
- `ensure_ascii=False`
- Field order: `uoff` → `mnemonic` → `regs` → `param` → `index` → `index_type` → `flags` → `target_uoff`
- Omit null/empty fields
- Never color JSON in default mode — it must be pipe-safe

### Text output (`dextrace run` default)

```
return: 42
return: 55
return: "https://evil.example.com/track"
```

No prefix ceremony. The value speaks for itself. Type annotation only when ambiguous:

```
return: 42          ← int, unambiguous
return: 42 (long)   ← when the method returns long
return: 3.14        ← float, unambiguous
```

### Human output format (Risk #3 — `--human` flag, future)

Instruction offsets as `[0x0000]` anchors: 4-digit zero-padded hex, leftmost column, fixed width.

```
[0x0000]  const/4      v1, #1
[0x0001]  if-le        v2, v1 → [0x0009]
[0x0003]  sub-int      v0, v2, v1
[0x0005]  invoke-static  Lp2/Fib;->fib(I)I, (v0)
[0x0007]  move-result  v0
[0x0009]  return       v2
```

Offset column: dim gray. Mnemonic: bold white. Registers: dim gray. Values: amber. Method references: cyan. This format is grep-friendly — `grep '[0x000[35]'` jumps to specific offsets.

## Message Format — stderr Only

stdout is data only (JSON or return value). All messages go to stderr.

```
[ERROR] malformed DEX: File too small to contain a valid DEX header
[ERROR] method not found: Lp1;->missing()I
[ERROR] unimplemented opcode: monitor-enter (pc=0x0006)
[ERROR] call stack overflow at Lp2;->infinite()V (depth 500)
[ERROR] null receiver: invoke-virtual at pc=0x0008
[ERROR] abstract method: Lp3/Base;->abstractFoo()I has no implementation
[ERROR] invoke-interface not implemented: Lp3/IFoo;->bar()I (pc=0x000a)
[ERROR] vtable miss: Lp3/Mid; has no method foo()I
[ERROR] unknown Android API: Landroid/telephony/SmsManager;->getDefault()Landroid/telephony/SmsManager; (pc=0x0004)
[WARN]  (reserved for future use)
[INFO]  loading DEX: classes.dex (4.2 MB)         ← --verbose only
[INFO]  building class hierarchy: 9842 classes     ← --verbose only
[INFO]  resolving entry: Lp4/Cmd;->buildUrl()...   ← --verbose only
[INFO]  executing...                                ← --verbose only
[INFO]  new-instance: Lp3/Mid; → handle #1                           ← --verbose only
[INFO]  invoke-virtual: Lp3/Base;->foo()I → Lp3/Mid;->foo()I         ← --verbose only
[INFO]  invoke-super: Lp3/Mid;->foo()I → Lp3/Base;->foo()I           ← --verbose only
```

- Fixed-width prefix brackets: `[ERROR]` (7 chars), `[WARN] ` (7 chars), `[INFO] ` (7 chars)
- `[ERROR]` and `[WARN]` are always shown
- `[INFO]` is shown only with `--verbose`
- Never mix: data to stdout, messages to stderr — always

## Exit Code Contract

| Code | Meaning | Example trigger |
|------|---------|-----------------|
| 0 | Success | Method executed, return value on stdout |
| 1 | User error | Method not found, malformed `--entry` sig, bad `--arg` |
| 2 | VM error | Unimplemented opcode, stack overflow |
| 3 | Parse error | Malformed DEX, truncated APK, bad ZIP |

## Typography

Terminal-native. No font choices — the user's terminal font applies. All output is ASCII-safe unless method names or string values contain Unicode (which is reproduced faithfully via `ensure_ascii=False`).

## Spacing

- Single blank line between logical sections in verbose output
- No decorative separators
- Consistent alignment: `[ERROR]`/`[WARN]`/`[INFO]` prefixes left-aligned and fixed-width

## Decisions Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-04-11 | Terminal Noir aesthetic | Security researchers need information density, not decorative chrome |
| 2026-04-11 | Semantic-only color | Every color has one fixed meaning — no decorative use; grep and pipe semantics preserved |
| 2026-04-11 | stderr for all messages | Preserves pipe semantics: `dextrace trace ... \| jq` works cleanly |
| 2026-04-11 | `[0x0000]` offset anchors in --human mode | grep-friendly, consistent with disassemblers analysts already use |
| 2026-04-11 | No --color by default | Dropped: adds Rich dependency without enough gain for P1/P2 scope |
| 2026-04-11 | No --short-sigs flag | Dropped: formatting layer overhead not worth it for P1/P2 scope |
| 2026-04-11 | Created by /design-consultation | CLI output design system for dextrace trace + dextrace run |
| 2026-04-16 | P3 [ERROR] messages for vtable failures | Null receiver, abstract method, invoke-interface, vtable miss each surface as clean [ERROR] with pc context — never a Python traceback |
| 2026-04-16 | invoke-virtual [INFO] trace shows resolved method | `invoke-virtual: Lp3/Base;->foo()I → Lp3/Mid;->foo()I` makes vtable dispatch visible in --verbose; essential for malware analysis debugging |
| 2026-04-16 | [WARN] no longer "reserved for P3+" | P3 errors go to [ERROR]; [WARN] remains reserved for future ambiguous-but-non-fatal conditions |
| 2026-04-26 | P4 unknown-API error message includes full sig + pc | Analysts need to know exactly which Android API is missing a stub so they can either skip the entry, file an issue, or supply `--strict-stubs` to surface void misses too |
