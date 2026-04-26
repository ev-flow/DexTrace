# DexTrace — Deferred Work

Items intentionally cut from earlier phases to keep MVPs narrow. Each entry
names a target phase, the reason it was cut, and the smallest scope that
would unblock the next caller.

---

## Cut from Phase 4 MVP (2026-04-26)

### P4.1 — Static fields, StringBuilder, Uri.encode, iput-wide
Many real Ahmyth methods (`MainService.<clinit>`, `IOSocket.url`,
`SMSManager.getSMSList`'s catch path) build URL strings via
`StringBuilder.append(...)` chains, write to static fields with `sput-*`,
and read the runtime context with `Landroid/content/Context;`-family
methods. P4 MVP avoided this whole surface by picking `sendSMS` (a leaf
method that uses the static SmsManager API exclusively).

**Unblocks**: any IoC method that builds URLs (`IOSocket.url`),
URL-encodes parameters, or stores cached state in static fields.

**Smallest scope to unblock the next sample**:
- `vm/handlers/field.py` — finish `sput-object`, `sput-wide`, `iput-wide`
  (currently 32-bit forms only)
- `vm/android_stubs/text.py` — StringBuilder (`<init>`, `append(String)`,
  `append(int)`, `toString`)
- `vm/android_stubs/uri.py` — `Uri.parse`, `Uri.encode`
- A heap "static fields" map keyed by `(class_desc, field_name)` so
  `sput-object` writes survive across run() calls if needed (or document
  reset semantics)

### P4.2 — IOSocket URL builder demo
End-to-end demo: run Ahmyth's `IOSocket.url()` and capture the C2 URL
that gets built (e.g. `http://attacker.example.com/?id=...`). Requires
P4.1 (StringBuilder + Uri.encode) and probably `Settings$Secure;->getString`
stubs for the device-id reads.

**Unblocks**: showing analysts a real captured C2 URL in `--trace`.

---

## Cut from Phase 5 design

### P5.1 — try/catch dispatch
P4 deliberately runs only the linear no-throw happy path. Ahmyth's
`sendSMS` has a `try { ... } catch (Exception)` that the interpreter
ignores because no in-method `throw` ever fires. Real coverage requires:
- Reading `code_item.tries` + `handlers` from the parser (already parsed,
  not yet consumed by the engine)
- A per-frame exception-handler stack
- `_ReturnSignal`-style `_ThrowSignal` that walks handlers
- `move-exception` opcode handler (currently unimplemented — would raise
  `unimplemented opcode` if the interpreter ever reached it)

**Why deferred**: stub-first design means we don't synthesize exceptions
(stubs return success values), so the catch path is dead code in P4.
First time we actually throw will be from a stub that models a failure
case (e.g. `URL.openConnection` returning `IOException`).

### P5.2 — const-string heap migration
Currently `const-string` writes a placeholder int (the string-pool index)
into the destination register. This works for code that immediately
hands the string to a stub (the stub can call `resolver.get_string(idx)`)
but breaks for code that stores the string and does pointer-equality or
re-loads it later. Migration target:
`const-string` → `heap.allocate("Ljava/lang/String;", value=<resolved str>)`
and put the *handle* in the register. Then stubs read via `heap.get_value`.

**Why deferred**: P4 sample's `const-string` constants
(`"address"`, `"body"`, etc.) are only used in unreachable catch paths,
so the placeholder-int hack still produces correct IoC capture for the
happy path. First sample where it matters: anything in P4.1 scope that
appends a literal to a StringBuilder.

### P5.3 — `vm/trace.py` ExecutionTrace + `--coverage` parity
P4 ships a flat `vm._api_calls: list[dict]` consumed by `--trace`. The
plan has a richer `ExecutionTrace` with branch decisions, register
reads/writes, and per-instruction timing. Build only when an analyst
asks for replay-debugging or when coverage-compare lands.

### P5.4 — `invoke-interface` + `invoke-polymorphic` + `invoke-custom`
Currently raise `DexTraceNotImplementedError` with the offending sig.
Phase 4's Ahmyth path doesn't hit any of these (sendSMS uses
invoke-static + invoke-virtual/range only). `invoke-interface` is the
first one likely to be needed (Cursor.moveToNext etc. when P4.1 lands).

### P5.5 — Coverage compare (`tests/coverage/compare.py`)
Static method enumeration vs dynamic vm.run() reach. The plan says
"tests, not production" — keep it that way; it's a quality gate, not a
user-facing CLI flag.

---

## Cut from Phase 6 design

### P6.1 — `vm/taint.py` taint tracking
Mark VM args as tainted; propagate through register moves, arithmetic,
string ops, and stub args; report "tainted args reached `sendTextMessage`"
in the trace. Useful when the IoC source isn't a method arg but a
contact-list query or a SharedPreferences read.

### P6.2 — `--explain` provenance
For each captured stub call arg, walk back through the trace and surface
"this string was built from `getDeviceId()` + `'?'` + `URL.encode(getLine1Number())`".
Depends on P6.1 (taint propagation) and P5.3 (richer ExecutionTrace).

---

## Process notes

- **Add new TODOs here**, not as inline `# TODO` comments in the code
  (the user's standing rule: testing/exploratory methods do not belong
  in production source). Code comments document _why_, not _what's next_.
- When finishing a TODO, delete the entry rather than crossing it out.
  Git history preserves what was done; this file is only for what's left.
