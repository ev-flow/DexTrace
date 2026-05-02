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

### P5.4 — `invoke-polymorphic` + `invoke-custom`
Both still raise `DexTraceNotImplementedError`. They need bootstrap
method machinery (method handles, invokedynamic-style call sites) which
no current sample reaches. `invoke-interface` is done as of P5f.

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
Depends on P6.1 (taint propagation). The richer ExecutionTrace from P5.3
(`vm/trace.py`) is in place and provides the per-instruction record
provenance walking will read from.

---

## Process notes

- **Add new TODOs here**, not as inline `# TODO` comments in the code
  (the user's standing rule: testing/exploratory methods do not belong
  in production source). Code comments document _why_, not _what's next_.
- When finishing a TODO, delete the entry rather than crossing it out.
  Git history preserves what was done; this file is only for what's left.
