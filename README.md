# DexTrace

**DexTrace** is a lightweight core for **Android APK / DEX parsing and call-tracing**.

It **does not decide whether an APK is malicious**.  
Instead, DexTrace focuses on producing a **clean, standardized, and reproducible representation** of:

- APK metadata
- AndroidManifest structure
- DEX internal tables
- Cross-references (XREF) between methods and APIs

These results are designed to be **consumed by higher-level engines**, such as  
👉 [Quark Engine](https://github.com/ev-flow/quark-engine) or other static / hybrid analysis frameworks.

> 🎯 Philosophy  
> DexTrace answers **“what is inside this APK / DEX?”**  
> not **“is this APK malicious?”**

---

## ✨ Current Features

### APK Support
- File hashes (MD5 / SHA1 / SHA256)
- File size and ZIP entries
- Multi-DEX enumeration (`classes.dex`, `classes2.dex`, …)

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
- Instruction iteration
- Offset-aware bytecode handling
- Designed to scale toward control-flow & data-flow analysis

### API Call Extraction (Call-Tracing)
- Extracts all `invoke-*` instructions
- Resolves:
  - **caller** class / method / prototype
  - **callee** class / method / prototype
  - opcode type and bytecode offset
- Produces **structured JSON XREF output**
- Safe against malformed indices and corrupted tables

---

## 📦 Installation

Development install (editable mode):

```bash
git clone https://github.com/ev-flow/DexTrace.git
cd DexTrace
pip install -e .
```

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

## API Call Extraction

Extract caller → callee API relationships:

```bash
dextrace dex --apis sample.apk
```

## Example Output

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
