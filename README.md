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

---

## ✨ Current Features

### APK Support
- File hashes (MD5 / SHA1 / SHA256)
- File size and ZIP entries

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

---

## 🔍 API Call Tracing (Quark-aligned)

DexTrace implements **progressive API tracing stages** aligned with  
**Quark Engine’s 5-stage detection model**.

### Stage 2 – API Calls
- Extracts all `invoke-*` instructions
- Resolves:
  - caller class / method / prototype
  - callee class / method / prototype
  - opcode type and bytecode offset
- Produces **structured XREF output**
- Safe against malformed indices and corrupted tables

### Stage 3 – API Sets (Per Method)
- Groups APIs **per caller method**
- Represents *which APIs are used together*
- Order-independent
- Designed for **combination-based rule matching**

### Stage 4 – API Call Sequences
- Preserves **static call order** within each method
- Offset-aware ordering (`invoke-*` sequence)
- Method-local (no CFG explosion)
- Designed for **sequence-based rule matching**

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

---

## Example Output

### Stage2
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
