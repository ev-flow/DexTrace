**DexTrace** is a lightweight core for **Android APK/DEX parsing and call-tracing**.  
It does not decide whether an APK is malicious; instead, it provides a **clean, standardized representation of APK metadata, DEX structure, and cross-references (XREF)** that can be consumed by engines such as [Quark Engine](https://github.com/ev-flow/quark-engine) or other analysis frameworks.  

---

## ✨ Planned Features

- **APK support**  
  - File hashes, size, entries, multi-DEX enumeration
- **Manifest parsing**  
  - Extract package, permissions, activities, services, receivers, providers
- **DEX parsing & call-tracing**  
  - Build caller → callee cross-references (XREF)
- **Data-driven opcode registry**  
  - Instructions defined in JSON, no hardcoded tables
- **Standardized JSON output**  
  - Clean machine-readable results for downstream tools
- **Lightweight & dependency-free**  
  - Pure Python standard library implementation

---

## 🚀 Installation

Development install (editable mode):

```bash
git clone https://github.com/ev-flow/DexTrace.git
cd dextrace
pip install -e .
