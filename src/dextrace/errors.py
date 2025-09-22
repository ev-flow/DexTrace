class DexTraceError(Exception):
    """Base error for DexTrace."""

class EntryNotFound(DexTraceError):
    """Raised when an expected entry is missing inside the APK (zip)."""

class BadDexFormat(DexTraceError):
    """Raised when a DEX file is malformed or unsupported."""

class BadAxmlFormat(DexTraceError):
    """Raised when AndroidManifest.xml (AXML) is malformed."""
