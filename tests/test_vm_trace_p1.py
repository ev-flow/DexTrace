# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
Week 1 / Phase 1 verification tests for dextrace trace + vm/decoder.

Fixture: tests/fixtures/samples/p1_const_return.dex
  class Lp1; { public static int main() { const/16 v0, 42; return v0; } }

One-liner verification (from design doc):
  python -m dextrace trace tests/fixtures/samples/p1_const_return.dex \
      --entry 'Lp1;->main()I' | python -c \
      "import sys,json; r=json.load(sys.stdin); assert r['instructions'][0]['mnemonic']=='const/16'"
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent / "fixtures" / "samples" / "p1_const_return.dex"
ENTRY = "Lp1;->main()I"
ROOT = Path(__file__).parent.parent


# ---------------------------------------------------------------------------
# Unit tests: Python API
# ---------------------------------------------------------------------------

def test_fixture_exists():
    assert FIXTURE.exists(), f"fixture not found: {FIXTURE}"


def test_walk_method_first_mnemonic():
    """First instruction of main() must be const/16."""
    from dextrace.vm.decoder import walk_method

    insns = walk_method(FIXTURE.read_bytes(), ENTRY)
    assert insns[0].mnemonic == "const/16"


def test_walk_method_last_mnemonic():
    """Last instruction of main() must be return."""
    from dextrace.vm.decoder import walk_method

    insns = walk_method(FIXTURE.read_bytes(), ENTRY)
    assert insns[-1].mnemonic == "return"


def test_walk_method_instruction_count():
    """main() has exactly 2 instructions: const/16 and return."""
    from dextrace.vm.decoder import walk_method

    insns = walk_method(FIXTURE.read_bytes(), ENTRY)
    assert len(insns) == 2


def test_walk_method_literal_param():
    """const/16 carries literal param '42'."""
    from dextrace.vm.decoder import walk_method

    insns = walk_method(FIXTURE.read_bytes(), ENTRY)
    assert insns[0].param == "42"


def test_walk_method_not_found():
    """MethodNotFound raised for a missing signature."""
    from dextrace.vm.decoder import walk_method, MethodNotFound

    with pytest.raises(MethodNotFound):
        walk_method(FIXTURE.read_bytes(), "Lp1;->missing()I")


# ---------------------------------------------------------------------------
# Integration tests: main() entry point (matches test_smoke.py pattern)
# ---------------------------------------------------------------------------

def _cli(*args: str) -> dict:
    """Invoke dextrace main() and return parsed JSON from captured stdout."""
    import io
    from unittest.mock import patch

    buf = io.StringIO()
    with patch("sys.stdout", buf):
        from dextrace.cli.main import main
        rc = main(list(args))
    assert rc == 0, f"dextrace {args} exited {rc}"
    return json.loads(buf.getvalue())


def test_cli_trace_envelope():
    """Output envelope has correct top-level keys and values."""
    result = _cli("trace", str(FIXTURE), "--entry", ENTRY)
    assert result["version"] == 1
    assert result["format"] == "trace"
    assert result["method"] == ENTRY
    assert "instructions" in result
    assert "source" in result


def test_cli_trace_first_mnemonic():
    """Week 1 one-liner: result['instructions'][0]['mnemonic'] == 'const/16'."""
    result = _cli("trace", str(FIXTURE), "--entry", ENTRY)
    assert result["instructions"][0]["mnemonic"] == "const/16"


def test_cli_trace_method_not_found_exit_code():
    """CLI returns 1 when --entry method is not in the DEX."""
    from dextrace.cli.main import main
    rc = main(["trace", str(FIXTURE), "--entry", "Lp1;->missing()I"])
    assert rc == 1
