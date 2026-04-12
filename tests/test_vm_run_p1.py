# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
P1 VM execution integration test.

Fixture: tests/fixtures/samples/p1_const_return.dex
  class Lp1; { public static void main() { const/16 v0, 42; return-void; } }

One-liner verification (Phase 1):
  dextrace run tests/fixtures/samples/p1_const_return.dex \
      --entry 'Lp1;->main()V' --dump-regs
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from unittest.mock import patch

import pytest

FIXTURE = (
    Path(__file__).parent / "fixtures" / "samples" / "p1_const_return.dex"
)
ENTRY = "Lp1;->main()V"


def test_fixture_exists():
    assert FIXTURE.exists(), f"P1 fixture not found: {FIXTURE}"


class TestVMRunP1:
    def test_python_api_returns_none(self):
        """DalvikVM.run() on p1_const_return.dex must return None (void)."""
        from dextrace.core.dex_resolver import DexResolver
        from dextrace.core.dex_code_map import build_sig_to_codeoff_map
        from dextrace.vm.engine import DalvikVM

        dex_bytes = FIXTURE.read_bytes()
        resolver = DexResolver(dex_bytes)
        sig_map = build_sig_to_codeoff_map(dex_bytes, resolver)

        vm = DalvikVM(dex_bytes, resolver, sig_map)
        result = vm.run(ENTRY, args=[])

        assert result is None
        assert vm.final_registers is not None
        assert vm.final_registers.get(0) == 42  # v0 holds 42 after const/16

    def test_cli_text_output(self):
        """dextrace run p1.dex --entry 'Lp1;->main()V' prints 'return: void'."""
        from dextrace.cli.main import main

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            rc = main(["run", str(FIXTURE), "--entry", ENTRY])

        assert rc == 0
        assert buf.getvalue().strip() == "return: void"

    def test_cli_dump_regs(self):
        """--dump-regs prints register values after void return."""
        from dextrace.cli.main import main

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            rc = main(["run", str(FIXTURE), "--entry", ENTRY, "--dump-regs"])

        assert rc == 0
        out = buf.getvalue()
        assert "return: void" in out
        assert "v0=42" in out

    def test_cli_json_output(self):
        """--json flag produces {'return': null}."""
        from dextrace.cli.main import main

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            rc = main(["run", str(FIXTURE), "--entry", ENTRY, "--json"])

        assert rc == 0
        doc = json.loads(buf.getvalue())
        assert doc["return"] is None

    def test_cli_method_not_found_exit_1(self):
        """Nonexistent entry method must exit with code 1."""
        from dextrace.cli.main import main

        rc = main(["run", str(FIXTURE), "--entry", "Lp1;->missing()V"])
        assert rc == 1
