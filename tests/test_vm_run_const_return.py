# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
Const-return VM execution integration test.

Fixture: tests/fixtures/samples/const_return.dex
  class Lcom/example/ConstReturn; { public static int main() { const/16 v0, 42; return v0; } }

One-liner verification:
  dextrace run tests/fixtures/samples/const_return.dex \
      --entry 'Lcom/example/ConstReturn;->main()I'
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from unittest.mock import patch

FIXTURE = (
    Path(__file__).parent / "fixtures" / "samples" / "const_return.dex"
)
ENTRY = "Lcom/example/ConstReturn;->main()I"


def test_fixture_exists():
    assert FIXTURE.exists(), f"fixture not found: {FIXTURE}"


class TestVMRunConstReturn:
    def test_python_api_returns_42(self):
        """DalvikVM.run() on const_return.dex must return 42."""
        from dextrace.core.dex_resolver import DexResolver
        from dextrace.core.dex_code_map import build_sig_to_codeoff_map
        from dextrace.vm.engine import DalvikVM

        dex_bytes = FIXTURE.read_bytes()
        resolver = DexResolver(dex_bytes)
        sig_map = build_sig_to_codeoff_map(dex_bytes, resolver)

        vm = DalvikVM(dex_bytes, resolver, sig_map)
        result = vm.run(ENTRY, args=[])

        assert result == 42

    def test_cli_text_output(self):
        """dextrace run const_return.dex --entry 'Lp1;->main()I' prints 'return: 42'."""
        from dextrace.cli.main import main

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            rc = main(["run", str(FIXTURE), "--entry", ENTRY])

        assert rc == 0
        assert buf.getvalue().strip() == "return: 42"

    def test_cli_dump_regs(self):
        """--dump-regs prints register values after int return."""
        from dextrace.cli.main import main

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            rc = main(["run", str(FIXTURE), "--entry", ENTRY, "--dump-regs"])

        assert rc == 0
        out = buf.getvalue()
        assert "return: 42" in out

    def test_cli_json_output(self):
        """--json flag produces {'return': 42}."""
        from dextrace.cli.main import main

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            rc = main(["run", str(FIXTURE), "--entry", ENTRY, "--json"])

        assert rc == 0
        doc = json.loads(buf.getvalue())
        assert doc["return"] == 42

    def test_cli_method_not_found_exit_1(self):
        """Nonexistent entry method must exit with code 1."""
        from dextrace.cli.main import main

        rc = main(["run", str(FIXTURE), "--entry", "Lp1;->missing()I"])
        assert rc == 1

