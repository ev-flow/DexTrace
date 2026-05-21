# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from tests.fixtures.dex_factory import build_minimal_test_dex

_REPO_ROOT = Path(__file__).resolve().parent.parent
_TOOLS_DIR = _REPO_ROOT / "tools"
_SAMPLES_DIR = _REPO_ROOT / "tests" / "fixtures" / "samples"


def pytest_configure(config):  # noqa: ARG001
    """Regenerate tests/fixtures/samples/*.dex from tools/gen_*_fixture.py.

    The .dex files are gitignored — they're deterministic outputs of the
    generators under tools/. Running every generator at session start keeps
    the fixtures fresh whenever a generator changes, and works the same way
    in CI and on a clean clone.
    """
    if not _TOOLS_DIR.is_dir():
        return
    _SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    for gen in sorted(_TOOLS_DIR.glob("gen_*_fixture.py")):
        subprocess.run(
            [sys.executable, str(gen)], check=True, cwd=_REPO_ROOT
        )


@pytest.fixture()
def dummy_dex_path(tmp_path: Path) -> Path:
    p = tmp_path / "dummy.dex"
    p.write_bytes(build_minimal_test_dex())
    return p
