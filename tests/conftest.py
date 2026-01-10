# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from __future__ import annotations

import pytest
from pathlib import Path

from tests.fixtures.dex_factory import build_minimal_test_dex


@pytest.fixture()
def dummy_dex_path(tmp_path: Path) -> Path:
    p = tmp_path / "dummy.dex"
    p.write_bytes(build_minimal_test_dex())
    return p
