# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from dextrace.cli.main import main


def test_help_runs(capsys):
    exit_code = main(["--help"])
    assert exit_code == 0


def test_version_runs(capsys):
    exit_code = main(["--version"])
    assert exit_code == 0
