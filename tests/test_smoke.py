from subprocess import run, PIPE
import sys


def test_help_runs():
    proc = run([sys.executable, "-m", "dextrace.cli.main", "-h"], stdout=PIPE, stderr=PIPE, text=True)
    assert proc.returncode == 0
    assert "DexTrace" in proc.stdout


def test_version_runs():
    proc = run([sys.executable, "-m", "dextrace.cli.main", "--version"], stdout=PIPE, stderr=PIPE, text=True)
    assert proc.returncode == 0
    assert "DexTrace" in proc.stdout
