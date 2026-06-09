# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("dextrace")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0+dev"
