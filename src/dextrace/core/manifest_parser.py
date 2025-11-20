# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


"""
Core manifest parser wrapper.

This module provides a thin wrapper around the legacy ManifestInspector so that
the core layer can rely on a stable interface:

    ManifestParser.parse(data: bytes) -> dict
"""

from typing import Any, Dict

from ..manifest.axml_parser import ManifestInspector
from ..errors import BadAxmlFormat


class ManifestParser:
    """Unified interface for parsing AndroidManifest.xml (AXML)."""

    @staticmethod
    def parse(data: bytes) -> Dict[str, Any]:
        """
        Parse AndroidManifest.xml in binary AXML format.

        This wraps ManifestInspector.parse() so that the core layer does not
        depend on the legacy implementation directly.

        Args:
            data (bytes): Raw bytes of AndroidManifest.xml in AXML format.

        Returns:
            Dict[str, Any]: Parsed manifest information. Typical keys include:
                - package
                - permissions
                - activities
                - services
                - receivers
                - providers

            If parsing fails, a dict with an "error" field is returned:
                {"error": "Bad AXML format"}
        """
        try:
            return ManifestInspector.parse(data)
        except BadAxmlFormat:
            return {"error": "Bad AXML format"}
