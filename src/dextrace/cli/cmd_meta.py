# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


import json
import os
import zipfile
from dextrace.core.apk_reader import ApkReader
from dextrace.core.apk_metadata import ApkMetadata
from dextrace.errors import BadAxmlFormat


def _error(msg: str, code: str = None) -> str:
    """
    Produce a standardized JSON-formatted error string.

    Parameters
    ----------
    msg : str
        Human-readable error message.
    code : str, optional
        Stable machine-readable error identifier.

    Returns
    -------
    str
        JSON string describing the error.
    """
    payload = {
        "error": msg,
    }
    if code:
        payload["code"] = code
    return json.dumps(payload, ensure_ascii=False, indent=2)


def run(args):
    apk_path = args.apk

    # === 1. File existence check ===
    if not os.path.exists(apk_path):
        print(_error(f"File not found: {apk_path}", "FILE_NOT_FOUND"))
        return 1

    if not os.path.isfile(apk_path):
        print(_error(f"Not a file: {apk_path}", "INVALID_TYPE"))
        return 1

    # === 2. ZIP / APK validity check ===
    try:
        reader = ApkReader(apk_path)
    except zipfile.BadZipFile:
        print(_error("Invalid APK file: not a valid ZIP archive", "BAD_ZIP"))
        return 1
    except Exception as e:
        print(_error(f"Unable to read APK: {str(e)}", "APK_READ_ERROR"))
        return 1

    # === 3. Parse metadata (Manifest / DEX / entries) ===
    try:
        meta = ApkMetadata(apk_path).get_metadata()
    except BadAxmlFormat:
        print(_error("Malformed AndroidManifest.xml (AXML parse failed)", "BAD_MANIFEST"))
        return 1
    except Exception as e:
        print(_error(f"Failed to extract metadata: {str(e)}", "META_PARSE_ERROR"))
        return 1

    # === 4. JSON serialization safety ===
    try:
        output = json.dumps(meta, indent=2)
    except Exception as e:
        print(_error(f"Failed to serialize metadata: {str(e)}", "JSON_ERROR"))
        return 1

    print(output)
    return 0


def register(parser):
    parser.add_argument(
        "apk",
        help="Path to APK file",
    )
    parser.set_defaults(func=run)
