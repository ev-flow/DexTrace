# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


from __future__ import annotations

import multiprocessing
import os
import signal
import subprocess
import sys
from dataclasses import dataclass
from os import PathLike
from typing import Any, Dict, List, Optional, Tuple, Union

PathT = Union[str, PathLike]


@dataclass(frozen=True)
class DextraceApiOptions:
    """
    One place to control how Quark calls DexTrace.
    Keep it stable: Quark imports this module, not CLI.
    """
    accept_optimized: bool = False
    include_disasm_hex: bool = True
    disasm_context_window: int = 2  # reserved (Quark can build context itself)


# ----------------------------
# Helpers (internal)
# ----------------------------

def _is_apk_path(p: str) -> bool:
    return str(p).lower().endswith(".apk")


def _is_dex_path(p: str) -> bool:
    return str(p).lower().endswith(".dex")


def _api_call_to_dict(x: Any) -> Optional[dict]:
    """
    DexApiExtractor.extract_api_calls() may return:
      - dict
      - ApiCall dataclass-like with to_dict()
    """
    if x is None:
        return None
    if isinstance(x, dict):
        return x
    if hasattr(x, "to_dict"):
        try:
            d = x.to_dict()  # type: ignore[attr-defined]
            return d if isinstance(d, dict) else None
        except Exception:
            return None
    return None


def _read_file_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


# ----------------------------
# APK helpers (public + stable, aligned to your ApkReader)
# ----------------------------

def list_apk_entries(apk_path: PathT) -> List[str]:
    """List all entries inside an APK (zip names)."""
    from dextrace.core.apk_reader import ApkReader  # type: ignore

    apk = ApkReader(str(apk_path))
    return apk.list_entries()


def list_apk_dex_names(apk_path: PathT) -> List[str]:
    """Return dex file names in APK: ['classes.dex', 'classes2.dex', ...] sorted."""
    entries = [n for n in list_apk_entries(apk_path) if isinstance(n, str) and n.endswith(".dex")]
    # stable: classes.dex first, then classes2.dex...
    entries.sort(key=lambda s: (s != "classes.dex", s))
    return entries


def read_apk_file(apk_path: PathT, name: str) -> bytes:
    """Read a file inside APK by entry name and return raw bytes."""
    from dextrace.core.apk_reader import ApkReader  # type: ignore

    apk = ApkReader(str(apk_path))
    return apk.read_file(name)


def iter_apk_dex_files(apk_path: PathT) -> List[Tuple[str, bytes]]:
    """
    Return list of (dex_name, dex_bytes) for all dex entries.
    Uses ApkReader.iter_dex_files() directly.
    """
    from dextrace.core.apk_reader import ApkReader  # type: ignore

    apk = ApkReader(str(apk_path))
    out = apk.iter_dex_files()
    out.sort(key=lambda t: (t[0] != "classes.dex", t[0]))
    return out


def read_all_dex_bytes(apk_path: PathT) -> List[bytes]:
    """Return all dex bytes from APK, in stable order."""
    return [b for _name, b in iter_apk_dex_files(apk_path)]


# ----------------------------
# DEX loading (internal)
# ----------------------------

def _load_dex_contexts(target: str) -> List[Tuple[str, bytes]]:
    """
    Return list of (dex_name, dex_bytes).
    """
    if _is_dex_path(target):
        return [("classes.dex", _read_file_bytes(target))]

    if _is_apk_path(target):
        return iter_apk_dex_files(target)

    # treat as raw dex-like file
    return [("classes.dex", _read_file_bytes(target))]


# ----------------------------
# Public APIs (Quark imports these)
# ----------------------------

def build_dex_report(
    target_path: PathT,
    *,
    accept_optimized: bool = False,
) -> Dict[str, Any]:
    """
    Pure-function version of `dextrace dex --apis --json <APK/DEX>`.

    Return JSON-serializable dict:
      {"version":1,"format":"dex","source":{...},"dex":{"api_calls":[...] },"errors":{...}}
    """
    target = str(target_path)

    from dextrace.core.dex_api_extractor import DexApiExtractor  # type: ignore

    out: Dict[str, Any] = {
        "version": 1,
        "format": "dex",
        "source": {"input": target},
        "dex": {"api_calls": []},
        "errors": {},
    }

    dexes = _load_dex_contexts(target)
    if not dexes:
        out["errors"]["__global__"] = {"error": "NoDexFound"}
        return out

    all_calls: List[dict] = []
    for dex_name, dex_bytes in dexes:
        try:
            # Newer extractor may accept accept_optimized
            try:
                ex = DexApiExtractor(dex_bytes, accept_optimized=bool(accept_optimized))  # type: ignore[arg-type]
            except TypeError:
                ex = DexApiExtractor(dex_bytes)  # type: ignore[call-arg]

            calls = ex.extract_api_calls()
            if isinstance(calls, list):
                for c in calls:
                    d = _api_call_to_dict(c)
                    if d is None:
                        continue
                    d.setdefault("source", {})
                    if isinstance(d["source"], dict):
                        d["source"].setdefault("dex", dex_name)
                    all_calls.append(d)

        except Exception as e:
            out["errors"][dex_name] = {"error": type(e).__name__, "message": str(e)}

    out["dex"]["api_calls"] = all_calls
    return out


def build_disasm_report(
    target_path: PathT,
    method_sig: str,
    *,
    accept_optimized: bool = False,
    include_hex: bool = True,
    context_window: int = 2,  # reserved for future; Quark can build context itself
    max_insns: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Pure-function version of:
      dextrace disasm <APK/DEX> --method <SIG>

    Return JSON-serializable dict:
      {"version":1,"format":"smali","source":{...},"methods":{sig:{...}},"errors":{...}}

    Per instruction dict contains:
      offset, byte_off, smali
      raw_hex (optional if include_hex)
    """
    _ = context_window  # reserved

    target = str(target_path)
    sig = str(method_sig)

    # NOTE: Ensure these import paths match your DexTrace repo layout.
    from dextrace.core.dex_resolver import DexResolver  # type: ignore
    from dextrace.core.dex_code_map import build_sig_to_codeoff_map  # type: ignore
    from dextrace.dalvik.disassembler import DalvikDisassembler  # type: ignore
    from dextrace.dalvik.smali import SmaliRenderer  # type: ignore

    out: Dict[str, Any] = {
        "version": 1,
        "format": "smali",
        "source": {"input": target},
        "methods": {},
        "errors": {},
    }

    dexes = _load_dex_contexts(target)
    if not dexes:
        out["errors"]["__global__"] = {"error": "NoDexFound"}
        return out

    found = False

    for dex_name, dex_bytes in dexes:
        try:
            resolver = DexResolver(dex_bytes)
            sig_to_codeoff = build_sig_to_codeoff_map(dex_bytes, resolver)

            code_off = sig_to_codeoff.get(sig)
            if code_off is None:
                continue  # not in this dex

            dis = DalvikDisassembler(
                dex_bytes=dex_bytes,
                resolver=resolver,
                accept_optimized=bool(accept_optimized),
            )
            renderer = SmaliRenderer(resolver)

            m = dis.disassemble_method(int(code_off), max_insns=max_insns)

            # labels: from DecodedInsn.target_uoff
            def _build_labels_by_uoff(insns: List[Any]) -> Dict[int, List[str]]:
                labs: Dict[int, List[str]] = {}
                for ins in insns:
                    tu = getattr(ins, "target_uoff", None)
                    if tu is None:
                        continue
                    try:
                        tu_i = int(tu)
                    except Exception:
                        continue
                    labs.setdefault(tu_i, []).append(f":L{tu_i:04x}")
                return labs

            labels_by_uoff = _build_labels_by_uoff(m.instructions)

            ins_list: List[Dict[str, Any]] = []
            for ins in m.instructions:
                uoff = int(getattr(ins, "uoff"))
                byte_off = int(getattr(ins, "byte_off"))

                # insert labels before instruction (Quark ignores lines starting with ':', but they help context)
                for lab in labels_by_uoff.get(uoff, []):
                    ins_list.append({"offset": uoff, "byte_off": byte_off, "smali": lab})

                smali = renderer.to_smali(ins)
                item: Dict[str, Any] = {"offset": uoff, "byte_off": byte_off, "smali": smali}

                if include_hex:
                    raw_hex = getattr(ins, "raw_hex", "") or ""
                    item["raw_hex"] = str(raw_hex)

                ins_list.append(item)

            out["source"]["dex"] = dex_name
            out["methods"][sig] = {
                "code_off": int(code_off),
                "registers_size": int(m.registers_size),
                "ins_size": int(m.ins_size),
                "outs_size": int(m.outs_size),
                "tries_size": int(m.tries_size),
                "insns_size": int(m.insns_size),
                "instructions": ins_list,
            }

            found = True
            break

        except Exception as e:
            out["errors"][dex_name] = {"error": type(e).__name__, "message": str(e)}
            continue

    if not found:
        out["errors"][sig] = {"error": "MethodNotFound"}

    return out


# ----------------------------
# Convenience wrappers (compat with your earlier draft)
# ----------------------------

def extract_api_calls(target: PathT, *, options: Optional[DextraceApiOptions] = None) -> Dict[str, Any]:
    options = options or DextraceApiOptions()
    return build_dex_report(str(target), accept_optimized=options.accept_optimized)


def disasm_method(target: PathT, method_sig: str, *, options: Optional[DextraceApiOptions] = None) -> Dict[str, Any]:
    options = options or DextraceApiOptions()
    return build_disasm_report(
        str(target),
        method_sig=str(method_sig),
        accept_optimized=options.accept_optimized,
        include_hex=options.include_disasm_hex,
        context_window=int(options.disasm_context_window),
    )


# ----------------------------
# Manifest APIs (optional)
# ----------------------------

def parse_manifest(apk_path: PathT) -> Dict[str, Any]:
    """
    Parse AndroidManifest.xml from APK.

    You said you want ManifestParser-related features to live behind api.py.
    Recommended placement: dextrace/core/manifest_parser.py

    Return JSON-serializable dict:
      {
        "package": "...",
        "permissions": [...],
        "activities": [...],
        "services": [...],
        "receivers": [...],
        "providers": [...],
      }
    """
    from dextrace.core.manifest_parser import ManifestParser  # type: ignore
    from dextrace.core.apk_reader import ApkReader

    apk = ApkReader(str(apk_path))
    mp = ManifestParser.parse(apk.read_file("AndroidManifest.xml"))

    # Adjust attribute names below to match your ManifestParser implementation.
    return {
        "package": mp.get("package_name", None) or mp.get("package", None),
        "permissions": list(mp.get("permissions", [])),
        "activities": list(mp.get("activities", [])),
        "services": list(mp.get( "services", [])),
        "receivers": list(mp.get("receivers", [])),
        "providers": list(mp.get("providers", [])),
    }


def get_apk_permissions(apk_path: PathT) -> List[str]:
    """Convenience API: return permissions list from manifest parsing."""
    d = parse_manifest(apk_path)
    perms = d.get("permissions")
    if isinstance(perms, list):
        return [str(x) for x in perms]
    return []


# ----------------------------
# VM execution (public + stable; Quark imports this)
# ----------------------------

def _execute_method_worker(
    target: str, entry_sig: str, args: List, memory_limit_mb: Optional[int]
) -> Optional[Any]:
    """Run ``entry_sig`` in the first DEX of ``target`` that defines it.

    Module-level (not a closure) so it can be pickled and dispatched to a
    spawn-based worker process (macOS/Windows). ``memory_limit_mb`` bounds the
    VM's heap allocation so an untrusted DEX cannot exhaust memory.
    """
    from dextrace.core.dex_resolver import DexResolver  # type: ignore
    from dextrace.core.dex_code_map import build_sig_to_codeoff_map  # type: ignore
    from dextrace.vm.engine import DalvikVM  # type: ignore

    for _dex_name, dex_bytes in _load_dex_contexts(target):
        try:
            resolver = DexResolver(dex_bytes)
            sig_to_codeoff = build_sig_to_codeoff_map(dex_bytes, resolver)
            if entry_sig not in sig_to_codeoff:
                continue
            vm = DalvikVM(
                dex_bytes, resolver, sig_to_codeoff,
                memory_limit_mb=memory_limit_mb,
            )
            return vm.run(entry_sig, args)
        except Exception:
            continue
    return None


def _process_worker(conn, fn, fn_args) -> None:
    """Run ``fn(*fn_args)`` and ship the result back over ``conn``.

    Module-level so it pickles for spawn-based start methods (macOS/Windows).
    Sends the return value on success, or ``None`` on any exception (including
    an unpicklable result) — the parent treats a received ``None`` and a dead
    worker identically, so no success/error tag is needed.
    """
    # Lead our own session/process group so the parent can later signal the
    # whole group and reap any grandchildren the worker spawns, not just us.
    if hasattr(os, "setsid"):
        try:
            os.setsid()
        except OSError:
            pass
    try:
        conn.send(fn(*fn_args))
    except Exception:
        conn.send(None)
    finally:
        conn.close()


def _signal_worker_group(proc, sig) -> None:
    """POSIX: send ``sig`` to the worker's process group (covers grandchildren).

    The worker calls ``os.setsid()``, so it leads a group whose id equals its
    own pid. We signal the group *only* when that holds — a guard that
    guarantees we never accidentally signal the parent's own group (e.g. if
    ``setsid`` failed, or before it ran).
    """
    if proc.pid is None:
        return
    try:
        if os.getpgid(proc.pid) == proc.pid:
            os.killpg(proc.pid, sig)
    except (OSError, ProcessLookupError):
        pass  # already gone, or not its own group leader


def _taskkill_tree(pid) -> None:
    """Windows: terminate the whole process tree rooted at ``pid``.

    ``taskkill /T`` walks child processes by parent pid (the Windows analogue
    of a POSIX process-group kill), so grandchildren the worker spawned are
    reaped too; ``/F`` forces it. taskkill ships with every Windows install.
    """
    if pid is None:
        return
    try:
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except (OSError, ValueError):
        pass  # taskkill unavailable — proc.kill() still reaps the worker itself


def _terminate_worker(proc) -> None:
    """Force a runaway worker *and its descendants* down — cross-platform.

    POSIX (macOS/Linux): escalate over the worker's process group, SIGTERM then
    SIGKILL. Windows: ``taskkill /F /T`` kills the process tree. On every
    platform ``proc.terminate()``/``proc.kill()`` is the always-present
    fallback that reaps at least the worker process itself.
    """
    if not proc.is_alive():
        return

    def signal_tree(sig) -> None:
        if hasattr(os, "killpg"):  # POSIX: process-group kill
            _signal_worker_group(proc, sig)
        elif sys.platform == "win32":
            _taskkill_tree(proc.pid)

    signal_tree(signal.SIGTERM)
    proc.terminate()  # signal the worker pid directly (fallback + race safety)
    proc.join(timeout=1)
    if proc.is_alive():
        signal_tree(signal.SIGKILL)
        proc.kill()
        proc.join()


def _run_with_timeout(fn, fn_args, timeout_s: float) -> Optional[Any]:
    """Run ``fn(*fn_args)`` in a separate process; return ``None`` on timeout.

    A process boundary lets the caller return promptly even when the worker is
    stuck in a pathological/untrusted DEX. Unlike ``ProcessPoolExecutor``, which
    only abandons a runaway worker (``shutdown(wait=False)`` cannot cancel a task
    that has already started), this path *terminates* the worker on timeout —
    ``terminate()`` then ``kill()`` — so no background process outlives the call.
    Args and the return value must be picklable to cross the boundary; anything
    else degrades to ``None``.
    """
    ctx = multiprocessing.get_context("spawn")
    parent_conn, child_conn = ctx.Pipe(duplex=False)
    proc = ctx.Process(target=_process_worker, args=(child_conn, fn, fn_args))

    try:
        proc.start()
        child_conn.close()  # only the worker holds the send end now
        if parent_conn.poll(timeout_s):
            value = parent_conn.recv()
            proc.join(timeout=1)  # worker is done; let it exit cleanly
            return value
        return None  # deadline passed — worker is killed in finally
    except Exception:
        # Unpicklable fn/args under spawn (start() fails), a worker that died
        # mid-send (recv -> EOFError), or any IPC error: honor the public
        # resolve-or-None contract instead of propagating to the caller.
        return None
    finally:
        child_conn.close()  # idempotent; closes it if start() never ran
        parent_conn.close()
        # Only a runaway/timed-out worker is still alive here; take its whole
        # process group down so no child or grandchild outlives the call.
        _terminate_worker(proc)


def execute_method(
    target_path: PathT,
    entry_sig: str,
    args: Optional[List] = None,
    *,
    timeout_s: float = 5.0,
    memory_limit_mb: Optional[int] = 1024,
) -> Optional[Any]:
    """
    Execute a single Dalvik method in the DexTrace VM and return its value.

    This is the stable public wrapper over ``dextrace.vm.engine.DalvikVM`` —
    callers (e.g. Quark) should import this instead of touching the VM directly.

    Accepts an APK or a raw DEX. DEX files are searched in stable order
    (classes.dex first); the method runs in the first DEX that contains it.

    Because the method body is untrusted, execution is sandboxed in a child
    process bounded on two axes: ``timeout_s`` (CPU/wall-clock) and
    ``memory_limit_mb`` (heap allocation, enforced predictively inside the VM
    at each allocation site, so it works on every platform).

    :param target_path: Path to an APK or DEX file.
    :param entry_sig: Dalvik method signature, e.g.
        'Lcom/example/Foo;->bar()Ljava/lang/String;'
    :param args: Positional arguments to pass to the method (default: []).
    :param timeout_s: Per-call wall-clock timeout in seconds (default: 5.0).
    :param memory_limit_mb: Cap on the VM's heap allocation in MiB
        (default: 1024). ``None`` or ``0`` (or any value <= 0) disables the cap.
        Enforced cross-platform — an over-budget allocation aborts the run
        (returning ``None``) before the memory is committed.
    :return: The method's return value, or ``None`` if the method is not found,
        execution raises, or the timeout/memory limit fires. Callers treat
        ``None`` as "could not resolve".
    """
    if args is None:
        args = []

    target = str(target_path)
    return _run_with_timeout(
        _execute_method_worker,
        (target, entry_sig, args, memory_limit_mb),
        timeout_s,
    )
