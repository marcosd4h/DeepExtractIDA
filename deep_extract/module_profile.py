"""
Module profile snapshot generation for PE binary analysis.

Produces ``module_profile.json`` -- a compact, pre-computed fingerprint that
summarises a module's identity, scale, library composition, API surface,
complexity characteristics, and security posture.  The profile is generated
from data already stored in the per-module SQLite database (``file_info`` and
``functions`` tables) so it adds negligible extraction time.

The profile is written unconditionally (not gated by ``--generate-cpp``).
"""

import json
import os
import pathlib
import sqlite3
import sys
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from .logging_utils import debug_print
from .db_connection import connect_sqlite as _connect_sqlite
from .cpp_generator import CppGenerator


# ---------------------------------------------------------------------------
# API-category pattern sets
# ---------------------------------------------------------------------------
# Each tuple contains substrings checked against function names from
# ``dangerous_api_calls`` and imported function names.  The match is
# case-insensitive prefix/substring.

_SECURITY_API_PATTERNS: Tuple[str, ...] = (
    "AdjustTokenPrivileges",
    "OpenProcessToken",
    "OpenThreadToken",
    "DuplicateTokenEx",
    "DuplicateToken",
    "ImpersonateLoggedOnUser",
    "ImpersonateNamedPipeClient",
    "ImpersonateSelf",
    "RevertToSelf",
    "SetTokenInformation",
    "GetTokenInformation",
    "AccessCheck",
    "AccessCheckByType",
    "SetSecurityInfo",
    "GetSecurityInfo",
    "SetNamedSecurityInfo",
    "GetNamedSecurityInfo",
    "ConvertStringSecurityDescriptor",
    "ConvertSecurityDescriptorToString",
    "SetSecurityDescriptorDacl",
    "SetSecurityDescriptorOwner",
    "AddAccessAllowedAce",
    "AddAccessDeniedAce",
    "InitializeSecurityDescriptor",
    "LookupPrivilegeValue",
    "LookupPrivilegeName",
    "LookupAccountSid",
    "LookupAccountName",
    "PrivilegeCheck",
    "SetThreadToken",
    "CreateRestrictedToken",
    "CheckTokenMembership",
    "AuthzAccessCheck",
    "LogonUser",
)

_CRYPTO_API_PATTERNS: Tuple[str, ...] = (
    "BCrypt",
    "NCrypt",
    "CryptEncrypt",
    "CryptDecrypt",
    "CryptCreateHash",
    "CryptDeriveKey",
    "CryptGenKey",
    "CryptGenRandom",
    "CryptHashData",
    "CryptImportKey",
    "CryptExportKey",
    "CryptAcquireContext",
    "CertOpenStore",
    "CertFindCertificateInStore",
    "CertGetCertificateChain",
    "CertVerifyCertificateChainPolicy",
    "CertCloseStore",
    "CertFreeCertificateContext",
    "CryptSignHash",
    "CryptVerifySignature",
    "CryptProtectData",
    "CryptUnprotectData",
)

_COM_API_PATTERNS: Tuple[str, ...] = (
    "CoCreateInstance",
    "CoCreateInstanceEx",
    "CoInitialize",
    "CoInitializeEx",
    "CoInitializeSecurity",
    "CoGetClassObject",
    "CoRegisterClassObject",
    "CoMarshalInterface",
    "CoUnmarshalInterface",
    "CLSIDFromProgID",
    "CLSIDFromString",
    "CoTaskMemAlloc",
    "CoTaskMemFree",
    "OleInitialize",
    "OleUninitialize",
    "SysAllocString",
    "SysFreeString",
    "VariantInit",
    "VariantClear",
    "SafeArrayCreate",
)

_RPC_API_PATTERNS: Tuple[str, ...] = (
    "RpcServerListen",
    "RpcServerRegisterIf",
    "RpcServerUseProtseq",
    "RpcServerInqBindings",
    "RpcBindingFromStringBinding",
    "RpcStringBindingCompose",
    "RpcStringFree",
    "RpcBindingFree",
    "NdrClientCall",
    "NdrServerCall",
    "NdrAsyncClientCall",
    "Ndr64AsyncClientCall",
    "NdrMesProcEncodeDecode",
    "RpcEpRegister",
    "UuidCreate",
    "UuidFromString",
    "UuidToString",
)

_WINRT_API_PATTERNS: Tuple[str, ...] = (
    "RoInitialize",
    "RoUninitialize",
    "RoActivateInstance",
    "RoGetActivationFactory",
    "RoRegisterActivationFactories",
    "WindowsCreateString",
    "WindowsDeleteString",
    "WindowsGetStringRawBuffer",
    "WindowsDuplicateString",
    "WindowsCompareStringOrdinal",
    "WindowsCreateStringReference",
)

_NAMED_PIPE_API_PATTERNS: Tuple[str, ...] = (
    "CreateNamedPipe",
    "ConnectNamedPipe",
    "DisconnectNamedPipe",
    "CallNamedPipe",
    "WaitNamedPipe",
    "TransactNamedPipe",
    "PeekNamedPipe",
    "GetNamedPipeInfo",
    "GetNamedPipeHandleState",
    "SetNamedPipeHandleState",
    "CreatePipe",
)

_PROCESS_API_PATTERNS: Tuple[str, ...] = (
    "CreateProcess",
    "CreateProcessAsUser",
    "CreateProcessWithLogon",
    "CreateProcessWithToken",
    "OpenProcess",
    "TerminateProcess",
    "NtCreateProcess",
    "NtCreateUserProcess",
    "ShellExecute",
    "WinExec",
    "CreateThread",
    "CreateRemoteThread",
    "CreateRemoteThreadEx",
    "SuspendThread",
    "ResumeThread",
    "NtCreateThread",
    "NtCreateThreadEx",
    "QueueUserAPC",
)

# Module-level import detection (matched case-insensitively against
# ``module_name`` / ``resolved_module`` and ``raw_module_name`` fields).
_COM_IMPORT_MODULES = frozenset(["combase.dll", "ole32.dll", "oleaut32.dll"])
_COM_IMPORT_APISET_MARKERS = ("com-l",)

_RPC_IMPORT_MODULES = frozenset(["rpcrt4.dll"])

_WINRT_IMPORT_APISET_MARKERS = ("winrt",)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _long_path(p: pathlib.Path) -> pathlib.Path:
    """Return *p* with the ``\\\\?\\`` long-path prefix on Windows."""
    if sys.platform != "win32":
        return p
    s = str(p.resolve())
    if s.startswith("\\\\?\\"):
        return pathlib.Path(s)
    return pathlib.Path("\\\\?\\" + s)


def _safe_parse_json(raw: Optional[str]) -> Any:
    """Parse a JSON string, returning *None* on failure or empty input."""
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None


def _api_matches_any(api_name: str, patterns: Tuple[str, ...]) -> bool:
    """Return *True* if *api_name* starts with any of the given *patterns*."""
    name_lower = api_name.lower()
    for pat in patterns:
        if name_lower.startswith(pat.lower()):
            return True
    return False


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _build_identity(file_info: Optional[sqlite3.Row],
                    module_name: str) -> Dict[str, Any]:
    """Build the ``identity`` section from the ``file_info`` table."""
    if file_info is None:
        return {
            "module_name": module_name,
            "file_name": None,
            "description": None,
            "company": None,
            "version": None,
        }
    keys = file_info.keys()
    return {
        "module_name": module_name,
        "file_name": file_info["file_name"] if "file_name" in keys else None,
        "description": file_info["file_description"] if "file_description" in keys else None,
        "company": file_info["company_name"] if "company_name" in keys else None,
        "version": (file_info["file_version"] if "file_version" in keys and file_info["file_version"]
                     else file_info.get("product_version") if "product_version" in keys else None),
    }


def _build_scale(cursor: sqlite3.Cursor,
                 file_info: Optional[sqlite3.Row]) -> Dict[str, Any]:
    """Build the ``scale`` section by querying the ``functions`` table."""
    # Total functions
    cursor.execute("SELECT COUNT(*) FROM functions")
    total_functions = cursor.fetchone()[0]

    # Named vs unnamed (sub_*)
    cursor.execute(
        "SELECT COUNT(*) FROM functions "
        "WHERE function_name NOT LIKE 'sub\\_%' ESCAPE '\\'"
    )
    named_functions = cursor.fetchone()[0]
    unnamed_sub_functions = total_functions - named_functions

    # Functions with usable decompiled output
    cursor.execute(
        "SELECT COUNT(*) FROM functions "
        "WHERE decompiled_code IS NOT NULL "
        "AND decompiled_code != 'Decompiler not available' "
        "AND decompiled_code NOT LIKE 'Decompilation failed:%'"
    )
    with_decompiled = cursor.fetchone()[0]

    # Functions with assembly
    cursor.execute(
        "SELECT COUNT(*) FROM functions WHERE assembly_code IS NOT NULL"
    )
    with_assembly = cursor.fetchone()[0]

    # Class count (distinct class prefixes from ``Class::Method`` names)
    cursor.execute(
        "SELECT function_name FROM functions "
        "WHERE function_name LIKE '%::%'"
    )
    classes = set()
    for row in cursor.fetchall():
        name = row[0] or ""
        if "::" in name:
            classes.add(name.split("::")[0])
    class_count = len(classes)

    # Export count from file_info.exports JSON
    export_count = 0
    if file_info is not None:
        keys = file_info.keys()
        if "exports" in keys and file_info["exports"]:
            exports = _safe_parse_json(file_info["exports"])
            if isinstance(exports, list):
                export_count = len(exports)

    return {
        "total_functions": total_functions,
        "named_functions": named_functions,
        "unnamed_sub_functions": unnamed_sub_functions,
        "with_decompiled": with_decompiled,
        "with_assembly": with_assembly,
        "class_count": class_count,
        "export_count": export_count,
    }


def _build_library_profile(cursor: sqlite3.Cursor) -> Dict[str, Any]:
    """Build the ``library_profile`` section using library tag detection."""
    cursor.execute("SELECT function_name, mangled_name FROM functions")

    tag_counter: Counter = Counter()
    app_count = 0
    total = 0

    for row in cursor.fetchall():
        total += 1
        tag = CppGenerator._detect_library_tag(row[0], row[1])
        if tag:
            tag_counter[tag] += 1
        else:
            app_count += 1

    library_count = total - app_count
    noise_ratio = round(library_count / total, 3) if total > 0 else 0.0

    return {
        "app_functions": app_count,
        "library_functions": library_count,
        "noise_ratio": noise_ratio,
        "breakdown": dict(tag_counter.most_common()),
    }


def _categorise_api(api_name: str) -> List[str]:
    """Return all category tags that *api_name* matches."""
    cats: List[str] = []
    if _api_matches_any(api_name, _SECURITY_API_PATTERNS):
        cats.append("security")
    if _api_matches_any(api_name, _CRYPTO_API_PATTERNS):
        cats.append("crypto")
    if _api_matches_any(api_name, _COM_API_PATTERNS):
        cats.append("com")
    if _api_matches_any(api_name, _RPC_API_PATTERNS):
        cats.append("rpc")
    if _api_matches_any(api_name, _WINRT_API_PATTERNS):
        cats.append("winrt")
    if _api_matches_any(api_name, _NAMED_PIPE_API_PATTERNS):
        cats.append("named_pipe")
    if _api_matches_any(api_name, _PROCESS_API_PATTERNS):
        cats.append("process")
    return cats


def _build_api_profile(cursor: sqlite3.Cursor,
                       file_info: Optional[sqlite3.Row]) -> Dict[str, Any]:
    """Build the ``api_profile`` section from dangerous-API data and imports."""

    # -- Function-level: aggregate dangerous_api_calls -----------------------
    cursor.execute("SELECT dangerous_api_calls FROM functions")

    dangerous_func_count = 0
    total_refs = 0
    cat_counts: Counter = Counter()

    for (raw_calls,) in cursor.fetchall():
        calls = _safe_parse_json(raw_calls)
        if not calls or not isinstance(calls, list):
            continue
        dangerous_func_count += 1
        total_refs += len(calls)
        for api in calls:
            api_name = api if isinstance(api, str) else str(api)
            for cat in _categorise_api(api_name):
                cat_counts[cat] += 1

    # -- Import-level: scan file_info.imports --------------------------------
    import_surface: Dict[str, Any] = {
        "com_present": False,
        "rpc_present": False,
        "winrt_present": False,
        "named_pipes_present": False,
        "com_modules": [],
        "rpc_modules": [],
        "winrt_apisets": [],
        "named_pipe_functions": [],
    }

    if file_info is not None:
        keys = file_info.keys()
        imports_raw = None
        if "imports" in keys and file_info["imports"]:
            imports_raw = file_info["imports"]
        imports_data = _safe_parse_json(imports_raw)

        if isinstance(imports_data, list):
            seen_com_modules: set = set()
            seen_rpc_modules: set = set()
            seen_winrt_apisets: set = set()
            seen_pipe_funcs: set = set()

            for entry in imports_data:
                if not isinstance(entry, dict):
                    continue
                mod_name = (entry.get("module_name") or "").lower()
                raw_mod = (entry.get("raw_module_name") or "").lower()
                resolved = (entry.get("resolved_module") or "").lower()

                # COM module detection
                if mod_name in _COM_IMPORT_MODULES or resolved in _COM_IMPORT_MODULES:
                    display = entry.get("module_name") or entry.get("resolved_module") or ""
                    if display and display not in seen_com_modules:
                        seen_com_modules.add(display)
                elif any(m in raw_mod for m in _COM_IMPORT_APISET_MARKERS):
                    display = entry.get("module_name") or entry.get("resolved_module") or raw_mod
                    if display and display not in seen_com_modules:
                        seen_com_modules.add(display)

                # RPC module detection
                if mod_name in _RPC_IMPORT_MODULES or resolved in _RPC_IMPORT_MODULES:
                    display = entry.get("module_name") or entry.get("resolved_module") or ""
                    if display and display not in seen_rpc_modules:
                        seen_rpc_modules.add(display)

                # WinRT API-set detection
                if any(m in raw_mod for m in _WINRT_IMPORT_APISET_MARKERS):
                    apiset_name = entry.get("raw_module_name") or ""
                    if apiset_name and apiset_name not in seen_winrt_apisets:
                        seen_winrt_apisets.add(apiset_name)

                # Named-pipe function detection (scan individual imports)
                funcs = entry.get("functions")
                if isinstance(funcs, list):
                    for func in funcs:
                        if not isinstance(func, dict):
                            continue
                        fname = func.get("function_name") or func.get("raw_name") or ""
                        if _api_matches_any(fname, _NAMED_PIPE_API_PATTERNS):
                            if fname and fname not in seen_pipe_funcs:
                                seen_pipe_funcs.add(fname)

            import_surface["com_modules"] = sorted(seen_com_modules)
            import_surface["com_present"] = len(seen_com_modules) > 0
            import_surface["rpc_modules"] = sorted(seen_rpc_modules)
            import_surface["rpc_present"] = len(seen_rpc_modules) > 0
            import_surface["winrt_apisets"] = sorted(seen_winrt_apisets)
            import_surface["winrt_present"] = len(seen_winrt_apisets) > 0
            import_surface["named_pipe_functions"] = sorted(seen_pipe_funcs)
            import_surface["named_pipes_present"] = len(seen_pipe_funcs) > 0

    return {
        "dangerous_api_functions": dangerous_func_count,
        "total_dangerous_refs": total_refs,
        "security_api_count": cat_counts.get("security", 0),
        "crypto_api_count": cat_counts.get("crypto", 0),
        "com_api_count": cat_counts.get("com", 0),
        "rpc_api_count": cat_counts.get("rpc", 0),
        "winrt_api_count": cat_counts.get("winrt", 0),
        "named_pipe_api_count": cat_counts.get("named_pipe", 0),
        "process_api_count": cat_counts.get("process", 0),
        "import_surface": import_surface,
    }


def _build_complexity_profile(cursor: sqlite3.Cursor) -> Dict[str, Any]:
    """Build the ``complexity_profile`` from loop analysis and assembly size."""
    cursor.execute("SELECT loop_analysis, assembly_code FROM functions")

    functions_with_loops = 0
    total_loops = 0
    asm_sizes: List[int] = []

    for (loop_raw, asm_raw) in cursor.fetchall():
        # Loop analysis
        loops = _safe_parse_json(loop_raw)
        if loops:
            if isinstance(loops, dict):
                loop_list = loops.get("loops") or loops.get("natural_loops")
                if isinstance(loop_list, list) and len(loop_list) > 0:
                    functions_with_loops += 1
                    total_loops += len(loop_list)
            elif isinstance(loops, list) and len(loops) > 0:
                functions_with_loops += 1
                total_loops += len(loops)

        # Assembly size (line count)
        if asm_raw:
            line_count = asm_raw.count("\n") + 1
            asm_sizes.append(line_count)

    avg_asm_size = round(sum(asm_sizes) / len(asm_sizes)) if asm_sizes else 0
    max_asm_size = max(asm_sizes) if asm_sizes else 0
    over_500 = sum(1 for s in asm_sizes if s > 500)

    return {
        "functions_with_loops": functions_with_loops,
        "total_loops": total_loops,
        "avg_asm_size": avg_asm_size,
        "max_asm_size": max_asm_size,
        "functions_over_500_instructions": over_500,
    }


def _build_security_posture(cursor: sqlite3.Cursor,
                            file_info: Optional[sqlite3.Row]) -> Dict[str, Any]:
    """Build the ``security_posture`` from PE security features and canary coverage."""

    result: Dict[str, Any] = {
        "aslr": None,
        "dep": None,
        "cfg": None,
        "seh": None,
        "canary_coverage_pct": None,
    }

    # Security features from file_info
    if file_info is not None:
        keys = file_info.keys()
        if "security_features" in keys and file_info["security_features"]:
            sec = _safe_parse_json(file_info["security_features"])
            if isinstance(sec, dict):
                result["aslr"] = sec.get("aslr_enabled")
                result["dep"] = sec.get("dep_enabled")
                result["cfg"] = sec.get("cfg_enabled")
                result["seh"] = sec.get("seh_enabled")

    # Canary coverage: percentage of non-trivial functions referencing
    # __security_check_cookie or __GSHandlerCheck in outbound xrefs.
    cursor.execute(
        "SELECT COUNT(*) FROM functions WHERE assembly_code IS NOT NULL"
    )
    total_with_asm = cursor.fetchone()[0]

    if total_with_asm > 0:
        cursor.execute(
            "SELECT COUNT(*) FROM functions "
            "WHERE (outbound_xrefs LIKE '%security_check_cookie%' "
            "   OR outbound_xrefs LIKE '%GSHandlerCheck%' "
            "   OR outbound_xrefs LIKE '%security_cookie%' "
            "   OR simple_outbound_xrefs LIKE '%security_check_cookie%' "
            "   OR simple_outbound_xrefs LIKE '%GSHandlerCheck%') "
            "AND assembly_code IS NOT NULL"
        )
        canary_funcs = cursor.fetchone()[0]
        result["canary_coverage_pct"] = round(
            (canary_funcs / total_with_asm) * 100, 1
        )

    return result


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def generate_module_profile(db_path: str,
                            output_dir: str,
                            module_name: str) -> bool:
    """Generate ``module_profile.json`` from the analysis database.

    Args:
        db_path: Path to the per-module SQLite analysis database.
        output_dir: Directory where ``module_profile.json`` will be written.
        module_name: Sanitised module name (e.g. ``appinfo_dll``).

    Returns:
        ``True`` on success, ``False`` on failure.
    """
    debug_print(f"Generating module profile for '{module_name}' ...")

    try:
        conn = _connect_sqlite(db_path, isolation_level="DEFERRED")
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Fetch file_info row (may not exist)
        file_info: Optional[sqlite3.Row] = None
        try:
            cursor.execute("SELECT * FROM file_info LIMIT 1")
            file_info = cursor.fetchone()
        except sqlite3.OperationalError:
            debug_print("WARNING - file_info table not found; "
                        "identity and security_posture will have null fields.")

        # Check functions table exists
        try:
            cursor.execute("SELECT COUNT(*) FROM functions")
        except sqlite3.OperationalError:
            debug_print("WARNING - functions table not found; "
                        "module profile will be minimal.")
            conn.close()
            return False

        # Build all sections
        profile: Dict[str, Any] = {
            "identity": _build_identity(file_info, module_name),
            "scale": _build_scale(cursor, file_info),
            "library_profile": _build_library_profile(cursor),
            "api_profile": _build_api_profile(cursor, file_info),
            "complexity_profile": _build_complexity_profile(cursor),
            "security_posture": _build_security_posture(cursor, file_info),
        }

        conn.close()

        # Write JSON
        out_path = pathlib.Path(output_dir)
        _long_path(out_path).mkdir(parents=True, exist_ok=True)
        profile_path = out_path / "module_profile.json"

        with open(_long_path(profile_path), "w", encoding="utf-8") as f:
            json.dump(profile, f, indent=4, ensure_ascii=False)

        debug_print(f"Module profile written to {profile_path}")
        return True

    except Exception as e:
        debug_print(f"ERROR - Failed to generate module profile: {e}")
        import traceback
        debug_print(traceback.format_exc())
        return False
