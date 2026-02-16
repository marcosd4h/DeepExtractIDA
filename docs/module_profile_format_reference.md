# Module Profile Format Reference

This document describes the format, computation, and purpose of `module_profile.json`, a pre-computed fingerprint summarising a module's identity, scale, library composition, API surface, complexity characteristics, and security posture.

Unlike `file_info.json` and `function_index.json`, the module profile is generated **unconditionally** after function extraction completes -- it does not require `--generate-cpp`. The profile reads exclusively from the per-module SQLite database (`file_info` and `functions` tables) and adds negligible extraction time.

---

## File Locations

The profile is written to a directory that depends on whether C++ generation is enabled:

- **With `--generate-cpp`**: `{cpp_output_dir}/{module_name}/module_profile.json` (co-located with generated C++ files)
- **Without `--generate-cpp`**: `{sqlite_db_dir}/module_profile.json` (next to the analysis database)

`module_name` is derived from the input file name as `{stem}_{extension}` (extension without the dot), then sanitized with `CppGenerator.sanitize_filename()` (`::` -> `_`, non `[a-zA-Z0-9_.-]` replaced with `_`, truncated to 100 chars). For example: `kernel32.dll` -> `kernel32_dll`.

Output directory resolution when `--generate-cpp` is enabled:

- **`main.py` default**: if `--cpp-output-dir` is not provided, output goes to `{sqlite_db_dir}/extracted_raw_code/{module_name}/`.
- **`main.py` with `--cpp-output-dir`**: output goes to `{cpp_output_dir}/{module_name}/`.
- **`headless_batch_extractor.ps1`**: passes `--cpp-output-dir "{StorageDir}/extracted_code"`, so the profile is written to `{StorageDir}/extracted_code/{module_name}/`.

---

## JSON Format (`module_profile.json`)

The profile contains six top-level sections, each aggregating a different aspect of the module.

### JSON Schema

```json
{
  "identity": {
    "module_name": "string",
    "file_name": "string | null",
    "description": "string | null",
    "company": "string | null",
    "version": "string | null"
  },
  "scale": {
    "total_functions": "number",
    "named_functions": "number",
    "unnamed_sub_functions": "number",
    "with_decompiled": "number",
    "with_assembly": "number",
    "class_count": "number",
    "export_count": "number"
  },
  "library_profile": {
    "app_functions": "number",
    "library_functions": "number",
    "noise_ratio": "number",
    "breakdown": {
      "<tag>": "number"
    }
  },
  "api_profile": {
    "dangerous_api_functions": "number",
    "total_dangerous_refs": "number",
    "security_api_count": "number",
    "crypto_api_count": "number",
    "com_api_count": "number",
    "rpc_api_count": "number",
    "winrt_api_count": "number",
    "named_pipe_api_count": "number",
    "process_api_count": "number",
    "import_surface": {
      "com_present": "boolean",
      "rpc_present": "boolean",
      "winrt_present": "boolean",
      "named_pipes_present": "boolean",
      "com_modules": ["string"],
      "rpc_modules": ["string"],
      "winrt_apisets": ["string"],
      "named_pipe_functions": ["string"]
    }
  },
  "complexity_profile": {
    "functions_with_loops": "number",
    "total_loops": "number",
    "avg_asm_size": "number",
    "max_asm_size": "number",
    "functions_over_500_instructions": "number"
  },
  "security_posture": {
    "aslr": "boolean | null",
    "dep": "boolean | null",
    "cfg": "boolean | null",
    "seh": "boolean | null",
    "canary_coverage_pct": "number | null"
  }
}
```

---

## Section Details

### `identity`

Basic identification metadata sourced from the `file_info` table.

- **`module_name`**: Sanitised module name (e.g. `appinfo_dll`).
- **`file_name`**: Original file name from the PE header (`file_info.file_name`).
- **`description`**: File description from the PE version resource (`file_info.file_description`).
- **`company`**: Company name from the PE version resource (`file_info.company_name`).
- **`version`**: File version string. Uses `file_info.file_version`; falls back to `file_info.product_version` when the file version is absent.

### `scale`

Function-level size metrics derived from the `functions` table.

- **`total_functions`**: Total rows in the `functions` table.
- **`named_functions`**: Functions whose `function_name` does **not** start with `sub_` (IDA's default prefix for unnamed subroutines).
- **`unnamed_sub_functions`**: `total_functions - named_functions`.
- **`with_decompiled`**: Functions with usable decompiled output (not `null`, not `"Decompiler not available"`, and not starting with `"Decompilation failed:"`).
- **`with_assembly`**: Functions with a non-null `assembly_code` column.
- **`class_count`**: Distinct class prefixes extracted from function names containing `::`.
- **`export_count`**: Number of entries in the `file_info.exports` JSON array.

### `library_profile`

Library-vs-application composition using the same detection logic as `function_index.json`.

Each function's `function_name` and `mangled_name` are checked against `CppGenerator._LIBRARY_PATTERNS`. Matching functions receive a tag (`WIL`, `STL`, `WRL`, `CRT`, `ETW/TraceLogging`); unmatched functions are counted as application code.

- **`app_functions`**: Functions with no library tag match.
- **`library_functions`**: Functions matching at least one library pattern.
- **`noise_ratio`**: `library_functions / total_functions`, rounded to three decimal places. A value of `0.475` means 47.5% of functions are library boilerplate.
- **`breakdown`**: Object mapping each detected library tag to its function count, ordered by frequency (most common first).

### `api_profile`

API surface analysis combining two data sources: function-level dangerous-API references and module-level import scanning.

#### Function-level counts

Aggregated from the `functions.dangerous_api_calls` JSON column. Each row is a JSON array of API names flagged during extraction.

- **`dangerous_api_functions`**: Number of functions with at least one dangerous API reference.
- **`total_dangerous_refs`**: Total dangerous API references across all functions.
- **`security_api_count`**: References matching security/token/ACL patterns (e.g. `AdjustTokenPrivileges`, `OpenProcessToken`, `ImpersonateLoggedOnUser`, `AccessCheck`).
- **`crypto_api_count`**: References matching cryptographic patterns (e.g. `BCrypt*`, `NCrypt*`, `CryptEncrypt`, `CertOpenStore`).
- **`com_api_count`**: References matching COM patterns (e.g. `CoCreateInstance`, `CoInitializeEx`, `CLSIDFromProgID`).
- **`rpc_api_count`**: References matching RPC patterns (e.g. `RpcServerListen`, `NdrClientCall*`, `UuidCreate`).
- **`winrt_api_count`**: References matching WinRT patterns (e.g. `RoInitialize`, `RoActivateInstance`, `WindowsCreateString`).
- **`named_pipe_api_count`**: References matching named-pipe patterns (e.g. `CreateNamedPipe*`, `ConnectNamedPipe`, `TransactNamedPipe`).
- **`process_api_count`**: References matching process/thread patterns (e.g. `CreateProcess*`, `OpenProcess`, `CreateRemoteThread`).

A single API reference can match multiple categories (e.g. an API that is both security-related and process-related).

#### `import_surface`

Module-level technology presence derived from the `file_info.imports` JSON column. Each import entry contains `module_name` (resolved DLL), `raw_module_name` (original import or API-set name), and a `functions[]` array.

- **`com_present`**: `true` if any imported module resolves to `combase.dll`, `ole32.dll`, or `oleaut32.dll`, or if an API-set name contains `com-l`.
- **`rpc_present`**: `true` if any imported module resolves to `RPCRT4.dll`.
- **`winrt_present`**: `true` if any API-set name contains `winrt` (e.g. `api-ms-win-core-winrt-l1-1-0`).
- **`named_pipes_present`**: `true` if any imported function matches a named-pipe pattern (`CreateNamedPipe*`, `ConnectNamedPipe`, `CallNamedPipe*`, `WaitNamedPipe*`, `TransactNamedPipe`, `PeekNamedPipe`, `DisconnectNamedPipe`).
- **`com_modules`**: Sorted list of COM-related module names detected in imports.
- **`rpc_modules`**: Sorted list of RPC-related module names detected in imports.
- **`winrt_apisets`**: Sorted list of WinRT-related API-set names detected in imports.
- **`named_pipe_functions`**: Sorted list of named-pipe function names detected in imports.

### `complexity_profile`

Structural complexity metrics from loop analysis and assembly size.

- **`functions_with_loops`**: Functions whose `loop_analysis` JSON contains at least one detected loop.
- **`total_loops`**: Sum of all detected loops across all functions.
- **`avg_asm_size`**: Average assembly line count per function (rounded to nearest integer). Only functions with non-null `assembly_code` are counted.
- **`max_asm_size`**: Largest assembly line count for any single function.
- **`functions_over_500_instructions`**: Number of functions exceeding 500 assembly lines.

### `security_posture`

Binary-level security features from PE metadata, plus stack-canary coverage computed from cross-reference data.

- **`aslr`**: `true` if `DYNAMIC_BASE` is set in `DllCharacteristics`. Sourced from `file_info.security_features.aslr_enabled`.
- **`dep`**: `true` if `NX_COMPAT` is set. Sourced from `file_info.security_features.dep_enabled`.
- **`cfg`**: `true` if `GUARD_CF` is set. Sourced from `file_info.security_features.cfg_enabled`.
- **`seh`**: `true` if `NO_SEH` is **not** set. Sourced from `file_info.security_features.seh_enabled`.
- **`canary_coverage_pct`**: Percentage of functions (with assembly code) that reference `__security_check_cookie`, `__GSHandlerCheck`, or `__security_cookie` in their outbound cross-references. A value of `78.5` means 78.5% of functions are protected by stack canaries.

---

## Example

```json
{
    "identity": {
        "module_name": "appinfo_dll",
        "file_name": "appinfo.dll",
        "description": "Application Information Service",
        "company": "Microsoft Corporation",
        "version": "10.0.26100.7824"
    },
    "scale": {
        "total_functions": 1166,
        "named_functions": 1050,
        "unnamed_sub_functions": 116,
        "with_decompiled": 1166,
        "with_assembly": 1166,
        "class_count": 60,
        "export_count": 5
    },
    "library_profile": {
        "app_functions": 598,
        "library_functions": 554,
        "noise_ratio": 0.475,
        "breakdown": {
            "WIL": 465,
            "WRL": 47,
            "ETW/TraceLogging": 40,
            "STL": 1,
            "CRT": 1
        }
    },
    "api_profile": {
        "dangerous_api_functions": 127,
        "total_dangerous_refs": 176,
        "security_api_count": 45,
        "crypto_api_count": 2,
        "com_api_count": 12,
        "rpc_api_count": 3,
        "winrt_api_count": 8,
        "named_pipe_api_count": 0,
        "process_api_count": 8,
        "import_surface": {
            "com_present": true,
            "rpc_present": true,
            "winrt_present": true,
            "named_pipes_present": false,
            "com_modules": ["combase.dll"],
            "rpc_modules": ["RPCRT4.dll"],
            "winrt_apisets": [
                "api-ms-win-core-winrt-error-l1-1-0",
                "api-ms-win-core-winrt-l1-1-0",
                "api-ms-win-core-winrt-string-l1-1-0"
            ],
            "named_pipe_functions": []
        }
    },
    "complexity_profile": {
        "functions_with_loops": 224,
        "total_loops": 488,
        "avg_asm_size": 57,
        "max_asm_size": 1733,
        "functions_over_500_instructions": 9
    },
    "security_posture": {
        "aslr": true,
        "dep": true,
        "cfg": true,
        "seh": true,
        "canary_coverage_pct": 78.5
    }
}
```

---

## Notes

- The profile is generated by `deep_extract/module_profile.py` via `generate_module_profile()`, called from `run_analysis_pipeline()` in `pe_context_extractor.py`.
- If the `file_info` table is missing (e.g. database was only partially populated), the `identity` and `security_posture` sections will contain `null` fields. Other sections still compute from the `functions` table.
- If dangerous API extraction was disabled (`--no-extract-dangerous-apis`), `api_profile` counts default to `0`. The `import_surface` sub-object is still populated from the `file_info.imports` column when available.
- If loop analysis was disabled (`--no-analyze-loops`), `complexity_profile.functions_with_loops` and `total_loops` default to `0`. Assembly-size metrics are still computed.
- `noise_ratio` is `0.0` when the `functions` table is empty (no division by zero).
- `canary_coverage_pct` is `null` when no functions have assembly code.
- The `*_api_count` fields count individual references, not unique API names. A single function calling `CreateProcessW` twice contributes 2 to `process_api_count`.
