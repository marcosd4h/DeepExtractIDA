# Function Index Format Reference

This document describes the format and purpose of `function_index.json`, a lightweight index used by AI agents to locate functions quickly without scanning hundreds of generated `.cpp` files or querying the SQLite database for basic metadata.

The index is generated **only when C++/report generation is enabled** (e.g., `--generate-cpp`) and at least one function exists in the `functions` table. It includes both functions with usable decompiled output and functions where decompilation failed.

---

## File Locations

The index is written into the per-module output directory:

- `{cpp_output_dir}/{module_name}/function_index.json`

`module_name` is derived from the input file name as `{stem}_{extension}` (extension without the dot), then sanitized with `CppGenerator.sanitize_filename()` (`::` -> `_`, non `[a-zA-Z0-9_.-]` replaced with `_`, truncated to 100 chars). For example: `kernel32.dll` -> `kernel32_dll`.

Output directory resolution:

- **`main.py` default**: if `--cpp-output-dir` is not provided, output goes to `{sqlite_db_dir}/extracted_raw_code/{module_name}/`.
- **`main.py` with `--cpp-output-dir`**: output goes to `{cpp_output_dir}/{module_name}/`.
- **`headless_batch_extractor.ps1`**: passes `--cpp-output-dir "{StorageDir}/extracted_code"`, so the index is written to `{StorageDir}/extracted_code/{module_name}/`.

---

## JSON Format (`function_index.json`)

The index maps each function name to its generated `.cpp` file (when available), plus lightweight metadata (`function_id`, decompilation/assembly availability, and optional library tag).

### JSON Schema

```json
{
  "<function_name>": {
    "file": "string | null",
    "library": "WIL | STL | WRL | CRT | ETW/TraceLogging | null",
    "function_id": 123,
    "has_decompiled": true,
    "has_assembly": true
  }
}
```

### Field Details

- **`function_name` (object key)**: The extracted function name, matching `functions.function_name` from the analysis database. This includes C++ class methods (`Class::Method`), thunks, and demangled names when available.
- **`file`**: The generated `.cpp` filename containing the function. The file is located in the same directory as the index. This field is `null` when decompilation failed and no C++ output file exists.
- **`library`**: Optional tag for known library/runtime boilerplate. Values:
  - `WIL` — Windows Implementation Library (`wil::`, `wistd::`, or mangled `@wil@@`, `@wistd@@`)
  - `STL` — C++ standard library (`std::`, `stdext::`, or mangled `@std@@`, `@stdext@@`)
  - `WRL` — Windows Runtime C++ Template Library (`Microsoft::WRL::`)
  - `CRT` — C/C++ runtime support (`__scrt_`, `__acrt_`, `_CRT_`)
  - `ETW/TraceLogging` — TraceLogging and ETW helpers (`_tlgWrite`, `TraceLoggingCorrelationVector::`)
  - `null` — No library match (treat as application code)
- **`function_id`**: Integer primary key from `functions.function_id`.
- **`has_decompiled`**: Boolean flag. `true` means valid decompiled output was available and the function was emitted to a `.cpp` file; `false` means decompilation failed or was unavailable.
- **`has_assembly`**: Boolean flag. `true` means `functions.assembly_code` was present for this function; `false` means no assembly listing was stored.

### Examples

```json
{
  "IsFamilyProvisioned": {
    "file": "appinfo_dll_standalone_group_50.cpp",
    "library": null,
    "function_id": 861,
    "has_decompiled": true,
    "has_assembly": true
  },
  "CSyncMLDPU::AppendAlertStatus": {
    "file": "coredpus_dll_CSyncMLDPU_group_1.cpp",
    "library": null,
    "function_id": 1732,
    "has_decompiled": true,
    "has_assembly": true
  },
  "wil::details_abi::ProcessLocalStorageData<...>::MakeAndInitialize": {
    "file": "appinfo_dll_standalone_group_1.cpp",
    "library": "WIL",
    "function_id": 37,
    "has_decompiled": true,
    "has_assembly": true
  },
  "SomeFailedFunc": {
    "file": null,
    "library": null,
    "function_id": 42,
    "has_decompiled": false,
    "has_assembly": true
  }
}
```

---

## Notes

- If a function name appears in multiple files, the **first occurrence** is retained in the index and later duplicates are ignored (a warning is logged). This keeps the index deterministic and compact.
- Functions with failed or unavailable decompilation are still included with `"file": null` and `"has_decompiled": false` so agents can discover all database functions from the index alone.
- Rich function-level metadata such as signatures and xref details remains in the SQLite database and `file_info.json`.
