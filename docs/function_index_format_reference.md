# Function Index Format Reference

This document describes the format and purpose of `function_index.json`, a lightweight index used by AI agents to locate functions quickly without scanning hundreds of generated `.cpp` files.

The index is generated **only when C++/report generation is enabled** (e.g., `--generate-cpp`) and at least one function has usable decompiled output (the same filter used for C++ file generation).

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

The index maps each function name to the `.cpp` file that contains its decompiled output, plus a lightweight library tag when the function is detected as boilerplate.

### JSON Schema

```json
{
  "<function_name>": {
    "file": "string",
    "library": "WIL | STL | WRL | CRT | ETW/TraceLogging | null"
  }
}
```

### Field Details

- **`function_name` (object key)**: The extracted function name, matching `functions.function_name` from the analysis database. This includes C++ class methods (`Class::Method`), thunks, and demangled names when available.
- **`file`**: The generated `.cpp` filename containing the function. The file is located in the same directory as the index.
- **`library`**: Optional tag for known library/runtime boilerplate. Values:
  - `WIL` — Windows Implementation Library (`wil::`, `wistd::`, or mangled `@wil@@`, `@wistd@@`)
  - `STL` — C++ standard library (`std::`, `stdext::`, or mangled `@std@@`, `@stdext@@`)
  - `WRL` — Windows Runtime C++ Template Library (`Microsoft::WRL::`)
  - `CRT` — C/C++ runtime support (`__scrt_`, `__acrt_`, `_CRT_`)
  - `ETW/TraceLogging` — TraceLogging and ETW helpers (`_tlgWrite`, `TraceLoggingCorrelationVector::`)
  - `null` — No library match (treat as application code)

### Examples

```json
{
  "IsFamilyProvisioned": {
    "file": "appinfo_dll_standalone_group_50.cpp",
    "library": null
  },
  "CSyncMLDPU::AppendAlertStatus": {
    "file": "coredpus_dll_CSyncMLDPU_group_1.cpp",
    "library": null
  },
  "wil::details_abi::ProcessLocalStorageData<...>::MakeAndInitialize": {
    "file": "appinfo_dll_standalone_group_1.cpp",
    "library": "WIL"
  }
}
```

---

## Notes

- If a function name appears in multiple files, the **first occurrence** is retained in the index and later duplicates are ignored (a warning is logged). This keeps the index deterministic and compact.
- The index is intentionally minimal; signatures and other metadata remain in `file_info.json`.
