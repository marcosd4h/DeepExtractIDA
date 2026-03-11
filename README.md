# DeepExtract - PE Context Extraction Framework

## Overview

**DeepExtract** is an IDA Pro 9.x plugin that bridges the gap between compiled PE binaries and AI coding agents. It extracts the full structural context of a binary (PE metadata, function signatures, disassembly, decompiled C/C++ code, cross-references, control flow, and more), and writes it in formats that agents like **Claude Code**, **Codex**, and **Cursor** can directly ingest and reason over. The goal is to let these agents read, navigate, and understand PE files the same way they understand source code repositories, enabling **AI-assisted vulnerability research** and **reverse engineering** at scale.

Results are written to a per-binary SQLite database, generated as C++ source files organized by module, and accompanied by JSON metadata. DeepExtract operates in two modes: **headless** for automated batch processing of large binary datasets, and **interactive** for targeted single-binary analysis within the IDA GUI.

## How It Works

The extraction pipeline has three stages:

```
PE Binary (.exe/.dll/.sys)
        |
        v
  IDA Pro 9.x + DeepExtract Plugin
  (disassembly, decompilation, analysis)
        |
        v
  Structured Output:
    - SQLite database (per-binary)
    - C++ source files (optional)
    - JSON metadata (module_profile, function_index, file_info)
```

**Stage 1 - Binary Loading.** IDA Pro loads the PE file, performs auto-analysis, and builds its internal database (IDB). If PDB symbols are available, IDA resolves function names and type information.

**Stage 2 - Extraction.** DeepExtract iterates over every function in the IDB and extracts:

- Disassembly and Hex-Rays decompiled code (when available)
- Inbound and outbound cross-references
- Stack frame metrics, string literals, global variable accesses
- Dangerous API calls, loop structures, vtable analysis (experimental), indirect call targets

At the file level, it extracts PE headers, imports, exports, sections, security features, Rich header data, TLS callbacks, and .NET CLR metadata.

**Stage 3 - Output.** All extracted data is written to a SQLite database. When C++ generation is enabled, the plugin groups decompiled functions into source files organized by class and module, and generates JSON metadata files (`function_index.json`, `module_profile.json`, `file_info.json`) alongside a human-readable report (`file_info.md`).

## Key Concepts

- **PE (Portable Executable):** The binary format used by Windows for executables (`.exe`), dynamic libraries (`.dll`), and drivers (`.sys`). PE files contain code sections, import/export tables, resource data, and metadata headers.

- **IDA Pro:** A disassembler and reverse engineering platform. IDA loads a binary, identifies functions, resolves cross-references, and builds a navigable representation of the code. The analysis results are stored in an IDA database (`.idb` / `.i64`).

- **Hex-Rays Decompiler:** An IDA Pro component that converts disassembled machine code into a C-like pseudo-code representation. DeepExtract stores this output as `decompiled_code` for each function.

- **Cross-references (xrefs):** Records of which functions call which other functions. **Inbound xrefs** list all callers of a function; **outbound xrefs** list all functions it calls. These form the binary's call graph.

- **Headless mode:** Running IDA Pro from the command line without a GUI, using `idat.exe` / `idat64.exe` with the `-A` flag. DeepExtract detects this mode and runs the full extraction pipeline automatically on startup.

- **Structured output:** The SQLite database and optional C++ files produced by DeepExtract. The database contains three tables (`file_info`, `functions`, `function_xrefs`) and is designed for programmatic queries by SQL, Python, or AI agent frameworks.

## Quick Start

**Install the plugin:**

```bash
hcli plugin install DeepExtract
```

**Extract a single binary (headless):**

```cmd
"C:\Program Files\IDA Professional 9.2\idat.exe" -A -L"C:\output\log.txt" -S"main.py --sqlite-db C:\output\kernel32.db --generate-cpp" "C:\Windows\System32\kernel32.dll"
```

**Batch-extract a directory:**

```powershell
.\headless_batch_extractor.ps1 -ExtractDirRecursive "C:\Windows\System32" -StorageDir "C:\Analysis"
```

**Interactive mode:** Open a binary in IDA Pro, then Edit > Plugins > DeepExtract (or `Ctrl-Shift-E`).

## Extraction Capabilities

The extractor operates at two levels: file-level metadata and per-function analysis.

### File-Level Metadata

The plugin extracts 30+ metadata points per binary:

- **Identification:** MD5, SHA256, file size, extension
- **PE headers:** Sections, entry points, Rich header (linker toolchain data), TLS callbacks
- **Version information:** Product name, company name, copyright, original filename, PDB path
- **Security features:** ASLR, DEP/NX, CFG, SafeSEH status, DLL characteristics
- **Runtime environment:** .NET assembly detection, CLR metadata, delay-load DLL imports

### Function-Level Analysis

For every identified function:

- **Signatures:** Base and extended function signatures, including demangled and mangled names
- **Code:** Full disassembly and Hex-Rays decompiled C/C++ output
- **Cross-references:** Inbound and outbound xrefs in full and simplified formats, plus a deduplicated relational table for SQL-based call graph queries
- **Dangerous API detection:** Matches outbound calls against 480+ security-critical APIs (e.g., CreateRemoteThread, LoadLibrary, CreateProcessW)
- **String literals:** Per-function string references
- **Global variable accesses:** Read/write references to global data
- **Stack frame analysis:** Aggregate frame sizes (locals, arguments, saved registers), frame pointer and exception handler flags, and stack canary detection via multi-heuristic analysis (variable names, security cookie calls, XOR patterns)
- **Loop analysis:** Natural loop detection via dominator-based back edges with SCC fallback for irreducible control flow, per-loop cyclomatic complexity, and infinite loop heuristic (zero exit edges)
- **VTable analysis (experimental):** Virtual call resolution for `[reg+offset]` call patterns, vtable slot inspection, and per-class method grouping from demangled names. Limited to single vtable at object offset 0; no multiple/virtual inheritance, thunk handling, or RTTI-based class hierarchy inference
- **Indirect call resolution (experimental):** Backward pattern matching to resolve common indirect call and jump patterns (register loads, memory dereferences, function pointer arrays), jump table detection via IDA's switch analysis with manual fallback, and basic obfuscation handling (XOR/ADD/SUB transforms). Coverage is limited to intra-procedural heuristics within a short instruction window

## Output Architecture

### SQLite Database

Each binary produces a SQLite database containing three tables.

**`file_info`** stores binary-level metadata:

- `file_path`, `file_name`, `file_extension`, `file_size_bytes`
- `md5_hash`, `sha256_hash`
- `imports`, `exports`, `entry_point`
- `file_version`, `product_version`, `company_name`, `pdb_path`
- `rich_header`, `tls_callbacks`, `is_net_assembly`, `clr_metadata`
- `dll_characteristics`, `security_features`, `exception_info`

**`functions`** stores per-function analysis data:

- `function_signature`, `mangled_name`, `function_name`
- `assembly_code`, `decompiled_code`
- `inbound_xrefs`, `outbound_xrefs` (full and simple JSON)
- `vtable_contexts`, `global_var_accesses`, `dangerous_api_calls`
- `string_literals`, `stack_frame`, `loop_analysis`
- `analysis_errors`, `created_at`

**`function_xrefs`** stores deduplicated cross-references for SQL-based call graph queries:

- `source_id`, `target_id` (foreign keys into `functions`)
- `target_name`, `target_module`
- `function_type` (generic, library, API, vtable, etc.)
- `xref_type`, `direction` (inbound/outbound)
- Unique constraint on `(source_id, target_id, target_name, target_module, xref_type, direction)`

### C++ Output (Optional)

When `--generate-cpp` is enabled, the plugin writes decompiled functions as grouped C++ source files:

- **Class methods:** Grouped by class into files of approximately 450-500 lines, named `{module}_{class}_group_N.cpp`. Methods are ordered alphabetically; each is preceded by a comment block with its name and signature.
- **Standalone functions:** Grouped into files of approximately 450-500 lines, named `{module}_standalone_group_N.cpp`, with the same ordering and comment conventions.
- **`function_index.json`:** Maps every function name to its `.cpp` file and library tag (WIL, STL, WRL, CRT, ETW/TraceLogging, or `null` for application code). See the [Function Index Format Reference](docs/function_index_format_reference.md).
- **`module_profile.json`:** Pre-computed module fingerprint covering identity, scale, library composition, API surface, complexity metrics, and security posture. See the [Module Profile Format Reference](docs/module_profile_format_reference.md).
- **`file_info.md` / `file_info.json`:** Human-readable and machine-readable analysis reports. See the [Analysis Metadata and Reports Reference](docs/file_info_format_reference.md).

## Usage Guide

### Installation

DeepExtract supports two deployment methods:

- **Plugin deployment:** Install into the IDA plugins directory. Once installed, the plugin is available in the GUI via Edit > Plugins > DeepExtract (or `Ctrl-Shift-E`) for interactive single-binary analysis, and via the command line for headless batch processing.
- **Standalone execution:** Clone the repository and run headless extraction directly from the source directory. See [Headless Batch Extraction](#headless-batch-extraction-powershell) and [Headless Mode (Individual File)](#headless-mode-individual-file) below.

To install as a plugin:

```bash
hcli plugin install DeepExtract
```

### Interactive Mode (GUI)

When a binary is open in IDA Pro, the plugin runs within the GUI and is accessible via:

- **Menu:** Edit > Plugins > DeepExtract
- **Hotkey:** `Ctrl-Shift-E`

This mode is designed for targeted analysis of a single binary. It presents a configuration dialog for:

- **Output paths:** SQLite database path and C++ output directory
- **Feature selection:** Dangerous APIs, strings, loops, stack frames
- **PE metadata:** Metadata extraction, Advanced PE, runtime info
- **Analysis parameters:** Thunk resolution depth and call validation confidence threshold
- **Progress monitoring:** Status indicator for the analysis pipeline

The interactive mode captures the current state of the researcher's IDA session, including renamed variables, custom comments, and manual type definitions stored in the `.idb`/`.i64`.

### Headless Batch Extraction (PowerShell)

The headless batch extractor processes PE binaries at scale without IDA's GUI. It accepts directories, file lists, or running process IDs as input, spawns concurrent IDA instances, and writes structured output (SQLite databases, C++ source files, JSON metadata) to a storage directory. The output is organized per-module and ready for analysis through AI agents such as Cursor or Claude Code via [DeepExtractRuntime](https://github.com/marcosd4h/DeepExtractRuntime).

**Resource expectations:** Batch extraction of large binary sets can run for several days and produce tens to hundreds of gigabytes of output depending on the number and size of modules. Plan disk space and machine availability accordingly.

Typical applications:

- **Process context capture:** Extract all modules loaded by a running process (`-TargetPid`) to reconstruct the full execution context of a target application, service, or malware sample.
- **OS internals analysis:** Extract `C:\Windows\System32` to build a queryable, decompiled representation of Windows usermode libraries for understanding OS functionality, API behavior, and inter-component dependencies.
- **Targeted binary auditing:** Point the extractor at a specific set of binaries to produce structured data for vulnerability research, threat hunting, or code review workflows.

#### Setup

Clone the repository:

```powershell
git clone https://github.com/marcosd4h/DeepExtractIDA.git
cd DeepExtractIDA
```

The script requires IDA Pro 9.x installed on the system. It auto-detects the IDA installation path; no additional configuration is needed. Run the extractor directly from the cloned directory:

```powershell
.\headless_batch_extractor.ps1 -ExtractDirRecursive "C:\Windows\System32" -StorageDir "C:\funvr\system32_internals"
```

The script locates IDA, iterates over all PE files in the target directory, downloads PDB symbols (enabled by default), and launches concurrent IDA processes to extract each binary. Results are written to `StorageDir`, organized by module, with each module producing a SQLite database, C++ source files, and JSON metadata.

#### Extraction Modes

The script supports three input modes, which can be combined in a single invocation:

- **Directory scan:** `-ExtractDirRecursive` for recursive scanning, `-ExtractDir` for top-level only. Both accept comma-separated lists and can be used together.
- **File list:** `-FilesToAnalyze` accepts a text file with one path per line.
- **PID mode:** `-TargetPid` extracts all modules loaded by one or more running processes (comma-separated PIDs).

Files from all sources are merged into one batch and deduplicated. C++ code generation is enabled by default in batch mode; disable with `-NoGenerateCpp`.

Additional batch parameters:

| Flag                      | Description                                          |
| ------------------------- | ---------------------------------------------------- |
| `-MaxConcurrentProcesses` | Number of parallel IDA processes (default: 4)        |
| `-StorageDir`             | Output directory for all analysis results (required) |
| `-IdaPath`                | Path to IDA executable (auto-detected if omitted)    |

#### Output Directory Structure

```
<StorageDir>/
├── AGENTS.md                      # AI agent runtime bootstrap (Cursor/Codex)
├── CLAUDE.md                      # AI agent runtime bootstrap (Claude Code)
├── analyzed_modules_list.txt      # List of files analyzed (all modes)
├── extraction_report.json         # Summary report with success/failure stats
├── analyzed_files.db              # Master tracking database
├── extracted_dbs/
│   └── <filename>_<hash>.db       # Individual analysis databases (one per file)
├── extracted_code/
│   └── <module_name>/             # Per-module output directory
│      ├── *.cpp                   # Generated C++ code (unless -NoGenerateCpp)
│      ├── function_index.json     # Function-to-file lookup index
│      ├── module_profile.json     # Pre-computed module fingerprint
│      ├── file_info.json          # Structured analysis metadata
│      └── file_info.md            # Human-readable analysis report
├── logs/
│   ├── batch_extractor_<timestamp>.log       # PowerShell batch execution log
│   ├── <filename>_<hash>_<timestamp>.log     # IDA analysis logs
│   ├── symchk_<filename>_<timestamp>.log     # Symbol download logs (if enabled)
│   └── symchk_<filename>_<timestamp>.log.err # Symbol download error logs (if enabled)
└── idb_cache/
    └── <filename>_<hash>.i64      # IDA database files
```

The `extraction_report.json` contains: extraction timestamp and mode, summary statistics (total, successful, failed), list of successfully extracted files with paths, and list of failed extractions with error details.

#### IDA Auto-Detection

The script searches for IDA Pro 9.x installations in standard paths:

```
C:\Program Files\IDA Professional 9.x\
C:\Program Files\IDA Pro 9.x\
C:\Program Files (x86)\IDA Professional 9.x\
C:\Program Files (x86)\IDA Pro 9.x\
```

The latest version is selected. Override with the `-IdaPath` parameter.

#### Symbol Downloading

The script downloads PDB debug symbols from Microsoft's public symbol server before IDA analysis. This is enabled by default and allows IDA to resolve function names and type information for richer output.

- Enabled by default; disable with `-NoDownloadSymbols`
- Downloads symbols only for the files being analyzed
- Runs up to 10 parallel `symchk.exe` processes
- Stores symbols in a local cache (default: `C:\symbols`), reused across runs
- Sets `_NT_SYMBOL_PATH` at user level (no admin required)

Requires `symchk.exe` from the [Windows SDK Debugging Tools](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/). The script auto-detects it from standard Windows SDK paths, or accepts a manual path via `-SymchkPath`.

| Flag                 | Description                                           |
| -------------------- | ----------------------------------------------------- |
| `-NoDownloadSymbols` | Skip automatic PDB downloading (enabled by default)   |
| `-SymbolStorePath`   | Local symbol cache directory (default: `C:\symbols`)  |
| `-SymchkPath`        | Path to `symchk.exe` (auto-detected from Windows SDK) |
| `-SymbolServerUrl`   | Symbol server URL (default: Microsoft public server)  |

#### Analysis Flags

| Flag                      | Description                                 |
| ------------------------- | ------------------------------------------- |
| `-NoExtractDangerousApis` | Skip dangerous API detection (480+ APIs)    |
| `-NoExtractStrings`       | Skip string literal extraction              |
| `-NoExtractStackFrame`    | Skip stack frame analysis                   |
| `-NoExtractGlobals`       | Skip global variable tracking               |
| `-NoAnalyzeLoops`         | Skip loop analysis                          |
| `-NoPeInfo`               | Skip PE version information extraction      |
| `-NoPeMetadata`           | Skip PE metadata extraction                 |
| `-NoAdvancedPe`           | Skip Rich header and TLS callback analysis  |
| `-NoRuntimeInfo`          | Skip .NET and delay-load DLL analysis       |
| `-ForceReanalyze`         | Force re-analysis even if already processed |
| `-NoGenerateCpp`          | Skip C++ code generation for AI review      |

#### Usage Examples

**Directory scan (recursive):**

```powershell
.\headless_batch_extractor.ps1 -ExtractDirRecursive "C:\Windows\System32" -StorageDir "C:\funvr\system32_internals"
```

**Non-recursive scan (top-level only):**

```powershell
.\headless_batch_extractor.ps1 -ExtractDir "C:\Windows" -StorageDir "C:\funvr\windows_root_internals"
```

**Mixed recursive and non-recursive:**

```powershell
.\headless_batch_extractor.ps1 `
    -ExtractDirRecursive "C:\Windows\System32","C:\Windows\SystemApps" `
    -ExtractDir "C:\Windows" `
    -StorageDir "C:\funvr\more_windows_internals"
```

**File list mode:**

```powershell
.\headless_batch_extractor.ps1 -FilesToAnalyze "targets.txt" -StorageDir "C:\funvr\vr_campaign1""
```

Where `targets.txt` contains:

```
C:\Windows\System32\kernel32.dll
C:\Windows\System32\ntdll.dll
C:\Program Files\MyApp\app.exe
```

**PID mode (single and multiple processes):**

```powershell
.\headless_batch_extractor.ps1 -TargetPid 1234 -StorageDir "C:\Analysis"
.\headless_batch_extractor.ps1 -TargetPid 1234,5678 -StorageDir "C:\Analysis"
```

**Custom IDA path:**

```powershell
.\headless_batch_extractor.ps1 -ExtractDir "C:\Malware" -StorageDir "C:\Analysis" -IdaPath "C:\IDA92\idat64.exe"
```

**Disable features for faster processing:**

```powershell
.\headless_batch_extractor.ps1 -ExtractDir "C:\Binaries" -StorageDir "C:\Analysis" -NoExtractStrings -NoGenerateCpp
```

**Adjust concurrency:**

```powershell
.\headless_batch_extractor.ps1 -ExtractDirRecursive "C:\Large\Dataset" -StorageDir "C:\Analysis" -MaxConcurrentProcesses 8
```

**Skip symbol downloading:**

```powershell
.\headless_batch_extractor.ps1 -ExtractDirRecursive "C:\Binaries" -StorageDir "C:\Analysis" -NoDownloadSymbols
```

**Custom symbol store path:**

```powershell
.\headless_batch_extractor.ps1 -ExtractDir "C:\Binaries" -StorageDir "C:\Analysis" -SymbolStorePath "D:\MySymbols"
```

#### Full Windows Codebase Extraction

These examples target key OS directories to extract and decompile the Windows usermode codebase into SQLite databases and C++ source files.

**Core OS libraries:**

```powershell
.\headless_batch_extractor.ps1 `
    -ExtractDirRecursive 'C:\Windows\System32','C:\Windows\SystemApps','C:\Program Files\Common Files','C:\Windows\IME','C:\Windows\ImmersiveControlPanel' `
    -ExtractDir 'C:\Windows' `
    -StorageDir "F:\Analysis\win11_full" `
    -MaxConcurrentProcesses 8
```

Covers `System32` (core libraries), `SystemApps` and `ImmersiveControlPanel` (UWP/packaged apps), `Common Files` (shared frameworks), and `IME` (input method components) recursively, plus top-level PE files under `C:\Windows` (e.g., `explorer.exe`, `regedit.exe`).

**Extended with SysWOW64 and kernel drivers:**

```powershell
.\headless_batch_extractor.ps1 `
    -ExtractDirRecursive 'C:\Windows\System32','C:\Windows\SysWOW64','C:\Windows\System32\drivers','C:\Windows\SystemApps','C:\Program Files\Common Files','C:\Windows\IME','C:\Windows\ImmersiveControlPanel' `
    -ExtractDir 'C:\Windows' `
    -StorageDir "F:\Analysis\win11_full_extended" `
    -MaxConcurrentProcesses 8
```

Adds 32-bit system libraries (`SysWOW64`) and kernel-mode drivers (`.sys` files under `drivers`).

**Maximum coverage (all installed applications):**

```powershell
.\headless_batch_extractor.ps1 `
    -ExtractDirRecursive 'C:\Windows\System32','C:\Windows\SysWOW64','C:\Windows\System32\drivers','C:\Windows\SystemApps','C:\Program Files','C:\Program Files (x86)','C:\Program Files\Common Files','C:\Windows\IME','C:\Windows\ImmersiveControlPanel' `
    -ExtractDir 'C:\Windows' `
    -StorageDir "F:\Analysis\win11_everything" `
    -MaxConcurrentProcesses 8
```

**Two-pass extraction (DB first, C++ second):**

```powershell
# Pass 1: DB-only extraction (skip C++ generation)
.\headless_batch_extractor.ps1 `
    -ExtractDirRecursive 'C:\Windows\System32','C:\Windows\SystemApps','C:\Program Files\Common Files','C:\Windows\IME','C:\Windows\ImmersiveControlPanel' `
    -ExtractDir 'C:\Windows' `
    -StorageDir "F:\Analysis\win11_full" `
    -NoGenerateCpp `
    -MaxConcurrentProcesses 8

# Pass 2: re-run with C++ generation on the same StorageDir
.\headless_batch_extractor.ps1 `
    -ExtractDirRecursive 'C:\Windows\System32','C:\Windows\SystemApps','C:\Program Files\Common Files','C:\Windows\IME','C:\Windows\ImmersiveControlPanel' `
    -ExtractDir 'C:\Windows' `
    -StorageDir "F:\Analysis\win11_full" `
    -ForceReanalyze `
    -MaxConcurrentProcesses 8
```

The first pass builds SQLite databases without C++ overhead. The second pass re-analyzes with full C++ generation. This is useful when queryable databases are needed as quickly as possible.

#### Getting Help

```powershell
.\headless_batch_extractor.ps1 -Help
Get-Help .\headless_batch_extractor.ps1 -Detailed
Get-Help .\headless_batch_extractor.ps1 -Full
Get-Help .\headless_batch_extractor.ps1 -Examples
```

### Headless Mode (Individual File)

For single-file analysis or custom scripting, invoke the plugin directly via IDA's command-line tool (`idat.exe` or `idat64.exe`).

```cmd
"C:\Program Files\IDA Professional 9.2\idat.exe" -A -L"C:\temp\pe_extraction_tests\output.log" -S"main.py --sqlite-db C:\temp\pe_extraction_tests\bitlockercsp.db" "C:\windows\system32\bitlockercsp.dll"
```

**IDA command-line arguments:**

- `-A`: Autonomous mode (no GUI)
- `-L`: Log file path
- `-S`: Plugin script to execute (`main.py`)
- `--sqlite-db`: Absolute path to the output SQLite database (required)

**Optional analysis flags:**

```cmd
--no-extract-dangerous-apis   # Skip dangerous API detection
--no-extract-strings          # Skip string literal extraction
--no-extract-stack-frame      # Skip stack frame analysis
--no-extract-globals          # Skip global variable tracking
--no-analyze-loops            # Skip loop analysis
--no-pe-info                  # Skip PE version info
--no-pe-metadata              # Skip PE metadata
--no-advanced-pe              # Skip Rich header/TLS callbacks
--no-runtime-info             # Skip .NET/delay-load analysis

--force-reanalyze            # Force re-analysis even if already complete
--generate-cpp               # Generate C++ output files for AI review
--cpp-output-dir <path>      # Custom directory for C++ output (defaults to extracted_raw_code/ next to db)
--thunk-depth N              # Maximum thunk resolution depth (default: 5)
--min-call-conf N            # Minimum confidence for call validation (10-100)
```

## Use Cases

DeepExtract produces structured data for several research workflows. Detailed documentation for each is in progress.

### AI-Assisted Code Review

The headless extractor generates C++ representations of decompiled binaries into the `extracted_code/` directory, organized by module. LLMs (Claude Code, Cursor, Codex) consume the `.cpp` files and `file_info.md` index to evaluate function logic, detect call patterns, and identify security-relevant invariants. For structured analysis workflows on top of this output, see the [AI Analysis Runtime](#ai-analysis-runtime) section.

### Interactive Analysis and Structured Export

The interactive plugin exports the current IDA database state, including renamed variables, custom comments, and manual type definitions from the `.idb`/`.i64`, into a SQLite database. Researchers can query the `functions`, `file_info`, and `function_xrefs` tables directly via SQL to analyze cross-references, data types, and metadata.

### Call Graph Traversal for Research Agents

Automated agents use the structured `inbound_xrefs`, `outbound_xrefs`, and the `function_xrefs` table to perform call graph traversal, evaluate reachability, resolve component dependencies, and generate technical summaries of subroutines based on their position in the global call graph.

## AI Analysis Runtime

The extraction output is designed to be consumed by [**DeepExtractRuntime**](https://github.com/marcosd4h/DeepExtractRuntime), a companion analysis runtime that operates on top of the SQLite databases and C++ files. The runtime deploys as an `.agent/` directory alongside the extraction data and operates across Claude Code, Cursor, Codex, and any AI coding environment that supports `AGENTS.md` or equivalent agent configuration.

The runtime provides:

- **Slash commands** for interactive analysis: `/triage`, `/audit`, `/explain`, `/lift-class`, `/trace-export`, `/data-flow`, `/taint`, `/hunt`, `/state-machines`, `/full-report`
- **Specialized agents** (code-lifter, re-analyst, triage-coordinator, type-reconstructor, verifier) that execute multi-step analysis pipelines
- **Analysis skills** covering function classification, call graph tracing, taint analysis, COM/WRL interface reconstruction, attack surface mapping, type reconstruction, and decompiler verification
- **Shared helper modules** providing database access, function resolution, API taxonomy (17 functional + 11 security categories), assembly metrics, struct scanning, caching, and cross-module graph analysis
- **Lifecycle hooks** that inject module context at session start and support batch processing

### Installing the Runtime

The headless batch extractor writes two bootstrap files (`AGENTS.md` and `CLAUDE.md`) into the output directory. These files contain the full installation procedure and are recognized automatically by AI coding agents. To install the runtime:

1. **Open the extraction output directory** (the `StorageDir` you passed to `headless_batch_extractor.ps1`) as a project in **Claude Code** or **Cursor**.
2. **Type `install DeepExtractRuntime`** in the agent chat.

The agent reads the bootstrap instructions from `AGENTS.md` / `CLAUDE.md` and executes the full setup automatically: cloning the [DeepExtractRuntime](https://github.com/marcosd4h/DeepExtractRuntime) repository into `.agent/`, creating the `.claude` symlink for Claude Code, installing the `.cursor/hooks.json` and `.cursor/rules` symlink for Cursor, and verifying the installation. No manual steps are required beyond the initial command.

Once installed, the runtime's slash commands (`/triage`, `/audit`, `/explain`, etc.) and specialized agents become available in the agent session. To update to the latest runtime version, type `update DeepExtractRuntime`.

See the [DeepExtractRuntime README](https://github.com/marcosd4h/DeepExtractRuntime) and [Onboarding Guide](https://github.com/marcosd4h/DeepExtractRuntime/blob/main/docs/ONBOARDING.md) for full documentation.

## Technical Requirements

- **Operating System:** Windows 10/11
- **IDA Pro:** Version 9.x (Pro edition required for headless mode)
- **Decompiler:** Hex-Rays Decompiler (optional; required for decompiled code output and C++ generation)
- **Python:** Python 3 environment configured within IDA (built-in with IDA 9.x)
- **Windows SDK Debugging Tools** (optional): Required for automatic symbol downloading (`symchk.exe`). Included with WinDbg and the [Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/); select "Debugging Tools for Windows" during SDK installation.
- **Dependencies:**
  - `pefile` (bundled in `deps/`; used for PE header parsing)
  - IDA Python SDK (built-in with IDA Pro)

## Documentation

Technical references for the extraction formats and database schemas:

- [**Data Format Reference**](docs/data_format_reference.md): SQLite schema, data architecture, and analysis heuristics
- [**Analysis Metadata and Reports Reference**](docs/file_info_format_reference.md): `file_info.md`, `file_info.json`, and C++ code output structure
- [**Function Index Format Reference**](docs/function_index_format_reference.md): `function_index.json` format and library tagging
- [**Module Profile Format Reference**](docs/module_profile_format_reference.md): `module_profile.json` computation covering identity, scale, library composition, API surface, complexity, and security posture

## Plugin Architecture

DeepExtract conforms to the IDA 9.x `plugmod_t` plugin architecture.

**Entry Point:** `main.py` (IDA plugin entry point via `PLUGIN_ENTRY()`)

**Core Modules:**

- `deep_extract/pe_context_extractor.py` - Main analysis pipeline and orchestration
- `deep_extract/extractor_core.py` - Public API hub; re-exports from all analysis modules
- `deep_extract/config.py` - Configuration dataclass and validation
- `deep_extract/constants.py` - Analysis limits, function type classification, dangerous API matching
- `deep_extract/schema.py` - SQLite schema management and migration
- `deep_extract/db_connection.py` - SQLite connection management and PRAGMA configuration
- `deep_extract/logging_utils.py` - Logging, memoization caching, and utility functions
- `deep_extract/json_safety.py` - JSON serialization with truncation and size limits
- `deep_extract/__init__.py` - Package init; re-exports public API from `extractor_core` and `pe_context_extractor`

**Analysis Modules:**

- `deep_extract/xref_analysis.py` - Cross-reference analysis and call graph building
- `deep_extract/vtable_analysis.py` - C++ vtable call resolution and method grouping (experimental)
- `deep_extract/loop_analysis.py` - Control flow and loop detection (dominator-based, SCC fallback)
- `deep_extract/indirect_call_analysis.py` - Indirect call resolution and jump table detection
- `deep_extract/interprocedural_analysis.py` - Cross-function data flow analysis
- `deep_extract/thunk_analysis.py` - Thunk chain resolution with configurable depth
- `deep_extract/string_analysis.py` - String literal extraction per function
- `deep_extract/stack_analysis.py` - Aggregate stack frame metrics and canary detection
- `deep_extract/name_extraction.py` - Function name extraction and demangling
- `deep_extract/import_resolution.py` - Import module resolution (IAT address to module name)
- `deep_extract/validation.py` - Call validation with confidence scoring
- `deep_extract/pe_metadata.py` - PE header, Rich header, TLS callback extraction

**Output Generation:**

- `deep_extract/cpp_generator.py` - C++ code generation for AI consumption
- `deep_extract/module_profile.py` - Module fingerprint generation (`module_profile.json`)
- `deep_extract/gui_dialog.py` - Interactive mode configuration dialog

**Utilities:**

- `deep_extract/utils/check_analyzed_files.py` - Batch analysis file-selection helper (hash, flags, stale lock checks)

**Plugin Lifecycle:**

- IDA loads `main.py` and invokes `PLUGIN_ENTRY()`
- Plugin factory (`DeepExtractPlugin`) initializes and creates a module instance
- Plugin module (`DeepExtractModule`) executes per-database
- Mode detection: presence of `--sqlite-db` in arguments selects headless mode; otherwise the GUI dialog is displayed
- Headless mode: runs the full pipeline, then exits via `ida_pro.qexit()`
- Interactive mode: displays the configuration dialog, then runs the pipeline with user-selected options
- Script mode (`-S`): `main.py` detects script execution, creates `DeepExtractModule` directly, and runs the pipeline without `PLUGIN_ENTRY()`

## Plugin Distribution

DeepExtract is packaged as an IDA 9.x plugin following the HCLI plugin format.

**Package contents:**

- `ida-plugin.json` - Plugin metadata and dependency specification
- `main.py` - Plugin entry point
- `deep_extract/` - Core analysis framework
- `deps/` - Bundled dependencies (pefile)

---

_DeepExtract - Developed by Marcos Oviedo for Agentic Vulnerability Research_
