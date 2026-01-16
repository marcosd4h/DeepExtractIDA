# DeepExtract - PE Context Extraction Framework

## Project Overview

DeepExtract is an **IDA Pro 9.x Plugin** and **Headless Analysis Framework** designed primarily for **headless batch processing** of PE binaries to facilitate AI-assisted Vulnerability Research (VR).

Traditional reverse engineering is manual and GUI-centric. This framework provides an automated interface for processing large datasets of PE (Portable Executable) files using IDA Pro's analysis engine. It transforms binary data—including assembly, control flow graphs, and decompiled code—into a **structured, AI-ready SQLite database**.

**Architecture:** Built on IDA 9.x's `plugmod_t` plugin architecture, DeepExtract provides dual-mode operation:

- **Headless Mode**: Command-line batch processing for large-scale analysis
- **Interactive Mode**: GUI integration for targeted analysis

By converting unstructured data into a queryable schema, this tool facilitates:

- **Programmatic Agentic Systems:** Utilize the structured SQLite output as a semantic knowledge base for **Research Agents** (e.g., via **LangGraph**) to perform automated code analysis and **Agentic Vulnerability Research**. This establishes a data layer for [Cyber Reasoning Systems (CRS)](https://www.hackerone.com/blog/cyber-reasoning-system-ai-security) to process binary logic at scale.
- **AI-Native Code Review:** Export sanitized decompiled code to C++ for analysis in **Claude Code**, **Cursor**, or **Codex**, enabling LLMs to process function logic and data-flow invariants without the volume of unprocessed disassembly.
- **Large-Scale Threat Hunting:** Automate the analysis of binaries to identify cross-ecosystem vulnerability patterns, insecure API usage, and structural characteristics.

## Use Cases

The primary purpose of DeepExtract is to extract structured data from PE binaries to support specialized research workflows. The following use cases demonstrate the application of this data in automated and interactive research. Detailed documentation for each case is **pending** and will be released in the coming days.

### AI-Assisted Code Understanding (Cursor / Claude Code)

This use case demonstrates the **headless extractor** feature by generating the necessary context for AI grounding. The tool exports a structured C++ representation of the binary into the `extracted_code/` directory, organized by module folders.

- **Grounding Architecture**: LLMs (e.g., Claude Code, Cursor) utilize the generated `.cpp` files and `file_info.md` index to evaluate implementation logic.
- **Workflow**: A researcher uses Cursor to audit specific functions, such as `ShellExecuteW`. The AI leverages the local context to explain parameters, detect call patterns, and identify logical invariants.
- **Reporting**: Automated generation of technical reports based on the source-level representation of decompiled logic.

### Interactive Analysis & Structured Data Export

This use case focuses on the **interactive UI plugin** for targeted analysis of individual binaries. It is designed to capture the latest state of a researcher's session, including renamed variables, custom comments, and manual type definitions stored in the `.idb`/`.i64`.

- **Data Capture**: The plugin exports the current IDA database state into a structured SQLite database.
- **Schema Visibility**: Researchers can query the `functions` and `file_info` tables to analyze data types, cross-references, and metadata directly via SQL.
- **Session Integration**: Facilitates the transfer of manual reverse engineering insights into a format compatible with external analysis tools.

### Deep Research Agents via Callgraph Traversal

Automated agents utilize the **LangGraph Deep Agent abstraction** to perform semantic reasoning across the binary's execution graph using structured `inbound_xrefs` and `outbound_xrefs`.

- **Callgraph Reasoning**: Agents traverse the `simple_outbound_xrefs` to evaluate reachability and component dependencies.
- **Automated Synthesis**: The system generates high-level technical summaries of subroutines by analyzing their position and interactions within the global callgraph.

### Autonomous Vulnerability Research (Claude Agent SDK)

This configuration implements an autonomous auditor using the [Claude Agent SDK](https://platform.claude.com/docs/en/agent-sdk/overview).

- **Skill-Based Extraction**: The agent utilizes "Skills" to interface with the SQLite backend, retrieving decompiled code and cross-reference data on-demand.
- **Primitive Discovery**: Automated scanning for vulnerability sinks (e.g., insecure API usage) grounded by the structured data layer.
- **Fail-Safe Monitoring**: Evaluation of complex logical paths where standard automated heuristics may require agentic verification.

## Extraction Capabilities

The extractor performs hierarchical analysis, transitioning from global binary metadata to function-level data.

### Binary & Metadata Extraction (File Level)

The tool captures over 30+ metadata points for every binary, creating a comprehensive **metadata profile** for the file:

- **Identification & Hashes:** MD5, SHA256, file size, and extension.
- **PE Header Intelligence:** Extraction of `sections`, `entry_point` JSON, `rich_header` (linker data), and `tls_callbacks`.
- **Version & Authenticity:** Product/Company names, legal copyright, original filenames, and internal PDB paths (`pdb_path`).
- **Security Posture:** `dll_characteristics` and `security_features` (ASLR, DEP, NX), along with `load_config` and `exception_info`.
- **Runtime Environment:** Detection of `.NET` assemblies (`is_net_assembly`) and full `clr_metadata` extraction.

### Function-Level Analysis

For every identified function, the tool extracts:

- **Identity & Signatures:** Both `function_signature` and `function_signature_extended`, including demangled and mangled names.
- **Assembly & Decompiled Code:** Full `assembly_code` and high-level `decompiled_code` (if Hex-Rays is available) are stored for direct semantic analysis.

### Security Context & Semantic Analysis

Beyond raw code, the tool performs deep heuristics to find vulnerability signals:

- **Dangerous API Detection:** Scans for 480+ security-critical APIs (e.g., `strcpy`, `CreateProcess`) stored in `dangerous_api_calls`.
- **String & Data Analysis:** Extracts `string_literals` and `global_var_accesses` specific to each function.
- **Stack & Memory Intelligence:** Detailed `stack_frame` layouts and variable sizes to identify potential overflow primitives.
- **Loop Intelligence:** Implements **Tarjan’s Algorithm** for `loop_analysis`, identifying natural loops, infinite loops, and cyclomatic complexity.

### Relationship & Control Flow Intelligence

- **Graph Connectivity:** Full `inbound_xrefs` (callers) and `outbound_xrefs` (callees), including "simple" versions for faster graph traversal.
- **C++ Reconstruction:** Resolves `vtable_contexts` and trace virtual function calls to reconstruct class hierarchies and polymorphism logic.

## Usage Guide

### Installation

DeepExtract supports two deployment methods:

- **Plugin Deployment**: Installation into the IDA plugins directory for integrated headless and interactive execution.
- **Standalone Execution**: Execution directly from the source directory.

To install as a plugin, copy the entire repository structure to IDA's plugins directory:

- Windows: `%APPDATA%\Hex-Rays\IDA Pro\plugins\DeepExtract\`
- Linux: `~/.idapro/plugins/DeepExtract/`
- macOS: `~/Library/Application Support/IDA Pro/plugins/DeepExtract/`

### Headless Batch Extraction (PowerShell Script)

For large-scale analysis, use the `headless_batch_extractor.ps1` PowerShell script to automate batch processing with concurrent IDA instances.

#### Features

- **Three Extraction Modes:**
  - **Directory Scan**: Recursively scan directories for PE files
  - **File List**: Process files from a text list (one path per line)
  - **PID Mode**: Extract all modules loaded by a running process
- **IDA Auto-Detection**: Automatically identifies the IDA installation (9.x series)
- **Concurrent Processing**: Spawns multiple IDA processes (default: 4) for parallel analysis
- **Conditional Filtering**: Tracks analyzed files to prevent redundant processing
- **Detailed Logging**: Per-file logs and error reporting

#### IDA Auto-Detection

The script automatically searches for IDA Pro installations in common paths:

```
C:\Program Files\IDA Professional 9.x\
C:\Program Files\IDA Pro 9.x\
C:\Program Files (x86)\IDA Professional 9.x\
C:\Program Files (x86)\IDA Pro 9.x\
```

The latest version is selected automatically. Override with `-IdaPath` parameter.

#### Usage Examples

**Directory Scan Mode (Recursive)**

```powershell
.\headless_batch_extractor.ps1 -ExtractDir "C:\Windows\System32" -StorageDir "C:\Analysis" -Recursive
```

Scans all PE files in System32 and subdirectories.

**File List Mode**

```powershell
.\headless_batch_extractor.ps1 -FilesToAnalyze "targets.txt" -StorageDir "C:\Analysis"
```

Where `targets.txt` contains:

```
C:\Windows\System32\kernel32.dll
C:\Windows\System32\ntdll.dll
C:\Program Files\MyApp\app.exe
```

**PID Mode (Process Module Extraction)**

```powershell
.\headless_batch_extractor.ps1 -TargetPid 1234 -StorageDir "C:\Analysis"
```

Extracts all modules loaded by process ID 1234. Creates a dedicated subfolder with naming format:

```
C:\Analysis\pid_1234_processname_20260115_143022\
```

**Custom IDA Path**

```powershell
.\headless_batch_extractor.ps1 -ExtractDir "C:\Malware" -StorageDir "C:\Analysis" -IdaPath "C:\IDA92\idat64.exe"
```

**Disable Specific Features (Faster Analysis)**

```powershell
# Skip string extraction and C++ generation for faster processing
.\headless_batch_extractor.ps1 -ExtractDir "C:\Binaries" -StorageDir "C:\Analysis" -NoExtractStrings -NoGenerateCpp
```

**Adjust Concurrency**

```powershell
# Run 8 concurrent IDA processes (for high-core systems)
.\headless_batch_extractor.ps1 -ExtractDir "C:\Large\Dataset" -StorageDir "C:\Analysis" -MaxConcurrentProcesses 8
```

#### Analysis Flags

| Flag                      | Description                                 |
| ------------------------- | ------------------------------------------- |
| `-NoExtractDangerousApis` | Skip dangerous API detection (300+ APIs)    |
| `-NoExtractStrings`       | Skip string literal extraction              |
| `-NoExtractStackFrame`    | Skip stack frame analysis                   |
| `-NoExtractGlobals`       | Skip global variable tracking               |
| `-NoAnalyzeLoops`         | Skip loop analysis (Tarjan's algorithm)     |
| `-NoPeInfo`               | Skip PE version information extraction      |
| `-NoPeMetadata`           | Skip PE metadata extraction                 |
| `-NoAdvancedPe`           | Skip Rich header and TLS callback analysis  |
| `-NoRuntimeInfo`          | Skip .NET and delay-load DLL analysis       |
| `-ForceReanalyze`         | Force re-analysis even if already processed |
| `-NoGenerateCpp`          | Skip C++ code generation for AI review      |

#### Output Structure

```
<StorageDir>/
├─ analyzed_modules_list.txt      # List of files analyzed (all modes)
├─ extraction_report.json         # Summary report with success/failure stats
├─ analyzed_files.db              # Master tracking database
├─ extracted_dbs/
│  └─ <filename>_<hash>.db        # Individual analysis databases (one per file)
├─ extracted_code/
│  └─ <filename>/                 # Generated C++ code (if enabled)
│     └─ *.cpp
├─ logs/
│  └─ <filename>_<timestamp>.log  # IDA analysis logs
└─ idb_cache/
   └─ <filename>_<hash>.i64       # IDA database files
```

The `extraction_report.json` contains:

- Extraction timestamp and mode
- Summary statistics (total, successful, failed)
- List of successfully extracted files with paths
- List of failed extractions with error details

#### Getting Help

```powershell
# Display built-in help with colorized output
.\headless_batch_extractor.ps1 -Help

# Use PowerShell's Get-Help for detailed parameter documentation
Get-Help .\headless_batch_extractor.ps1 -Detailed

# Show all available parameters
Get-Help .\headless_batch_extractor.ps1 -Full

# Show usage examples only
Get-Help .\headless_batch_extractor.ps1 -Examples
```

#### Enterprise Workflow Example

```powershell
# Phase 1: Initial scan of system binaries (skip C++ for speed)
.\headless_batch_extractor.ps1 `
    -ExtractDir "C:\Windows\System32" `
    -StorageDir "C:\Analysis\SystemBinaries" `
    -Recursive `
    -NoGenerateCpp `
    -MaxConcurrentProcesses 8

# Phase 2: Targeted analysis of specific malware samples with full extraction
.\headless_batch_extractor.ps1 `
    -FilesToAnalyze "C:\Samples\targets.txt" `
    -StorageDir "C:\Analysis\MalwareSamples" `
    -MaxConcurrentProcesses 4

# Phase 3: Runtime module extraction from suspicious process
.\headless_batch_extractor.ps1 `
    -TargetPid 5678 `
    -StorageDir "C:\Analysis\RuntimeExtraction"
```

### Headless Mode (Individual File Extraction)

For single-file analysis or custom scripting, run the plugin directly in headless mode using IDA's command-line tool (`idat.exe` or `idat64.exe`).

**Example: Analyze a single binary**

```cmd
"C:\Program Files\IDA Professional 9.2\idat.exe" -A -L"C:\temp\pe_extraction_tests\output.log" -S"main.py --sqlite-db C:\temp\pe_extraction_tests\bitlockercsp.db" "C:\windows\system32\bitlockercsp.dll"
```

**Command-Line Arguments:**

- `-A`: Autonomous mode (no GUI)
- `-L`: Log file path
- `-S`: Plugin script to execute (`main.py`)
- `--sqlite-db`: Absolute path to the output SQLite database (required)

**Optional Analysis Flags:**

```cmd
# Disable specific extraction features
--no-extract-dangerous-apis   # Skip dangerous API detection
--no-extract-strings          # Skip string literal extraction
--no-extract-stack-frame      # Skip stack frame analysis
--no-extract-globals          # Skip global variable tracking
--no-analyze-loops            # Skip loop analysis
--no-pe-info                  # Skip PE version info
--no-pe-metadata              # Skip PE metadata
--no-advanced-pe              # Skip Rich header/TLS callbacks
--no-runtime-info             # Skip .NET/delay-load analysis

# Additional options
--force-reanalyze            # Force re-analysis even if already complete
--generate-cpp               # Generate C++ output files for AI review
--cpp-output-dir <path>      # Custom directory for C++ output (defaults to extracted_raw_code/ next to db)
--thunk-depth N              # Maximum thunk resolution depth (default: 10)
--min-call-conf N            # Minimum confidence for call validation (10-100)
```

### Interactive Mode (GUI)

When a binary is open in the IDA Pro GUI, the plugin is accessible via:

- **Menu**: Edit → Plugins → DeepExtract
- **Hotkey**: `Ctrl-Shift-E`

The interactive mode provides a configuration interface for:

- **Output Management**: Specification of the SQLite database path and C++ output directory.
- **Feature Selection**: Selection of analysis modules (Dangerous APIs, Strings, Loops, Stack Frames).
- **PE Metadata Configuration**: Selection of PE extraction parameters (Metadata, Advanced PE, Runtime Info).
- **Analysis Parameters**: Configuration of thunk resolution depth and confidence thresholds for call validation.
- **Execution Monitoring**: A progress indicator displays the status of the analysis pipeline.

## Output Architecture

For a comprehensive technical reference of the data architecture, schemas, and analysis heuristics, see the [Data Format Reference](docs/data_format_reference.md).

The results are stored in two primary relational tables within the SQLite database.

### Table: `file_info`

High-level metadata for the binary, including:

- `file_path`, `file_name`, `file_extension`, `file_size_bytes`.
- `md5_hash`, `sha256_hash`.
- `imports`, `exports`, `entry_point`.
- `file_version`, `product_version`, `company_name`, `pdb_path`.
- `rich_header`, `tls_callbacks`, `is_net_assembly`, `clr_metadata`.
- `dll_characteristics`, `security_features`, `exception_info`.

### Table: `functions`

The core table containing granular data for every function in the binary:

- `function_signature`, `mangled_name`, `function_name`.
- `assembly_code`, `decompiled_code`.
- `inbound_xrefs`, `outbound_xrefs` (Full & Simple JSON).
- `vtable_contexts`, `global_var_accesses`, `dangerous_api_calls`.
- `string_literals`, `stack_frame`, `loop_analysis`.
- `analysis_errors`, `created_at`.

### Directory: `extracted_raw_code/` (Optional)

If `--generate-cpp` is used, the tool creates a folder structure containing **one individual `.cpp` file per function**. Additionally, it generates a **single Markdown file per module** (`file_info.md`) that serves as a high-level index and technical report for the binary.

## Technical Requirements

- **IDA Pro:** Version 9.0 or later (Pro edition required for headless mode)
- **Decompiler:** Hex-Rays Decompiler (optional, but required for C-code generation and advanced analysis)
- **Python:** Python 3 environment configured within IDA (built-in with IDA 9.x)
- **Dependencies:**
  - `pefile` (Bundled in `deps/`; used for PE header parsing)
  - IDA Python SDK (built-in with IDA Pro)

## Plugin Architecture

DeepExtract conforms to the IDA 9.x plugin architecture for compatibility and maintainability:

**Entry Point:** `main.py` - IDA plugin entry point using `PLUGIN_ENTRY()`

**Core Modules:**

- `deep_extract/pe_context_extractor.py` - Main analysis pipeline and orchestration
- `deep_extract/extractor_core.py` - Core extraction functions (xrefs, strings, stack frames)
- `deep_extract/xref_analysis.py` - Cross-reference analysis and call graph building
- `deep_extract/vtable_analysis.py` - C++ vtable reconstruction
- `deep_extract/loop_analysis.py` - Control flow and loop detection (Tarjan's algorithm)
- `deep_extract/pe_metadata.py` - PE header, Rich header, TLS callback extraction
- `deep_extract/cpp_generator.py` - C++ code generation for AI consumption
- `deep_extract/schema.py` - SQLite schema management and migration
- `deep_extract/config.py` - Configuration dataclass and validation

**Plugin Lifecycle:**

- IDA loads `main.py` and calls `PLUGIN_ENTRY()`
- Plugin factory (`DeepExtractPlugin`) initializes and creates module instance
- Plugin module (`DeepExtractModule`) handles per-database execution
- Detects headless vs. interactive mode based on command-line arguments
- In headless mode: runs full pipeline and exits via `ida_pro.qexit()`
- In interactive mode: displays the configuration interface for user selection.

## Plugin Distribution

DeepExtract is packaged as an IDA 9.x plugin following Hex-Rays' HCLI plugin format:

**Package Contents:**

- `ida-plugin.json` - Plugin metadata and dependency specification
- `main.py` - Plugin entry point
- `deep_extract/` - Core analysis framework
- `deps/` - Bundled dependencies (pefile)

**Distribution Methods:**

1. **Manual Installation**: Copy to IDA plugins directory
2. **HCLI Package**: Distribute as ZIP with `ida-plugin.json` for automated installation
3. **GitHub Release**: Publish tagged releases for version management

**Compatibility:**

- IDA Pro 9.0+
- Windows, Linux, macOS
- x86-64 architecture

---

_DeepExtract - Developed by Marcos Oviedo for Agentic Vulnerability Research_
