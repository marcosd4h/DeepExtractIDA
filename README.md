# DeepExtract - PE Context Extraction Framework

## 1. Project Overview

DeepExtract is a specialized **IDA Pro 9.x Plugin** and **Headless Analysis Framework** designed to bridge the gap between raw binary disassembly and modern AI-assisted Vulnerability Research (VR).

Traditional reverse engineering is manual and GUI-centric. This framework operates as an IDA Pro plugin supporting both interactive and headless modes, utilizing IDA Pro's powerful analysis engine to mass-process PE (Portable Executable) files. It transforms unstructured binary data—assembly, control flow graphs, and decompiled code—into a **structured, AI-ready SQLite database**.

**Architecture:** Built on IDA 9.x's modern `plugmod_t` plugin architecture, DeepExtract provides dual-mode operation:

- **Headless Mode**: Command-line batch processing for enterprise-scale analysis
- **Interactive Mode**: GUI integration for ad-hoc analysis (placeholder for future implementation)

By converting binary opacity into queryable structure, this tool enables:

- **Programmatic AI Agents:** Leverage the structured SQLite output as a semantic knowledge base for **Deep Research Agents** (e.g., via **LangGraph**) to perform autonomous code understanding and **Agentic Vulnerability Research**. This transforms the extraction process into a foundation for [Cyber Reasoning Systems (CRS)](https://www.hackerone.com/blog/cyber-reasoning-system-ai-security) capable of reasoning about binary logic at scale.
- **AI-Native Code Review:** Export sanitized decompiled code to C++ for immediate analysis in **Claude Code**, **Cursor**, or **Codex**, enabling LLMs to reason about function logic and data-flow invariants without the noise of raw disassembly.
- **Enterprise-Scale Threat Hunting:** Orchestrate the analysis of thousands of binaries to identify cross-ecosystem vulnerability patterns, insecure API usage, and structural weaknesses at scale.

## 2. Key Extraction Capabilities

The extractor performs hierarchical analysis, moving from global binary metadata to granular function-level intelligence.

### I. Binary & Metadata Extraction (File Level)

The tool captures over 30+ metadata points for every binary, creating a comprehensive "identity" for the file:

- **Identification & Hashes:** MD5, SHA256, file size, and extension.
- **PE Header Intelligence:** Detailed extraction of `sections`, `entry_point` JSON, `rich_header` (undocumented linker data), and `tls_callbacks`.
- **Version & Authenticity:** Product/Company names, legal copyright, original filenames, and internal PDB paths (`pdb_path`).
- **Security Posture:** Detailed `dll_characteristics` and `security_features` (ASLR, DEP, NX), along with `load_config` and `exception_info`.
- **Runtime Environment:** Automated detection of `.NET` assemblies (`is_net_assembly`) and full `clr_metadata` extraction.

### II. Function-Level Analysis

For every identified function, the tool extracts:

- **Identity & Signatures:** Both `function_signature` and `function_signature_extended`, including demangled and mangled names.
- **Assembly & Decompiled Code:** Full `assembly_code` and high-level `decompiled_code` (if Hex-Rays is available) are stored for direct semantic analysis.

### III. Security Context & Semantic Analysis

Beyond raw code, the tool performs deep heuristics to find vulnerability signals:

- **Dangerous API Detection:** Scans for 300+ security-critical APIs (e.g., `strcpy`, `CreateProcess`) stored in `dangerous_api_calls`.
- **String & Data Analysis:** Extracts `string_literals` and `global_var_accesses` specific to each function.
- **Stack & Memory Intelligence:** Detailed `stack_frame` layouts and variable sizes to identify potential overflow primitives.
- **Loop Intelligence:** Implements **Tarjan’s Algorithm** for `loop_analysis`, identifying natural loops, infinite loops, and cyclomatic complexity.

### IV. Relationship & Control Flow Intelligence

- **Graph Connectivity:** Full `inbound_xrefs` (callers) and `outbound_xrefs` (callees), including "simple" versions for faster graph traversal.
- **C++ Reconstruction:** Resolves `vtable_contexts` and trace virtual function calls to reconstruct class hierarchies and polymorphism logic.

## 3. AI System Integration (Critical)

This framework is the "Ingestion Layer" for AI-driven security tools.

### High-Fidelity Deep Agent Architectures (LangGraph)

By utilizing the [LangGraph Deep Agents](https://docs.langchain.com/oss/python/deepagents/overview) framework, researchers can build autonomous systems that treat the SQLite output as a queryable **World Model**.

#### Example A: Autonomous Subroutine Synthesis & Documentation (LangGraph)

This agent performs recursive callgraph traversal to generate high-level technical internals for undocumented subroutines. By analyzing the **context of each function within the callgraph**, the agent synthesizes a holistic understanding of how internal logic, state transitions, and data-flow invariants operate.

- **Node - Planner:** Receives an `entry_point` (e.g., a method of a given RPC interface) and initializes a `write_todos` list for breadth-first traversal.
- **Node - Explorer (Subagent):** Performs high-performance traversal using `simple_outbound_xrefs` to identify callees. It filters by `xref_type` (e.g., "Call Near", "Jump") and resolves targets across module boundaries using the tool's built-in cross-DB resolution logic.
- **Node - Analyst:** Fetches both `decompiled_code` and `assembly_code` for comparative analysis. It leverages the **callgraph context**—including `vtable_contexts`, `stack_frame` layouts, and relationship patterns—to infer local variable semantics and logical invariants.
- **Node - Synthesizer:** Aggregates findings from subagents, using `loop_analysis` (Tarjan's) and cross-function relationship context to document the subroutine's internal behavior, producing a comprehensive internals markdown document.

#### Example B: Agentic Discovery of LPE Primitives (Logical Bug Hunting) (LangGraph)

This agent targets Windows-specific logical vulnerabilities—such as controllable LoadLibrary calls, Command Injection, or Registry-based persistence—by identifying sinks where user-controllable arguments influence privileged operations.

- **Sink Discovery:** The agent queries `dangerous_api_calls` for high-impact primitives: `LoadLibrary*`, `CreateProcess*`, `ShellExecute*`, or `RegSetValue*`. It cross-references these with `vtable_contexts` to identify if the sinks are located within specific **COM or WinRT classes**, providing immediate architectural context.
- **Backward Data-Flow Slicing:** Using `simple_inbound_xrefs`, the agent recursively crawls the callgraph backward from the sink. It leverages `file_info.exports` to identify public API boundaries and `vtable_contexts` to determine reachability via **COM/WinRT interface methods**, mapping the path to its ultimate external entry point.
- **Argument Origin Analysis:** The agent fetches `decompiled_code` to trace the data-flow of the sink's critical arguments (e.g., `lpLibFileName` or `lpCommandLine`). It cross-references `string_literals` to determine if the path is hardcoded or partially derived from external input buffers.
- **Logical Gate Auditing:** By resolving `vtable_contexts` and `global_var_accesses`, the agent analyzes whether the execution path is gated by security checks (e.g., `SeImpersonatePrivilege` checks or "IsAdmin" logic), scoring the primitive based on the potential for logical bypass.

#### Example C: On-Demand Extraction via MCP (Model Context Protocol)

This architecture implements a focused **Binary Context Server** using the Model Context Protocol. It allows an LLM (e.g., Claude or Cursor) to query specific binary context directly into its conversation.

- **Tool - `get_function_logic`:** Receives a `module_name` and `function_name`. The server queries the SQLite backend and returns the `decompiled_code`, `assembly_code`, and `stack_frame` as a single structured context block.
- **Tool - `resolve_caller_chain`:** Given a function, returns a list of parent functions from `simple_inbound_xrefs`, enabling the LLM to "walk" the callgraph on-demand to answer specific reachability questions during a code review session.

#### Example D: Modular VR Specialist (Claude SDK & Agent Skills)

This example utilizes the [Claude Agent SDK](https://platform.claude.com/docs/en/agent-sdk/overview) and [Agent Skills](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview) to build a "Vulnerability Researcher" specialist without low-level graph orchestration.

- **Skill - `binary-intelligence`:** A filesystem-based skill containing instructions on how to interpret the tool's SQLite schema and domain-specific knowledge about Windows LPE primitives.
- **Autonomous Loop:** Using `claude_agent_sdk.query`, the agent is tasked with "Auditing the IOCTL handlers in `ntoskrnl.exe` for memory corruption."
- **Progressive Disclosure:** The agent uses the `Bash` tool to run targeted SQLite queries. It starts with `file_info.exports`, then triggers the `Read` tool to fetch `decompiled_code` for specific handlers, utilizing its bundled `SKILL.md` to reason about the output until it identifies a potential bug or completes the audit.

### AI-Assisted Code Review (Context Grounding)

The tool exports sanitized decompiled code into `extracted_raw_code/` as **one individual `.cpp` file per function**. This format is engineered to **ground** AI-native agents (e.g., **Claude Code**, **Cursor**, or **Codex**) by providing a high-fidelity semantic layer that fits perfectly into their internal agent harnesses.

- **Semantic Search & Context Discovery:** By providing a structured C++ codebase, you enable Cursor and Claude Code to leverage their native **semantic search** and `grep` capabilities. This allows the agent to "find the context" autonomously, traversing the binary's logic as if it were a high-level source repository.
- **Enhanced Planning (Plan Mode):** Grounding agents in clean C-style code instead of raw assembly allows for more accurate **task decomposition**. Agents can research the codebase to identify relevant files, ask clarifying questions, and create detailed implementation plans for complex vulnerability research tasks.
- **Verified Reasoning:** Feeding high-level source files minimizes hallucination and enables agents to reason about **data-flow invariants** and security gates using evidence-based analysis, matching the best practices for robust agentic workflows.

## 4. Usage Guide

### Installation

DeepExtract can be used in two ways:

1. **As a Plugin** (Recommended): Install via IDA's plugin directory for both headless and interactive use
2. **Standalone**: Run directly from the source directory

To install as a plugin, copy the entire repository structure to IDA's plugins directory:

- Windows: `%APPDATA%\Hex-Rays\IDA Pro\plugins\DeepExtract\`
- Linux: `~/.idapro/plugins/DeepExtract/`
- macOS: `~/Library/Application Support/IDA Pro/plugins/DeepExtract/`

### Headless Mode (Command-Line)

Run the plugin in headless mode for batch processing using IDA's command-line tool (`idat.exe` or `idat64.exe`).

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
--thunk-depth N              # Maximum thunk resolution depth (default: 10)
--min-call-conf N            # Minimum confidence for call validation (10-100)
```

### Interactive Mode (GUI)

When a binary is open in IDA Pro GUI, invoke the plugin via:

- **Menu**: Edit → Plugins → DeepExtract
- **Hotkey**: `Ctrl-Shift-E`

**Note:** Interactive configuration dialog is planned for future releases. Currently displays an informational message about headless usage.

### Batch Processing (Enterprise Orchestration)

For scanning entire directories, use the PowerShell orchestrator: `batch_tool/directory_functions_extractor_sqlite.ps1`.

```powershell
.\directory_functions_extractor_sqlite.ps1 -extractDir "C:\Windows\System32" -storageDir "C:\Analysis_Results" -recursive
```

**Enterprise Features:**

- **Concurrency:** Spawns multiple IDA processes (default: 4) to maximize CPU utilization.
- **Stateful Analysis:** Maintains a master `analyzed_files.db` to track progress. If the script is interrupted, it resumes where it left off.
- **Stale Lock Recovery:** Automatically detects if an IDA process hung (stale > 3 hours) and unlocks the file for re-analysis.
- **Change Detection:** Re-analyzes files only if their MD5/SHA256 hash changes.

## 5. Output Architecture

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

## 6. Technical Requirements

- **IDA Pro:** Version 9.0 or later (Pro edition required for headless mode)
- **Decompiler:** Hex-Rays Decompiler (optional, but required for C-code generation and advanced analysis)
- **Python:** Python 3 environment configured within IDA (built-in with IDA 9.x)
- **Dependencies:**
  - `pefile` (Bundled in `deps/`; used for PE header parsing)
  - IDA Python SDK (built-in with IDA Pro)

## 7. Plugin Architecture

DeepExtract follows IDA 9.x's modern plugin architecture for maximum compatibility and maintainability:

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

1. IDA loads `main.py` and calls `PLUGIN_ENTRY()`
2. Plugin factory (`DeepExtractPlugin`) initializes and creates module instance
3. Plugin module (`DeepExtractModule`) handles per-database execution
4. Detects headless vs. interactive mode based on command-line arguments
5. In headless mode: runs full pipeline and exits via `ida_pro.qexit()`
6. In interactive mode: displays configuration dialog (currently placeholder)

## 8. Plugin Distribution

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
