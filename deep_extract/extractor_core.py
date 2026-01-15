"""
Core utilities and module re-exports for PE binary analysis.

This module serves as the hub for utility functions and maintains backward compatibility
by re-exporting functions from specialized analysis modules.

Module Architecture:
    This codebase uses a hub-and-spoke architecture to manage circular dependencies:
    
    - `logging_utils.py` (base): No analysis module imports. Provides debug_print,
      caching, and safe_decode. All other modules import from here.
    
    - `constants.py` (base): No analysis module imports. Defines constants.
    
    - `extractor_core.py` (hub): Imports and re-exports from all specialized modules.
      External scripts should import from here for backward compatibility.
    
    - Specialized modules (spokes): `name_extraction.py`, `vtable_analysis.py`,
      `indirect_call_analysis.py`, `xref_analysis.py`, `validation.py`,
      `pe_metadata.py`, `loop_analysis.py`
    
    Import Rules:
    1. Specialized modules may import from `logging_utils.py` and `constants.py`
    2. Specialized modules use forward references (late binding) for cross-module calls
    3. `extractor_core.py` imports from all modules at load time (re-exports)
    4. External scripts should import from `extractor_core.py`
    
Thread Safety:
    Caching functions are NOT thread-safe by default. For multi-threaded use:
    - Use `_cached_getseg_threadsafe()` and `_cached_is_loaded_threadsafe()`
    - Call `clear_ida_caches()` between concurrent analysis sessions
    - IDA scripting is typically single-threaded; locks add overhead
"""

import json
import os
import time
from typing import Dict, List, Set, Optional, Any

# Local imports
from . import constants

# --- Unified logging and caching from logging_utils ---
# Import centralized implementations to avoid code duplication
from .logging_utils import (
    debug_print,
    set_log_level,
    get_log_level,
    safe_decode,
    _cached_getseg,
    _cached_is_loaded,
    clear_caches as clear_ida_caches,
    _cached_getseg_threadsafe,
    _cached_is_loaded_threadsafe,
    get_cache_stats,
    validate_directory,
    get_script_dir
)

# Function type classification constants (re-exported from constants)
from .constants import FT_UNK, FT_GEN, FT_LIB, FT_API, FT_MEM, FT_VTB, FT_SYS

# Optional capability flags should come from the modules that own them.
# - pefile is owned/imported (optionally) by pe_metadata.py
# - HAS_LOOP_DETECTOR is owned by loop_analysis.py (ida_gdl availability)
from .pe_metadata import pefile
from .loop_analysis import HAS_LOOP_DETECTOR

_DANGEROUS_API_CACHE: Dict[str, List[str]] = {}


def load_dangerous_api_calls(file_path: str = "dangerous_apis.json") -> List[str]:
    """
    Loads a list of dangerous API calls from a JSON or text file.

    Legacy compatibility wrapper around constants.DANGEROUS_API_CALLS.
    If file_path is missing or invalid, falls back to the JSON-backed constants.
    """
    if file_path in _DANGEROUS_API_CACHE:
        return list(_DANGEROUS_API_CACHE[file_path])

    try:
        script_dir = get_script_dir()
        api_list_path = os.path.join(script_dir, file_path)
        if os.path.exists(api_list_path):
            if api_list_path.lower().endswith(".json"):
                with open(api_list_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if isinstance(data, list):
                    _DANGEROUS_API_CACHE[file_path] = [str(item).strip() for item in data if str(item).strip()]
                    return list(_DANGEROUS_API_CACHE[file_path])
            else:
                with open(api_list_path, 'r', encoding='utf-8') as f:
                    _DANGEROUS_API_CACHE[file_path] = [line.strip() for line in f if line.strip()]
                    return list(_DANGEROUS_API_CACHE[file_path])
    except Exception as e:
        debug_print(f"WARNING - Could not load dangerous API calls file '{file_path}': {e}")

    _DANGEROUS_API_CACHE[file_path] = sorted(constants.DANGEROUS_API_CALLS)
    return list(_DANGEROUS_API_CACHE[file_path])

# ==============================================================================
# MODULE RE-EXPORTS FOR BACKWARD COMPATIBILITY
# ==============================================================================

# Re-export from thunk_analysis module
from .thunk_analysis import (
    resolve_thunk_target,
    set_max_thunk_depth
)

# Re-export from string_analysis module
from .string_analysis import (
    build_string_map,
    extract_function_strings
)

# Re-export from stack_analysis module
from .stack_analysis import (
    extract_stack_frame_info
)

# Re-export from name_extraction module
from .name_extraction import (
    get_raw_function_name,
    get_raw_long_function_name,
    _clean_method_signature,
    get_function_name_at,
    extract_detailed_function_names,
    extract_vtable_function_names,
    extract_unified_function_names,
    get_extended_function_signature,
    clear_name_caches  # Export cache management
)

# Re-export constants helpers (previously defined here)
from .constants import (
    resolve_apiset,
    is_dangerous_api,
    _strip_import_prefix
)

# Re-export from xref_analysis module
from .xref_analysis import (
    map_xref_type_to_string,
    classify_function_type,
    extract_function_xrefs,
    build_import_address_set,
    get_module_name_from_import,
    check_for_dangerous_calls
)

# Re-export from pe_metadata module
from .pe_metadata import (
    extract_imports,
    extract_exports,
    extract_entry_point,
    extract_all_entry_points,
    extract_all_entry_points_with_methods,
    extract_version_info,
    extract_pe_metadata,
    extract_advanced_pe_info,
    _extract_detailed_rich_header,
    _get_rich_tool_name,
    _parse_rich_header_manually,
    _extract_tls_callbacks_metadata,
    _extract_single_tls_callback_metadata,
    extract_runtime_info,
    calculate_file_hashes,
    _rebase_pe_entry_point,
    _validate_entry_point_address,
    _ensure_json_serializable
)

# Re-export from vtable_analysis module
from .vtable_analysis import (
    _resolve_vtable_entry,
    get_vtable_context,
    analyze_vtable_calls,
    is_vtable_call_pattern,
    analyze_vtable_structure,
    find_vtable_base_address,
    resolve_memory_reference,
    analyze_vtable_size,
    is_valid_function_pointer,
    extract_vtable_methods,
    resolve_vtable_targets
)

# Re-export from indirect_call_analysis module
from .indirect_call_analysis import (
    analyze_jump_table,
    detect_manual_jump_table,
    is_indirect_jump_instruction,
    analyze_indirect_calls,
    is_indirect_call_pattern,
    perform_indirect_call_dataflow,
    track_register_loads,
    analyze_memory_target,
    analyze_function_pointer_array,
    track_displacement_loads,
    track_computed_address,
    resolve_indirect_call_targets,
    track_register_loads_across_blocks
)

# Re-export from validation module
from .validation import (
    validate_function_call,
    validate_instruction_context,
    validate_target_address,
    validate_call_flow,
    validate_function_signature,
    validate_context_consistency,
    check_false_positive_patterns,
    validate_and_normalize_xref_data,
    set_min_validation_conf
)

# Re-export from loop_analysis module
from .loop_analysis import (
    extract_loop_analysis
)

# Update __all__ for explicit exports
__all__ = [
    # Core utilities (from logging_utils.py)
    'debug_print',
    'set_log_level',
    'get_log_level',
    'safe_decode',
    'get_script_dir',
    'validate_directory',
    'clear_ida_caches',
    '_cached_getseg',
    '_cached_is_loaded',
    # Thread-safe cache variants
    '_cached_getseg_threadsafe',
    '_cached_is_loaded_threadsafe',
    'get_cache_stats',
    
    # Thunk resolution
    'set_max_thunk_depth',
    'resolve_thunk_target',
    
    # String/Stack utilities
    'build_string_map',
    'extract_function_strings',
    'extract_stack_frame_info',
    'load_dangerous_api_calls',
    
    # Constants
    'FT_UNK', 'FT_GEN', 'FT_LIB', 'FT_API', 'FT_MEM', 'FT_VTB', 'FT_SYS',
    'HAS_LOOP_DETECTOR',
    'pefile',
    
    # Constants Helpers
    'resolve_apiset',
    'is_dangerous_api',
    
    # Name extraction (from name_extraction.py)
    'get_raw_function_name',
    'get_raw_long_function_name',
    '_clean_method_signature',
    'get_function_name_at',
    'extract_detailed_function_names',
    'extract_vtable_function_names',
    '_strip_import_prefix',
    'extract_unified_function_names',
    'get_extended_function_signature',
    
    # XRef analysis (from xref_analysis.py)
    'map_xref_type_to_string',
    'classify_function_type',
    'extract_function_xrefs',
    'build_import_address_set',
    'get_module_name_from_import',
    'check_for_dangerous_calls',
    
    # PE metadata (from pe_metadata.py)
    'extract_imports',
    'extract_exports',
    'extract_entry_point',
    'extract_all_entry_points',
    'extract_all_entry_points_with_methods',
    'extract_version_info',
    'extract_pe_metadata',
    'extract_advanced_pe_info',
    '_extract_detailed_rich_header',
    '_get_rich_tool_name',
    '_parse_rich_header_manually',
    '_extract_tls_callbacks_metadata',
    '_extract_single_tls_callback_metadata',
    'extract_runtime_info',
    'calculate_file_hashes',
    '_rebase_pe_entry_point',
    '_validate_entry_point_address',
    '_ensure_json_serializable',
    
    # VTable analysis (from vtable_analysis.py)
    '_resolve_vtable_entry',
    'get_vtable_context',
    'analyze_vtable_calls',
    'is_vtable_call_pattern',
    'analyze_vtable_structure',
    'find_vtable_base_address',
    'resolve_memory_reference',
    'analyze_vtable_size',
    'is_valid_function_pointer',
    'extract_vtable_methods',
    'resolve_vtable_targets',
    
    # Indirect call analysis (from indirect_call_analysis.py)
    'analyze_jump_table',
    'detect_manual_jump_table',
    'is_indirect_jump_instruction',
    'analyze_indirect_calls',
    'is_indirect_call_pattern',
    'perform_indirect_call_dataflow',
    'track_register_loads',
    'analyze_memory_target',
    'analyze_function_pointer_array',
    'track_displacement_loads',
    'track_computed_address',
    'resolve_indirect_call_targets',
    'track_register_loads_across_blocks',
    
    # Validation (from validation.py)
    'validate_function_call',
    'validate_instruction_context',
    'validate_target_address',
    'validate_call_flow',
    'validate_function_signature',
    'validate_context_consistency',
    'check_false_positive_patterns',
    'validate_and_normalize_xref_data',
    'set_min_validation_conf',
    
    # Loop analysis (from loop_analysis.py)
    'extract_loop_analysis',
]
