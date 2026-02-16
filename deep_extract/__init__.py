"""
PE Context Extraction Tool - IDA Pro script for PE binary analysis.

This package provides a structured framework for extracting detailed information
from PE binaries using IDA Pro, including:
- Function cross-references (inbound/outbound)
- VTable analysis and C++ class reconstruction
- Indirect call resolution through data flow analysis
- Jump table detection
- Loop analysis using Tarjan's SCC algorithm
- PE metadata extraction (imports, exports, resources, Rich header, TLS callbacks)
- Stack frame analysis
- String literal extraction
- Dangerous API call detection
- Call validation with confidence scoring

Main Entry Points:
    - pe_file_context_extractor.main(): Main IDA script entry point
    - config.AnalysisConfig: Configuration dataclass
    - extractor_core.*: Public API for analysis functions
"""

__version__ = "1.0.0"
__author__ = "Stager Labs"
__license__ = "Proprietary"

# Core configuration
from .config import AnalysisConfig

# Main analysis functions (from extractor_core)
from .extractor_core import (
    # Logging and utilities
    debug_print,
    set_log_level,
    get_log_level,
    safe_decode,
    get_script_dir,
    validate_directory,
    clear_ida_caches,
    get_cache_stats,
    
    # Thunk resolution
    set_max_thunk_depth,
    resolve_thunk_target,
    
    # String and stack analysis
    build_string_map,
    extract_function_strings,
    extract_stack_frame_info,
    
    # Name extraction
    get_raw_function_name,
    get_raw_long_function_name,
    get_function_name_at,
    extract_detailed_function_names,
    extract_unified_function_names,
    
    # Cross-reference analysis
    map_xref_type_to_string,
    classify_function_type,
    extract_function_xrefs,
    build_import_address_set,
    check_for_dangerous_calls,
    
    # PE metadata extraction
    extract_imports,
    extract_exports,
    extract_entry_point,
    extract_all_entry_points,
    extract_all_entry_points_with_methods,
    extract_version_info,
    extract_pe_metadata,
    extract_advanced_pe_info,
    extract_runtime_info,
    calculate_file_hashes,
    
    # VTable analysis
    get_vtable_context,
    analyze_vtable_calls,
    analyze_vtable_structure,
    
    # Indirect call analysis
    analyze_indirect_calls,
    analyze_jump_table,
    
    # Validation
    validate_function_call,
    set_min_validation_conf,
    
    # Loop analysis
    extract_loop_analysis,
)

# Plugin entry points (from pe_context_extractor)
# These are used by the main plugin to run the analysis pipeline
from .pe_context_extractor import (
    run_analysis_pipeline,
    parse_arguments,
    validate_arguments,
)

# GUI dialog (from gui_dialog)
from .gui_dialog import (
    show_config_dialog,
)

# Constants
from .constants import (
    # Function type classification
    FT_UNK, FT_GEN, FT_LIB, FT_API, FT_MEM, FT_VTB, FT_SYS,
    
    # Analysis limits
    MAX_TLS_CALLBACKS,
    DEFAULT_THUNK_DEPTH,
    CACHE_MAX_SIZE,
    VTABLE_SEARCH_LIMIT,
    JUMP_TABLE_MAX_ENTRIES,
    JUMP_TABLE_MAX_MISSES,
    MAX_ASSEMBLY_LINES,
    MAX_REGISTER_TRACKING_DEPTH,
    CONTEXT_SEARCH_RANGE,
    MAX_VTABLE_OFFSET,
    SUSPICIOUS_CALL_DISTANCE,
    LOW_ADDRESS_THRESHOLD,
    
    # API resolution
    resolve_apiset,
    is_dangerous_api,
    
    # Crypto constants
    CRYPTO_CONSTANTS,
)

# C++ generation
from .cpp_generator import (
    CppGenerator,
    generate_standalone_markdown_documentation,
    generate_extraction_documentation,
)

# Module profile generation
from .module_profile import (
    generate_module_profile,
)

# Schema management
from .schema import (
    CURRENT_SCHEMA_VERSION,
    SCHEMA_VERSION_DESCRIPTION,
    check_and_validate_schema,
    validate_schema_version,
    migrate_schema,
)

# JSON safety utilities
from .json_safety import (
    to_json_safe,
    safe_json_dumps,
    validate_json_field,
    safe_serialize_xrefs,
    safe_serialize_strings,
)

__all__ = [
    # Version
    '__version__',
    
    # Configuration
    'AnalysisConfig',
    
    # Plugin entry points
    'run_analysis_pipeline',
    'parse_arguments',
    'validate_arguments',
    
    # GUI dialog
    'show_config_dialog',
    
    # Logging and utilities
    'debug_print',
    'set_log_level',
    'get_log_level',
    'safe_decode',
    'get_script_dir',
    'validate_directory',
    'clear_ida_caches',
    'get_cache_stats',
    
    # Thunk resolution
    'set_max_thunk_depth',
    'resolve_thunk_target',
    
    # String and stack analysis
    'build_string_map',
    'extract_function_strings',
    'extract_stack_frame_info',
    
    # Name extraction
    'get_raw_function_name',
    'get_raw_long_function_name',
    'get_function_name_at',
    'extract_detailed_function_names',
    'extract_unified_function_names',
    
    # Cross-reference analysis
    'map_xref_type_to_string',
    'classify_function_type',
    'extract_function_xrefs',
    'build_import_address_set',
    'check_for_dangerous_calls',
    
    # PE metadata extraction
    'extract_imports',
    'extract_exports',
    'extract_entry_point',
    'extract_all_entry_points',
    'extract_all_entry_points_with_methods',
    'extract_version_info',
    'extract_pe_metadata',
    'extract_advanced_pe_info',
    'extract_runtime_info',
    'calculate_file_hashes',
    
    # VTable analysis
    'get_vtable_context',
    'analyze_vtable_calls',
    'analyze_vtable_structure',
    
    # Indirect call analysis
    'analyze_indirect_calls',
    'analyze_jump_table',
    
    # Validation
    'validate_function_call',
    'set_min_validation_conf',
    
    # Loop analysis
    'extract_loop_analysis',
    
    # Constants
    'FT_UNK', 'FT_GEN', 'FT_LIB', 'FT_API', 'FT_MEM', 'FT_VTB', 'FT_SYS',
    'MAX_TLS_CALLBACKS',
    'DEFAULT_THUNK_DEPTH',
    'CACHE_MAX_SIZE',
    'VTABLE_SEARCH_LIMIT',
    'JUMP_TABLE_MAX_ENTRIES',
    'JUMP_TABLE_MAX_MISSES',
    'MAX_ASSEMBLY_LINES',
    'MAX_REGISTER_TRACKING_DEPTH',
    'CONTEXT_SEARCH_RANGE',
    'MAX_VTABLE_OFFSET',
    'SUSPICIOUS_CALL_DISTANCE',
    'LOW_ADDRESS_THRESHOLD',
    'resolve_apiset',
    'is_dangerous_api',
    'CRYPTO_CONSTANTS',
    
    # C++ generation
    'CppGenerator',
    'generate_standalone_markdown_documentation',
    'generate_extraction_documentation',
    
    # Module profile generation
    'generate_module_profile',
    
    # Schema management
    'CURRENT_SCHEMA_VERSION',
    'SCHEMA_VERSION_DESCRIPTION',
    'check_and_validate_schema',
    'validate_schema_version',
    'migrate_schema',
    
    # JSON safety utilities
    'to_json_safe',
    'safe_json_dumps',
    'validate_json_field',
    'safe_serialize_xrefs',
    'safe_serialize_strings',
]
