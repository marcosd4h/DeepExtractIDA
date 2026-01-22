import re
import os
import json
import bisect

# Function type classification constants
FT_UNK = 0    # Unknown function type
FT_GEN = 1    # General internal function
FT_LIB = 2    # Static library function  
FT_API = 3    # Windows API function
FT_MEM = 4    # Memory/indirect call
FT_VTB = 8    # VTable reference
FT_SYS = 16   # Syscall stub / inlined syscall

# Process exit codes
EXIT_SUCCESS = 0
EXIT_FAILURE = 1

# Analysis Limits
MAX_TLS_CALLBACKS = 256          # Maximum TLS callbacks to enumerate
DEFAULT_THUNK_DEPTH = 5          # Default depth for thunk resolution
CACHE_MAX_SIZE = 100000          # Maximum memoization cache entries
VTABLE_SEARCH_LIMIT = 20         # Backward instruction search limit for vtable analysis
JUMP_TABLE_MAX_ENTRIES = 100     # Maximum jump table entries to process
JUMP_TABLE_MAX_MISSES = 3        # Sparse table gap tolerance

# Function Extraction Limits (Centralized magic numbers)
MAX_ASSEMBLY_LINES = 900000      # Maximum assembly lines per function to prevent memory exhaustion
MAX_REGISTER_TRACKING_DEPTH = 15 # Maximum instructions to track backward for register loads
CONTEXT_SEARCH_RANGE = 50        # Instructions to search around call site for context validation

# VTable Analysis Limits
MAX_VTABLE_OFFSET = 0x1000       # Maximum reasonable vtable offset (4KB)

# Call Validation Thresholds
SUSPICIOUS_CALL_DISTANCE = 0x10000000  # 256MB - calls beyond this are suspicious
LOW_ADDRESS_THRESHOLD = 0x10000        # 64KB - very low addresses are suspicious

# Jump Table Analysis Thresholds
MIN_JUMP_TABLE_CONFIDENCE = 30.0       # Minimum confidence percentage to accept jump table detection

# Loop Analysis Configuration
DEFAULT_LOOP_BLOCK_LIMIT = 5000  # Default maximum basic blocks before skipping loop analysis
LOOP_ANALYSIS_WARNING_THRESHOLD = 500  # Warn when function exceeds this block count

# Batch Processing Configuration
BATCH_SIZE_SMALL_BINARY = 200    # Batch size for binaries with < 500 functions
BATCH_SIZE_MEDIUM_BINARY = 100   # Batch size for binaries with 500-5000 functions
BATCH_SIZE_LARGE_BINARY = 50     # Batch size for binaries with > 5000 functions
SMALL_BINARY_THRESHOLD = 500     # Function count threshold for small binaries
LARGE_BINARY_THRESHOLD = 5000    # Function count threshold for large binaries

# Decompilation Configuration
DECOMPILATION_SIZE_WARNING = 1000000  # Function size in bytes to trigger warning (1MB)
DECOMPILATION_TIMEOUT_WARNING = 30.0  # Seconds after which decompilation is considered slow
DECOMPILATION_MIN_OUTPUT_LENGTH = 10  # Minimum length for valid decompiled output

# Database Performance Configuration
COMMIT_TIME_SLOW_THRESHOLD = 2.0  # Seconds - reduce batch size if commit takes longer
BATCH_SIZE_MIN = 25               # Minimum batch size
BATCH_SIZE_MAX = 500              # Maximum batch size
BATCH_SIZE_REDUCTION_FACTOR = 2   # Factor to reduce batch size when slow
BATCH_SIZE_INCREASE_AMOUNT = 50   # Amount to increase batch size when fast
COMMIT_TIME_FAST_THRESHOLD = 0.5  # Seconds - increase batch size if commit is faster

# Progress Reporting Configuration
PROGRESS_REPORT_PERCENTAGE = 10   # Report progress every N percent

# Inter-procedural Analysis Configuration
INTERPROCEDURAL_ENABLED = True           # Enable/disable inter-procedural analysis
INTERPROCEDURAL_MAX_DEPTH = 3            # Maximum call chain depth to analyze
INTERPROCEDURAL_MAX_CALLEES = 5          # Max callees to analyze per function
INTERPROCEDURAL_MAX_CALLERS = 5          # Max callers to analyze per function
INTERPROCEDURAL_CONFIDENCE_THRESHOLD = 50.0  # Min confidence before trying deeper analysis

# Crypto Detection Constants (for TLS callback analysis)
CRYPTO_CONSTANTS = frozenset([
    0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476,  # MD5 constants
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,  # SHA-256 constants
    0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210   # Common crypto constants
])

# Anti-debugging API patterns (for TLS callback security analysis)
ANTI_DEBUG_APIS = frozenset([
    'isdebuggerpresent', 'checkremotedebuggerpresent',
    'ntquerysysteminformation', 'ntqueryinformationprocess',
    'ntsetinformationthread', 'ntquerysysteminformation',
    'outputdebugstringa', 'outputdebugstringw',
    'findwindowa', 'findwindoww',  # Looking for debugger windows
    'getwindowthreadprocessid',  # Detecting debugger processes
    'createtoolhelp32snapshot', 'process32first', 'process32next',  # Process enumeration
    'queryperformancecounter', 'gettickcount', 'gettickcount64',  # Timing checks
    'ntcreatethreadex', 'ntsetinformationthread',  # Thread hiding
    'zwsetsystemtime',  # System manipulation
])

# Validation Scoring Constants
VALIDATION_SCORES = {
    'instruction_context_valid': 20,
    'target_address_valid': 25,
    'call_flow_valid': 20,
    'function_signature_valid': 15,
    'context_consistent': 10,
    'high_confidence_analysis': 10,
    'medium_confidence_analysis': 5,
    'target_in_same_segment': 2,
    'base_in_data_segment': 20,
    'is_indirect_jump': 20
}

VALIDATION_PENALTIES = {
    'obvious_data_location': 20,
    'unaligned_address': 15,
    'very_small_function': 10,
    'no_code_at_target': 25
}

# --- Data Loading ---

def _load_json_data(filename, default=None):
    """Helper to load JSON data from the data directory."""
    if default is None:
        default = {}
    try:
        current_dir = os.path.dirname(os.path.realpath(__file__))
        data_path = os.path.join(current_dir, 'data', filename)
        if os.path.exists(data_path):
            with open(data_path, 'r') as f:
                return json.load(f)
    except Exception:
        # In case of error (e.g. file not found), return default
        # Logging is not available here to avoid circular imports
        pass
    return default

# Load API-Set map
def _sanitize_apiset_map(raw_map: dict) -> dict:
    """Remove malformed entries and normalize key casing."""
    sanitized = {}
    if not isinstance(raw_map, dict):
        return sanitized
    for key, value in raw_map.items():
        if not isinstance(key, str) or not isinstance(value, str):
            continue
        normalized_key = key.lower()
        normalized_value = value.lower()
        if not normalized_key.endswith(".dll"):
            normalized_key += ".dll"
        if not normalized_value or not normalized_value.endswith(".dll"):
            continue
        sanitized[normalized_key] = normalized_value
    return sanitized

APISET_MAP = _sanitize_apiset_map(_load_json_data('apisets.json', default={}))
_APISET_KEYS_SORTED = sorted(APISET_MAP.keys())
_UNRESOLVED_APISET_LOGGED = set()


def _log_unresolved_apiset(module_name: str, reason: str) -> None:
    """Best-effort logging for unresolved API-set entries."""
    if module_name in _UNRESOLVED_APISET_LOGGED:
        return
    _UNRESOLVED_APISET_LOGGED.add(module_name)
    try:
        from .logging_utils import debug_print
        debug_print(f"WARNING - Unresolved API-set '{module_name}': {reason}")
    except Exception:
        # Avoid raising from constants module
        pass

# Load Dangerous APIs (convert list back to set for O(1) lookup)
_dangerous_api_list = _load_json_data('dangerous_apis.json', default=[])
DANGEROUS_API_CALLS = set(_dangerous_api_list)


# --- Helper Functions ---

def resolve_apiset(module_name: str, log_unresolved: bool = True) -> str:
    """
    Resolve an API-set module name to its concrete implementation with best-fit matching.
    
    Logs unresolved API-sets to track Windows API evolution.
    
    :param module_name: The API-set module name to resolve
    :param log_unresolved: Whether to log when API-set cannot be resolved
    :return: The resolved concrete DLL name (or original if not resolvable)
    """
    if not module_name:
        return module_name
    
    # Store original for comparison
    original_module = module_name
    
    # Normalize to lowercase for lookup
    normalized = module_name.lower()
    if not normalized.endswith(".dll"):
        normalized += ".dll"
    
    # 1. Exact match
    if normalized in APISET_MAP:
        return APISET_MAP[normalized]
    
    # 2. Best-fit matching by progressively shortening the version suffix.
    # The regex looks for patterns like '-l1-1-0' at the end of the DLL name.
    # Updated regex to handle broader version patterns like l2-1-0 vs l1-1-0
    match = re.search(r'(-l\d+(?:-\d+)*)\.dll$', normalized)
    if match:
        # The part of the name before the version string, e.g., "api-ms-win-core-foo"
        base_name = normalized[:match.start(1)]
        
        # The version string itself, e.g., "-l1-1-0"
        version_part = match.group(1)
        
        # Split the version string into components, e.g., ['', 'l1', '1', '0']
        version_components = version_part.split('-')
        
        # Strategy A: Prefix matching (existing)
        # Iterate from most specific to least specific version prefix
        for i in range(len(version_components), 1, -1):
            # Create a prefix to search for, e.g., "api-ms-win-core-foo-l1-1-"
            prefix = base_name + '-'.join(version_components[:i]) + '-'
            
            # Find keys starting with prefix via binary search over a sorted key list.
            # This avoids scanning the full APISET_MAP for each prefix attempt.
            left = bisect.bisect_left(_APISET_KEYS_SORTED, prefix)
            right = bisect.bisect_left(_APISET_KEYS_SORTED, prefix + '\uffff')
            candidates = _APISET_KEYS_SORTED[left:right]

            if candidates:
                # Keys are sorted ascending; best-fit is the highest version, which will
                # be the last key in the candidate range.
                best_key = candidates[-1]
                resolved = APISET_MAP[best_key]
                return resolved

        # Strategy B: Fuzzy Base Name Matching (New)
        # If specific version prefixes failed, try to find ANY version of this API set.
        # This handles cases like 'l2-1-0' requested but only 'l1-1-0' available.
        # Search for "api-ms-win-core-foo-l"
        prefix = base_name + '-l'
        left = bisect.bisect_left(_APISET_KEYS_SORTED, prefix)
        right = bisect.bisect_left(_APISET_KEYS_SORTED, prefix + '\uffff')
        candidates = _APISET_KEYS_SORTED[left:right]
        
        if candidates:
            # Return the highest available version as best guess
            best_key = candidates[-1]
            return APISET_MAP[best_key]

    # If no match is found, log it for tracking API evolution
    # (Logging disabled here to keep constants.py pure)
    
    # Return original module name as fallback (optionally log if it looks like an API-set)
    if log_unresolved:
        normalized_lower = normalized.lower()
        if normalized_lower.startswith(("api-", "api-ms-", "ext-")) or "-l" in normalized_lower:
            _log_unresolved_apiset(normalized, "no mapping found")
    return module_name


def _strip_import_prefix(sym_name: str) -> str:
    """
    Removes common import-thunk prefixes (__imp_load_, __imp_, _imp_, _o_).
    
    :param sym_name: The symbol name to process
    :return: The symbol name with prefixes removed
    """
    if not sym_name:
        return sym_name
    # Handle prefixes in order of specificity (longest first)
    for prefix in ("__imp_load_", "__imp_", "_imp_", "_o__", "_o_"):
        if sym_name.startswith(prefix):
            return sym_name[len(prefix):]
    return sym_name


def is_dangerous_api(func_name: str) -> bool:
    """
    Check if a function name (with or without import prefixes) is a dangerous API call.
    
    :param func_name: The function name to check
    :return: True if the function is considered dangerous, False otherwise
    """
    if not func_name:
        return False
    
    # Check the raw name first
    if func_name.lower() in DANGEROUS_API_CALLS:
        return True
    
    # Strip import prefixes and check again
    stripped_name = _strip_import_prefix(func_name)
    if stripped_name.lower() in DANGEROUS_API_CALLS:
        return True
    
    # Check for WPP_ prefix (Windows software tracing)
    if stripped_name.startswith("WPP_"):
        return True
    
    return False
