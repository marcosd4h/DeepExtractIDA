"""
Unified logging and caching utilities for PE binary analysis.

Centralized logging, caching, and common utilities used
across all analysis modules. It has minimal dependencies to avoid circular imports.

Thread Safety Note:
    The caching functions (_cached_getseg, _cached_is_loaded) use module-level
    dictionaries without locks. These are designed for single-threaded IDA script
    execution. If multi-threaded access is required, use the thread-safe variants
    or call clear_caches() between concurrent analysis sessions.
"""

import os
import threading
from datetime import datetime
from typing import Optional, Dict, Any

# Lazy imports for IDA modules to support testing outside IDA
_ida_kernwin = None
_ida_loader = None
_ida_segment = None
_ida_bytes = None
_ida_idaapi = None


def _get_ida_modules():
    """Lazy load IDA modules to avoid import errors outside IDA."""
    global _ida_kernwin, _ida_loader, _ida_segment, _ida_bytes, _ida_idaapi
    if _ida_kernwin is None:
        try:
            import ida_kernwin
            import ida_loader
            import ida_segment
            import ida_bytes
            import ida_idaapi
            _ida_kernwin = ida_kernwin
            _ida_loader = ida_loader
            _ida_segment = ida_segment
            _ida_bytes = ida_bytes
            _ida_idaapi = ida_idaapi
        except ImportError:
            pass
    return _ida_kernwin, _ida_loader, _ida_segment, _ida_bytes, _ida_idaapi


# --- Logging configuration with proper log levels ---
_LOG_LEVELS = {"TRACE": 10, "DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50}
_CURRENT_LOG_LEVEL_NAME = os.environ.get('EXTRACTOR_LOG_LEVEL', 'INFO').upper()
_CURRENT_LOG_LEVEL = _LOG_LEVELS.get(_CURRENT_LOG_LEVEL_NAME, 20)


def set_log_level(level_name: str) -> None:
    """
    Set runtime log level (TRACE/DEBUG/INFO/WARNING/ERROR/CRITICAL).
    
    Messages below this level will be filtered out for performance.
    
    Args:
        level_name: The log level name to set
    """
    global _CURRENT_LOG_LEVEL_NAME, _CURRENT_LOG_LEVEL
    if not isinstance(level_name, str):
        return
    level_name_upper = level_name.upper()
    if level_name_upper in _LOG_LEVELS:
        _CURRENT_LOG_LEVEL_NAME = level_name_upper
        _CURRENT_LOG_LEVEL = _LOG_LEVELS[level_name_upper]
        debug_print(f"Log level set to {level_name_upper}")


def get_log_level() -> str:
    """Returns the current log level name."""
    return _CURRENT_LOG_LEVEL_NAME


def _parse_log_level_from_message(msg: str) -> tuple:
    """
    Extracts log level from message prefix.
    
    Messages should be formatted as "LEVEL - message" or just "message".
    
    Args:
        msg: The log message
        
    Returns:
        Tuple of (level_value, level_name, clean_message)
    """
    # Check for explicit level prefix
    for level_name, level_value in _LOG_LEVELS.items():
        prefix = f"{level_name} - "
        if msg.startswith(prefix):
            return level_value, level_name, msg[len(prefix):]
    
    # Default to INFO if no level specified
    return _LOG_LEVELS['INFO'], 'INFO', msg


def debug_print(msg: str) -> None:
    """
    Prints a timestamped message to the IDA console and optionally to a log file.
    
    This is the canonical logging function for the extraction tool. All modules
    should import and use this function instead of defining their own.
    
    Includes log level filtering for performance.
    
    Messages can include level prefix: "ERROR - message", "WARNING - message", etc.
    If no prefix is provided, defaults to INFO level.
    
    Args:
        msg: The message to log (optionally with level prefix)
    
    Example:
        debug_print("INFO - Starting analysis")
        debug_print("ERROR - Failed to process function")
        debug_print("This is an INFO message by default")
    """
    # Parse message level
    msg_level, level_name, clean_msg = _parse_log_level_from_message(msg)
    
    # Filter based on current log level (performance optimization)
    if msg_level < _CURRENT_LOG_LEVEL:
        return
    
    # Format message with timestamp and level
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Keep original message if it already has level prefix, otherwise add it
    if msg.startswith(level_name + " - "):
        log_message = f"[{timestamp}] {msg}"
    else:
        log_message = f"[{timestamp}] {level_name} - {clean_msg}"
    
    ida_kernwin, ida_loader, _, _, _ = _get_ida_modules()
    
    # Output to IDA console
    try:
        if ida_kernwin:
            ida_kernwin.msg(log_message + "\n")
        else:
            print(log_message)
    except Exception:
        print(log_message)
    
    # Output to log file if configured
    try:
        if ida_loader:
            log_file = ida_loader.get_plugin_options("log")
            if log_file:
                with open(log_file, 'a', encoding='utf-8') as f:
                    f.write(log_message + "\n")
                    f.flush()
                    os.fsync(f.fileno())
    except Exception as e:
        # Don't fail silently but don't crash either
        try:
            if ida_kernwin:
                ida_kernwin.msg(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR - Logging to file failed: {str(e)}\n")
        except Exception:
            pass


# Convenience functions for specific log levels
def log_trace(msg: str) -> None:
    """Log a TRACE level message."""
    debug_print(f"TRACE - {msg}")


def log_debug(msg: str) -> None:
    """Log a DEBUG level message."""
    debug_print(f"DEBUG - {msg}")


def log_info(msg: str) -> None:
    """Log an INFO level message."""
    debug_print(f"INFO - {msg}")


def log_warning(msg: str) -> None:
    """Log a WARNING level message."""
    debug_print(f"WARNING - {msg}")


def log_error(msg: str) -> None:
    """Log an ERROR level message."""
    debug_print(f"ERROR - {msg}")


def log_critical(msg: str) -> None:
    """Log a CRITICAL level message."""
    debug_print(f"CRITICAL - {msg}")


def safe_decode(byte_string) -> str:
    """
    Safely decodes a byte string to UTF-8 string, with fallback to latin-1.
    
    Args:
        byte_string: The bytes to decode, or None, or already a string
        
    Returns:
        The decoded string, or empty string if input is None
    """
    if byte_string is None:
        return ""
    if not isinstance(byte_string, bytes):
        return str(byte_string)
    try:
        return byte_string.decode('utf-8')
    except UnicodeDecodeError:
        return byte_string.decode('latin-1', 'replace')


def get_script_dir() -> str:
    """
    Returns the directory containing the extraction tool scripts.
    
    This is useful for locating data files (e.g., dangerous_apis.json, apisets.json)
    that are shipped alongside the Python modules.
    
    Returns:
        Absolute path to the extraction_tool directory
    """
    return os.path.dirname(os.path.abspath(__file__))


def validate_directory(path: str, create: bool = False) -> bool:
    """
    Validates that a directory exists and is writable.
    
    Args:
        path: Path to the directory to validate
        create: If True, attempt to create the directory if it doesn't exist
        
    Returns:
        True if the directory exists (or was created) and is writable, False otherwise
    """
    try:
        if not os.path.exists(path):
            if create:
                os.makedirs(path, exist_ok=True)
                debug_print(f"Created directory: {path}")
            else:
                return False
        
        if not os.path.isdir(path):
            debug_print(f"ERROR - Path exists but is not a directory: {path}")
            return False
        
        # Check if writable by attempting to create a temp file
        test_file = os.path.join(path, '.write_test')
        try:
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
            return True
        except (IOError, OSError) as e:
            debug_print(f"ERROR - Directory is not writable: {path} - {e}")
            return False
            
    except Exception as e:
        debug_print(f"ERROR - Failed to validate directory {path}: {e}")
        return False


# --- Caching infrastructure ---
# Thread-safe caching using LRU cache with proper locking mechanisms
# All cache operations now use locks to prevent race conditions

# Import cache size limit from constants if available
try:
    from .constants import CACHE_MAX_SIZE
except ImportError:
    CACHE_MAX_SIZE = 100000

_getseg_cache = {}
_is_loaded_cache = {}
_cache_lock = threading.Lock()


def _cached_getseg(ea: int) -> Optional[Any]:
    """
    Thread-safe memoized wrapper for ida_segment.getseg() to avoid repeated lookups.
    
    This function now uses proper locking to ensure thread safety. All access
    to the cache is synchronized using a global lock.
    
    Args:
        ea: The effective address to look up
        
    Returns:
        The segment object or None
    """
    with _cache_lock:
        # Check cache first (inside lock)
        if ea in _getseg_cache:
            return _getseg_cache[ea]
        
        # Load IDA modules
        _, _, ida_segment, _, _ = _get_ida_modules()
        if ida_segment is None:
            return None
        
        # Perform lookup and cache result
        result = ida_segment.getseg(ea)
        
        # Implement LRU-like eviction when cache grows too large
        if len(_getseg_cache) >= CACHE_MAX_SIZE:
            # Evict approximately 10% of cache entries (oldest ones)
            # Simple strategy: clear and rebuild on overflow
            items_to_evict = CACHE_MAX_SIZE // 10
            for _ in range(items_to_evict):
                if _getseg_cache:
                    # Pop first item (FIFO approximation)
                    _getseg_cache.pop(next(iter(_getseg_cache)))
        
        _getseg_cache[ea] = result
        return result


def _cached_getseg_threadsafe(ea: int) -> Optional[Any]:
    """
    Thread-safe variant of _cached_getseg().
    
    Note: This function is now identical to _cached_getseg() since the base
    implementation is now thread-safe. Kept for backward compatibility.
    
    Args:
        ea: The effective address to look up
        
    Returns:
        The segment object or None
    """
    return _cached_getseg(ea)


def _cached_is_loaded(ea: int) -> bool:
    """
    Thread-safe memoized wrapper for ida_bytes.is_loaded() to avoid repeated lookups.
    
    This function now uses proper locking to ensure thread safety. All access
    to the cache is synchronized using a global lock.
    
    Args:
        ea: The effective address to check
        
    Returns:
        True if the address is loaded, False otherwise
    """
    with _cache_lock:
        # Check cache first (inside lock)
        if ea in _is_loaded_cache:
            return _is_loaded_cache[ea]
        
        # Load IDA modules
        _, _, _, ida_bytes, _ = _get_ida_modules()
        if ida_bytes is None:
            return False
        
        # Perform lookup and cache result
        result = ida_bytes.is_loaded(ea)
        
        # Implement LRU-like eviction when cache grows too large
        if len(_is_loaded_cache) >= CACHE_MAX_SIZE:
            # Evict approximately 10% of cache entries (oldest ones)
            items_to_evict = CACHE_MAX_SIZE // 10
            for _ in range(items_to_evict):
                if _is_loaded_cache:
                    # Pop first item (FIFO approximation)
                    _is_loaded_cache.pop(next(iter(_is_loaded_cache)))
        
        _is_loaded_cache[ea] = result
        return result


def _cached_is_loaded_threadsafe(ea: int) -> bool:
    """
    Thread-safe variant of _cached_is_loaded().
    
    Note: This function is now identical to _cached_is_loaded() since the base
    implementation is now thread-safe. Kept for backward compatibility.
    
    Args:
        ea: The effective address to check
        
    Returns:
        True if the address is loaded, False otherwise
    """
    return _cached_is_loaded(ea)


def clear_caches() -> None:
    """
    Clears all memoization caches.
    
    Call this between analysis sessions or when memory pressure is high.
    This function is thread-safe.
    """
    global _getseg_cache, _is_loaded_cache
    with _cache_lock:
        _getseg_cache = {}
        _is_loaded_cache = {}
    
    # Clear name extraction caches
    try:
        from .name_extraction import clear_name_caches
        clear_name_caches()
    except ImportError:
        pass
    
    # Clear inter-procedural analysis caches
    try:
        from .interprocedural_analysis import clear_interprocedural_caches
        clear_interprocedural_caches()
    except ImportError:
        pass


def get_cache_stats() -> Dict[str, int]:
    """
    Returns statistics about the current cache state.
    
    Returns:
        Dictionary with cache size statistics
    """
    return {
        "getseg_cache_size": len(_getseg_cache),
        "is_loaded_cache_size": len(_is_loaded_cache),
        "max_cache_size": CACHE_MAX_SIZE
    }


# --- Exported symbols ---
__all__ = [
    # Logging
    'debug_print',
    'set_log_level',
    'get_log_level',
    'log_trace',
    'log_debug',
    'log_info',
    'log_warning',
    'log_error',
    'log_critical',
    
    # String utilities
    'safe_decode',
    
    # Directory utilities
    'get_script_dir',
    'validate_directory',
    
    # Caching (thread-safe)
    '_cached_getseg',
    '_cached_is_loaded',
    'clear_caches',
    'get_cache_stats',
    
    # Thread-safe caching variants (now identical to base - kept for compatibility)
    '_cached_getseg_threadsafe',
    '_cached_is_loaded_threadsafe',
]
