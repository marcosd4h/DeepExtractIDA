# Standard library imports
import argparse
import json
import os
import pathlib
import sqlite3
import sys
import threading
import time
import traceback
from contextlib import contextmanager
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple

# Third-party imports (IDA Pro)
import ida_auto
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_loader
import ida_name
import ida_nalt
import ida_pro
import idautils
import idc

# Local imports - handle both package and standalone execution
# When run via IDA's -S flag, this script runs as __main__ without package context
try:
    from . import constants
    from . import cpp_generator
    from . import extractor_core
    from . import json_safety
    from . import module_profile as _module_profile
    from . import schema
    from .config import AnalysisConfig
    from .logging_utils import debug_print, get_log_level
except ImportError:
    # Running as standalone script - add parent directory to path so Python
    # recognizes 'extraction_tool' as a proper package with relative imports working
    _script_dir = pathlib.Path(__file__).resolve().parent
    _parent_dir = _script_dir.parent
    if str(_parent_dir) not in sys.path:
        sys.path.insert(0, str(_parent_dir))
    
    # Add bundled dependencies to path
    _deps_dir = _script_dir / "deps"
    if _deps_dir.exists() and str(_deps_dir) not in sys.path:
        sys.path.insert(0, str(_deps_dir))
    
    from extraction_tool import constants
    from extraction_tool import cpp_generator
    from extraction_tool import extractor_core
    from extraction_tool import json_safety
    from extraction_tool import module_profile as _module_profile
    from extraction_tool import schema
    from extraction_tool.config import AnalysisConfig
    from extraction_tool.logging_utils import debug_print, get_log_level

# Default SQLite PRAGMA settings for database connections
_DEFAULT_SQLITE_PRAGMAS = {
    "journal_mode": "WAL",
    "synchronous": "NORMAL",
    "cache_size": -2000000,
    "temp_store": "MEMORY",
    "busy_timeout_ms": 20000,
}


# =============================================================================
# Pipeline Timing and Progress Tracking
# =============================================================================

def _format_duration(seconds: float) -> str:
    """Format a duration in seconds to a human-readable string.
    
    Examples:
        _format_duration(65.5) -> "1m 5s"
        _format_duration(3725) -> "1h 2m 5s"
        _format_duration(0.5) -> "0.5s"
    """
    if seconds < 60:
        return f"{seconds:.1f}s" if seconds < 10 else f"{int(seconds)}s"
    
    minutes, secs = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m {secs}s"
    
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m {secs}s"


class PipelineTimer:
    """Tracks timing for analysis pipeline phases.
    
    Usage:
        timer = PipelineTimer()
        timer.start_phase("import_extraction")
        # ... do work ...
        timer.end_phase("import_extraction")
        timer.print_summary("myfile.dll", functions_count=1234)
    """
    
    def __init__(self):
        self.phase_start_times: Dict[str, float] = {}
        self.phase_durations: Dict[str, float] = {}
        self.overall_start_time: float = time.time()
        self.functions_processed: int = 0
        self.cpp_files_generated: int = 0
    
    def start_phase(self, phase_name: str) -> None:
        """Start timing a phase."""
        self.phase_start_times[phase_name] = time.time()
    
    def end_phase(self, phase_name: str, log_message: Optional[str] = None) -> float:
        """End timing a phase and optionally log a message.
        
        Returns:
            Duration of the phase in seconds.
        """
        if phase_name not in self.phase_start_times:
            return 0.0
        
        duration = time.time() - self.phase_start_times[phase_name]
        self.phase_durations[phase_name] = duration
        
        if log_message:
            debug_print(f"[PHASE] {log_message} ({_format_duration(duration)})")
        
        return duration
    
    def get_phase_duration(self, phase_name: str) -> float:
        """Get the duration of a completed phase."""
        return self.phase_durations.get(phase_name, 0.0)
    
    def get_total_duration(self) -> float:
        """Get total elapsed time since timer creation."""
        return time.time() - self.overall_start_time
    
    def print_summary(self, file_name: str) -> None:
        """Print a comprehensive timing summary."""
        total_duration = self.get_total_duration()
        
        debug_print("=" * 80)
        debug_print(f"Analysis Summary for {file_name}")
        debug_print("=" * 80)
        
        # Phase breakdown
        if self.phase_durations:
            debug_print("Phase Timing Breakdown:")
            for phase_name, duration in self.phase_durations.items():
                percentage = (duration / total_duration * 100) if total_duration > 0 else 0
                formatted_name = phase_name.replace("_", " ").title()
                debug_print(f"  {formatted_name:30s} {_format_duration(duration):>10s} ({percentage:5.1f}%)")
        
        debug_print("-" * 80)
        debug_print(f"  {'Total Duration':30s} {_format_duration(total_duration):>10s}")
        
        # Function statistics
        if self.functions_processed > 0:
            debug_print("")
            debug_print("Processing Statistics:")
            debug_print(f"  Functions processed:     {self.functions_processed:,}")
            
            # Calculate throughput from function extraction phase
            func_extraction_time = self.phase_durations.get("function_extraction", total_duration)
            if func_extraction_time > 0:
                throughput = self.functions_processed / func_extraction_time
                debug_print(f"  Throughput:              {throughput:.1f} functions/sec")
            
            if self.cpp_files_generated > 0:
                debug_print(f"  C++ files generated:     {self.cpp_files_generated:,}")
        
        debug_print("=" * 80)


class ProgressTracker:
    """Tracks progress for batch processing with ETA calculation."""
    
    def __init__(self, total_items: int, phase_name: str = "Processing"):
        self.total_items = total_items
        self.phase_name = phase_name
        self.processed_items = 0
        self.start_time = time.time()
        self.last_report_time = 0.0
        self.report_interval = 5.0  # Minimum seconds between progress reports
    
    def update(self, items_processed: int) -> None:
        """Update the count of processed items."""
        self.processed_items = items_processed
    
    def increment(self, count: int = 1) -> None:
        """Increment the processed count."""
        self.processed_items += count
    
    def get_progress_string(self) -> str:
        """Get a progress string with percentage and ETA.
        
        Returns:
            String like "1,234/5,678 (21.7%) - ETA: 12m 34s"
        """
        if self.total_items == 0:
            return "0/0 (0%)"
        
        percentage = (self.processed_items / self.total_items) * 100
        elapsed = time.time() - self.start_time
        
        # Calculate ETA
        eta_str = ""
        if self.processed_items > 0 and elapsed > 0:
            rate = self.processed_items / elapsed
            remaining_items = self.total_items - self.processed_items
            if rate > 0:
                eta_seconds = remaining_items / rate
                eta_str = f" - ETA: {_format_duration(eta_seconds)}"
        
        return f"{self.processed_items:,}/{self.total_items:,} ({percentage:.1f}%){eta_str}"
    
    def should_report(self) -> bool:
        """Check if enough time has passed to report progress."""
        current_time = time.time()
        if current_time - self.last_report_time >= self.report_interval:
            self.last_report_time = current_time
            return True
        return False
    
    def log_progress(self, batch_num: Optional[int] = None) -> None:
        """Log the current progress if enough time has passed."""
        if not self.should_report():
            return
        
        progress_str = self.get_progress_string()
        if batch_num is not None:
            debug_print(f"Committed batch {batch_num}. Progress: {progress_str}")
        else:
            debug_print(f"Progress: {progress_str}")


def _normalize_sqlite_pragmas(pragmas: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Normalize and sanitize PRAGMA values to a safe subset."""
    merged = dict(_DEFAULT_SQLITE_PRAGMAS)
    if isinstance(pragmas, dict):
        merged.update(pragmas)

    # Allow-list string pragmas to avoid invalid values causing runtime failures
    def _clean_upper(value: Any) -> Optional[str]:
        if value is None:
            return None
        return str(value).strip().upper()

    journal_mode = _clean_upper(merged.get("journal_mode")) or _DEFAULT_SQLITE_PRAGMAS["journal_mode"]
    if journal_mode not in {"WAL", "DELETE", "TRUNCATE", "PERSIST", "MEMORY", "OFF"}:
        journal_mode = _DEFAULT_SQLITE_PRAGMAS["journal_mode"]
    merged["journal_mode"] = journal_mode

    synchronous = _clean_upper(merged.get("synchronous")) or _DEFAULT_SQLITE_PRAGMAS["synchronous"]
    if synchronous not in {"OFF", "NORMAL", "FULL", "EXTRA"}:
        synchronous = _DEFAULT_SQLITE_PRAGMAS["synchronous"]
    merged["synchronous"] = synchronous

    temp_store = _clean_upper(merged.get("temp_store")) or _DEFAULT_SQLITE_PRAGMAS["temp_store"]
    if temp_store not in {"DEFAULT", "FILE", "MEMORY"}:
        temp_store = _DEFAULT_SQLITE_PRAGMAS["temp_store"]
    merged["temp_store"] = temp_store

    try:
        merged["cache_size"] = int(merged.get("cache_size"))
    except Exception:
        merged["cache_size"] = _DEFAULT_SQLITE_PRAGMAS["cache_size"]

    try:
        merged["busy_timeout_ms"] = int(merged.get("busy_timeout_ms"))
    except Exception:
        merged["busy_timeout_ms"] = _DEFAULT_SQLITE_PRAGMAS["busy_timeout_ms"]

    return merged


def _apply_sqlite_pragmas(conn: sqlite3.Connection, pragmas: Optional[Dict[str, Any]]) -> None:
    """Apply configured SQLite PRAGMAs to a connection."""
    p = _normalize_sqlite_pragmas(pragmas)
    # Apply as early as possible after connect
    conn.execute(f"PRAGMA journal_mode = {p['journal_mode']}")
    conn.execute(f"PRAGMA synchronous = {p['synchronous']}")
    conn.execute(f"PRAGMA cache_size = {p['cache_size']}")
    conn.execute(f"PRAGMA temp_store = {p['temp_store']}")
    conn.execute(f"PRAGMA busy_timeout = {p['busy_timeout_ms']}")


def _connect_sqlite(
    db_path: str,
    pragmas: Optional[Dict[str, Any]] = None,
    *,
    timeout_seconds: float = 20.0,
    isolation_level: str = "IMMEDIATE",
    check_same_thread: bool = False,
) -> sqlite3.Connection:
    """Create a SQLite connection and apply PRAGMAs in one place."""
    conn = sqlite3.connect(
        db_path,
        timeout=timeout_seconds,
        isolation_level=isolation_level,
        check_same_thread=check_same_thread,
    )
    _apply_sqlite_pragmas(conn, pragmas)
    return conn


def _get_connection(db_path: str, pragmas: Optional[Dict[str, Any]] = None) -> sqlite3.Connection:
    """
    Create a new SQLite connection for the given database path.
    
    SQLite connections are lightweight and creating new connections per-call
    avoids thread-safety issues with connection pooling.
    
    Args:
        db_path: Path to the SQLite database file
        pragmas: Optional dictionary of PRAGMA settings
        
    Returns:
        New SQLite connection object
    """
    return _connect_sqlite(db_path, pragmas=pragmas, check_same_thread=False)


def init_sqlite_db(db_path: str, force_reanalyze: bool = False, pragmas: Optional[Dict[str, Any]] = None) -> bool:
    """
    Initializes the SQLite database for a single binary's analysis results.
    """
    conn = None
    debug_print(f"TRACE - Starting: init_sqlite_db for {db_path}")
    start_time = time.time()
    try:
        conn = _connect_sqlite(db_path, pragmas=pragmas, check_same_thread=False)
        
        # First, check if schema validation is needed (skip for new databases)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        existing_tables = {row[0] for row in cursor.fetchall()}
        is_new_database = len(existing_tables) == 0
        
        if not is_new_database and not force_reanalyze:
            # Validate existing schema before proceeding
            schema_valid, schema_message = schema.check_and_validate_schema(db_path, force_reanalyze)
            if not schema_valid:
                debug_print(f"ERROR - Schema validation failed: {schema_message}")
                conn.close()
                return False
            debug_print(schema_message)
        
        with conn:
            if force_reanalyze:
                debug_print("Force re-analyze is on: Dropping old tables to ensure fresh schema.")
                conn.execute('DROP TABLE IF EXISTS functions')
                conn.execute('DROP TABLE IF EXISTS file_info')
                conn.execute('DROP TABLE IF EXISTS schema_version')

            # Create schema_version table first
            conn.execute('''
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY,
                    description TEXT NOT NULL,
                    applied_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    migration_notes TEXT
                )
            ''')
            
            # Initialize schema version
            if not schema.initialize_schema_version(conn, schema.CURRENT_SCHEMA_VERSION, 
                                                   schema.SCHEMA_VERSION_DESCRIPTION):
                debug_print("ERROR - Failed to initialize schema version")
                return False
            
            # Create file_info table to store file metadata once
            conn.execute('''
                CREATE TABLE IF NOT EXISTS file_info (
                    file_path TEXT NOT NULL,
                    base_dir TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    file_extension TEXT,
                    file_size_bytes BIGINT,
                    md5_hash TEXT,
                    sha256_hash TEXT,
                    imports TEXT,
                    exports TEXT,
                    entry_point JSON,
                    file_version TEXT,
                    product_version TEXT,
                    company_name TEXT,
                    file_description TEXT,
                    internal_name TEXT,
                    original_filename TEXT,
                    legal_copyright TEXT,
                    product_name TEXT,
                    time_date_stamp_str TEXT,
                    file_modified_date_str TEXT,
                    sections TEXT,
                    pdb_path TEXT,
                    rich_header TEXT,
                    tls_callbacks TEXT,
                    is_net_assembly BOOLEAN,
                    clr_metadata TEXT,
                    idb_cache_path TEXT,
                    dll_characteristics TEXT,
                    security_features TEXT,
                    exception_info TEXT,
                    load_config TEXT,
                    analysis_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (file_path)
                )
            ''')
            
            # Create functions table without duplicated file info
            conn.execute('''
                CREATE TABLE IF NOT EXISTS functions (
                    function_id INTEGER PRIMARY KEY,
                    function_signature TEXT NOT NULL,
                    function_signature_extended TEXT,
                    mangled_name TEXT NOT NULL,
                    function_name TEXT NOT NULL,
                    assembly_code TEXT,
                    decompiled_code TEXT,
                    inbound_xrefs TEXT,
                    outbound_xrefs TEXT,
                    simple_inbound_xrefs TEXT,
                    simple_outbound_xrefs TEXT,
                    vtable_contexts TEXT,
                    global_var_accesses TEXT,
                    dangerous_api_calls TEXT,
                    string_literals TEXT,
                    stack_frame TEXT,
                    loop_analysis TEXT,
                    analysis_errors TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create indices for common queries (drop conflicting legacy ones first)
            conn.execute('DROP INDEX IF EXISTS idx_functions_name')
            conn.execute('DROP INDEX IF EXISTS idx_functions_signature')

            # Case-insensitive function lookups and sorting
            conn.execute('CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(function_name COLLATE NOCASE)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_functions_mangled ON functions(mangled_name COLLATE NOCASE)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_functions_signature ON functions(function_signature COLLATE NOCASE)')

            # Case-insensitive lookups on file_info
            conn.execute('CREATE INDEX IF NOT EXISTS idx_file_info_lower_name ON file_info(LOWER(file_name))')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_file_info_lower_ext ON file_info(LOWER(file_extension))')
        
        duration = time.time() - start_time
        debug_print(f"TRACE - Finished: init_sqlite_db. Duration: {duration:.4f}s")
        return True
        
    except Exception as e:
        debug_print(f"ERROR - Error initializing database: {str(e)}")
        return False
    finally:
        if conn:
            conn.close()

def combine_imports(regular_imports: list, delay_load_imports: list) -> list:
    """Combines regular and delay-load imports, merging by module using in-place operations."""
    if not regular_imports:
        regular_imports = []
    if not delay_load_imports:
        delay_load_imports = []

    if not delay_load_imports:
        for mod in regular_imports:
            for func in mod['functions']:
                func['is_delay_loaded'] = False
        return regular_imports
    
    if not regular_imports:
        for mod in delay_load_imports:
            for func in mod['functions']:
                func['is_delay_loaded'] = True
        return delay_load_imports

    for mod in regular_imports:
        for func in mod['functions']:
            func['is_delay_loaded'] = False
            
    for mod in delay_load_imports:
        for func in mod['functions']:
            func['is_delay_loaded'] = True
    
    if len(regular_imports) >= len(delay_load_imports):
        base_list = regular_imports
        merge_list = delay_load_imports
    else:
        base_list = delay_load_imports
        merge_list = regular_imports
    
    module_index = {mod['module_name'].lower(): mod for mod in base_list}
    
    for dll in merge_list:
        module_name_lower = dll['module_name'].lower()
        if module_name_lower in module_index:
            existing_mod = module_index[module_name_lower]
            # Use mangled_name for deduplication (fall back to function_name for compatibility)
            existing_func_names = {f.get('mangled_name') or f.get('function_name') or f.get('name', '') for f in existing_mod['functions']}
            existing_mod['functions'].extend(
                func for func in dll['functions'] if (func.get('mangled_name') or func.get('function_name') or func.get('name', '')) not in existing_func_names
            )
        else:
            base_list.append(dll)
            module_index[module_name_lower] = dll

    return base_list

@contextmanager
def get_db_connection(db_path, max_retries=720, retry_delay=5, pragmas: Optional[Dict[str, Any]] = None):
    """
    A context manager to safely connect to a SQLite database with retries.
    
    Creates a new connection for each call to avoid thread-safety issues.
    SQLite connections are lightweight and creating them per-call is the
    recommended approach for concurrent scenarios.
    
    Args:
        db_path: Path to the SQLite database file
        pragmas: Optional dictionary of PRAGMA settings
        max_retries: Maximum number of retry attempts for locked database
        retry_delay: Delay in seconds between retry attempts
        
    Yields:
        SQLite connection object
    """
    conn = None
    attempt = 0
    last_error = None
    start_time = time.time()

    while attempt < max_retries:
        try:
            conn = _get_connection(db_path, pragmas=pragmas)
            yield conn
            break
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e):
                attempt += 1
                last_error = e
                if attempt < max_retries:
                    elapsed_minutes = (time.time() - start_time) / 60
                    debug_print(f"WARNING - Database locked for {elapsed_minutes:.1f} minutes, retrying in {retry_delay} seconds (attempt {attempt}/{max_retries})")
                    time.sleep(retry_delay)
                    continue
            raise
        except sqlite3.Error as e:
            debug_print(f"ERROR - SQLite error during connection: {str(e)}")
            raise
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass  # Ignore errors during cleanup

    if attempt == max_retries:
        total_minutes = (time.time() - start_time) / 60
        debug_print(f"ERROR - Failed to access database after {total_minutes:.1f} minutes of attempts: {str(last_error)}")
        raise last_error

def init_common_db(common_db_path: str, pragmas: Optional[Dict[str, Any]] = None,
                   max_retries: int = 30, retry_delay: float = 2.0) -> bool:
    """Initializes the common database used to track the analysis status of all files.
    
    Uses its own retry loop around the DDL statements to handle concurrent access
    from multiple IDA instances during batch processing.  The previous approach
    relied on ``get_db_connection()``'s ``@contextmanager``-based retry, but that
    mechanism cannot recover from statement-level "database is locked" errors
    (Python's ``@contextmanager`` raises ``RuntimeError`` if the generator tries
    to ``yield`` a second time after catching a thrown exception).
    
    This dedicated retry creates a fresh connection on each attempt so that both
    connection-level and statement-level lock contention are handled correctly.
    
    Args:
        common_db_path: Path to the common tracking database file.
        pragmas: Optional dictionary of PRAGMA settings.
        max_retries: Maximum number of retry attempts (default 30 = ~60 seconds).
        retry_delay: Seconds to sleep between retries (default 2.0).
    """
    debug_print(f"TRACE - Starting: init_common_db for {common_db_path}")
    overall_start = time.time()
    last_error: Optional[Exception] = None

    for attempt in range(1, max_retries + 1):
        conn = None
        try:
            conn = _connect_sqlite(
                common_db_path,
                pragmas=pragmas,
                timeout_seconds=20.0,
                isolation_level="DEFERRED",   # DEFERRED avoids immediate write-lock contention on connect
                check_same_thread=False,
            )
            conn.execute('''
                CREATE TABLE IF NOT EXISTS analyzed_files (
                    file_path TEXT PRIMARY KEY NOT NULL,
                    base_dir TEXT,
                    file_name TEXT,
                    file_extension TEXT,
                    md5_hash TEXT,
                    sha256_hash TEXT,
                    analysis_db_path TEXT,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    analysis_flags TEXT,
                    analysis_start_timestamp TIMESTAMP,
                    analysis_completion_timestamp TIMESTAMP
                )
            ''')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_files_name ON analyzed_files(file_name)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_files_hash ON analyzed_files(md5_hash, sha256_hash)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_an_files_status_lower_name ON analyzed_files(status, LOWER(file_name))')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_an_files_lower_name ON analyzed_files(LOWER(file_name))')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_an_files_lower_ext ON analyzed_files(LOWER(file_extension))')
            conn.commit()

            duration = time.time() - overall_start
            if attempt > 1:
                debug_print(f"TRACE - init_common_db succeeded after {attempt} attempt(s)")
            debug_print(f"TRACE - Finished: init_common_db. Duration: {duration:.4f}s")
            return True

        except sqlite3.OperationalError as e:
            last_error = e
            if "database is locked" in str(e) or "database is busy" in str(e):
                elapsed = time.time() - overall_start
                debug_print(f"WARNING - Common DB locked during init (attempt {attempt}/{max_retries}, "
                           f"elapsed {elapsed:.1f}s). Retrying in {retry_delay}s...")
                time.sleep(retry_delay)
                continue
            # Non-lock OperationalError -- do not retry
            debug_print(f"ERROR - Error initializing common database: {str(e)}")
            return False

        except Exception as e:
            debug_print(f"ERROR - Error initializing common database: {str(e)}")
            return False

        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    # All retries exhausted
    total_seconds = time.time() - overall_start
    debug_print(f"ERROR - Failed to initialize common database after {max_retries} attempts "
               f"({total_seconds:.1f}s): {str(last_error)}")
    return False

def update_common_db(common_db_path: str, file_info: dict, analysis_db_path: str, analysis_flags: dict,
                     pragmas: Optional[Dict[str, Any]] = None,
                     max_retries: int = 30, retry_delay: float = 2.0) -> bool:
    """Updates the analysis status of a file in the common tracking database to 'COMPLETE'.
    
    Uses its own retry loop (same rationale as ``init_common_db``) to handle
    statement-level "database is locked" errors that the ``@contextmanager``-based
    retry in ``get_db_connection`` cannot recover from.
    """
    debug_print(f"TRACE - Starting: update_common_db for {file_info.get('file_path')}")
    overall_start = time.time()
    last_error: Optional[Exception] = None

    for attempt in range(1, max_retries + 1):
        conn = None
        try:
            conn = _connect_sqlite(
                common_db_path,
                pragmas=pragmas,
                timeout_seconds=20.0,
                isolation_level="DEFERRED",
                check_same_thread=False,
            )
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE analyzed_files 
                SET 
                    base_dir = ?, file_name = ?, file_extension = ?,
                    md5_hash = ?, sha256_hash = ?,
                    analysis_db_path = ?, status = ?, analysis_flags = ?,
                    analysis_completion_timestamp = CURRENT_TIMESTAMP
                WHERE file_path = ?
            ''', (
                file_info.get('base_dir'),
                file_info.get('file_name'),
                file_info.get('file_extension'),
                file_info.get('md5_hash'),
                file_info.get('sha256_hash'),
                analysis_db_path,
                'COMPLETE',
                json.dumps(analysis_flags, sort_keys=True),
                file_info.get('file_path')
            ))
            conn.commit()

            duration = time.time() - overall_start
            if attempt > 1:
                debug_print(f"TRACE - update_common_db succeeded after {attempt} attempt(s)")
            debug_print(f"TRACE - Finished: update_common_db. Duration: {duration:.4f}s")
            return True

        except sqlite3.OperationalError as e:
            last_error = e
            if "database is locked" in str(e) or "database is busy" in str(e):
                elapsed = time.time() - overall_start
                debug_print(f"WARNING - Common DB locked during update (attempt {attempt}/{max_retries}, "
                           f"elapsed {elapsed:.1f}s). Retrying in {retry_delay}s...")
                time.sleep(retry_delay)
                continue
            debug_print(f"ERROR - Error updating common database: {str(e)}")
            return False

        except Exception as e:
            debug_print(f"ERROR - Error updating common database: {str(e)}")
            return False

        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    # All retries exhausted
    total_seconds = time.time() - overall_start
    debug_print(f"ERROR - Failed to update common database after {max_retries} attempts "
               f"({total_seconds:.1f}s): {str(last_error)}")
    return False

def parse_arguments() -> Optional[dict]:
    """
    Parses command-line arguments passed to the IDA script using argparse.
    """
    parser = argparse.ArgumentParser(description="PE File Context Extractor for IDA Pro")
    parser.add_argument("--sqlite-db", required=True, help="Absolute path to the SQLite database")
    
    # Feature toggles (default True)
    parser.add_argument("--no-extract-dangerous-apis", action="store_false", dest="extract_dangerous_apis", default=True)
    parser.add_argument("--no-extract-strings", action="store_false", dest="extract_strings", default=True)
    parser.add_argument("--no-extract-stack-frame", action="store_false", dest="extract_stack_frame", default=True)
    parser.add_argument("--no-extract-globals", action="store_false", dest="extract_globals", default=True)
    parser.add_argument("--no-analyze-loops", action="store_false", dest="analyze_loops", default=True)
    parser.add_argument("--no-pe-info", action="store_false", dest="extract_pe_info", default=True)
    parser.add_argument("--no-pe-metadata", action="store_false", dest="extract_pe_metadata", default=True)
    parser.add_argument("--no-advanced-pe", action="store_false", dest="extract_advanced_pe", default=True)
    parser.add_argument("--no-runtime-info", action="store_false", dest="extract_runtime_info", default=True)
    
    # Config toggles (default False or None)
    parser.add_argument("--force-reanalyze", action="store_true", default=False)
    parser.add_argument("--generate-cpp", action="store_true", default=False)
    parser.add_argument("--cpp-output-dir", type=str, default=None, help="Directory for C++ output files (defaults to extracted_raw_code/ next to db)")
    parser.add_argument("--thunk-depth", type=int, default=None)
    parser.add_argument("--min-call-conf", type=float, default=None)

    # Process argv from IDA
    # idc.ARGV contains all arguments including script name
    # We ignore the script name (first argument)
    try:
        argv = idc.ARGV[1:] if len(idc.ARGV) > 1 else []
        args = parser.parse_args(argv)
        return vars(args)
    except SystemExit:
        extractor_core.debug_print("Argument parsing failed.")
        return None
    except Exception as e:
        extractor_core.debug_print(f"ERROR - Argument parsing exception: {str(e)}")
        return None

def validate_arguments(args: Optional[dict]) -> Optional[dict]:
    """Validates the parsed command-line arguments."""
    if not args:
        return None
        
    sqlite_db_dir = os.path.dirname(args['sqlite_db'])
    try:
        if not os.path.exists(sqlite_db_dir):
            debug_print(f"Creating SQLite database directory: {sqlite_db_dir}")
            os.makedirs(sqlite_db_dir, exist_ok=True)
    except (OSError, PermissionError) as e:
        debug_print(f"ERROR - Error creating SQLite database directory '{sqlite_db_dir}': {str(e)}")
        return None
    except Exception as e:
        debug_print(f"ERROR - Unexpected error during argument validation: {str(e)}")
        return None
           
    return args

def prepare_for_analysis(input_file_path, common_db_path, current_args, current_hashes,
                         pragmas: Optional[Dict[str, Any]] = None,
                         max_retries: int = 30, retry_delay: float = 2.0):
    """Checks if a file needs to be analyzed and locks it in the common database.
    
    Uses its own retry loop (same rationale as ``init_common_db``) for write
    operations to handle concurrent "database is locked" errors correctly.
    
    Returns:
        True:  File needs analysis and has been locked.
        False: File does not need analysis (already analyzed, in progress, etc.) -- skip.
        None:  An error occurred -- caller should treat as failure.
    """
    debug_print(f"TRACE - Starting: prepare_for_analysis for {input_file_path}")
    overall_start = time.time()
    last_error: Optional[Exception] = None

    if current_args.get('force_reanalyze'):
        debug_print("Forcing re-analysis as per user request. Will attempt to lock file.")

    current_flags = json.dumps(current_args, sort_keys=True)

    for attempt in range(1, max_retries + 1):
        conn = None
        try:
            conn = _connect_sqlite(
                common_db_path,
                pragmas=pragmas,
                timeout_seconds=20.0,
                isolation_level="DEFERRED",
                check_same_thread=False,
            )
            cursor = conn.cursor()

            cursor.execute('''
                SELECT status, md5_hash, sha256_hash, analysis_flags, analysis_db_path, analysis_start_timestamp
                FROM analyzed_files
                WHERE file_path = ?
            ''', (input_file_path,))
            result = cursor.fetchone()

            needs_analysis = False
            reason = ""

            if not result:
                needs_analysis = True
                reason = "No previous analysis found."
            else:
                status, stored_md5, stored_sha256, stored_flags, stored_db_path, start_time_str = result
                current_args_norm = {k: v for k, v in current_args.items() if k != 'force_reanalyze'}

                if current_args.get('force_reanalyze'):
                    needs_analysis = True
                    reason = "Forcing re-analysis via command-line flag."
                elif status == 'ANALYZING':
                    if start_time_str:
                        try:
                            lock_time = datetime.strptime(start_time_str.split('.')[0], '%Y-%m-%d %H:%M:%S')
                            lock_age_hours = (datetime.now() - lock_time).total_seconds() / 3600

                            if lock_age_hours > 3.0:
                                needs_analysis = True
                                reason = f"Stale lock found (locked for {lock_age_hours:.1f} hours). Taking over."
                            else:
                                debug_print(f"File analysis is already in progress (locked for {lock_age_hours:.1f} hours). Skipping.")
                                return False
                        except (ValueError, TypeError):
                            debug_print(f"Could not parse timestamp '{start_time_str}'. Skipping file to be safe.")
                            return False
                    else:
                        needs_analysis = True
                        reason = "ANALYZING status found without a start time. Taking over."

                elif current_hashes['md5'] != stored_md5 or current_hashes['sha256'] != stored_sha256:
                    needs_analysis = True
                    reason = "File hashes have changed."
                else:
                    try:
                        stored_args = json.loads(stored_flags or '{}')
                        stored_args_norm = {k: v for k, v in stored_args.items() if k != 'force_reanalyze'}
                        if current_args_norm != stored_args_norm:
                            needs_analysis = True
                            reason = "Analysis flags have changed."
                    except (json.JSONDecodeError, TypeError):
                        needs_analysis = True
                        reason = "Could not parse or compare stored analysis flags."

            if needs_analysis:
                debug_print(f"{reason} Locking file for analysis.")
                cursor.execute('''
                    INSERT OR REPLACE INTO analyzed_files (
                        file_path, base_dir, file_name, file_extension,
                        md5_hash, sha256_hash, status, analysis_flags, 
                        analysis_db_path, analysis_start_timestamp, analysis_completion_timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, NULL)
                ''', (
                    input_file_path,
                    os.path.dirname(input_file_path),
                    os.path.basename(input_file_path),
                    os.path.splitext(input_file_path)[1],
                    current_hashes['md5'],
                    current_hashes['sha256'],
                    'ANALYZING',
                    current_flags,
                    stored_db_path if result else None
                ))
                conn.commit()
                duration = time.time() - overall_start
                if attempt > 1:
                    debug_print(f"TRACE - prepare_for_analysis succeeded after {attempt} attempt(s)")
                debug_print(f"TRACE - Finished: prepare_for_analysis (needed analysis). Duration: {duration:.4f}s")
                return True
            else:
                debug_print("File already analyzed and is up to date. Skipping analysis.")
                duration = time.time() - overall_start
                debug_print(f"TRACE - Finished: prepare_for_analysis (skipped). Duration: {duration:.4f}s")
                return False

        except sqlite3.OperationalError as e:
            last_error = e
            if "database is locked" in str(e) or "database is busy" in str(e):
                elapsed = time.time() - overall_start
                debug_print(f"WARNING - Common DB locked during prepare_for_analysis "
                           f"(attempt {attempt}/{max_retries}, elapsed {elapsed:.1f}s). "
                           f"Retrying in {retry_delay}s...")
                time.sleep(retry_delay)
                continue
            debug_print(f"ERROR - Error during analysis preparation: {str(e)}. Aborting analysis.")
            debug_print(traceback.format_exc())
            return None

        except Exception as e:
            debug_print(f"ERROR - Error during analysis preparation: {str(e)}. Aborting analysis.")
            debug_print(traceback.format_exc())
            return None

        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    # All retries exhausted
    total_seconds = time.time() - overall_start
    debug_print(f"ERROR - Failed to prepare for analysis after {max_retries} attempts "
               f"({total_seconds:.1f}s): {str(last_error)}. Aborting analysis.")
    return None

def _init_profile_stats() -> Dict[str, Any]:
    return {
        "stage_totals": {},
        "stage_counts": {},
        "stage_slowest": {},
        "function_slowest": [],
        "slow_limit": 5,
    }


def _profile_add_stage(profile: Optional[Dict[str, Any]], stage: str, duration: float, ea: Optional[int] = None, name: Optional[str] = None) -> None:
    if not profile or duration is None:
        return
    if duration < 0:
        duration = 0.0
    profile["stage_totals"][stage] = profile["stage_totals"].get(stage, 0.0) + duration
    profile["stage_counts"][stage] = profile["stage_counts"].get(stage, 0) + 1
    if ea is not None and name:
        current = profile["stage_slowest"].get(stage)
        if current is None or duration > current[0]:
            profile["stage_slowest"][stage] = (duration, ea, name)


def _profile_track_slowest(profile: Optional[Dict[str, Any]], duration: float, ea: int, name: str) -> None:
    if not profile or duration is None:
        return
    if duration < 0:
        return
    entries = profile["function_slowest"]
    limit = profile.get("slow_limit", 5)
    item = (duration, ea, name)
    if len(entries) < limit:
        entries.append(item)
        return
    min_idx = min(range(len(entries)), key=lambda i: entries[i][0])
    if duration > entries[min_idx][0]:
        entries[min_idx] = item


def _decompile_with_timeout(func, timeout_seconds: float):
    """Run ida_hexrays.decompile() in a daemon thread with a hard timeout.

    The decompile call executes in a background thread while the main thread
    waits via ``join(timeout)``.  If the worker does not finish in time it is
    abandoned (left as a leaked daemon thread) and ``TimeoutError`` is raised
    so the caller can skip the function and continue.  The abandoned thread
    will be cleaned up when the IDA process exits.

    This avoids the previous ``PyThreadState_SetAsyncExc`` approach which
    cannot interrupt a C-level call that never returns to Python bytecode.
    """
    result_holder: List = []
    error_holder: List = []

    def _worker():
        try:
            cfunc = ida_hexrays.decompile(func)
            result_holder.append(cfunc)
        except Exception as exc:
            error_holder.append(exc)

    worker = threading.Thread(target=_worker, daemon=True)
    worker.start()
    worker.join(timeout_seconds)

    if worker.is_alive():
        raise TimeoutError(
            f"Decompilation timed out after {timeout_seconds:.0f}s"
        )
    if error_holder:
        raise error_holder[0]
    return result_holder[0] if result_holder else None


def _process_single_function(ea: int, string_map: Dict[int, Any], has_decompiler: bool, options: Dict[str, bool], addr_to_id: Dict[int, int], profile: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """
    Extracts data for a single function.
    
    :param ea: Effective address of the function.
    :param string_map: Pre-computed string map.
    :param has_decompiler: Whether decompiler is available.
    :param options: Extraction options (flags).
    :param addr_to_id: Map of function addresses to their sequential IDs.
    :return: Dictionary of extracted data or None on failure.
    """
    try:
        analysis_errors: List[Dict[str, Any]] = []

        func = ida_funcs.get_func(ea)
        if not func:
            return None

        mangled_name = ida_funcs.get_func_name(ea) or f"sub_{ea:X}"
        demangled_name = ida_name.demangle_name(mangled_name, ida_name.MNG_LONG_FORM) or mangled_name
        
        # Extended signature extraction (Precise Prototypes)
        extended_signature = extractor_core.get_extended_function_signature(ea)
        
        # Assembly extraction
        assembly_start = time.perf_counter()
        assembly_lines = []
        for curr_ea in idautils.FuncItems(func.start_ea):
            if len(assembly_lines) >= constants.MAX_ASSEMBLY_LINES:
                break
            disasm = ida_lines.tag_remove(ida_lines.generate_disasm_line(curr_ea))
            if disasm:
                assembly_lines.append(disasm)
        _profile_add_stage(profile, "assembly", time.perf_counter() - assembly_start, ea, demangled_name)
        
        if len(assembly_lines) >= constants.MAX_ASSEMBLY_LINES:
            extractor_core.debug_print(f"WARNING - Function at 0x{ea:X} truncated (>{constants.MAX_ASSEMBLY_LINES} lines).")
            analysis_errors.append({
                "stage": "assembly",
                "severity": "warning",
                "reason": "max_lines_reached",
                "max_lines": constants.MAX_ASSEMBLY_LINES,
            })

        # Decompilation
        decompiled_code = ""
        if has_decompiler:
            decompile_start = time.perf_counter()
            decompiler = None
            try:
                func_size = func.end_ea - func.start_ea
                if func_size > constants.DECOMPILATION_SIZE_WARNING:
                    extractor_core.debug_print(f"WARNING - Large function at 0x{ea:X} ({func_size} bytes).")

                decompiler = _decompile_with_timeout(func, constants.DECOMPILATION_TIMEOUT)
                if decompiler:
                    decompiled_code = str(decompiler)
                    if not decompiled_code or len(decompiled_code.strip()) < constants.DECOMPILATION_MIN_OUTPUT_LENGTH:
                        decompiled_code = "Decompilation produced empty output"
                else:
                    decompiled_code = "Decompiler returned None"
            except TimeoutError as te:
                decompiled_code = f"Decompilation failed: {str(te)}"
                extractor_core.debug_print(
                    f"WARNING - Decompilation timed out for {demangled_name} at 0x{ea:X} "
                    f"after {constants.DECOMPILATION_TIMEOUT}s — skipping decompilation for this function"
                )
                analysis_errors.append({
                    "stage": "decompile",
                    "severity": "warning",
                    "error": str(te),
                    "reason": "timeout",
                    "timeout_seconds": constants.DECOMPILATION_TIMEOUT,
                })
            except Exception as e:
                decompiled_code = f"Decompilation failed: {str(e)}"
                analysis_errors.append({"stage": "decompile", "error": str(e)})
            finally:
                # Explicitly release the cfuncptr_t object to free type info references.
                # Without this, IDA's type system accumulates leaked refcounts across
                # thousands of decompilations, causing "Type info leak" warnings on exit.
                decompiler = None
            _profile_add_stage(profile, "decompile", time.perf_counter() - decompile_start, ea, demangled_name)
        else:
            decompiled_code = "Decompiler not available"

        # Cross-references
        xref_start = time.perf_counter()
        try:
            xref_data = extractor_core.extract_function_xrefs(ea)
        except Exception as e:
            analysis_errors.append({"stage": "xrefs", "error": str(e)})
            xref_data = {
                "inbound_xrefs": [],
                "outbound_xrefs": [],
                "vtable_contexts": [],
                "global_var_accesses": [],
            }
        _profile_add_stage(profile, "xrefs", time.perf_counter() - xref_start, ea, demangled_name)
        
        # Simplify inbound xrefs (Include all refs targeting this function)
        simplify_start = time.perf_counter()
        simple_inbound = []
        for xref in xref_data.get('inbound_xrefs', []):
            source_ea_str = xref.get('source_ea', '0x0')
            try:
                source_ea = int(source_ea_str, 16)
            except (ValueError, TypeError):
                continue
            
            # Resolve the containing function for the source address
            source_func = ida_funcs.get_func(source_ea)
            if source_func:
                # Source is a function - resolve start for consistent ID/Name
                func_start = source_func.start_ea
                clean_name = extractor_core.get_raw_function_name(func_start)
                func_id = addr_to_id.get(func_start)
            else:
                # Source is data or code outside a function
                clean_name = extractor_core.get_raw_function_name(source_ea)
                func_id = None
            
            simple_inbound.append({
                'function_name': clean_name,
                'function_id': func_id,
                'module_name': constants.resolve_apiset(xref.get('source_module_name', 'internal')),
                'function_type': xref.get('source_function_type', extractor_core.FT_UNK),
                'xref_type': xref.get('xref_type', 'Unknown'),
                'extraction_type': 'script'
            })

        # Simplify outbound xrefs (Include all refs targeting functions, imports, or data)
        simple_outbound = []
        for xref in xref_data.get('outbound_xrefs', []):
            target_ea_str = xref.get('target_ea', '0x0')
            try:
                target_ea = int(target_ea_str, 16)
            except (ValueError, TypeError):
                target_ea = 0
                
            # If internal, resolve to function start for consistent ID/Name resolution
            target_func = ida_funcs.get_func(target_ea) if target_ea else None
            
            if target_func:
                # Case 1: Target is an internal function
                func_start = target_func.start_ea
                clean_name = extractor_core.get_raw_function_name(func_start)
                func_id = addr_to_id.get(func_start)
            else:
                # Case 2: Target is data or an external import
                clean_name = extractor_core.get_raw_function_name(target_ea) if target_ea else xref.get('function_name', '')
                
                # Set ID to null for non-functions
                func_id = None
            
            simple_outbound.append({
                'function_name': clean_name,
                'function_id': func_id,
                'module_name': constants.resolve_apiset(xref.get('module_name', '')),
                'function_type': xref.get('function_type', extractor_core.FT_UNK),
                'xref_type': xref.get('xref_type', 'Unknown'),
                'extraction_type': 'script'
            })
        _profile_add_stage(profile, "xref_simplify", time.perf_counter() - simplify_start, ea, demangled_name)

        # Granular extractions
        loop_analysis = None
        if options.get('analyze_loops') and extractor_core.HAS_LOOP_DETECTOR:
            loop_start = time.perf_counter()
            try:
                loop_analysis = extractor_core.extract_loop_analysis(ea)
            except Exception as e:
                loop_analysis = None
                analysis_errors.append({"stage": "loop_analysis", "error": str(e)})
            _profile_add_stage(profile, "loop_analysis", time.perf_counter() - loop_start, ea, demangled_name)
        # Normalize absent loop analysis to a stable JSON object shape
        if loop_analysis is None:
            loop_analysis = {"loops": [], "loop_count": 0, "analysis_available": False}

        global_accesses = None
        if options.get('extract_globals'):
            global_accesses = xref_data.get("global_var_accesses", [])
        if global_accesses is None:
            global_accesses = []

        stack_frame = None
        if options.get('extract_stack_frame'):
            stack_start = time.perf_counter()
            try:
                stack_frame = extractor_core.extract_stack_frame_info(ea)
            except Exception as e:
                stack_frame = None
                analysis_errors.append({"stage": "stack_frame", "error": str(e)})
            _profile_add_stage(profile, "stack_frame", time.perf_counter() - stack_start, ea, demangled_name)
        if stack_frame is None:
            stack_frame = {"local_vars_size": None, "args_size": None, "has_canary": None, "analysis_available": False}

        string_literals = None
        if options.get('extract_strings'):
            strings_start = time.perf_counter()
            string_literals = list(string_map.get(ea, []))
            _profile_add_stage(profile, "string_literals", time.perf_counter() - strings_start, ea, demangled_name)
        if string_literals is None:
            string_literals = []

        dangerous_calls = None
        if options.get('extract_dangerous_apis'):
            dangerous_start = time.perf_counter()
            try:
                dangerous_calls = extractor_core.check_for_dangerous_calls(xref_data["outbound_xrefs"])
                # Validate the JSON string; if malformed, fall back to empty list.
                # Previous code tried json.loads + re-serialize on failure which would
                # itself throw on truly invalid JSON.  Simple fallback is safer.
                if dangerous_calls and not json_safety.validate_json_field(dangerous_calls, "dangerous_api_calls")[0]:
                    debug_print(f"WARNING - Dangerous API calls JSON failed validation for 0x{ea:X}, resetting to empty")
                    dangerous_calls = "[]"
            except Exception as e:
                dangerous_calls = None
                analysis_errors.append({"stage": "dangerous_api_calls", "error": str(e)})
            _profile_add_stage(profile, "dangerous_calls", time.perf_counter() - dangerous_start, ea, demangled_name)
        if dangerous_calls is None:
            dangerous_calls = "[]"

        # Build entry
        return {
            'function_id': addr_to_id.get(ea),
            'function_signature': demangled_name,
            'function_signature_extended': extended_signature,
            'mangled_name': mangled_name,
            'function_name': extractor_core.get_raw_function_name(ea),
            'assembly_code': '\n'.join(assembly_lines),
            'decompiled_code': decompiled_code,
            'inbound_xrefs': json_safety.safe_serialize_xrefs(xref_data["inbound_xrefs"], "inbound_xrefs"),
            'outbound_xrefs': json_safety.safe_serialize_xrefs(xref_data["outbound_xrefs"], "outbound_xrefs"),
            'simple_inbound_xrefs': json_safety.safe_serialize_xrefs(simple_inbound, "simple_inbound_xrefs"),
            'simple_outbound_xrefs': json_safety.safe_serialize_xrefs(simple_outbound, "simple_outbound_xrefs"),
            'vtable_contexts': json_safety.safe_serialize_vtable_contexts(xref_data["vtable_contexts"], "vtable_contexts"),
            'global_var_accesses': json_safety.to_json_safe(global_accesses, max_list_items=1000, field_name="global_var_accesses"),
            'loop_analysis': json_safety.safe_serialize_loop_analysis(loop_analysis, "loop_analysis"),
            'stack_frame': json_safety.to_json_safe(stack_frame, field_name="stack_frame"),
            'string_literals': json_safety.safe_serialize_strings(string_literals, "string_literals"),
            'dangerous_api_calls': dangerous_calls,
            'analysis_errors': json_safety.to_json_safe(analysis_errors, max_list_items=100, field_name="analysis_errors")
        }

    except Exception as e:
        debug_print(f"ERROR - Processing function 0x{ea:X}: {str(e)}")
        return None

def extract_all_functions(sqlite_db_path, hashes, imports_json, exports_json, entry_points_json, version_info, pe_metadata, advanced_pe_info, runtime_info, file_modified_date_str, idb_cache_path, has_decompiler, db_pragmas: Optional[Dict[str, Any]] = None, **kwargs):
    """
    The main data extraction loop that processes every function in the binary.
    """
    debug_print("TRACE - Starting: extract_all_functions")
    overall_start_time = time.time()
    functions_processed_count = 0
    
    # Map kwargs to options dict
    options = {
        'extract_dangerous_apis': kwargs.get('extract_dangerous_apis', True),
        'extract_strings': kwargs.get('extract_strings', True),
        'extract_stack_frame': kwargs.get('extract_stack_frame', True),
        'extract_globals': kwargs.get('extract_globals', True),
        'analyze_loops': kwargs.get('analyze_loops', True),
    }

    profile_enabled = get_log_level() in ("TRACE", "DEBUG")
    profile = _init_profile_stats() if profile_enabled else None
    
    try:
        input_file_path = ida_nalt.get_input_file_path()
        file_size = os.path.getsize(input_file_path)
        base_dir = os.path.dirname(input_file_path)
        file_name = os.path.basename(input_file_path)
        _, file_extension = os.path.splitext(file_name)
        
        string_map_start = time.perf_counter()
        string_map = extractor_core.build_string_map() if options['extract_strings'] else {}
        _profile_add_stage(profile, "build_string_map", time.perf_counter() - string_map_start)
        
        # Enumerate functions once (IDA generators can be expensive on large binaries)
        enum_start = time.perf_counter()
        function_addresses = list(idautils.Functions())
        _profile_add_stage(profile, "enumerate_functions", time.perf_counter() - enum_start)
        num_functions = len(function_addresses)
        
        # Pre-calculate address to ID map for internal cross-references
        # SQLite PRIMARY KEYs start at 1
        addr_map_start = time.perf_counter()
        addr_to_id = {ea: i + 1 for i, ea in enumerate(function_addresses)}
        _profile_add_stage(profile, "build_addr_map", time.perf_counter() - addr_map_start)
        
        # Adaptive batch sizing
        if num_functions < constants.SMALL_BINARY_THRESHOLD:
            BATCH_SIZE = constants.BATCH_SIZE_SMALL_BINARY
        elif num_functions < constants.LARGE_BINARY_THRESHOLD:
            BATCH_SIZE = constants.BATCH_SIZE_MEDIUM_BINARY
        else:
            BATCH_SIZE = constants.BATCH_SIZE_LARGE_BINARY
        
        # Initialize progress tracker
        debug_print(f"Queued {num_functions:,} functions for extraction")
        progress = ProgressTracker(num_functions, "Function extraction")
        total_batches = (num_functions + BATCH_SIZE - 1) // BATCH_SIZE  # Ceiling division
        current_batch = 0
        
        with get_db_connection(sqlite_db_path, pragmas=db_pragmas) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Clear old data
            try:
                cursor.execute('BEGIN IMMEDIATE')
                cursor.execute('DELETE FROM functions')
                cursor.execute('COMMIT')
            except Exception as e:
                cursor.execute('ROLLBACK')
                raise e

            # Insert file info
            cursor.execute('''
                INSERT OR REPLACE INTO file_info (
                    file_path, base_dir, file_name, file_extension,
                    file_size_bytes, md5_hash, sha256_hash, imports, exports, entry_point,
                    file_version, product_version, company_name,
                    file_description, internal_name, original_filename, legal_copyright,
                    product_name, time_date_stamp_str, file_modified_date_str,
                    sections, pdb_path, rich_header,
                    tls_callbacks, is_net_assembly, clr_metadata, idb_cache_path,
                    dll_characteristics, security_features, exception_info, load_config,
                    analysis_timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                input_file_path, base_dir, file_name, file_extension,
                file_size,
                hashes['md5'],
                hashes['sha256'],
                imports_json,
                exports_json,
                entry_points_json,
                version_info.get('FileVersion'),
                version_info.get('ProductVersion'),
                version_info.get('CompanyName'),
                version_info.get('FileDescription'),
                version_info.get('InternalName'),
                version_info.get('OriginalFilename'),
                version_info.get('LegalCopyright'),
                version_info.get('ProductName'),
                pe_metadata.get('time_date_stamp_str'),
                file_modified_date_str,
                json_safety.to_json_safe(pe_metadata.get('sections'), max_list_items=200, field_name="sections"),
                pe_metadata.get('pdb_path'),
                json_safety.to_json_safe(advanced_pe_info.get('rich_header'), field_name="rich_header"),
                json_safety.to_json_safe(advanced_pe_info.get('tls_callbacks'), max_list_items=256, field_name="tls_callbacks"),
                runtime_info.get('is_net_assembly'),
                json_safety.to_json_safe(runtime_info.get('clr_metadata'), field_name="clr_metadata"),
                idb_cache_path,
                json_safety.to_json_safe(pe_metadata.get('dll_characteristics'), field_name="dll_characteristics"),
                json_safety.to_json_safe(pe_metadata.get('security_features'), field_name="security_features"),
                json_safety.to_json_safe(pe_metadata.get('exception_info'), field_name="exception_info"),
                json_safety.to_json_safe(pe_metadata.get('load_config'), field_name="load_config"),
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))
            conn.commit()

            # Reanalyze
            debug_print("Reanalyzing all functions...")
            reanalyze_start = time.perf_counter()
            for ea in function_addresses:
                f = ida_funcs.get_func(ea)
                if f: ida_funcs.reanalyze_function(f)
            _profile_add_stage(profile, "reanalyze_functions", time.perf_counter() - reanalyze_start)
            
            # Process functions
            cursor.execute('BEGIN IMMEDIATE')
            batch_count = 0
            
            for idx, ea in enumerate(function_addresses):
                func_total_start = time.perf_counter()
                func_data = _process_single_function(ea, string_map, has_decompiler, options, addr_to_id, profile=profile)
                func_total_duration = time.perf_counter() - func_total_start
                if profile_enabled:
                    func_name = extractor_core.get_raw_function_name(ea)
                    _profile_add_stage(profile, "process_function_total", func_total_duration, ea, func_name)
                    _profile_track_slowest(profile, func_total_duration, ea, func_name)
                
                if func_data:
                    insert_start = time.perf_counter()
                    cursor.execute('''
                        INSERT INTO functions (
                            function_id, function_signature, function_signature_extended, mangled_name, function_name,
                            assembly_code, decompiled_code, inbound_xrefs, outbound_xrefs,
                            simple_inbound_xrefs, simple_outbound_xrefs,
                            vtable_contexts, global_var_accesses, loop_analysis, stack_frame,
                            string_literals, dangerous_api_calls, analysis_errors
                        ) VALUES (
                            :function_id, :function_signature, :function_signature_extended, :mangled_name, :function_name,
                            :assembly_code, :decompiled_code, :inbound_xrefs, :outbound_xrefs,
                            :simple_inbound_xrefs, :simple_outbound_xrefs,
                            :vtable_contexts, :global_var_accesses, :loop_analysis, :stack_frame,
                            :string_literals, :dangerous_api_calls, :analysis_errors
                        )
                    ''', func_data)
                    _profile_add_stage(profile, "db_insert", time.perf_counter() - insert_start)
                    functions_processed_count += 1
                    batch_count += 1
                
                # Batch commit
                if batch_count >= BATCH_SIZE:
                    commit_start = time.perf_counter()
                    cursor.execute('COMMIT')
                    cursor.execute('BEGIN IMMEDIATE')
                    _profile_add_stage(profile, "db_commit", time.perf_counter() - commit_start)
                    batch_count = 0
                    current_batch += 1
                    progress.update(functions_processed_count)
                    progress.log_progress(batch_num=current_batch)
            
            final_commit_start = time.perf_counter()
            cursor.execute('COMMIT')
            _profile_add_stage(profile, "db_commit", time.perf_counter() - final_commit_start)
            
        duration = time.time() - overall_start_time
        debug_print(f"TRACE - Finished: extract_all_functions. Duration: {duration:.4f}s")
        if profile_enabled and profile:
            debug_print("TRACE - extract_all_functions profiling summary (per-stage totals):")
            for stage, stage_time in sorted(profile["stage_totals"].items(), key=lambda item: item[1], reverse=True):
                count = profile["stage_counts"].get(stage, 0)
                avg = stage_time / count if count else 0.0
                debug_print(f"TRACE -   {stage}: {stage_time:.2f}s over {count} calls (avg {avg:.4f}s)")
            if profile["function_slowest"]:
                debug_print("TRACE - Slowest functions (overall):")
                for stage_time, ea, name in sorted(profile["function_slowest"], key=lambda item: item[0], reverse=True):
                    debug_print(f"TRACE -   {name} @ 0x{ea:X}: {stage_time:.3f}s")
            if profile["stage_slowest"]:
                debug_print("TRACE - Slowest by stage:")
                for stage, (stage_time, ea, name) in sorted(profile["stage_slowest"].items(), key=lambda item: item[1][0], reverse=True):
                    debug_print(f"TRACE -   {stage}: {name} @ 0x{ea:X} ({stage_time:.3f}s)")
        return True
        
    except Exception as e:
        debug_print(f"ERROR - Error in extract_all_functions: {str(e)}")
        debug_print(traceback.format_exc())
        return functions_processed_count > 0

def handle_database_setup(config: AnalysisConfig) -> Optional[bool]:
    """Initializes databases and checks if analysis should proceed.
    
    Returns:
        True:  Databases initialized and file locked for analysis -- proceed.
        False: File does not need analysis (already analyzed) -- skip gracefully.
        None:  An error occurred during setup -- caller should return failure exit code.
    """
    extractor_core.debug_print(f"TRACE - Starting: handle_database_setup")
    try:
        if not init_common_db(str(config.common_db_path), pragmas=config.get_common_db_pragmas()):
            extractor_core.debug_print("ERROR - Failed to initialize common database. Aborting.")
            return None
        
        prepare_result = prepare_for_analysis(
            str(config.input_file_path),
            str(config.common_db_path),
            config.to_dict(),
            config.file_hashes,
            pragmas=config.get_common_db_pragmas(),
        )
        if prepare_result is None:
            # Error occurred during preparation
            extractor_core.debug_print("ERROR - Analysis preparation failed. Aborting.")
            return None
        if prepare_result is False:
            # File already analyzed -- not an error, just skip
            extractor_core.debug_print("File does not require analysis. Skipping.")
            return False
        
        if not init_sqlite_db(
            str(config.sqlite_db_path),
            force_reanalyze=config.force_reanalyze,
            pragmas=config.get_sqlite_pragmas(),
        ):
            extractor_core.debug_print("ERROR - Failed to initialize SQLite database")
            return None
        
        return True
    except Exception as e:
        extractor_core.debug_print(f"ERROR - Error in handle_database_setup: {str(e)}")
        return None

def build_file_info_dict(config: AnalysisConfig, pe_data: Dict[str, Any]) -> Dict[str, Any]:
    """Builds the file_info dictionary for database storage."""
    version_info = pe_data.get('version_info', {})
    pe_metadata = pe_data.get('pe_metadata', {})
    advanced_pe_info = pe_data.get('advanced_pe_info', {})
    runtime_info = pe_data.get('runtime_info', {})
    
    file_info = {
        'file_path': str(config.input_file_path),
        'base_dir': str(config.input_file_path.parent),
        'file_name': config.input_file_path.name,
        'file_extension': config.input_file_path.suffix,
        'file_size_bytes': os.path.getsize(str(config.input_file_path)),
        'md5_hash': config.file_hashes.get('md5'),
        'sha256_hash': config.file_hashes.get('sha256'),
        'imports': pe_data.get('imports_json', '[]'),
        'exports': pe_data.get('exports_json', '[]'),
        'entry_point': pe_data.get('entry_points_json', '[]'),
        'sections': json_safety.to_json_safe(pe_metadata.get('sections'), max_list_items=200, field_name="sections"),
        'pdb_path': pe_metadata.get('pdb_path'),
        'rich_header': json_safety.to_json_safe(advanced_pe_info.get('rich_header'), field_name="rich_header"),
        'tls_callbacks': json_safety.to_json_safe(advanced_pe_info.get('tls_callbacks'), max_list_items=256, field_name="tls_callbacks"),
        'is_net_assembly': runtime_info.get('is_net_assembly'),
        'clr_metadata': json_safety.to_json_safe(runtime_info.get('clr_metadata'), field_name="clr_metadata"),
        'time_date_stamp_str': pe_metadata.get('time_date_stamp_str'),
        'file_modified_date_str': pe_data.get('file_modified_date_str'),
        'idb_cache_path': pe_data.get('idb_cache_path')
    }
    file_info.update(version_info)
    return file_info

def handle_database_updates(config: AnalysisConfig, pe_data: Dict[str, Any]) -> bool:
    """Updates the common database with analysis results."""
    try:
        file_info = build_file_info_dict(config, pe_data)
        
        storage_dir = config.common_db_path.parent
        analysis_db_path_rel = os.path.relpath(
            str(config.sqlite_db_path),
            str(storage_dir)
        ).replace('\\', '/')
        
        success = update_common_db(
            str(config.common_db_path),
            file_info,
            analysis_db_path_rel,
            config.to_dict(),
            pragmas=config.get_common_db_pragmas(),
        )
        return success
    except Exception as e:
        extractor_core.debug_print(f"ERROR - Error in handle_database_updates: {str(e)}")
        return False

def _resolve_module_name_and_profile_dir(config: AnalysisConfig) -> Tuple[str, pathlib.Path]:
    """Compute the sanitised module name and output directory for the module profile.

    When ``--generate-cpp`` is enabled the profile is co-located with the
    generated C++ files.  Otherwise it is written next to the SQLite database.
    """
    name_without_ext = config.input_file_path.stem
    extension = config.input_file_path.suffix.lstrip('.')

    if extension:
        module_name = cpp_generator.CppGenerator.sanitize_filename(f"{name_without_ext}_{extension}")
    else:
        module_name = cpp_generator.CppGenerator.sanitize_filename(name_without_ext)

    if config.generate_cpp:
        if config.cpp_output_dir:
            base_dir = config.cpp_output_dir
        else:
            base_dir = config.sqlite_db_path.parent / "extracted_raw_code"
        profile_dir = base_dir / module_name
    else:
        profile_dir = config.sqlite_db_path.parent

    return module_name, profile_dir


def generate_output_files(config: AnalysisConfig, sqlite_db_path: str) -> Tuple[int, int, int]:
    """Generates C++ files and documentation."""
    if not config.generate_cpp:
        return (0, 0, 0)
    
    try:
        base_name = config.input_file_path.name
        name_without_ext = config.input_file_path.stem
        extension = config.input_file_path.suffix.lstrip('.')
        
        if extension:
            module_name = cpp_generator.CppGenerator.sanitize_filename(f"{name_without_ext}_{extension}")
        else:
            module_name = cpp_generator.CppGenerator.sanitize_filename(name_without_ext)
        
        # Use custom cpp_output_dir if provided, otherwise default to extracted_raw_code/ next to db
        if config.cpp_output_dir:
            extracted_code_dir = config.cpp_output_dir
        else:
            db_dir = config.sqlite_db_path.parent
            extracted_code_dir = db_dir / "extracted_raw_code"
        module_dir = extracted_code_dir / module_name
        
        generator = cpp_generator.CppGenerator(
            output_dir=pathlib.Path(module_dir),
            module_name=module_name
        )
        
        with get_db_connection(sqlite_db_path, pragmas=config.get_sqlite_pragmas()) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT function_id, function_name, function_signature,
                       function_signature_extended, mangled_name, assembly_code,
                       decompiled_code
                FROM functions
                WHERE decompiled_code IS NOT NULL 
                AND decompiled_code != 'Decompiler not available'
                AND decompiled_code NOT LIKE 'Decompilation failed:%'
            ''')
            functions_for_cpp = cursor.fetchall()

            # Include failed decompilation entries in function_index.json with file=null.
            cursor.execute('''
                SELECT function_id, function_name, mangled_name, assembly_code
                FROM functions
                WHERE function_name IS NOT NULL
                AND (
                    decompiled_code IS NULL
                    OR decompiled_code = 'Decompiler not available'
                    OR decompiled_code LIKE 'Decompilation failed:%'
                )
            ''')
            failed_functions_for_index = cursor.fetchall()

            if functions_for_cpp or failed_functions_for_index:
                return generator.generate_cpp_files_with_markdown(
                    functions_for_cpp,
                    sqlite_db_path,
                    failed_functions_for_index
                )
            return (0, 0, 0)
    except Exception as e:
        extractor_core.debug_print(f"ERROR - Failed to generate C++ files: {str(e)}")
        return (0, 0, 0)

def check_dependencies() -> Dict[str, Any]:
    """Checks availability of optional dependencies."""
    capabilities = {
        'pefile': False,
        'hexrays': False,
        'ida_gdl': False,
        'features_available': [],
        'features_disabled': [],
        'warnings': []
    }
    
    if extractor_core.pefile is not None:
        capabilities['pefile'] = True
        capabilities['features_available'].extend([
            'PE metadata extraction', 'Rich header analysis', 'TLS callback detection',
            '.NET assembly detection', 'Delay-load imports'
        ])
    else:
        capabilities['warnings'].append("'pefile' not available")
        capabilities['features_disabled'].extend(['Rich header analysis', 'Delay-load imports'])
    
    try:
        if ida_hexrays.init_hexrays_plugin():
            capabilities['hexrays'] = True
            capabilities['features_available'].append('Hex-Rays decompilation')
        else:
            capabilities['warnings'].append("Hex-Rays decompiler not available")
    except Exception:
        capabilities['warnings'].append("Hex-Rays decompiler not available")
    
    if extractor_core.HAS_LOOP_DETECTOR:
        capabilities['ida_gdl'] = True
        capabilities['features_available'].append('Loop analysis')
    else:
        capabilities['warnings'].append("'ida_gdl' not available")
    
    return capabilities

def run_analysis_pipeline(config: AnalysisConfig) -> int:
    """Orchestrates the complete PE analysis workflow."""
    debug_print("Starting analysis pipeline...")
    
    # Initialize pipeline timer for phase tracking
    timer = PipelineTimer()
    file_name = config.input_file_path.name if config.input_file_path else "unknown"
    
    # Dependency/capability check (do not hard-fail; degrade gracefully where possible).
    caps = check_dependencies()
    for w in caps.get("warnings", []):
        debug_print(f"WARNING - Dependency check: {w}")
        
    try:
        file_hashes = extractor_core.calculate_file_hashes(str(config.input_file_path))
        if not file_hashes:
            file_hashes = {'md5': None, 'sha256': None}
        config.file_hashes = file_hashes
        
        setup_result = handle_database_setup(config)
        if setup_result is None:
            # Genuine error (database locked, init failure, etc.) -- report failure
            debug_print("ERROR - Database setup failed. Exiting with error.")
            return 1
        if setup_result is False:
            # File already analyzed, no work needed -- not an error
            return 0
        
        # Track IDA auto-analysis time
        timer.start_phase("ida_auto_analysis")
        ida_auto.auto_wait()
        timer.end_phase("ida_auto_analysis", f"IDA auto-analysis complete")
        
        idb_cache_path_abs = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        storage_dir = config.sqlite_db_path.parent
        idb_cache_path = os.path.relpath(idb_cache_path_abs, str(storage_dir)).replace('\\', '/')
        config.idb_cache_path = idb_cache_path
        
        try:
            mtime = os.path.getmtime(str(config.input_file_path))
            file_modified_date_str = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
        except OSError:
            file_modified_date_str = None
        
        has_decompiler = False
        try:
            if ida_hexrays.init_hexrays_plugin():
                has_decompiler = True
        except Exception:
            pass
        
        # PE extraction (requires pefile). If unavailable, proceed with IDA-only extraction.
        version_info: Dict[str, Any] = {}
        pe_metadata: Dict[str, Any] = {}
        advanced_pe_info: Dict[str, Any] = {"rich_header": {}, "tls_callbacks": []}
        runtime_info: Dict[str, Any] = {}

        if extractor_core.pefile is None:
            debug_print("WARNING - 'pefile' not installed; skipping PE parsing-dependent extraction.")
            # Disable pefile-dependent toggles for this run to avoid partial data assumptions downstream.
            config.extract_pe_info = False
            config.extract_pe_metadata = False
            config.extract_advanced_pe = False
            config.extract_runtime_info = False
        else:
            pe_object = None
            try:
                pe_object = extractor_core.pefile.PE(str(config.input_file_path), fast_load=False)

                version_info = extractor_core.extract_version_info(pe_object) if config.extract_pe_info else {}
                pe_metadata = extractor_core.extract_pe_metadata(pe_object) if config.extract_pe_metadata else {}

                if config.extract_advanced_pe:
                    advanced_pe_info = extractor_core.extract_advanced_pe_info(pe_object, has_decompiler, config.force_reanalyze)

                runtime_info = extractor_core.extract_runtime_info(pe_object) if config.extract_runtime_info else {}

            except Exception as e:
                debug_print(f"ERROR - PE parsing failed: {e}")
                return 1
            finally:
                if pe_object is not None:
                    try:
                        pe_object.close()
                    except Exception as e:
                        debug_print(f"WARNING - Failed to close PE object: {e}")
            
        # Imports/Exports
        timer.start_phase("import_export_extraction")
        raw_imports_list = extractor_core.extract_imports()
        exports_list = extractor_core.extract_exports()
        imports_list = combine_imports(raw_imports_list, runtime_info.get('delay_load_imports', []))
        
        imports_json = json_safety.to_json_safe(imports_list, max_list_items=1000, field_name="imports")
        exports_json = json_safety.to_json_safe(exports_list, max_list_items=5000, field_name="exports")
        
        entry_points = extractor_core.extract_all_entry_points_with_methods()
        entry_points_json = json_safety.to_json_safe(entry_points, max_list_items=100, field_name="entry_points")
        timer.end_phase("import_export_extraction", f"Import/export extraction complete")
        
        # Function Extraction
        timer.start_phase("function_extraction")
        analysis_args = config.get_analysis_args_dict()
        functions_result = extract_all_functions(
            str(config.sqlite_db_path), file_hashes, imports_json, exports_json,
            entry_points_json, version_info, pe_metadata, advanced_pe_info, runtime_info,
            file_modified_date_str, idb_cache_path, has_decompiler,
            db_pragmas=config.get_sqlite_pragmas(),
            **analysis_args
        )
        
        # Get function count from database for summary
        try:
            with get_db_connection(str(config.sqlite_db_path), pragmas=config.get_sqlite_pragmas()) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM functions")
                timer.functions_processed = cursor.fetchone()[0]
        except Exception:
            pass
        
        timer.end_phase("function_extraction", f"Function extraction complete ({timer.functions_processed:,} functions)")
        
        if not functions_result:
            timer.print_summary(file_name)
            return 1
        
        # Module Profile Generation (always runs, independent of --generate-cpp)
        timer.start_phase("module_profile")
        try:
            profile_module_name, profile_dir = _resolve_module_name_and_profile_dir(config)
            _module_profile.generate_module_profile(
                str(config.sqlite_db_path),
                str(profile_dir),
                profile_module_name
            )
        except Exception as e:
            debug_print(f"WARNING - Module profile generation failed: {e}")
        timer.end_phase("module_profile", "Module profile generation complete")
            
        # Output Generation
        if config.generate_cpp:
            timer.start_phase("cpp_generation")
            cpp_result = generate_output_files(config, str(config.sqlite_db_path))
            if cpp_result:
                timer.cpp_files_generated = cpp_result[0]  # cpp_files_generated count
            timer.end_phase("cpp_generation", f"C++ generation complete ({timer.cpp_files_generated:,} files)")
            
        # DB Update
        timer.start_phase("database_finalization")
        pe_data = {
            'version_info': version_info,
            'pe_metadata': pe_metadata,
            'advanced_pe_info': advanced_pe_info,
            'runtime_info': runtime_info,
            'imports_json': imports_json,
            'exports_json': exports_json,
            'entry_points_json': entry_points_json,
            'file_modified_date_str': file_modified_date_str,
            'idb_cache_path': idb_cache_path,
        }
        
        if not handle_database_updates(config, pe_data):
            timer.end_phase("database_finalization")
            timer.print_summary(file_name)
            return 1
        
        timer.end_phase("database_finalization")
        
        # Print final summary
        timer.print_summary(file_name)
            
        return 0
        
    except Exception as e:
        debug_print(f"ERROR - Pipeline failed: {str(e)}")
        debug_print(traceback.format_exc())
        return 1
