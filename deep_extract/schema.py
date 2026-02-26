"""
Database schema management and migration for PE binary analysis.

This module defines schema versioning and validation
to prevent schema drift and ensure data integrity across tool versions.
"""

import sqlite3
import json
from typing import Dict, Optional, List, Tuple
from datetime import datetime

from .logging_utils import debug_print


# Current schema version - increment when making schema changes
CURRENT_SCHEMA_VERSION = 1
SCHEMA_VERSION_DESCRIPTION = "Initial production schema for PE analysis"


def get_expected_schema() -> Dict[str, List[str]]:
    """
    Returns the expected schema structure for validation.
    
    Returns:
        Dictionary mapping table names to lists of column definitions
    """
    return {
        'schema_version': [
            'version INTEGER PRIMARY KEY',
            'description TEXT NOT NULL',
            'applied_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP',
            'migration_notes TEXT'
        ],
        'file_info': [
            'file_path TEXT NOT NULL',
            'base_dir TEXT NOT NULL',
            'file_name TEXT NOT NULL',
            'file_extension TEXT',
            'file_size_bytes BIGINT',
            'md5_hash TEXT',
            'sha256_hash TEXT',
            'imports TEXT',
            'exports TEXT',
            'entry_point JSON',
            'file_version TEXT',
            'product_version TEXT',
            'company_name TEXT',
            'file_description TEXT',
            'internal_name TEXT',
            'original_filename TEXT',
            'legal_copyright TEXT',
            'product_name TEXT',
            'time_date_stamp_str TEXT',
            'file_modified_date_str TEXT',
            'sections TEXT',
            'pdb_path TEXT',
            'rich_header TEXT',
            'tls_callbacks TEXT',
            'is_net_assembly BOOLEAN',
            'clr_metadata TEXT',
            'idb_cache_path TEXT',
            'dll_characteristics TEXT',
            'security_features TEXT',
            'exception_info TEXT',
            'load_config TEXT',
            'analysis_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP',
            'PRIMARY KEY (file_path)'
        ],
        'functions': [
            'function_id INTEGER PRIMARY KEY',
            'function_signature TEXT NOT NULL',
            'function_signature_extended TEXT',
            'mangled_name TEXT NOT NULL',
            'function_name TEXT NOT NULL',
            'assembly_code TEXT',
            'decompiled_code TEXT',
            'inbound_xrefs TEXT',
            'outbound_xrefs TEXT',
            'simple_inbound_xrefs TEXT',
            'simple_outbound_xrefs TEXT',
            'vtable_contexts TEXT',
            'global_var_accesses TEXT',
            'dangerous_api_calls TEXT',
            'string_literals TEXT',
            'stack_frame TEXT',
            'loop_analysis TEXT',
            'analysis_errors TEXT',
            'created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP'
        ],
        'function_xrefs': [
            'id INTEGER PRIMARY KEY AUTOINCREMENT',
            'source_id INTEGER',
            'target_id INTEGER',
            'target_name TEXT NOT NULL',
            'target_module TEXT',
            'function_type INTEGER DEFAULT 0',
            'xref_type TEXT',
            'direction TEXT NOT NULL',
        ]
    }


def get_current_schema_version(conn: sqlite3.Connection) -> Optional[int]:
    """
    Gets the current schema version from the database.
    
    Args:
        conn: SQLite database connection
        
    Returns:
        The schema version number, or None if schema_version table doesn't exist
    """
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1")
        result = cursor.fetchone()
        return result[0] if result else None
    except sqlite3.OperationalError as e:
        if "no such table" in str(e).lower():
            return None
        raise


def validate_schema_version(conn: sqlite3.Connection, required_version: int = CURRENT_SCHEMA_VERSION) -> Tuple[bool, str]:
    """
    Validates that the database schema matches the required version.
    
    Args:
        conn: SQLite database connection
        required_version: The required schema version (default: CURRENT_SCHEMA_VERSION)
        
    Returns:
        Tuple of (is_valid, message)
    """
    try:
        current_version = get_current_schema_version(conn)
        
        if current_version is None:
            return False, "Schema version table missing - database needs initialization"
        
        if current_version < required_version:
            return False, (f"Schema version mismatch: found v{current_version}, "
                          f"required v{required_version}. Migration needed.")
        
        if current_version > required_version:
            return False, (f"Schema version mismatch: found v{current_version}, "
                          f"tool expects v{required_version}. Update tool to latest version.")
        
        return True, f"Schema version v{current_version} validated successfully"
        
    except Exception as e:
        return False, f"Schema validation error: {str(e)}"


def validate_schema_structure(conn: sqlite3.Connection) -> Tuple[bool, List[str]]:
    """
    Validates that all required tables and columns exist.
    
    Args:
        conn: SQLite database connection
        
    Returns:
        Tuple of (is_valid, list of validation errors)
    """
    errors = []
    expected_schema = get_expected_schema()
    
    try:
        cursor = conn.cursor()
        
        # Check each table
        for table_name, expected_columns in expected_schema.items():
            # Check if table exists
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                (table_name,)
            )
            if not cursor.fetchone():
                errors.append(f"Missing required table: {table_name}")
                continue
            
            # Get actual columns
            cursor.execute(f"PRAGMA table_info({table_name})")
            actual_columns = {row[1] for row in cursor.fetchall()}  # row[1] is column name
            
            # Extract expected column names (parse column definitions)
            expected_column_names = set()
            for col_def in expected_columns:
                # Split on space and take first part (column name)
                parts = col_def.strip().split()
                if parts and parts[0] not in ('PRIMARY', 'FOREIGN', 'UNIQUE', 'CHECK'):
                    expected_column_names.add(parts[0])
            
            # Check for missing columns
            missing_columns = expected_column_names - actual_columns
            if missing_columns:
                errors.append(f"Table '{table_name}' missing columns: {', '.join(missing_columns)}")
        
        return len(errors) == 0, errors
        
    except Exception as e:
        errors.append(f"Schema structure validation error: {str(e)}")
        return False, errors


def initialize_schema_version(conn: sqlite3.Connection, version: int = CURRENT_SCHEMA_VERSION,
                              description: str = SCHEMA_VERSION_DESCRIPTION) -> bool:
    """
    Initializes the schema_version table with the current version.
    
    Args:
        conn: SQLite database connection
        version: Schema version to record
        description: Description of this schema version
        
    Returns:
        True on success, False on failure
    """
    try:
        with conn:
            # Create schema_version table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY,
                    description TEXT NOT NULL,
                    applied_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    migration_notes TEXT
                )
            ''')
            
            # Insert current version
            conn.execute('''
                INSERT OR REPLACE INTO schema_version (version, description, applied_timestamp)
                VALUES (?, ?, ?)
            ''', (version, description, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        
        debug_print(f"Initialized schema version: v{version}")
        return True
        
    except Exception as e:
        debug_print(f"ERROR - Failed to initialize schema version: {str(e)}")
        return False


def migrate_schema(conn: sqlite3.Connection, from_version: int, to_version: int) -> bool:
    """
    Migrates database schema from one version to another.
    
    Args:
        conn: SQLite database connection
        from_version: Current schema version
        to_version: Target schema version
        
    Returns:
        True on success, False on failure
    """
    debug_print(f"Migrating schema from v{from_version} to v{to_version}...")
    
    try:
        # Define migration paths
        migrations = {
            # Future migrations will be added here when schema changes are needed
        }
        
        # Execute migrations in sequence
        current = from_version
        while current < to_version:
            next_version = current + 1
            migration_key = (current, next_version)
            
            if migration_key not in migrations:
                debug_print(f"ERROR - No migration path from v{current} to v{next_version}")
                return False
            
            migration_func = migrations[migration_key]
            if not migration_func(conn):
                debug_print(f"ERROR - Migration from v{current} to v{next_version} failed")
                return False
            
            # Update schema version
            with conn:
                conn.execute('''
                    INSERT OR REPLACE INTO schema_version (version, description, applied_timestamp)
                    VALUES (?, ?, ?)
                ''', (next_version, f"Migrated from v{current}", 
                      datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            
            debug_print(f"Successfully migrated to v{next_version}")
            current = next_version
        
        return True
        
    except Exception as e:
        debug_print(f"ERROR - Schema migration failed: {str(e)}")
        import traceback
        debug_print(traceback.format_exc())
        return False


def _apply_essential_pragmas(conn: sqlite3.Connection) -> None:
    """Apply the essential PRAGMAs that affect correctness during concurrent access."""
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 20000")


def check_and_validate_schema(db_path: str, force_reanalyze: bool = False,
                              pragmas: Optional[dict] = None) -> Tuple[bool, str]:
    """
    Full schema validation entry point.
    
    This function performs all schema checks and returns actionable error messages.
    
    Args:
        db_path: Path to the database
        force_reanalyze: If True, allows re-initialization of schema
        pragmas: Optional dictionary of PRAGMA settings for consistency
            with the rest of the codebase. Falls back to essential PRAGMAs
            (WAL + busy_timeout) when not provided.
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    conn = None
    try:
        conn = sqlite3.connect(db_path, timeout=20)
        # Apply user-supplied PRAGMAs when available, otherwise essential defaults
        if pragmas and isinstance(pragmas, dict):
            for key, value in pragmas.items():
                if key == "busy_timeout_ms":
                    conn.execute(f"PRAGMA busy_timeout = {value}")
                else:
                    conn.execute(f"PRAGMA {key} = {value}")
        else:
            _apply_essential_pragmas(conn)
        
        # Check if this is a new database
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        existing_tables = {row[0] for row in cursor.fetchall()}
        
        is_new_database = len(existing_tables) == 0
        
        if is_new_database:
            # New database - initialize with current schema
            debug_print("New database detected - initializing schema...")
            if not initialize_schema_version(conn, CURRENT_SCHEMA_VERSION, SCHEMA_VERSION_DESCRIPTION):
                return False, "Failed to initialize schema version"
            return True, "New database initialized with current schema"
        
        # Existing database - validate version
        current_version = get_current_schema_version(conn)
        
        if current_version is None:
            if force_reanalyze:
                # Allow re-initialization if forced
                debug_print("No schema version found - initializing (force_reanalyze=True)...")
                if not initialize_schema_version(conn, CURRENT_SCHEMA_VERSION, SCHEMA_VERSION_DESCRIPTION):
                    return False, "Failed to initialize schema version"
                return True, "Schema version initialized on existing database"
            else:
                return False, (f"Schema version missing. Database may be from an old tool version.\n"
                              f"Expected version: v{CURRENT_SCHEMA_VERSION}\n"
                              f"Action: Use --force-reanalyze to reinitialize, or migrate manually.")
        
        # Validate version match (attempt migration if needed)
        is_valid, message = validate_schema_version(conn, CURRENT_SCHEMA_VERSION)
        if not is_valid:
            if current_version < CURRENT_SCHEMA_VERSION:
                debug_print(message)
                if migrate_schema(conn, current_version, CURRENT_SCHEMA_VERSION):
                    current_version = CURRENT_SCHEMA_VERSION
                else:
                    return False, (f"{message}\n"
                                  f"Action: Migration failed. Use --force-reanalyze to recreate.")
            else:
                return False, (f"{message}\n"
                              f"Action: Update extraction_tool to the latest version.")
        
        # Validate structure
        structure_valid, structure_errors = validate_schema_structure(conn)
        if not structure_valid:
            error_details = "\n  - ".join(structure_errors)
            return False, (f"Schema structure validation failed:\n  - {error_details}\n"
                          f"Action: Database schema is corrupted or incomplete. "
                          f"Use --force-reanalyze to recreate.")
        
        return True, f"Schema validation passed: v{current_version}"
        
    except Exception as e:
        import traceback
        debug_print(f"ERROR - Schema validation exception: {str(e)}")
        debug_print(traceback.format_exc())
        return False, f"Schema validation exception: {str(e)}"
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


# Example migration function template (for future use)
__all__ = [
    'CURRENT_SCHEMA_VERSION',
    'SCHEMA_VERSION_DESCRIPTION',
    'get_expected_schema',
    'get_current_schema_version',
    'validate_schema_version',
    'validate_schema_structure',
    'initialize_schema_version',
    'migrate_schema',
    'check_and_validate_schema',
]
