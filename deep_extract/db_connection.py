"""
Shared SQLite connection utilities for PE binary analysis.

Provides centralized connection creation with PRAGMA configuration so that
all modules (pe_context_extractor, cpp_generator, module_profile, etc.)
use consistent WAL mode, busy timeout, and cache settings.

This module deliberately has no analysis-module imports to avoid circular
dependencies in the hub-and-spoke architecture.
"""

import sqlite3
from typing import Any, Dict, Optional


_DEFAULT_SQLITE_PRAGMAS: Dict[str, Any] = {
    "journal_mode": "WAL",
    "synchronous": "NORMAL",
    "cache_size": -2000000,
    "temp_store": "MEMORY",
    "busy_timeout_ms": 20000,
}


def normalize_sqlite_pragmas(pragmas: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Normalize and sanitize PRAGMA values to a safe subset."""
    merged = dict(_DEFAULT_SQLITE_PRAGMAS)
    if isinstance(pragmas, dict):
        merged.update(pragmas)

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


def apply_sqlite_pragmas(conn: sqlite3.Connection, pragmas: Optional[Dict[str, Any]] = None) -> None:
    """Apply configured SQLite PRAGMAs to a connection."""
    p = normalize_sqlite_pragmas(pragmas)
    conn.execute(f"PRAGMA journal_mode = {p['journal_mode']}")
    conn.execute(f"PRAGMA synchronous = {p['synchronous']}")
    conn.execute(f"PRAGMA cache_size = {p['cache_size']}")
    conn.execute(f"PRAGMA temp_store = {p['temp_store']}")
    conn.execute(f"PRAGMA busy_timeout = {p['busy_timeout_ms']}")


def connect_sqlite(
    db_path: str,
    pragmas: Optional[Dict[str, Any]] = None,
    *,
    timeout_seconds: float = 20.0,
    isolation_level: str = "IMMEDIATE",
    check_same_thread: bool = False,
) -> sqlite3.Connection:
    """Create a SQLite connection and apply PRAGMAs in one place.

    This is the single entry point that all modules should use to open
    database connections, ensuring consistent WAL mode and busy-timeout
    configuration across the entire pipeline.
    """
    conn = sqlite3.connect(
        db_path,
        timeout=timeout_seconds,
        isolation_level=isolation_level,
        check_same_thread=check_same_thread,
    )
    apply_sqlite_pragmas(conn, pragmas)
    return conn


DEFAULT_SQLITE_PRAGMAS = _DEFAULT_SQLITE_PRAGMAS

__all__ = [
    "DEFAULT_SQLITE_PRAGMAS",
    "normalize_sqlite_pragmas",
    "apply_sqlite_pragmas",
    "connect_sqlite",
]
