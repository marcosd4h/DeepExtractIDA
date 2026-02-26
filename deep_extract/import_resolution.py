"""
Import/module resolution helpers.

This module exists to centralize logic across:
- name extraction (needs module name for __imp_ symbols)
- xref analysis (needs module attribution for imports)

Design goals:
- minimal dependencies (no imports from other analysis modules)
- safe to import early (no circular dependencies)
"""

from __future__ import annotations

from typing import Dict, Optional

import ida_nalt

from .logging_utils import safe_decode


_import_module_map: Optional[Dict[int, str]] = None


def _build_import_module_map() -> Dict[int, str]:
    """Build a complete address -> module_name mapping from all IAT entries."""
    result: Dict[int, str] = {}
    try:
        nimps = ida_nalt.get_import_module_qty()
        for i in range(nimps):
            module_name = ida_nalt.get_import_module_name(i)
            if not module_name:
                continue
            if isinstance(module_name, bytes):
                module_name = safe_decode(module_name)
            module_name = str(module_name)
            if not module_name.lower().endswith(".dll"):
                module_name = module_name + ".dll"

            def imp_cb(ea, _name, _ordinal, _mod=module_name):
                result[ea] = _mod
                return True

            ida_nalt.enum_import_names(i, imp_cb)
    except Exception:
        pass
    return result


def _ensure_map() -> Dict[int, str]:
    """Lazily build the import module map on first access."""
    global _import_module_map
    if _import_module_map is None:
        _import_module_map = _build_import_module_map()
    return _import_module_map


def get_module_name_from_import(target_ea: int) -> str:
    """
    Return the import module name (DLL) that owns the IAT entry at `target_ea`.

    Uses a precomputed O(1) lookup map instead of scanning all modules per call.

    Args:
        target_ea: IAT entry address in IDA address space.

    Returns:
        Module name ending in '.dll' when known, otherwise ''.
    """
    return _ensure_map().get(target_ea, "")


def clear_import_resolution_caches() -> None:
    """Clear module resolution caches (call between analysis sessions if desired)."""
    global _import_module_map
    _import_module_map = None


__all__ = [
    "get_module_name_from_import",
    "clear_import_resolution_caches",
]
