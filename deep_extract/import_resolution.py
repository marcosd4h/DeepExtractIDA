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

from functools import lru_cache

import ida_nalt

from .logging_utils import safe_decode


@lru_cache(maxsize=20000)
def get_module_name_from_import(target_ea: int) -> str:
    """
    Return the import module name (DLL) that owns the IAT entry at `target_ea`.

    Args:
        target_ea: IAT entry address in IDA address space.

    Returns:
        Module name ending in '.dll' when known, otherwise ''.
    """
    try:
        nimps = ida_nalt.get_import_module_qty()
        for i in range(nimps):
            module_name = ida_nalt.get_import_module_name(i)
            if not module_name:
                continue

            if isinstance(module_name, bytes):
                module_name = safe_decode(module_name)
            module_name = str(module_name)

            found_in_module = False

            def imp_cb(ea, _name, _ordinal):
                nonlocal found_in_module
                if ea == target_ea:
                    found_in_module = True
                    return False  # stop enumeration
                return True

            ida_nalt.enum_import_names(i, imp_cb)
            if found_in_module:
                if module_name.lower().endswith(".dll"):
                    return module_name
                return module_name + ".dll"
    except Exception:
        # Keep failure silent; callers already handle unknown module cases.
        return ""

    return ""


def clear_import_resolution_caches() -> None:
    """Clear module resolution caches (call between analysis sessions if desired)."""
    get_module_name_from_import.cache_clear()


__all__ = [
    "get_module_name_from_import",
    "clear_import_resolution_caches",
]

