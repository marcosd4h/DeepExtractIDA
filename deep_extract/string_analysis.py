"""
String analysis utilities for PE binary analysis.
"""

import hashlib
import os
import time
import pickle
import tempfile
from typing import Dict, Set, List, Optional

import idautils
import ida_bytes
import ida_funcs
import ida_nalt
import ida_loader

from .logging_utils import debug_print, safe_decode

def build_string_map(cache_file: Optional[str] = None, use_cache: bool = True) -> Dict[int, Set[str]]:
    """
    Builds a map of all string literals in the binary to the functions that reference them.
    
    Supports optional disk caching for large binaries.
    
    :param cache_file: Optional path to cache file. If None, uses temp directory.
    :param use_cache: Whether to use disk caching (default True).
    :return: Dictionary mapping function_ea -> set of strings
    """
    debug_print("TRACE - Starting: build_string_map")
    start_time = time.time()
    
    # Try to load from cache if enabled
    if use_cache:
        try:
            if cache_file is None:
                # Generate cache filename based on input file hash
                input_file = ida_nalt.get_input_file_path()
                file_hash = hashlib.md5(input_file.encode()).hexdigest()[:16]
                cache_file = os.path.join(tempfile.gettempdir(), f"ida_string_map_{file_hash}.cache")
            
            # Check if cache exists and is recent (modified after IDB)
            if os.path.exists(cache_file):
                idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
                idb_mtime = os.path.getmtime(idb_path) if idb_path and os.path.exists(idb_path) else 0
                cache_mtime = os.path.getmtime(cache_file)
                
                if cache_mtime > idb_mtime:
                    debug_print(f"Loading string map from cache: {cache_file}")
                    with open(cache_file, 'rb') as f:
                        cached_data = pickle.load(f)
                        duration = time.time() - start_time
                        debug_print(f"TRACE - Loaded cached string map in {duration:.4f}s")
                        return cached_data
                else:
                    debug_print("Cache is stale, rebuilding string map...")
        except Exception as e:
            debug_print(f"WARNING - Could not load string map cache: {e}. Building fresh.")
    
    # Build the string map
    string_map = {}
    string_count = 0
    xref_count = 0
    
    try:
        # First pass: count strings for progress reporting
        total_strings = sum(1 for _ in idautils.Strings())
        debug_print(f"Processing {total_strings} string literals...")
        
        for idx, s_info in enumerate(idautils.Strings()):
            try:
                strtype = getattr(s_info, 'strtype', ida_nalt.STRTYPE_C)
                str_bytes = ida_bytes.get_strlit_contents(s_info.ea, -1, strtype)
                if not str_bytes:
                    continue
                
                s = safe_decode(str_bytes)
                if not s or len(s) <= 1:
                    continue
                
                string_count += 1
                
                # Process xrefs for this string
                for xref in idautils.XrefsTo(s_info.ea):
                    func = ida_funcs.get_func(xref.frm)
                    if func:
                        func_ea = func.start_ea
                        if func_ea not in string_map:
                            string_map[func_ea] = set()
                        string_map[func_ea].add(s)
                        xref_count += 1
                
                # Progress reporting for large binaries
                if total_strings > 10000 and idx > 0 and idx % (total_strings // 10) == 0:
                    progress = (idx * 100) // total_strings
                    debug_print(f"String map progress: {progress}% ({idx}/{total_strings})")
                    
            except Exception as e:
                debug_print(f"ERROR - Could not process string at {s_info.ea:X}: {e}")
                import traceback
                debug_print(traceback.format_exc())
        
        debug_print(f"Processed {string_count} strings with {xref_count} cross-references")
        
        # Save to cache if enabled
        if use_cache and cache_file:
            try:
                with open(cache_file, 'wb') as f:
                    pickle.dump(string_map, f, protocol=pickle.HIGHEST_PROTOCOL)
                debug_print(f"Saved string map cache to: {cache_file}")
            except Exception as e:
                debug_print(f"WARNING - Could not save string map cache to '{cache_file}': {e}")
    
    except Exception as e:
        import traceback
        string_count_info = f"{string_count} strings" if 'string_count' in locals() else "unknown strings"
        xref_count_info = f"{xref_count} xrefs" if 'xref_count' in locals() else "unknown xrefs"
        debug_print(f"ERROR - Error building string map (processed {string_count_info}, {xref_count_info}): {e}")
        debug_print(traceback.format_exc())
    
    duration = time.time() - start_time
    debug_print(f"TRACE - Finished: build_string_map. Duration: {duration:.4f}s")
    return string_map

def extract_function_strings(function_ea: int) -> List[str]:
    """
    Extracts all unique string literals referenced by a single function.
    """
    debug_print(f"TRACE - Starting: extract_function_strings for 0x{function_ea:X}")
    start_time = time.time()
    try:
        func = ida_funcs.get_func(function_ea)
        if not func:
            return []

        strings = set()
        for item_ea in idautils.FuncItems(function_ea):
            for xref in idautils.XrefsFrom(item_ea):
                target_addr = xref.to
                if ida_bytes.is_strlit(ida_bytes.get_flags(target_addr)):
                    strtype = ida_nalt.get_str_type(target_addr)
                    if strtype == ida_nalt.BADADDR or strtype < 0:
                        strtype = ida_nalt.STRTYPE_C
                    
                    str_bytes = ida_bytes.get_strlit_contents(target_addr, -1, strtype)
                    if str_bytes:
                        s = safe_decode(str_bytes)
                        if s and len(s) > 1:
                            strings.add(s)

        duration = time.time() - start_time
        debug_print(f"TRACE - Finished: extract_function_strings for 0x{function_ea:X}. Duration: {duration:.4f}s")
        return list(strings)
    except Exception as e:
        debug_print(f"ERROR - Failed to extract strings for function at 0x{function_ea:X}: {e}")
        import traceback
        debug_print(traceback.format_exc())
        return []
