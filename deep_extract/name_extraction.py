"""
Name extraction and demangling utilities for PE binary analysis.

This module handles function name extraction, demangling,
and cleanup utilities for IDA Pro analysis.

Uses LRU caching to reduce hot-loop overhead in name extraction.
"""

from typing import Dict, Optional, Tuple, Any
from functools import lru_cache
import idc
import ida_funcs
import ida_name
import idaapi
import ida_bytes
import ida_idaapi
import ida_segment
import ida_ida
import ida_nalt

from . import constants
from .logging_utils import debug_print, safe_decode, _cached_getseg
from .import_resolution import get_module_name_from_import as _get_module_name_from_import


# LRU cache for name extraction to reduce hot loop overhead
# These caches significantly improve performance during xref extraction
@lru_cache(maxsize=10000)
def _cached_get_func_name(ea: int) -> str:
    """Cached wrapper for ida_funcs.get_func_name."""
    return ida_funcs.get_func_name(ea) or ""


@lru_cache(maxsize=10000)
def _cached_demangle_name(mangled_name: str, form: int) -> Optional[str]:
    """Cached wrapper for ida_name.demangle_name."""
    return ida_name.demangle_name(mangled_name, form)


def clear_name_caches():
    """Clear all name extraction caches. Call between analysis sessions."""
    _cached_get_func_name.cache_clear()
    _cached_demangle_name.cache_clear()
    debug_print("Name extraction caches cleared")


def _extract_name_from_signature(signature: str) -> Optional[str]:
    """
    Extracts the function name from a full signature string (MNG_LONG_FORM).
    Handles complex nested templates and return types correctly.
    
    Format: ReturnType Namespace::Name<TemplateArgs>(FuncArgs)
    
    :param signature: The full signature string
    :return: The extracted Name<TemplateArgs> or None if failed
    """
    if not signature:
        return None
        
    try:
        # 1. Find the start of function arguments '(', respecting template nesting
        # Scan forward, counting <> depth
        # We need the first '(' that is at depth 0
        arg_start = -1
        depth = 0
        for i, char in enumerate(signature):
            if char == '<':
                depth += 1
            elif char == '>':
                depth -= 1
            elif char == '(' and depth == 0:
                arg_start = i
                break
        
        # If no arguments found (e.g. variable), use end of string
        if arg_start == -1:
            name_part = signature
        else:
            name_part = signature[:arg_start].strip()
            
        # 2. Find the start of the function name (separator from ReturnType)
        # Scan backward from end of name_part, skipping over template blocks
        # Stop at first space, '*', or '&' that is at depth 0
        
        # Reverse scan is tricky with templates. 
        # Better: Scan forward and keep track of the last valid separator index at depth 0
        last_sep = -1
        depth = 0
        
        # We only scan up to the end of name_part
        for i, char in enumerate(name_part):
            if char == '<':
                depth += 1
            elif char == '>':
                depth -= 1
            elif depth == 0:
                # Potential separators between ReturnType and Name
                if char in (' ', '*', '&'):
                    last_sep = i
        
        if last_sep != -1:
            return name_part[last_sep+1:].strip()
        
        # No separator found? Maybe no return type or constructor?
        return name_part
        
    except Exception:
        return None


def _strip_func_args(name: str) -> str:
    """
    Strips function arguments from a name string, respecting template nesting.
    Example: "func<int(int)>(int)" -> "func<int(int)>"
    
    :param name: The name string to process
    :return: The name without function arguments
    """
    if not name:
        return ""
    
    depth = 0
    for i, char in enumerate(name):
        if char == '<':
            depth += 1
        elif char == '>':
            depth -= 1
        elif char == '(' and depth == 0:
            return name[:i].strip()
    return name


def get_extended_function_signature(ea: int) -> str:
    """
    Extracts the full C-style prototype for a function using IDA's type system.
    Includes argument names and types if available.
    
    :param ea: Effective address of the function.
    :return: Full C-style prototype string.
    """
    try:
        import ida_typeinf
        import ida_nalt
        tif = ida_typeinf.tinfo_t()
        if ida_nalt.get_tinfo(tif, ea) or ida_typeinf.guess_tinfo(tif, ea) != ida_typeinf.GUESS_FUNC_FAILED:
            # print_tinfo(prefix, indent, cmtindent, flags, tif, name, cmt)
            mangled_name = ida_funcs.get_func_name(ea) or f"sub_{ea:X}"
            name = mangled_name

            demangled_name = _cached_demangle_name(mangled_name, ida_name.MNG_SHORT_FORM)
            if demangled_name:
                demangled_name = _strip_func_args(demangled_name)
                demangled_name = _clean_method_signature(demangled_name.strip())
                if demangled_name:
                    name = demangled_name

            proto = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, tif, name, '')
            if proto:
                return proto
    except Exception as e:
        debug_print(f"WARNING - Failed to extract extended signature for 0x{ea:X}: {e}")
    
    # Fallback to demangled name if type info extraction fails
    return ""


def get_raw_function_name(ea: int) -> str:
    """
    Extracts a clean, short, demangled function name for a given effective address (ea).

    This function demangles the name, removes C++ parameter lists, and strips common
    compiler/linker prefixes like 'public:' or '[thunk]:'. It's designed to produce
    a simple, readable function name.
    
    Uses LRU caching for hot-loop performance.
    Now improved to handle non-function addresses by finding the closest symbol (head).

    :param ea: The effective address of the function or an address within it.
    :return: A cleaned-up, human-readable function name string.
    """
    try:
        # 1. Get the mangled name from the function address (use cache for performance)
        mangled_name = _cached_get_func_name(ea)
        
        if not mangled_name:
            # Fallback for names at addresses that might not be the start of a function
            func = ida_funcs.get_func(ea)
            if func:
                mangled_name = _cached_get_func_name(func.start_ea)
            else:
                # Not a function address. Try to find the head of the item
                head_ea = ida_bytes.get_item_head(ea)
                
                # Check for string literal
                # If the target is a string, return its content instead of its label (e.g. "String2")
                try:
                    # Method 1: Check flags (if IDA analyzed it)
                    flags = ida_bytes.get_full_flags(head_ea)
                    is_string = ida_bytes.is_strlit(flags)
                    
                    # Method 2: Fallback check if it looks like a string (for unanalyzed data)
                    if not is_string:
                         # Read a few bytes to see if it looks like a C-string (printable + null)
                         # Limit check to reasonable length
                         potential_bytes = ida_bytes.get_bytes(head_ea, 64)
                         if potential_bytes:
                            # Check for simple ASCII string
                            try:
                                # Find first null byte
                                null_idx = potential_bytes.find(b'\0')
                                if null_idx > 3: # Minimum length to consider it a string worth extracting
                                    candidate = potential_bytes[:null_idx]
                                    # Check if printable ASCII
                                    if all(32 <= b <= 126 for b in candidate):
                                        # It looks like a string, force return it
                                        is_string = True
                            except Exception:
                                pass

                    if is_string:
                        from ida_nalt import STRTYPE_TERMCHR
                        str_type = idc.get_str_type(head_ea)
                        # If type is unknown, assume C-string
                        if str_type is None: str_type = STRTYPE_TERMCHR
                            
                        content_bytes = ida_bytes.get_strlit_contents(head_ea, -1, str_type)
                        if content_bytes:
                            content = content_bytes.decode('utf-8', 'replace')
                            # Escape quotes and backslashes
                            content = content.replace('\\', '\\\\').replace('"', '\\"')
                            return f'"{content}"'
                except Exception:
                    pass

                mangled_name = ida_name.get_name(head_ea)
                
                # If we found a name at the head, and it's not the same address, add the offset
                if mangled_name and head_ea != ea:
                    offset = ea - head_ea
                    mangled_name = f"{mangled_name}+0x{offset:X}"
            
            if not mangled_name:
                # DEEP SEARCH: Scan back for the nearest named symbol (e.g. start of vtable)
                seg = _cached_getseg(ea)
                if seg:
                    seg_name = ida_segment.get_segm_name(seg)
                    
                    # Detailed handling for exception metadata
                    if seg_name in [".pdata", "pdata"]:
                        # RUNTIME_FUNCTION is 12 bytes on x64
                        offset = ea - seg.start_ea
                        index = offset // 12
                        
                        # Try to resolve the function this ExceptionTable entry points to
                        # RUNTIME_FUNCTION { DWORD BeginAddress; DWORD EndAddress; DWORD UnwindInfoAddress; }
                        try:
                            # Read the first DWORD (BeginAddress RVA)
                            rva_start = ida_bytes.get_dword(ea)
                            if rva_start != 0:
                                image_base = ida_nalt.get_imagebase()
                                target_ea = image_base + rva_start
                                
                                if ida_bytes.is_mapped(target_ea):
                                    # Get the function name at this target address
                                    target_name = _cached_get_func_name(target_ea)
                                    if not target_name:
                                        target_name = ida_name.get_name(target_ea)
                                        
                                    if target_name:
                                        demangled = _cached_demangle_name(target_name, ida_name.MNG_SHORT_FORM)
                                        if demangled:
                                            target_name = demangled
                                        
                                        clean_target = _clean_method_signature(target_name.split('(')[0].strip())
                                        if clean_target:
                                            return clean_target
                        except Exception:
                            pass
                            
                        return f"ExceptionTable[{index}]"
                    
                    # Scan back up to 4KB for a name (Parent Table)
                    curr = ea
                    limit = max(seg.start_ea, ea - 0x1000)
                    while curr >= limit:
                        name = ida_name.get_name(curr)
                        if name:
                            offset = ea - curr
                            demangled = ida_name.demangle_name(name, ida_name.MNG_SHORT_FORM)
                            base_name = demangled or name
                            
                            # Clean up the base name (remove public: etc)
                            base_name = _clean_method_signature(base_name.split('(')[0].strip())
                            
                            # Detect VTable and format as index
                            if "::`vftable'" in base_name or "::`vbtable'" in base_name:
                                ptr_size = 8 if ida_ida.inf_is_64bit() else 4
                                if offset % ptr_size == 0:
                                    index = offset // ptr_size

                                    # Try to resolve the target of this vtable entry to provide a better name
                                    try:
                                        if ptr_size == 8:
                                            target_ea = ida_bytes.get_qword(ea)
                                        else:
                                            target_ea = ida_bytes.get_dword(ea)

                                        if target_ea != ida_idaapi.BADADDR:
                                            # Check if target has a name
                                            target_name = _cached_get_func_name(target_ea)
                                            if not target_name:
                                                target_name = ida_name.get_name(target_ea)

                                            if target_name:
                                                # Clean up the target name
                                                demangled = _cached_demangle_name(target_name, ida_name.MNG_SHORT_FORM)
                                                if demangled:
                                                    target_name = demangled
                                                
                                                clean_target = _clean_method_signature(target_name.split('(')[0].strip())
                                                if clean_target:
                                                    return clean_target
                                    except Exception:
                                        # Fallback to index if resolution fails
                                        pass

                                    return f"{base_name}[{index}]"

                            # Generic Data Reference Resolution (e.g. CFG tables, RTTI, EH)
                            # If we are in a data section and haven't resolved a specific vtable index,
                            # try to resolve what this data points to (Pointer or RVA).
                            try:
                                # Only attempt this for data segments to avoid misinterpreting code
                                if seg and (seg.perm & ida_segment.SEGPERM_EXEC) == 0:
                                    image_base = ida_nalt.get_imagebase()
                                    
                                    # 1. Check RVA (4 bytes) - Common in x64 .rdata (CFG, EH, etc.)
                                    # Use get_dword to read 4 bytes even if unaligned (IDA handles this)
                                    rva_val = ida_bytes.get_dword(ea)
                                    # Ensure RVA is reasonable (not 0)
                                    if rva_val != 0: 
                                        rva_target = image_base + rva_val
                                        
                                        if ida_bytes.is_mapped(rva_target):
                                            # Prioritize function names
                                            target_name = _cached_get_func_name(rva_target)
                                            if not target_name:
                                                target_name = ida_name.get_name(rva_target)
                                                
                                            if target_name:
                                                demangled = _cached_demangle_name(target_name, ida_name.MNG_SHORT_FORM)
                                                if demangled:
                                                    target_name = demangled
                                                clean_target = _clean_method_signature(target_name.split('(')[0].strip())
                                                
                                                if clean_target:
                                                    return clean_target

                                    # 2. Check Absolute Pointer (Native size) - if RVA failed
                                    ptr_val = ida_idaapi.BADADDR
                                    if ida_ida.inf_is_64bit():
                                        ptr_val = ida_bytes.get_qword(ea)
                                    else:
                                        ptr_val = ida_bytes.get_dword(ea)
                                        
                                    if ptr_val != ida_idaapi.BADADDR and ptr_val != 0 and ida_bytes.is_mapped(ptr_val):
                                        # Only check if different from RVA target
                                        if not (not ida_ida.inf_is_64bit() and ptr_val == rva_val + image_base):
                                            target_name = _cached_get_func_name(ptr_val)
                                            if not target_name:
                                                target_name = ida_name.get_name(ptr_val)

                                            if target_name:
                                                demangled = _cached_demangle_name(target_name, ida_name.MNG_SHORT_FORM)
                                                if demangled:
                                                    target_name = demangled
                                                clean_target = _clean_method_signature(target_name.split('(')[0].strip())
                                                if clean_target:
                                                    return clean_target
                            except Exception:
                                pass

                            return f"{base_name}+0x{offset:X}"
                        
                        prev = ida_bytes.prev_head(curr, limit)
                        if prev == ida_idaapi.BADADDR or prev == curr:
                            curr -= 1
                        else:
                            curr = prev
                    
                    # Final fallback: check for repeat comments (IDA auto-generated info)
                    cmt = idc.get_cmt(ea, 1) # 1 = repeatable
                    if cmt:
                        # Clean the comment if it's a function name
                        return f"Ref:{_clean_method_signature(cmt.split('(')[0].strip())}"

                    return f"{seg_name}:0x{ea:X}"
                return f"sub_{ea:X}"

        # 2. Demangle the name using cached API to avoid repeated demanglings
        demangled_name = _cached_demangle_name(mangled_name, ida_name.MNG_SHORT_FORM)
        
        # Check for truncation in short form (heuristic: unbalanced brackets)
        # If it looks truncated or suspiciously short compared to a potentially long template, try Long Form
        is_potentially_truncated = False
        if demangled_name:
             if demangled_name.count('<') != demangled_name.count('>'):
                 is_potentially_truncated = True
        
        if is_potentially_truncated:
             # Fallback to recovery from long form
             long_demangled = _cached_demangle_name(mangled_name, ida_name.MNG_LONG_FORM)
             if long_demangled:
                 recovered_name = _extract_name_from_signature(long_demangled)
                 if recovered_name:
                     demangled_name = recovered_name

        # 3. If demangling fails, use the mangled name. If it succeeds, clean it up.
        if demangled_name is None:
            # Fallback: still attempt to strip parameters from user-applied names
            raw_name = mangled_name.split('(')[0]
        else:
            # Strip parameters using smart stripper that respects templates
            raw_name = _strip_func_args(demangled_name)
            
            # Legacy cleanup: Remove return type decorations if any remain (common in data)
            raw_name = raw_name.replace('near *', '').replace('near', '').replace('far *', '').replace('far', '')

        # Special handling for VTables found directly by name (e.g. at the start)
        # Try to resolve the first entry to a function name to provide better context
        if "::`vftable'" in raw_name or "::`vbtable'" in raw_name:
            try:
                # Check the first pointer in the vtable
                ptr_size = 8 if ida_ida.inf_is_64bit() else 4
                if ptr_size == 8:
                    target_ea = ida_bytes.get_qword(ea)
                else:
                    target_ea = ida_bytes.get_dword(ea)

                if target_ea != ida_idaapi.BADADDR:
                    target_name = _cached_get_func_name(target_ea)
                    if not target_name:
                        target_name = ida_name.get_name(target_ea)

                    if target_name:
                        demangled = _cached_demangle_name(target_name, ida_name.MNG_SHORT_FORM)
                        if demangled:
                            target_name = demangled
                        
                        clean_target = _clean_method_signature(target_name.split('(')[0].strip())
                        if clean_target:
                            # Use the resolved function name
                            raw_name = clean_target
            except Exception:
                pass

        # 4. Clean up any remaining common IDA prefixes like 'public:' or '[thunk]:'
        cleaned = _clean_method_signature(raw_name.strip())
        
        # 5. Also strip import prefixes if present
        return constants._strip_import_prefix(cleaned)

    except Exception as e:
        import traceback
        debug_print(f"ERROR - Error extracting raw function name for address 0x{ea:X}: {str(e)}")
        debug_print(traceback.format_exc())
        return f"error_parsing_name_at_0x{ea:X}"


def get_raw_long_function_name(mangled_name_str: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Demangles a function name string using both short and long forms.
    
    Uses cached demangling for hot-loop performance.

    :param mangled_name_str: The mangled name to be demangled.
    :return: A tuple containing (short_demangled_name, long_demangled_name).
             If demangling fails for a specific form, the original mangled name is
             used as a fallback for that form. Returns (None, None) for invalid input.
    """
    if not mangled_name_str or not isinstance(mangled_name_str, str):
        return None, None

    # Demangle using the short form (use cache for performance)
    short_demangled_name = _cached_demangle_name(mangled_name_str, ida_name.MNG_SHORT_FORM)
    if short_demangled_name is None:
        short_demangled_name = mangled_name_str

    # Demangle using the long form (use cache for performance)
    long_demangled_name = _cached_demangle_name(mangled_name_str, ida_name.MNG_LONG_FORM)
    if long_demangled_name is None:
        long_demangled_name = mangled_name_str

    return short_demangled_name, long_demangled_name


def _clean_method_signature(signature: str) -> str:
    """
    Strips common prefixes from a C++ method signature.

    Removes prefixes like '[thunk]:', 'public:', 'private:', 'protected:', and 'virtual'
    to produce a cleaner method name.

    :param signature: The C++ method signature string.
    :return: The cleaned signature.
    """
    # Remove potential [thunk] prefix first
    if signature.startswith("[thunk]:"):
        # The old logic incorrectly parsed class methods by searching for any ':',
        # which clashed with '::'. This logic strips the thunk prefix and lets
        # the loop below handle other prefixes like 'public:'.
        signature = signature[len("[thunk]:"):].strip()

    prefixes_to_remove = ["public:", "private:", "protected:", "virtual"]
    # Iteratively remove prefixes, continuing as long as we are making changes.
    # This replaces the previous logic and handles repeated prefixes.
    original_len = -1
    while len(signature) != original_len:
        original_len = len(signature)
        for prefix in prefixes_to_remove:
            if signature.startswith(prefix):
                # Remove the prefix and any immediately following whitespace
                signature = signature[len(prefix):].lstrip()

    return signature


def get_function_name_at(ea: int) -> Optional[Dict[str, str]]:
    """
    Retrieves detailed name information for a function or data at a given address.

    It returns a dictionary containing the mangled name and both short and long forms
    of the demangled name. This is useful for getting full name details in
    a structured format.

    :param ea: The effective address of the target.
    :return: A dictionary with 'mangled', 'short', and 'long' names, or None if no name exists.
    """
    if ea == idaapi.BADADDR:
        return None

    mangled_name_str = None
    func = ida_funcs.get_func(ea)
    if func:
        mangled_name_str = ida_funcs.get_func_name(func.start_ea)
    else:
        # Maybe it's a name at an address not part of a function?
        mangled_name_str = ida_name.get_name(ea)

    if not mangled_name_str:
        return None

    short_demangled_name, long_demangled_name = get_raw_long_function_name(mangled_name_str)

    return {
        "mangled": mangled_name_str,
        "short": safe_decode(short_demangled_name),
        "long": safe_decode(long_demangled_name)
    }


def get_module_name_from_import(target_ea: int) -> str:
    """
    Gets the module name for an import address.
    NOTE: Delegates to `import_resolution` to avoid duplication/circular deps.
    
    :param target_ea: The import address
    :return: Module name or empty string
    """
    try:
        return _get_module_name_from_import(int(target_ea))
    except Exception as e:
        debug_print(f"ERROR - Error getting module name for import 0x{target_ea:X}: {str(e)}")
    
    return ""


@lru_cache(maxsize=5000)
def extract_detailed_function_names(ea: int) -> Dict[str, str]:
    """
    Extract function name variants including mangled, short, and long forms.
    
    This function provides multiple forms of function names for better analysis:
    - mangled_name: The raw compiler-generated name
    - short_name: Clean function name without parameters
    - long_name: Full signature with return type and parameters
    - display_name: Best name for display purposes
    - module_name: Module name if it's an import
    
    Uses LRU caching for hot-loop performance.
    
    :param ea: The effective address to extract names from
    :return: Dictionary containing name variants (hashable dict keys only)
    """
    result = {
        'mangled_name': '',
        'short_name': '',
        'long_name': '',
        'display_name': '',
        'module_name': ''
    }
    
    try:
        # First try to get the function name (use cached version)
        mangled_name = _cached_get_func_name(ea)
        if not mangled_name:
            # Try getting name at address (for non-function symbols)
            mangled_name = ida_name.get_name(ea)
        
        if mangled_name:
            result['mangled_name'] = mangled_name
            
            # Try to extract short and long demangled names
            short_demangled, long_demangled = get_raw_long_function_name(mangled_name)
            
            if short_demangled and short_demangled != mangled_name:
                result['short_name'] = short_demangled
            else:
                # Fallback: use clean method signature for short name
                result['short_name'] = _clean_method_signature(mangled_name)
            
            if long_demangled and long_demangled != mangled_name:
                result['long_name'] = long_demangled
            else:
                # Use mangled name as fallback for long name
                result['long_name'] = mangled_name
            
            # Set display name (prefer short, fallback to mangled)
            result['display_name'] = result['short_name'] or result['mangled_name']
            
            # Check if it's an import and extract module name
            if mangled_name.startswith('__imp_') or mangled_name.startswith('_imp_'):
                module_name = get_module_name_from_import(ea)
                if module_name:
                    result['module_name'] = module_name
                else:
                    result['module_name'] = 'external.dll'
            
            # Check for vtable patterns
            vtable_patterns = ["vtable", "vftable", "vtbl", "::`vftable'"]
            if any(pattern in mangled_name.lower() for pattern in vtable_patterns):
                result['module_name'] = 'vtable'
        
        else:
            # No name found - generate placeholder
            result['display_name'] = f"sub_{ea:X}"
            result['short_name'] = result['display_name']
            result['long_name'] = result['display_name']
    
    except Exception as e:
        import traceback
        debug_print(f"ERROR - Error extracting name variants for 0x{ea:X}: {str(e)}")
        debug_print(traceback.format_exc())
        result['display_name'] = f"error_parsing_name_at_0x{ea:X}"
        result['short_name'] = result['display_name']
        result['long_name'] = result['display_name']
    
    return result


def extract_vtable_function_names(vtable_ea: int, method_offset: int) -> Dict[str, str]:
    """
    Extract name variants for a vtable method at a specific offset.
    
    :param vtable_ea: Address of the vtable
    :param method_offset: Offset within the vtable
    :return: Dictionary containing vtable method name information
    """
    result = {
        'vtable_name': '',
        'method_name': '',
        'method_short_name': '',
        'method_long_name': '',
        'method_mangled_name': ''
    }
    
    try:
        # Get vtable name
        vtable_name = ida_name.get_name(vtable_ea)
        if vtable_name:
            result['vtable_name'] = vtable_name
        
        # Calculate method address
        method_ea = vtable_ea + method_offset
        
        # Check if there's a valid pointer at this offset
        if ida_bytes.is_mapped(method_ea):
            # Get the target function address
            target_ea = ida_bytes.get_qword(method_ea) if _cached_getseg(method_ea) else ida_idaapi.BADADDR
            
            if target_ea != ida_idaapi.BADADDR and ida_bytes.is_mapped(target_ea):
                # Extract name variants for the method
                method_names = extract_detailed_function_names(target_ea)
                result['method_name'] = method_names['display_name']
                result['method_short_name'] = method_names['short_name']
                result['method_long_name'] = method_names['long_name']
                result['method_mangled_name'] = method_names['mangled_name']
    
    except Exception as e:
        import traceback
        debug_print(f"ERROR - Error extracting vtable method names for vtable 0x{vtable_ea:X} offset {method_offset}: {str(e)}")
        debug_print(traceback.format_exc())
    
    return result


# Import directly from constants module
from .constants import _strip_import_prefix


def extract_unified_function_names(ea: int, fallback_name_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Unified function name extraction with structured fallback logic.
    
    This function implements consistent name extraction logic across all processing paths,
    with better error handling and fallback chains inspired by simple_outbound_xrefs.
    
    :param ea: The effective address to extract names from
    :param fallback_name_info: Optional name_info dict for fallback
    :return: Dictionary containing all name forms with consistent fallback logic
    """
    result = {
        'display_name': '',
        'short_name': '',
        'long_name': '',
        'mangled_name': '',
        'module_name': '',
        'extraction_success': False
    }
    
    try:
        # First, try full name extraction
        try:
            detailed_names = extract_detailed_function_names(ea)
            if detailed_names and detailed_names.get('display_name'):
                result.update({
                    'display_name': detailed_names['display_name'],
                    'short_name': detailed_names['short_name'],
                    'long_name': detailed_names['long_name'],
                    'mangled_name': detailed_names['mangled_name'],
                    'module_name': detailed_names['module_name'],
                    'extraction_success': True
                })
                
                # If we got a good display name, we're done
                if result['display_name'] and not result['display_name'].startswith('sub_'):
                    return result
                    
        except Exception as e:
            debug_print(f"WARNING - Comprehensive name extraction failed for 0x{ea:X}: {str(e)}")
        
        # Second, try get_raw_function_name for consistency (like simple_outbound)
        try:
            raw_name = get_raw_function_name(ea)
            if raw_name and not raw_name.startswith('sub_') and not raw_name.startswith('error_'):
                result['short_name'] = raw_name
                if not result['display_name']:
                    result['display_name'] = raw_name
                result['extraction_success'] = True
        except Exception as e:
            debug_print(f"WARNING - get_raw_function_name failed for 0x{ea:X}: {str(e)}")
        
        # Third, fallback to name_info if provided (like simple_outbound fallback logic)
        if fallback_name_info and not result['extraction_success']:
            try:
                if fallback_name_info.get('short') and not result['short_name']:
                    result['short_name'] = fallback_name_info['short']
                if fallback_name_info.get('long') and not result['long_name']:
                    result['long_name'] = fallback_name_info['long']
                if fallback_name_info.get('mangled') and not result['mangled_name']:
                    result['mangled_name'] = fallback_name_info['mangled']
                if not result['display_name']:
                    result['display_name'] = result['short_name'] or result['long_name'] or result['mangled_name']
                if result['display_name']:
                    result['extraction_success'] = True
            except Exception as e:
                debug_print(f"WARNING - Fallback name extraction failed for 0x{ea:X}: {str(e)}")
        
        # Final fallback: generate placeholder name
        if not result['display_name']:
            result['display_name'] = f"sub_{ea:X}"
            result['short_name'] = result['display_name']
            result['long_name'] = result['display_name']
    
    except Exception as e:
        debug_print(f"ERROR - Error in unified function name extraction for 0x{ea:X}: {str(e)}")
        result['display_name'] = f"error_parsing_name_at_0x{ea:X}"
        result['short_name'] = result['display_name']
        result['long_name'] = result['display_name']
    
    return result

