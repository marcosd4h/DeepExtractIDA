"""
Cross-reference and call flow analysis for PE binary analysis.

This module covers cross-reference extraction, function classification,
and call flow analysis including vtable calls, indirect calls, and jump tables.
"""

# Standard library imports
import json
import time
from typing import Dict, List, Optional, Any, Tuple, Set

# Third-party imports (IDA Pro)
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_name
import ida_nalt
import ida_segment
import ida_xref
import idautils
import idc

# Local imports
from . import constants
from .constants import FT_UNK, FT_GEN, FT_LIB, FT_API, FT_MEM, FT_VTB, FT_SYS
from .logging_utils import debug_print, _cached_getseg, _cached_is_loaded
from .name_extraction import (
    extract_detailed_function_names,
    extract_unified_function_names,
    extract_vtable_function_names,
    get_function_name_at,
    _clean_method_signature
)
from .import_resolution import get_module_name_from_import as _get_module_name_from_import
from .vtable_analysis import (
    get_vtable_context,
    analyze_vtable_calls
)
from .indirect_call_analysis import (
    analyze_indirect_calls,
    is_indirect_jump_instruction,
    analyze_jump_table
)
from .thunk_analysis import resolve_thunk_target
from .validation import (
    validate_function_call,
    validate_and_normalize_xref_data
)

# Import pefile with graceful fallback and bundled support
try:
    import pefile
except ImportError:
    try:
        import sys
        import os
        # Try to find it in the local deps folder relative to this file
        _deps_path = os.path.join(os.path.dirname(__file__), 'deps')
        if os.path.exists(_deps_path) and _deps_path not in sys.path:
            sys.path.insert(0, _deps_path)
        import pefile
    except ImportError:
        pefile = None

# Import directly from constants module
from .constants import _strip_import_prefix


def map_xref_type_to_string(xref_type: int) -> str:
    """
    Converts an IDA cross-reference type constant to a human-readable string.

    :param xref_type: The numeric xref type constant from IDA APIs.
    :return: A string describing the cross-reference type.
    """
    type_map = {
        ida_xref.fl_CF: "Call Far",
        ida_xref.fl_CN: "Call Near",
        ida_xref.fl_JF: "Jump Far",
        ida_xref.fl_JN: "Jump Near",
        ida_xref.fl_F: "Ordinary Flow",
        ida_xref.dr_O: "Offset",
        ida_xref.dr_W: "Write",
        ida_xref.dr_R: "Read",
        ida_xref.dr_T: "Text (user specified)",
        ida_xref.dr_I: "Informational",
        ida_xref.XREF_USER: "User Defined",
        ida_xref.XREF_TAIL: "Tail",
        ida_xref.XREF_BASE: "Base Offset",
    }
    base_type = xref_type & 0x1F
    type_str = type_map.get(base_type, f"Unknown Type ({base_type})")

    flags = []
    if xref_type & ida_xref.XREF_USER: flags.append("User")
    if xref_type & ida_xref.XREF_TAIL: flags.append("Tail")
    if xref_type & ida_xref.XREF_BASE: flags.append("Base")

    if flags:
        type_str += f" [{', '.join(flags)}]"

    return type_str


def build_import_address_set() -> Set[int]:
    """
    Builds a set of all import addresses for quick lookup during classification.
    Augmented to include delay-load imports and '__imp_load_' thunks.
    :return: Set of import addresses
    """
    import_addresses = set()

    try:
        # Regular IAT entries
        nimps = ida_nalt.get_import_module_qty()
        for i in range(nimps):
            def imp_cb(ea, name, ordinal):
                import_addresses.add(ea)
                return True
            ida_nalt.enum_import_names(i, imp_cb)

        # Delay-load thunks
        for ea, name in idautils.Names():
            if name.startswith("__imp_load_") or name.startswith("_imp_load_"):
                import_addresses.add(ea)

        # Parse delay import directory with pefile
        try:
            if pefile is not None:
                pe_path = ida_nalt.get_input_file_path()
                pe = pefile.PE(pe_path, fast_load=True)
                if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
                    ida_base = ida_nalt.get_imagebase()
                    pe_base = pe.OPTIONAL_HEADER.ImageBase
                    for dll in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                        for imp in dll.imports:
                            if imp.address:
                                ea = (imp.address - pe_base) + ida_base
                                if _cached_is_loaded(ea):
                                    import_addresses.add(ea)
                del pe
        except Exception as e:
            debug_print(f"WARNING - Failed delay-import enumeration via pefile: {e}")

    except Exception as e:
        import traceback
        debug_print(f"ERROR - Error building import address set: {str(e)}")
        debug_print(traceback.format_exc())

    return import_addresses


def get_module_name_from_import(target_ea):
    """
    Gets the module name for an import address.
    
    :param target_ea: The import address
    :return: Module name or empty string
    """
    try:
        return _get_module_name_from_import(int(target_ea))
    except Exception as e:
        import traceback
        debug_print(f"ERROR - Error getting module name for import 0x{target_ea:X}: {str(e)}")
        debug_print(traceback.format_exc())
    
    return ""


def classify_function_type(target_ea: int, import_addresses: Optional[Set[int]] = None, _recursion_depth: int = 0) -> Tuple[int, str, str]:
    """
    Classifies a function or target address into one of the predefined types.
    
    :param target_ea: The effective address to classify
    :param import_addresses: Set of import addresses for quick lookup
    :param _recursion_depth: Internal parameter to track recursion depth (do not set manually)
    :return: Tuple of (function_type, module_name, resolved_name)
    """
    # Prevent infinite recursion on pathological thunk chains
    MAX_RECURSION_DEPTH = 10
    if _recursion_depth > MAX_RECURSION_DEPTH:
        debug_print(f"WARNING - Maximum recursion depth reached while classifying function at 0x{target_ea:X}")
        return FT_UNK, "thunk_cycle", f"thunk_cycle_0x{target_ea:X}"
    
    if import_addresses is None:
        import_addresses = set()
    
    func_type = FT_UNK
    module_name = ""
    resolved_name = ""
    
    # Check if it's an import first
    if target_ea in import_addresses:
        func_type = FT_API
        resolved_name = ida_name.get_name(target_ea) or f"import_0x{target_ea:X}"
        
        module_name = get_module_name_from_import(target_ea)
        if not module_name:
            # Fallback patterns
            if resolved_name.startswith("__imp_"):
                parts = resolved_name[6:].split("_", 1)
                if len(parts) > 1:
                    potential_module = parts[0]
                    if potential_module.lower() in ["kernel32", "ntdll", "user32", "advapi32", "ws2_32", "msvcrt", "ole32", "shell32"]:
                        module_name = potential_module + ".dll"
        
        if not module_name:
            module_name = "external.dll"
        
        return func_type, module_name, resolved_name
    
    # Get function at target address
    target_func = ida_funcs.get_func(target_ea)
    
    if target_func:
        func_flags = target_func.flags
        resolved_name = ida_funcs.get_func_name(target_ea) or f"sub_{target_ea:X}"
        
        # Check for library function
        if func_flags & ida_funcs.FUNC_LIB:
            func_type = FT_LIB
            module_name = "static_library"
        
        # Check for thunk function
        elif func_flags & ida_funcs.FUNC_THUNK:
            thunk_target = resolve_thunk_target(target_ea)
            if thunk_target != target_ea:
                return classify_function_type(thunk_target, import_addresses, _recursion_depth + 1)
            else:
                func_type = FT_LIB
                module_name = "thunk_library"
        
        # Regular internal function
        else:
            func_type = FT_GEN
            module_name = "internal"
    
    else:
        # Not a function - check if it's a vtable reference, data, or code outside function
        head_ea = ida_bytes.get_item_head(target_ea)
        name = ida_name.get_name(head_ea)
        
        if name:
            resolved_name = name
            if head_ea != target_ea:
                resolved_name += f"+0x{target_ea - head_ea:X}"
            
            # Check demangled name for vtable patterns
            demangled = ida_name.demangle_name(name, ida_name.MNG_SHORT_FORM) or name
            name_lower = demangled.lower()
            
            if any(pattern in name_lower for pattern in ["vtable", "vftable", "vtbl", "::`vftable'", "::`vbtable'"]):
                func_type = FT_VTB
                module_name = "vtable"
            
            elif name.startswith("__imp_") or name.startswith("_imp_"):
                func_type = FT_API
                module_name = get_module_name_from_import(target_ea) or get_module_name_from_import(head_ea)
                if not module_name:
                    module_name = "external.dll"
            
            else:
                func_type = FT_MEM
                module_name = "data"
            
        else:
            # Still no name - check flags and segment
            flags = ida_bytes.get_full_flags(target_ea)
            if ida_bytes.is_code(flags):
                func_type = FT_GEN
                module_name = "internal"
                resolved_name = f"code_0x{target_ea:X}"
            else:
                func_type = FT_UNK
                module_name = "data"
                seg = _cached_getseg(target_ea)
                if seg:
                    seg_name = ida_segment.get_segm_name(seg)
                    resolved_name = f"{seg_name}:0x{target_ea:X}"
                else:
                    resolved_name = f"unknown_0x{target_ea:X}"
    
    # Detect tiny syscall stubs
    if func_type == FT_GEN and target_func:
        try:
            if (target_func.end_ea - target_func.start_ea) <= 20:
                has_sys = False
                for insn_ea in idautils.FuncItems(target_func.start_ea):
                    mnem = idc.print_insn_mnem(insn_ea).lower()
                    if mnem in ["syscall", "sysenter"] or (mnem == "int" and idc.get_operand_value(insn_ea,0)==0x2e):
                        has_sys = True
                        break
                if has_sys:
                    func_type = FT_SYS
                    module_name = "ntdll"
        except Exception:
            pass
    
    return func_type, module_name, resolved_name


def check_for_dangerous_calls(outbound_xrefs: List[Dict[str, Any]], dangerous_api_set: Optional[Set[str]] = None) -> str:
    """
    Checks a function's outbound calls against a set of known dangerous APIs.

    :param outbound_xrefs: A list of outbound cross-references from a function.
    :param dangerous_api_set: Legacy parameter (ignored - uses constants module).
    :return: A JSON string containing a list of unique dangerous calls found.
    """
    debug_print("TRACE - Starting: check_for_dangerous_calls")
    start_time = time.time()
    found_dangerous_calls = []
    try:
        for xref in outbound_xrefs:
            function_name = xref.get("function_name")
            if function_name and constants.is_dangerous_api(function_name):
                found_dangerous_calls.append(function_name)

    except TypeError as e:
        debug_print(f"ERROR - Error processing outbound xrefs for dangerous calls: {e}")
    
    duration = time.time() - start_time
    debug_print(f"TRACE - Finished: check_for_dangerous_calls. Duration: {duration:.4f}s")
    return json.dumps(list(set(found_dangerous_calls)))


# ==============================================================================
# Helper functions for extract_function_xrefs
# ==============================================================================

def _initialize_xref_data():
    """
    Initialize the cross-reference data structure.
    :return: Empty xref data dictionary
    """
    return {
        "inbound_xrefs": [],
        "outbound_xrefs": [],
        "vtable_contexts": [],
        "global_var_accesses": []
    }


def _get_excluded_targets():
    """
    Returns set of function names that should be excluded from xref analysis.
    :return: Set of excluded function names
    """
    return {
        "_guard_dispatch_icall_nop",
        "__guard_dispatch_icall_fptr",
        "__security_check_cookie",
        "WPP_GLOBAL_Control"
    }


def _process_inbound_xref(xref, target_ea, import_addresses):
    """
    Process a single inbound cross-reference.
    
    :param xref: The xref object from IDA
    :param target_ea: The target function address
    :param import_addresses: Set of import addresses
    :return: Tuple of (inbound_xref_data, is_vtable_candidate, source_ea)
    """
    source_ea = xref.frm
    xref_type_str = map_xref_type_to_string(xref.type)
    
    if xref_type_str == "Ordinary Flow":
        return None, False, source_ea
    
    source_loc_str = f"0x{source_ea:X}"
    is_vtable_candidate = False
    detailed_names = {}
    source_name_info = None  # Initialize to avoid unbound variable errors
    
    # Detailed processing for code references
    if xref.iscode:
        source_func = ida_funcs.get_func(source_ea)
        if source_func and source_func.start_ea != ida_idaapi.BADADDR:
            try:
                detailed_names = extract_detailed_function_names(source_func.start_ea)
                source_name = detailed_names['display_name']
                
                if not source_name or source_name.startswith('sub_'):
                    source_name_info = get_function_name_at(source_func.start_ea)
                    if source_name_info:
                        source_name = source_name_info['long']
                    else:
                        source_name = "Unknown Function"
                else:
                    source_name_info = {
                        'mangled': detailed_names['mangled_name'],
                        'short': detailed_names['short_name'],
                        'long': detailed_names['long_name']
                    }
            except Exception as e:
                debug_print(f"WARNING - Failed name extraction for inbound source 0x{source_func.start_ea:X}: {str(e)}")
                source_name_info = get_function_name_at(source_func.start_ea)
                if source_name_info:
                    source_name = source_name_info['long']
                else:
                    source_name = "Unknown Function"
            
            source_loc_str += f" (in {source_name})"
            
            # Detailed function classification for source
            try:
                source_func_type, source_module_name, source_resolved_name = classify_function_type(source_func.start_ea, import_addresses)
                
                source_module_host = source_module_name or "internal"
                if source_module_name and not source_module_name.lower() in ("internal", "indirect", "static"):
                    source_module_name = constants.resolve_apiset(source_module_name)
                
                if source_resolved_name:
                    source_resolved_name = _strip_import_prefix(source_resolved_name)
                    
            except Exception as e:
                debug_print(f"WARNING - Failed source function classification for 0x{source_func.start_ea:X}: {str(e)}")
                source_func_type = FT_UNK
                source_module_name = "internal"
                source_module_host = "internal"
                source_resolved_name = source_name
        else:
            source_loc_str += " (in Unknown Function)"
            source_func_type = FT_UNK
            source_module_name = "unknown"
            source_module_host = "unknown"
            source_resolved_name = f"code_outside_function_0x{source_ea:X}"
            
    else:
        # Data reference processing
        source_loc_str += " (Data)"
        
        # Use smarter classification for inbound data references
        source_func_type, source_module_name, source_resolved_name = classify_function_type(source_ea, import_addresses)
        source_module_host = source_module_name
        
        # If classification didn't provide a module host, default to data
        if not source_module_host:
            source_module_host = "data"
            source_module_name = "data"
        
        # Segment check for vtable candidate
        seg = _cached_getseg(source_ea)
        if seg:
            seg_name = ida_segment.get_segm_name(seg)
            source_loc_str += f" (Segment: {seg_name})"
            if seg_name in [".rdata", ".rodata", ".text", ".data"]:
                if (seg.perm & ida_segment.SEGPERM_WRITE) == 0 and (seg.perm & ida_segment.SEGPERM_READ):
                    is_vtable_candidate = True
                    # If it's a vtable candidate but wasn't classified as FT_VTB, upgrade it
                    if source_func_type == FT_UNK:
                        source_func_type = FT_VTB
    
    # Detailed validation
    call_confidence = 50.0
    validation_checks = []
    validation_warnings = []
    
    try:
        if xref.iscode and xref_type_str in ["Call Far", "Call Near", "Jump Far", "Jump Near"]:
            confidence_info = {'confidence': 'medium'}
            is_valid_inbound_call, inbound_call_confidence, inbound_validation_info = validate_function_call(
                source_ea, target_ea, xref_type_str, source_resolved_name, confidence_info
            )
            
            if is_valid_inbound_call:
                call_confidence = inbound_call_confidence
                validation_checks = inbound_validation_info.get('validation_checks', [])
            else:
                validation_warnings = inbound_validation_info.get('warnings', [])
                call_confidence = max(10.0, inbound_call_confidence)
                
    except Exception as e:
        debug_print(f"WARNING - Failed inbound validation for 0x{source_ea:X}: {str(e)}")
        validation_warnings.append(f"validation_error: {str(e)}")
    
    # Store detailed inbound xref data
    inbound_xref_data = {
        "source_ea": f"0x{source_ea:X}",
        "source_location_details": source_loc_str,
        "xref_type": xref_type_str,
        "is_code": xref.iscode == 1,
        "is_vtable_candidate": is_vtable_candidate,
        "source_name_info": source_name_info,
        "source_function_name": source_resolved_name,
        "source_function_name_short": detailed_names.get('short_name', ''),
        "source_function_name_long": detailed_names.get('long_name', ''),
        "source_function_name_mangled": detailed_names.get('mangled_name', ''),
        "source_module_name": source_module_name,
        "source_module_host": source_module_host,
        "source_function_type": source_func_type,
        "call_confidence": round(call_confidence, 2),
        "validation_checks": validation_checks,
        "extraction_type": "detailed_inbound"
    }
    
    if inbound_xref_data["is_code"] and xref_type_str in ["Call Far", "Call Near", "Offset", "Jump Far", "Jump Near"]:
        inbound_xref_data["function_name"] = source_resolved_name
    
    if validation_warnings:
        inbound_xref_data["validation_warnings"] = validation_warnings
    
    inbound_xref_data = validate_and_normalize_xref_data(inbound_xref_data, "detailed_inbound")
    
    return inbound_xref_data, is_vtable_candidate, source_ea


def _extract_inbound_xrefs(target_ea: int, import_addresses: Set[int], xref_data: Dict[str, List[Any]]) -> List[int]:
    """
    Extract all inbound cross-references for a function.
    
    :param target_ea: The target function address
    :param import_addresses: Set of import addresses
    :param xref_data: Dictionary to store results (modified in-place)
    :return: List of source_ea addresses that are vtable candidates
    """
    processed_inbound_calls = set()
    vtable_candidates = []
    
    for xref in idautils.XrefsTo(target_ea):
        try:
            inbound_xref_data, is_vtable_candidate, source_ea = _process_inbound_xref(xref, target_ea, import_addresses)
            
            if inbound_xref_data is None:
                continue
            
            # Create unique key
            source_resolved_name = inbound_xref_data.get("source_function_name", "")
            xref_type_str = inbound_xref_data.get("xref_type", "")
            inbound_call_key = (source_ea, xref_type_str, source_resolved_name)
            
            if inbound_call_key in processed_inbound_calls:
                continue
            processed_inbound_calls.add(inbound_call_key)
            
            xref_data["inbound_xrefs"].append(inbound_xref_data)
            
            if is_vtable_candidate:
                vtable_candidates.append(source_ea)
                
        except Exception as e:
            debug_print(f"ERROR - Error processing inbound xref from 0x{xref.frm:X}: {str(e)}")
            # Add error recovery entry
            error_xref_data = {
                "source_ea": f"0x{xref.frm:X}",
                "source_location_details": f"0x{xref.frm:X} (Error: {str(e)})",
                "xref_type": map_xref_type_to_string(xref.type),
                "is_code": xref.iscode == 1,
                "is_vtable_candidate": False,
                "source_name_info": None,
                "source_function_name": f"error_processing_0x{xref.frm:X}",
                "extraction_type": "error_recovery"
            }
            error_xref_data = validate_and_normalize_xref_data(error_xref_data, "error_recovery")
            xref_data["inbound_xrefs"].append(error_xref_data)
    
    return vtable_candidates


def _extract_vtable_contexts_from_inbound(vtable_candidates: List[int], xref_data: Dict[str, List[Any]]) -> None:
    """
    Extract VTable contexts from inbound vtable candidate references.
    
    :param vtable_candidates: List of source_ea addresses that are vtable candidates
    :param xref_data: Dictionary to store results (modified in-place)
    """
    for source_ea in vtable_candidates:
        try:
            vtable_context = get_vtable_context(source_ea)
            if not vtable_context:
                continue
            
            reconstructed_classes = {}
            current_class_name = None
            
            for entry in vtable_context:
                resolved_name = entry.get("points_to_name", "")
                
                if not resolved_name or resolved_name.startswith("0x") or resolved_name == "NULL":
                    current_class_name = None
                    continue
                
                entry_class_name = None
                cleaned_name = _clean_method_signature(resolved_name)
                if "::" in cleaned_name:
                    parts = cleaned_name.split('(')[0].rsplit("::", 1)
                    if len(parts) > 1:
                        entry_class_name = parts[0].strip()
                
                if not entry_class_name or "adjustor" in cleaned_name:
                    current_class_name = None
                    continue
                
                if entry_class_name != current_class_name:
                    current_class_name = entry_class_name
                    if current_class_name not in reconstructed_classes:
                        reconstructed_classes[current_class_name] = []
                
                method_in_class = cleaned_name.replace(f"{current_class_name}::", "", 1).strip()
                reconstructed_classes[current_class_name].append(f"    virtual {method_in_class} = 0;")
            
            # Format classes
            final_cpp_defs = []
            for class_name, methods in reconstructed_classes.items():
                unique_methods = list(dict.fromkeys(methods))
                
                cpp_class = f"class {class_name} {{\npublic:\n"
                cpp_class += "\n".join(unique_methods)
                cpp_class += "\n};"
                final_cpp_defs.append(cpp_class)
            
            if final_cpp_defs:
                vtable_entry = {
                    "reconstructed_classes": final_cpp_defs,
                    "source_ea": f"0x{source_ea:X}",
                    "extraction_type": "detailed_vtable_analysis"
                }
                xref_data["vtable_contexts"].append(vtable_entry)
                
        except Exception as e:
            debug_print(f"ERROR - Error processing vtable context at 0x{source_ea:X}: {str(e)}")


def _process_vtable_call_targets(item_ea, target_addr, xref_type_str, import_addresses, processed_calls, xref_data):
    """
    Process vtable call targets and add them to xref data.
    
    :param item_ea: The instruction address
    :param target_addr: The target address
    :param xref_type_str: The xref type string
    :param import_addresses: Set of import addresses
    :param processed_calls: Set to track processed calls (modified in-place)
    :param xref_data: Dictionary to store results (modified in-place)
    :return: True if vtable calls were processed, False otherwise
    """
    try:
        is_vtable, vtable_targets, vtable_info = analyze_vtable_calls(item_ea, target_addr, import_addresses)
    except Exception as e:
        debug_print(f"ERROR - VTable analysis failed for 0x{item_ea:X}: {str(e)}")
        return False
    
    if not is_vtable or not vtable_targets:
        return False
    
    for vtbl_target in vtable_targets:
        try:
            vtbl_func_type, vtbl_module_name, vtbl_resolved_name = classify_function_type(vtbl_target, import_addresses)
            
            # Skip if target is the same as the function being analyzed
            if vtbl_target == item_ea:
                continue
            
            vtbl_unified_names = extract_unified_function_names(vtbl_target)
            
            if vtbl_unified_names['display_name'] and not vtbl_unified_names['display_name'].startswith('sub_'):
                vtbl_resolved_name = vtbl_unified_names['display_name']
            
            vtable_method_names = extract_vtable_function_names(
                vtable_info.get('vtable_addr', 0),
                vtable_info.get('method_offset', 0)
            )
            
            vtbl_confidence_info = {'confidence': 'high'}
            is_valid_vtable_call, vtbl_call_confidence, vtbl_validation_info = validate_function_call(
                item_ea, vtbl_target, f"{xref_type_str} (VTable)", vtbl_resolved_name, vtbl_confidence_info
            )
            
            if not is_valid_vtable_call:
                continue
            
            vtbl_call_key = (vtbl_target, f"{xref_type_str} (VTable)", vtbl_resolved_name)
            if vtbl_call_key in processed_calls:
                continue
            processed_calls.add(vtbl_call_key)
            
            vtable_xref_data = {
                "source_instruction_ea": f"0x{item_ea:X}",
                "target_ea": f"0x{vtbl_target:X}",
                "resolved_target_ea": f"0x{vtbl_target:X}",
                "xref_type": f"{xref_type_str} (VTable)",
                "function_name": vtbl_resolved_name,
                "short_function_name": vtbl_unified_names['short_name'],
                "function_name_short": vtbl_unified_names['short_name'],
                "function_name_long": vtbl_unified_names['long_name'],
                "function_name_mangled": vtbl_unified_names['mangled_name'],
                "module_name": vtbl_module_name,
                "function_type": FT_VTB,
                "is_tail_call": False,
                "is_thunk_resolved": False,
                "is_vtable_call": True,
                "call_confidence": round(vtbl_call_confidence, 2),
                "validation_checks": vtbl_validation_info.get('validation_checks', []),
                "extraction_type": "unified_vtable",
                "vtable_info": {
                    "vtable_address": f"0x{vtable_info.get('vtable_addr', 0):X}",
                    "vtable_name": vtable_method_names['vtable_name'],
                    "method_offset": vtable_info.get('method_offset', 0),
                    "method_short_name": vtable_method_names['method_short_name'],
                    "method_long_name": vtable_method_names['method_long_name'],
                    "method_mangled_name": vtable_method_names['method_mangled_name'],
                    "vtable_size": vtable_info.get('vtable_size', 0)
                }
            }
            
            if vtbl_validation_info.get('warnings'):
                vtable_xref_data["validation_warnings"] = vtbl_validation_info['warnings']
            
            xref_data["outbound_xrefs"].append(vtable_xref_data)
            
        except Exception as e:
            debug_print(f"ERROR - Error processing vtable target 0x{vtbl_target:X}: {str(e)}")
            continue
    
    return True


def _process_indirect_call_targets(item_ea: int, target_addr: int, xref_type_str: str, 
                                   import_addresses: Set[int], excluded_targets: Set[str], 
                                   processed_calls: Set[Tuple[int, str, str]], 
                                   xref_data: Dict[str, List[Any]]) -> bool:
    """
    Process indirect call targets and add them to xref data.
    
    :param item_ea: The instruction address
    :param target_addr: The target address
    :param xref_type_str: The xref type string
    :param import_addresses: Set of import addresses
    :param excluded_targets: Set of function names to exclude
    :param processed_calls: Set to track processed calls (modified in-place)
    :param xref_data: Dictionary to store results (modified in-place)
    :return: True if indirect calls were processed, False otherwise
    """
    try:
        is_indirect, indirect_targets, indirect_info = analyze_indirect_calls(item_ea, target_addr, import_addresses)
    except Exception as e:
        debug_print(f"ERROR - Indirect call analysis failed for 0x{item_ea:X}: {str(e)}")
        return False
    
    if not is_indirect or not indirect_targets:
        return False
    
    for indirect_target in indirect_targets:
        try:
            indirect_func_type, indirect_module_name, indirect_resolved_name = classify_function_type(indirect_target, import_addresses)
            
            # Skip if target is the same as current instruction
            if indirect_target == item_ea:
                continue
            
            indirect_unified_names = extract_unified_function_names(indirect_target)
            
            if indirect_unified_names['display_name'] and not indirect_unified_names['display_name'].startswith('sub_'):
                indirect_resolved_name = indirect_unified_names['display_name']
            
            raw_target_name = ida_name.get_name(indirect_target) or ""
            if (indirect_resolved_name in excluded_targets or
                raw_target_name in excluded_targets or
                raw_target_name.startswith("WPP_")):
                continue
            
            is_valid_indirect_call, indirect_call_confidence, indirect_validation_info = validate_function_call(
                item_ea, indirect_target, f"{xref_type_str} (Indirect)", indirect_resolved_name, indirect_info
            )
            
            if not is_valid_indirect_call:
                continue
            
            indirect_call_key = (indirect_target, f"{xref_type_str} (Indirect)", indirect_resolved_name)
            if indirect_call_key in processed_calls:
                continue
            processed_calls.add(indirect_call_key)
            
            final_func_type = indirect_func_type
            if indirect_info.get('confidence') == 'high' and final_func_type == FT_GEN:
                final_func_type = FT_MEM
            
            indirect_xref_data = {
                "source_instruction_ea": f"0x{item_ea:X}",
                "target_ea": f"0x{indirect_target:X}",
                "resolved_target_ea": f"0x{indirect_target:X}",
                "xref_type": f"{xref_type_str} (Indirect)",
                "function_name": indirect_resolved_name,
                "short_function_name": indirect_unified_names['short_name'],
                "function_name_short": indirect_unified_names['short_name'],
                "function_name_long": indirect_unified_names['long_name'],
                "function_name_mangled": indirect_unified_names['mangled_name'],
                "module_name": indirect_module_name,
                "function_type": final_func_type,
                "is_tail_call": False,
                "is_thunk_resolved": False,
                "is_indirect_call": True,
                "call_confidence": round(indirect_call_confidence, 2),
                "validation_checks": indirect_validation_info.get('validation_checks', []),
                "extraction_type": "unified_indirect",
                "indirect_call_info": {
                    "call_type": indirect_info.get('call_type', 'unknown'),
                    "confidence": indirect_info.get('confidence', 'low'),
                    "analysis_method": indirect_info.get('memory_type', indirect_info.get('object_type', 'dataflow'))
                }
            }
            
            if indirect_validation_info.get('warnings'):
                indirect_xref_data["validation_warnings"] = indirect_validation_info['warnings']
            
            xref_data["outbound_xrefs"].append(indirect_xref_data)
            
        except Exception as e:
            debug_print(f"ERROR - Error processing indirect target 0x{indirect_target:X}: {str(e)}")
            continue
    
    return True


def _process_jump_table_targets(item_ea, import_addresses, excluded_targets, function_being_analyzed, processed_calls, xref_data):
    """
    Process jump table targets and add them to xref data.
    
    Includes confidence scoring from jump table detection.
    
    :param item_ea: The instruction address
    :param import_addresses: Set of import addresses
    :param excluded_targets: Set of function names to exclude
    :param function_being_analyzed: The function object being analyzed
    :param processed_calls: Set to track processed calls (modified in-place)
    :param xref_data: Dictionary to store results (modified in-place)
    """
    try:
        if not is_indirect_jump_instruction(item_ea):
            return
        
        # Get jump table targets with confidence scoring
        jump_table_targets, jt_detection_confidence, jt_detection_info = analyze_jump_table(item_ea)
        
        # Skip if confidence is too low (likely false positive)
        if jt_detection_confidence < constants.MIN_JUMP_TABLE_CONFIDENCE:
            debug_print(f"TRACE - Skipping jump table at 0x{item_ea:X} due to low confidence "
                       f"({jt_detection_confidence:.1f}% < {constants.MIN_JUMP_TABLE_CONFIDENCE}%)")
            return
        
        for jump_target in jump_table_targets:
            try:
                if (jump_target, "Jump Table", "") in processed_calls:
                    continue
                
                jump_target_func = ida_funcs.get_func(jump_target)
                if jump_target_func and function_being_analyzed.start_ea == jump_target_func.start_ea:
                    continue
                
                resolved_jump_target = resolve_thunk_target(jump_target)
                jt_func_type, jt_module_name, jt_resolved_name = classify_function_type(resolved_jump_target, import_addresses)
                
                jt_unified_names = extract_unified_function_names(resolved_jump_target)
                
                if jt_unified_names['display_name'] and not jt_unified_names['display_name'].startswith('sub_'):
                    jt_resolved_name = jt_unified_names['display_name']
                elif not jt_resolved_name:
                    jt_resolved_name = f"jump_table_target_0x{jump_target:X}"
                
                # Use detection confidence in validation
                jt_confidence_info = {
                    'confidence': 'high' if jt_detection_confidence >= 80 else 'medium' if jt_detection_confidence >= 50 else 'low',
                    'detection_confidence': jt_detection_confidence,
                    'detection_method': jt_detection_info['method']
                }
                is_valid_jt_call, jt_call_confidence, jt_validation_info = validate_function_call(
                    item_ea, resolved_jump_target, "Jump Table", jt_resolved_name, jt_confidence_info
                )
                
                if not is_valid_jt_call:
                    continue
                
                jt_call_key = (jump_target, "Jump Table", jt_resolved_name)
                if jt_call_key in processed_calls:
                    continue
                processed_calls.add(jt_call_key)
                
                jump_table_xref_data = {
                    "source_instruction_ea": f"0x{item_ea:X}",
                    "target_ea": f"0x{jump_target:X}",
                    "resolved_target_ea": f"0x{resolved_jump_target:X}" if resolved_jump_target != jump_target else f"0x{jump_target:X}",
                    "xref_type": "Jump Table",
                    "function_name": jt_resolved_name,
                    "short_function_name": jt_unified_names['short_name'],
                    "function_name_short": jt_unified_names['short_name'],
                    "function_name_long": jt_unified_names['long_name'],
                    "function_name_mangled": jt_unified_names['mangled_name'],
                    "module_name": jt_module_name or "internal",
                    "function_type": jt_func_type if jt_func_type != FT_UNK else FT_GEN,
                    "is_tail_call": True,
                    "is_thunk_resolved": resolved_jump_target != jump_target,
                    "is_jump_table_target": True,
                    "call_confidence": round(jt_call_confidence, 2),
                    "validation_checks": jt_validation_info.get('validation_checks', []),
                    "extraction_type": "unified_jump_table",
                    "jump_table_detection_confidence": round(jt_detection_confidence, 2),
                    "jump_table_detection_method": jt_detection_info['method']
                }
                
                if resolved_jump_target != jump_target:
                    original_name = ida_name.get_name(jump_target) or f"jump_target_0x{jump_target:X}"
                    jump_table_xref_data["original_target_name"] = original_name
                
                if jt_validation_info.get('warnings'):
                    jump_table_xref_data["validation_warnings"] = jt_validation_info['warnings']
                
                xref_data["outbound_xrefs"].append(jump_table_xref_data)
                
            except Exception as e:
                debug_print(f"ERROR - Error processing jump table target 0x{jump_target:X}: {str(e)}")
        
    except Exception as e:
        debug_print(f"ERROR - Jump table analysis failed for 0x{item_ea:X}: {str(e)}")


def _process_regular_call(item_ea: int, target_addr: int, xref_type_str: str, 
                         import_addresses: Set[int], excluded_targets: Set[str], 
                         function_being_analyzed: Any, processed_calls: Set[Tuple[int, str, str]], 
                         xref_data: Dict[str, List[Any]]) -> None:
    """
    Process a regular (direct) function call.
    
    :param item_ea: The instruction address
    :param target_addr: The target address
    :param xref_type_str: The xref type string
    :param import_addresses: Set of import addresses
    :param excluded_targets: Set of function names to exclude
    :param function_being_analyzed: The function object being analyzed
    :param processed_calls: Set to track processed calls (modified in-place)
    :param xref_data: Dictionary to store results (modified in-place)
    """
    # Resolve thunk and classify
    resolved_target = resolve_thunk_target(target_addr)
    func_type, module_name, resolved_name = classify_function_type(resolved_target, import_addresses)
    
    unified_names = extract_unified_function_names(resolved_target)
    
    if unified_names['display_name'] and not unified_names['display_name'].startswith('sub_'):
        resolved_name = unified_names['display_name']
    elif not resolved_name or resolved_name.startswith("indirect_") or resolved_name.startswith("import_"):
        resolved_name = unified_names['display_name']
    
    if unified_names['module_name'] and not module_name:
        module_name = unified_names['module_name']
    
    # Final normalization
    resolved_name = _strip_import_prefix(resolved_name)
    module_host_name = module_name or "internal"
    module_name = constants.resolve_apiset(module_host_name)
    
    if func_type == FT_API and not module_name:
        module_name = get_module_name_from_import(target_addr)
    
    raw_target_name = ida_name.get_name(target_addr) or ""
    
    if (resolved_name in excluded_targets or
        raw_target_name in excluded_targets or
        raw_target_name.startswith("WPP_")):
        return
    
    # Detect tail calls
    is_tail_call = False
    target_func_of_xref = ida_funcs.get_func(target_addr)
    if xref_type_str.startswith("Jump") and target_func_of_xref:
        if (target_func_of_xref.start_ea == target_addr and
            target_func_of_xref.start_ea != function_being_analyzed.start_ea):
            is_tail_call = True
    
    # Create unique key
    call_key = (target_addr, xref_type_str, resolved_name)
    if call_key in processed_calls:
        return
    processed_calls.add(call_key)
    
    # Validate the function call
    is_valid_call, call_confidence, validation_info = validate_function_call(
        item_ea, resolved_target, xref_type_str, resolved_name
    )
    
    if not is_valid_call:
        return
    
    # Store detailed outbound xref data
    outbound_xref_data = {
        "source_instruction_ea": f"0x{item_ea:X}",
        "target_ea": f"0x{target_addr:X}",
        "resolved_target_ea": f"0x{resolved_target:X}" if resolved_target != target_addr else f"0x{target_addr:X}",
        "xref_type": xref_type_str,
        "function_name": resolved_name,
        "short_function_name": unified_names['short_name'],
        "function_name_short": unified_names['short_name'],
        "function_name_long": unified_names['long_name'],
        "function_name_mangled": unified_names['mangled_name'],
        "module_name": module_name,
        "module_host": module_host_name,
        "function_type": func_type,
        "is_tail_call": is_tail_call,
        "is_thunk_resolved": resolved_target != target_addr,
        "call_confidence": round(call_confidence, 2),
        "validation_checks": validation_info.get('validation_checks', []),
        "extraction_type": "unified_outbound"
    }
    
    if resolved_target != target_addr:
        original_name = ida_name.get_name(target_addr) or f"thunk_0x{target_addr:X}"
        outbound_xref_data["original_target_name"] = original_name
    
    if validation_info.get('warnings'):
        outbound_xref_data["validation_warnings"] = validation_info['warnings']
    
    xref_data["outbound_xrefs"].append(outbound_xref_data)


def _process_global_variable_access(target_addr, xref_type, processed_globals, xref_data):
    """
    Process a global variable read/write access.
    
    :param target_addr: The target address
    :param xref_type: The xref type (read or write)
    :param processed_globals: Set to track processed globals (modified in-place)
    :param xref_data: Dictionary to store results (modified in-place)
    :return: True if processed, False if skipped
    """
    seg = _cached_getseg(target_addr)
    if not seg or not (seg.perm & ida_segment.SEGPERM_READ) or (seg.perm & ida_segment.SEGPERM_EXEC):
        return False
    
    access_type = "Read" if xref_type == ida_xref.dr_R else "Write"
    global_key = (target_addr, access_type)
    
    if global_key in processed_globals:
        return False
    
    var_name = ida_name.get_name(target_addr) or f"0x{target_addr:X}"
    display_name = var_name
    
    try:
        if var_name and not var_name.startswith("0x"):
            stripped_name = _strip_import_prefix(var_name)
            demangled = ida_name.demangle_name(stripped_name, ida_name.MNG_SHORT_FORM)
            if demangled:
                display_name = _clean_method_signature(demangled.split('(')[0].strip())
            else:
                display_name = stripped_name
    except Exception:
        display_name = var_name
    
    xref_data["global_var_accesses"].append({
        "address": f"0x{target_addr:X}",
        "name": display_name,
        "access_type": access_type
    })
    processed_globals.add(global_key)
    return True


def _extract_outbound_xrefs(target_ea: int, import_addresses: Set[int], 
                           excluded_targets: Set[str], xref_data: Dict[str, List[Any]]) -> None:
    """
    Extract all outbound cross-references for a function.
    
    :param target_ea: The function address being analyzed
    :param import_addresses: Set of import addresses
    :param excluded_targets: Set of function names to exclude
    :param xref_data: Dictionary to store results (modified in-place)
    """
    function_being_analyzed = ida_funcs.get_func(target_ea)
    if not function_being_analyzed:
        return
    
    processed_globals = set()
    processed_calls = set()
    
    for item_ea in idautils.FuncItems(target_ea):
        for xref in idautils.XrefsFrom(item_ea):
            target_addr = xref.to
            
            # --- Global Variable Access Logic ---
            if xref.type == ida_xref.dr_R or xref.type == ida_xref.dr_W:
                if _process_global_variable_access(target_addr, xref.type, processed_globals, xref_data):
                    continue
            
            # --- Detailed Outbound Call/Jump Logic ---
            xref_type_str = map_xref_type_to_string(xref.type)
            
            if xref_type_str == "Ordinary Flow":
                continue
            
            # Check for recursive call
            target_func_of_xref = ida_funcs.get_func(target_addr)
            if target_func_of_xref and function_being_analyzed.start_ea == target_func_of_xref.start_ea:
                continue
            
            # Check for vtable calls
            if _process_vtable_call_targets(item_ea, target_addr, xref_type_str, import_addresses, processed_calls, xref_data):
                continue
            
            # Check for indirect calls
            if _process_indirect_call_targets(item_ea, target_addr, xref_type_str, import_addresses, excluded_targets, processed_calls, xref_data):
                continue
            
            # Regular call processing
            _process_regular_call(item_ea, target_addr, xref_type_str, import_addresses, excluded_targets, 
                                function_being_analyzed, processed_calls, xref_data)
        
        # --- Jump Table Analysis ---
        _process_jump_table_targets(item_ea, import_addresses, excluded_targets, function_being_analyzed, processed_calls, xref_data)


def extract_function_xrefs(function_ea):
    """
    Extracts full cross-reference data for a single function.
    
    This includes inbound/outbound references, vtable contexts, and global variable accesses.
    Refactored to use helper functions for better maintainability.

    :param function_ea: The starting effective address of the function.
    :return: Dictionary containing xref data.
    """
    debug_print(f"TRACE - Starting: extract_function_xrefs for 0x{function_ea:X}")
    start_time = time.time()
    
    try:
        # Build import address set for fast classification
        import_addresses = build_import_address_set()
        
        # Initialize result structure
        xref_data = _initialize_xref_data()
        
        # Get excluded targets
        excluded_targets = _get_excluded_targets()
        
        # Extract inbound cross-references and identify vtable candidates
        vtable_candidates = _extract_inbound_xrefs(function_ea, import_addresses, xref_data)
        
        # Extract vtable contexts from inbound references
        _extract_vtable_contexts_from_inbound(vtable_candidates, xref_data)
        
        # Extract outbound cross-references (includes calls, jumps, and global accesses)
        _extract_outbound_xrefs(function_ea, import_addresses, excluded_targets, xref_data)
        
        duration = time.time() - start_time
        debug_print(f"TRACE - Finished: extract_function_xrefs for 0x{function_ea:X}. Duration: {duration:.4f}s")
        return xref_data
        
    except Exception as e:
        import traceback
        debug_print(f"ERROR - Error in extract_function_xrefs: {str(e)}")
        debug_print(traceback.format_exc())
        return _initialize_xref_data()
