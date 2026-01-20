"""
PE header, Rich header, TLS callbacks, and file metadata extraction.

This module handles PE file parsing, including imports, exports,
entry points, version information, Rich headers, TLS callbacks, and runtime metadata.
"""

# Standard library imports
import hashlib
import os
import struct
import time
import traceback
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple

# Third-party imports (IDA Pro)
import ida_auto
import ida_bytes
import ida_entry
import ida_funcs
import ida_ida
import ida_idaapi
import ida_loader
import ida_name
import ida_nalt
import ida_segment
import ida_ua
import idaapi
import idautils
import idc

# Local imports
from . import constants
from .logging_utils import debug_print, safe_decode, _cached_getseg, _cached_is_loaded

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


def get_raw_function_name(ea: int) -> str:
    """Forward reference to name_extraction module."""
    from .name_extraction import get_raw_function_name as _get_fn
    return _get_fn(ea)


def get_raw_long_function_name(mangled_name_str: str) -> Tuple[Optional[str], Optional[str]]:
    """Forward reference to name_extraction module."""
    from .name_extraction import get_raw_long_function_name as _get_long_fn
    return _get_long_fn(mangled_name_str)


def extract_detailed_function_names(ea: int) -> Dict[str, str]:
    """Forward reference to name_extraction module."""
    from .name_extraction import extract_detailed_function_names as _extract_names
    return _extract_names(ea)


def extract_imports() -> List[Dict[str, Any]]:
    """
    Extracts all imported functions from the binary's import address table (IAT).

    It iterates through each imported module (DLL) and enumerates all functions
    imported from it, returning a structured list of modules and their functions.
    Includes API-set resolution and improved function name cleaning.
    :return: A list of dictionaries, where each dictionary represents an imported
             module and contains a list of its imported functions with both raw
             and resolved module names.
    """
    debug_print("TRACE - Starting: extract_imports")
    start_time = time.time()
    imports = []
    try:
        nimps = ida_nalt.get_import_module_qty()
        debug_print(f"Found {nimps} import modules")

        for i in range(nimps):
            module_name = ida_nalt.get_import_module_name(i)
            if not module_name:
                module_name = "unknown_module"

            if isinstance(module_name, bytes):
                module_name = safe_decode(module_name)

            # Ensure module name ends with .dll (case-insensitive)
            if not module_name.lower().endswith('.dll'):
                 module_name += ".dll"

            # Store the original (raw) module name
            raw_module_name = module_name
            
            # Resolve API-set DLLs to actual implementing DLLs
            resolved_module_name = constants.resolve_apiset(module_name)
            
            # Determine if this is an API-set module
            is_api_set = resolved_module_name != raw_module_name

            module_imports = []
            debug_print(f"Processing import module: {raw_module_name}" + 
                       (f" -> {resolved_module_name}" if is_api_set else ""))

            def imp_cb(ea, name, ordinal):
                if not name:
                    name = ida_name.get_name(ea)

                if not name:
                    # Validate ordinal before using it
                    if ordinal is not None and isinstance(ordinal, int):
                        name = f"ord_{ordinal}"
                    else:
                        name = f"unknown_import_0x{ea:X}"

                # Ensure name is a string before demangling
                name_str = name if isinstance(name, str) else str(name)
                if isinstance(name_str, bytes):
                    name_str = safe_decode(name_str)

                # Apply enhanced function name cleaning (strip import prefixes including _o_)
                cleaned_name = constants._strip_import_prefix(name_str)

                short_demangled_name, long_demangled_name = get_raw_long_function_name(cleaned_name)

                # If demangling failed, use the cleaned name
                if not short_demangled_name:
                    short_demangled_name = cleaned_name
                if not long_demangled_name:
                    long_demangled_name = cleaned_name

                import_info = {
                    "address": f"0x{ea:X}",
                    "mangled_name": cleaned_name,
                    "raw_name": name_str,
                    "function_name": safe_decode(short_demangled_name),
                    "function_signature_extended": safe_decode(long_demangled_name),
                    "ordinal": ordinal,
                    "is_delay_loaded": False
                }
                module_imports.append(import_info)
                return True

            ida_nalt.enum_import_names(i, imp_cb)

            # Create module entry
            module_entry = {
                "module_name": resolved_module_name,
                "raw_module_name": raw_module_name,
                "is_api_set": is_api_set,
                "resolved_module": resolved_module_name if is_api_set else None,
                "functions": module_imports
            }
            
            imports.append(module_entry)

        debug_print(f"Finished extracting {len(imports)} import modules")
    except Exception as e:
        nimps_attempted = ida_nalt.get_import_module_qty() if 'nimps' not in locals() else nimps
        debug_print(f"ERROR - Error during import extraction (processed {len(imports)}/{nimps_attempted} modules): {str(e)}")
        debug_print(traceback.format_exc())
    
    duration = time.time() - start_time
    debug_print(f"TRACE - Finished: extract_imports. Duration: {duration:.4f}s")
    return imports


def extract_exports() -> List[Dict[str, Any]]:
    """
    Extracts all exported functions from the binary's export table.

    It iterates through the entry points in IDA and gathers information about each
    exported function, including its name, address, and ordinal. It also handles
    forwarded exports.
    :return: A list of dictionaries, where each represents an exported function.
    """
    debug_print("TRACE - Starting: extract_exports")
    start_time = time.time()
    exports = []
    try:
        for i, entry_data in enumerate(idautils.Entries()):
            index, ordinal, ea, name = entry_data

            if not name:
                name = ida_name.get_name(ea)

            if not name:
                # Validate ordinal before using it
                if ordinal is not None and isinstance(ordinal, int):
                    name = f"ord_{ordinal}"
                else:
                    name = f"export_{index}"

            # Ensure name is a string before demangling
            name_str = name if isinstance(name, str) else str(name)
            if isinstance(name_str, bytes):
                 name_str = safe_decode(name_str)


            short_demangled_name, long_demangled_name = get_raw_long_function_name(name_str)

            # Check for forwarded export using the correct API
            is_forwarded = False
            forwarded_to = ""
            forwarder_data = ida_entry.get_entry_forwarder(ordinal)
            if forwarder_data:
                is_forwarded = True
                forwarded_to = safe_decode(forwarder_data)

            export_info = {
                "index": index,
                "address": f"0x{ea:X}",
                "mangled_name": name_str,
                "function_name": safe_decode(short_demangled_name),
                "function_signature_extended": safe_decode(long_demangled_name),
                "ordinal": ordinal,
                "is_forwarded": is_forwarded
            }

            if is_forwarded:
                export_info["forwarded_to"] = forwarded_to

            exports.append(export_info)

        debug_print(f"Finished extracting {len(exports)} exports")
    except Exception as e:
        debug_print(f"ERROR - Error during export extraction (processed {len(exports)} exports, "
                   f"last processed: {exports[-1] if exports else 'none'}): {str(e)}")
        debug_print(traceback.format_exc())
    
    duration = time.time() - start_time
    debug_print(f"TRACE - Finished: extract_exports. Duration: {duration:.4f}s")
    return exports


def extract_entry_point():
    """
    Extracts the main entry point function name from the PE file.

    This function finds the primary entry point of the executable using the
    multi-method detection pipeline for consistent results.
    :return: A string containing the main entry point function name, or None if not found/invalid.
    """
    debug_print("TRACE - Starting: extract_entry_point")
    start_time = time.time()
    entry_point_name = None
    
    try:
        entry_points = extract_all_entry_points_with_methods()
        if not entry_points:
            debug_print("No entry points detected.")
            return None

        primary_entry = next((ep for ep in entry_points if ep.get('is_primary')), None)
        if not primary_entry:
            primary_entry = entry_points[0]

        entry_ea = primary_entry.get('address_int')
        if entry_ea is None:
            entry_ea_str = primary_entry.get('address', '0x0')
            entry_ea = int(entry_ea_str, 16) if isinstance(entry_ea_str, str) and entry_ea_str.startswith('0x') else int(entry_ea_str)

        if entry_ea != idaapi.BADADDR and entry_ea > 0 and _validate_entry_point_address(entry_ea):
            entry_point_name = primary_entry.get('function_name') or get_raw_function_name(entry_ea)
            if not entry_point_name:
                entry_point_name = f"entry_{entry_ea:X}"
            debug_print(f"Entry point function: {entry_point_name}")
        else:
            debug_print("No valid entry point found in the binary")
            
    except Exception as e:
        debug_print(f"ERROR - Error during entry point extraction: {str(e)}")
        debug_print(traceback.format_exc())
    
    duration = time.time() - start_time
    debug_print(f"TRACE - Finished: extract_entry_point. Duration: {duration:.4f}s")
    return entry_point_name


def extract_all_entry_points() -> List[Dict[str, Any]]:
    """
    Extracts ALL entry points from the PE file, including main entry and all exports.
    :return: A list of dictionaries containing entry point information.
    """
    debug_print("TRACE - Starting: extract_all_entry_points")
    start_time = time.time()
    entry_points = []
    
    try:
        entry_qty = ida_entry.get_entry_qty()
        debug_print(f"Found {entry_qty} total entry points (including exports)")
        
        for i in range(entry_qty):
            try:
                entry_ordinal = ida_entry.get_entry_ordinal(i)
                
                if entry_ordinal != idaapi.BADADDR:
                    entry_ea = ida_entry.get_entry(entry_ordinal)
                    
                    if entry_ea != idaapi.BADADDR:
                        entry_name = ida_entry.get_entry_name(entry_ordinal)
                        func = ida_funcs.get_func(entry_ea)
                        
                        if func:
                            func_name = ida_funcs.get_func_name(func.start_ea)
                            mangled_name = func_name
                            function_signature_extended = None
                            if func_name:
                                function_signature_extended = ida_name.demangle_name(func_name, ida_name.MNG_LONG_FORM)
                        else:
                            func_name = f"entry_{entry_ea:X}"
                            mangled_name = func_name
                            function_signature_extended = None
                        
                        entry_info = {
                            "index": i,
                            "ordinal": entry_ordinal,
                            "address": f"0x{entry_ea:X}",
                            "entry_name": entry_name or "",
                            "mangled_name": mangled_name or f"sub_{entry_ea:X}",
                            "function_name": func_name or f"sub_{entry_ea:X}",
                            "function_signature_extended": function_signature_extended,
                            "is_primary": i == 0
                        }
                        
                        entry_points.append(entry_info)
                        
                        if i == 0:
                            debug_print(f"Primary entry point: {function_signature_extended or func_name} at 0x{entry_ea:X}")
                            
            except Exception as e:
                entry_ea_str = f"0x{entry_ea:X}" if 'entry_ea' in locals() and entry_ea != ida_idaapi.BADADDR else "unknown"
                debug_print(f"ERROR - Error processing entry point {i} (ordinal={entry_ordinal}, ea={entry_ea_str}): {str(e)}")
                continue
                
    except Exception as e:
        debug_print(f"ERROR - Error during entry points extraction: {str(e)}")
        debug_print(traceback.format_exc())
    
    duration = time.time() - start_time
    debug_print(f"TRACE - Finished: extract_all_entry_points. Found {len(entry_points)} entry points. Duration: {duration:.4f}s")
    return entry_points


def extract_all_entry_points_with_methods():
    """
    Extracts ALL entry points using multiple detection methods with confidence scoring.
    :return: A list of dictionaries containing entry point information with detection metadata.
    """
    debug_print("TRACE - Starting: extract_all_entry_points_with_methods")
    start_time = time.time()
    
    all_entry_points = []
    detected_pairs = set()
    detected_addresses = set()
    primary_entry_found = False

    def _add_entry_if_new(entry_ea, method, details, confidence, is_primary_candidate=False):
        nonlocal primary_entry_found
        if entry_ea is None or entry_ea == idaapi.BADADDR or entry_ea <= 0:
            return

        if (entry_ea, method) in detected_pairs:
            return

        if not _validate_entry_point_address(entry_ea):
            debug_print(f"Skipping invalid entry point 0x{entry_ea:X} from {details}")
            return

        # Ensure function is defined
        if not ida_funcs.get_func(entry_ea):
            try:
                ida_funcs.add_func(entry_ea)
                ida_auto.plan_and_wait(entry_ea)
            except Exception as func_err:
                debug_print(f"WARNING - Could not auto-create function at 0x{entry_ea:X}: {func_err}")

        detected_pairs.add((entry_ea, method))
        detected_addresses.add(entry_ea)

        is_primary = False
        if is_primary_candidate and not primary_entry_found:
            is_primary = True
            primary_entry_found = True

        name_info = extract_detailed_function_names(entry_ea)
        ordinal = -1
        index = -1
        
        # Try to find matching entry for ordinal/index
        for i in range(ida_entry.get_entry_qty()):
            current_ord = ida_entry.get_entry_ordinal(i)
            if ida_entry.get_entry(current_ord) == entry_ea:
                ordinal = current_ord
                index = i
                break

        function_name = ""
        entry_name = ""
        mangled_name = ""
        function_signature_extended = ""
        
        if name_info and name_info.get('display_name'):
            function_name = name_info['display_name']
            function_signature_extended = name_info.get('long_name', '')
            mangled_name = name_info.get('mangled_name', '')
            entry_name = mangled_name
        
        if not function_name:
            function_name = f"entry_point_0x{entry_ea:X}"
            entry_name = function_name
            mangled_name = function_name

        entry = {
            "address": f"0x{entry_ea:X}",
            "address_int": entry_ea,
            "detection_method": method,
            "method_details": details,
            "confidence": float(confidence),
            "is_primary": is_primary,
            "entry_name": entry_name,
            "mangled_name": mangled_name,
            "function_name": function_name,
            "function_signature_extended": function_signature_extended,
            "ordinal": ordinal,
            "index": index,
            "is_validated": True,
            "detection_success": True,
            "detection_errors": []
        }
        all_entry_points.append(entry)

    try:
        # Strategy 1: IDA Entry Point API
        debug_print("Method 1: Using IDA Entry Point API...")
        try:
            ida_entries = extract_all_entry_points()
            for i, entry in enumerate(ida_entries):
                address = int(entry.get('address', '0x0'), 16)
                _add_entry_if_new(address, "ida_entry_api", "IDA Entry Point API", 95, is_primary_candidate=(i == 0))
        except Exception as e:
            debug_print(f"WARNING - IDA Entry Point API failed: {str(e)}")

        # Strategy 2: Direct PE header access
        debug_print("Method 2: Using direct PE header access...")
        pe_header_methods = [
            ("ida_ida.inf_get_start_ip()", lambda: ida_ida.inf_get_start_ip() if hasattr(ida_ida, 'inf_get_start_ip') else None),
            ("idc.get_inf_attr(INF_START_IP)", lambda: _rebase_pe_entry_point(idc.get_inf_attr(idc.INF_START_IP)) if hasattr(idc, 'INF_START_IP') else None),
            ("idc.get_inf_attr(3)", lambda: _rebase_pe_entry_point(idc.get_inf_attr(3)))
        ]

        for name, method_func in pe_header_methods:
            try:
                entry_ea = method_func()
                if entry_ea:
                    _add_entry_if_new(entry_ea, "pe_header_direct", f"Direct PE header via {name}", 90, is_primary_candidate=True)
            except Exception as e:
                debug_print(f"INFO - PE header method {name} failed: {e}")

        all_entry_points.sort(key=lambda x: (not x.get('is_primary', False), -x.get('confidence', 0), x.get('address_int', 0)))
        
    except Exception as e:
        debug_print(f"ERROR - Error during entry point extraction "
                   f"(found {len(all_entry_points)} entry points so far, "
                   f"primary_found={primary_entry_found}): {str(e)}")
        debug_print(traceback.format_exc())
    
    duration = time.time() - start_time
    debug_print(f"TRACE - Finished: extract_all_entry_points_with_methods. Found {len(all_entry_points)} detections. Duration: {duration:.4f}s")
    return all_entry_points


def extract_version_info(pe: Any) -> Dict[str, str]:
    """
    Extracts file version information from the PE file's resources.

    :param pe: An initialized pefile.PE object.
    :return: A dictionary containing the extracted version information.
    """
    debug_print("TRACE - Starting: extract_version_info")
    start_time = time.time()
    
    standard_keys = [
        'FileVersion', 'ProductVersion', 'CompanyName', 'FileDescription',
        'InternalName', 'OriginalFilename', 'LegalCopyright', 'ProductName'
    ]
    version_info = {key: "" for key in standard_keys}

    try:
        if hasattr(pe, 'VS_VERSIONINFO') and hasattr(pe, 'FileInfo') and len(pe.FileInfo) > 0:
            for file_info_entry in pe.FileInfo[0]:
                if hasattr(file_info_entry, 'StringTable'):
                    for string_table_entry in file_info_entry.StringTable:
                        for key, value in string_table_entry.entries.items():
                            decoded_key = safe_decode(key)
                            if decoded_key in version_info:
                                version_info[decoded_key] = safe_decode(value)

        # Get fixed version info
        if hasattr(pe, 'VS_FIXEDFILEINFO'):
            if pe.VS_FIXEDFILEINFO and len(pe.VS_FIXEDFILEINFO) > 0:
                fixed_info = pe.VS_FIXEDFILEINFO[0]
                
                if fixed_info.FileVersionMS > 0 or fixed_info.FileVersionLS > 0:
                    version_info['FileVersion'] = f"{fixed_info.FileVersionMS >> 16}.{fixed_info.FileVersionMS & 0xFFFF}.{fixed_info.FileVersionLS >> 16}.{fixed_info.FileVersionLS & 0xFFFF}"
                if fixed_info.ProductVersionMS > 0 or fixed_info.ProductVersionLS > 0:
                    version_info['ProductVersion'] = f"{fixed_info.ProductVersionMS >> 16}.{fixed_info.ProductVersionMS & 0xFFFF}.{fixed_info.ProductVersionLS >> 16}.{fixed_info.ProductVersionLS & 0xFFFF}"

    except Exception as e:
        debug_print(f"ERROR - Exception during version info extraction: {str(e)}")
        debug_print(traceback.format_exc())

    duration = time.time() - start_time
    debug_print(f"TRACE - Finished: extract_version_info. Duration: {duration:.4f}s")
    return version_info


def extract_pe_metadata(pe):
    """
    Extracts metadata from the PE file header including sections, PDB path, timestamp,
    and security-relevant loader information.
    
    Added to include:
    - DllCharacteristics flags (ASLR, DEP, CFG, etc.)
    - Control Flow Guard (CFG) information
    - SafeSEH configuration  
    - Exception directory presence
    - Additional loader security features

    :param pe: An initialized pefile.PE object.
    :return: A dictionary containing the extracted PE metadata.
    """
    debug_print("TRACE - Starting: extract_pe_metadata")
    start_time = time.time()
    metadata = {
        "sections": [],
        "pdb_path": None,
        "time_date_stamp_str": None,
        "dll_characteristics": {},
        "security_features": {},
        "exception_info": {}
    }
    try:
        # Extract DllCharacteristics (security and loader flags)
        if hasattr(pe, 'OPTIONAL_HEADER') and hasattr(pe.OPTIONAL_HEADER, 'DllCharacteristics'):
            dll_char = pe.OPTIONAL_HEADER.DllCharacteristics
            metadata["dll_characteristics"] = {
                "raw_value": f"0x{dll_char:04X}",
                "DYNAMIC_BASE": bool(dll_char & 0x0040),  # ASLR
                "FORCE_INTEGRITY": bool(dll_char & 0x0080),  # Code integrity checks
                "NX_COMPAT": bool(dll_char & 0x0100),  # DEP/NX
                "NO_ISOLATION": bool(dll_char & 0x0200),  # No isolation
                "NO_SEH": bool(dll_char & 0x0400),  # No SEH
                "NO_BIND": bool(dll_char & 0x0800),  # No binding
                "APPCONTAINER": bool(dll_char & 0x1000),  # App container
                "WDM_DRIVER": bool(dll_char & 0x2000),  # WDM driver
                "GUARD_CF": bool(dll_char & 0x4000),  # Control Flow Guard
                "TERMINAL_SERVER_AWARE": bool(dll_char & 0x8000)  # Terminal server aware
            }
        
        # Extract security features summary
        dll_char_dict = metadata.get("dll_characteristics", {})
        metadata["security_features"] = {
            "aslr_enabled": dll_char_dict.get("DYNAMIC_BASE", False),
            "dep_enabled": dll_char_dict.get("NX_COMPAT", False),
            "cfg_enabled": dll_char_dict.get("GUARD_CF", False),
            "seh_enabled": not dll_char_dict.get("NO_SEH", True),
            "code_integrity": dll_char_dict.get("FORCE_INTEGRITY", False),
            "isolated": not dll_char_dict.get("NO_ISOLATION", False)
        }
        
        # Extract exception directory information
        try:
            if hasattr(pe, 'OPTIONAL_HEADER') and hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY'):
                # Exception directory is entry 3
                if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 3:
                    exception_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
                    metadata["exception_info"] = {
                        "present": exception_dir.VirtualAddress != 0,
                        "virtual_address": f"0x{exception_dir.VirtualAddress:X}",
                        "size": exception_dir.Size
                    }
                    
                    # SafeSEH is indicated by exception directory in 32-bit binaries
                    if exception_dir.VirtualAddress != 0 and not ida_ida.inf_is_64bit():
                        metadata["security_features"]["safeseh_present"] = True
        except Exception as e:
            debug_print(f"WARNING - Failed to extract exception directory: {str(e)}")
        
        # Extract Load Config directory (contains CFG tables, SEH info, etc.)
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
                load_config = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
                metadata["load_config"] = {
                    "present": True,
                    "size": load_config.Size if hasattr(load_config, 'Size') else None,
                    "se_handler_table": f"0x{load_config.SEHandlerTable:X}" if hasattr(load_config, 'SEHandlerTable') else None,
                    "se_handler_count": load_config.SEHandlerCount if hasattr(load_config, 'SEHandlerCount') else None,
                    "guard_cf_check_function": f"0x{load_config.GuardCFCheckFunctionPointer:X}" if hasattr(load_config, 'GuardCFCheckFunctionPointer') else None,
                    "guard_cf_dispatch": f"0x{load_config.GuardCFDispatchFunctionPointer:X}" if hasattr(load_config, 'GuardCFDispatchFunctionPointer') else None,
                    "guard_flags": f"0x{load_config.GuardFlags:X}" if hasattr(load_config, 'GuardFlags') else None
                }
                
                # Update security features based on load config
                if hasattr(load_config, 'SEHandlerCount') and load_config.SEHandlerCount > 0:
                    metadata["security_features"]["safeseh_handlers"] = load_config.SEHandlerCount
                
                if hasattr(load_config, 'GuardCFCheckFunctionPointer') and load_config.GuardCFCheckFunctionPointer != 0:
                    metadata["security_features"]["cfg_check_function_present"] = True
        except AttributeError:
            # Load config not present (not unusual for older binaries)
            pass
        except Exception as e:
            debug_print(f"WARNING - Failed to extract load config: {str(e)}")
        
        # Extract TimeDateStamp
        if hasattr(pe, 'FILE_HEADER') and hasattr(pe.FILE_HEADER, 'TimeDateStamp'):
            try:
                timestamp = pe.FILE_HEADER.TimeDateStamp
                dt_object = datetime.fromtimestamp(timestamp)
                metadata["time_date_stamp_str"] = dt_object.strftime("%Y-%m-%d %H:%M:%S")
            except Exception as e:
                debug_print(f"Could not parse TimeDateStamp: {e}")

        # Extract Section Information
        for sec in pe.sections:
            sec_info = {
                "name": safe_decode(sec.Name).rstrip('\x00'),
                "virtual_address": f"0x{sec.VirtualAddress:X}",
                "virtual_size": sec.Misc_VirtualSize,
                "raw_size": sec.SizeOfRawData,
                "characteristics": f"0x{sec.Characteristics:X}",
                "readable": bool(sec.Characteristics & 0x40000000),
                "writable": bool(sec.Characteristics & 0x80000000),
                "executable": bool(sec.Characteristics & 0x20000000)
            }
            metadata["sections"].append(sec_info)

        # Extract PDB Path
        try:
            pdb_path_ida = ida_loader.get_path(ida_loader.PATH_TYPE_PDB)
            if pdb_path_ida:
                metadata["pdb_path"] = pdb_path_ida
                return metadata
        except AttributeError:
            pass

        # Try legacy API
        try:
            pdb_path_ida = ida_nalt.get_pdb_path()
            if pdb_path_ida:
                metadata["pdb_path"] = pdb_path_ida
                return metadata
        except AttributeError:
            pass

        # Fallback to pefile parsing
        if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
            for entry_idx, entry in enumerate(pe.DIRECTORY_ENTRY_DEBUG):
                if entry.struct.Type == pefile.DEBUG_TYPE['IMAGE_DEBUG_TYPE_CODEVIEW']:
                    try:
                        cv_data = pe.get_data(entry.struct.AddressOfRawData, entry.struct.SizeOfData)
                        pdb_path_bytes = None
                        if cv_data and cv_data.startswith(b'RSDS'):
                            pdb_path_bytes = cv_data[24:]
                        elif cv_data and cv_data.startswith(b'NB10'):
                            pdb_path_bytes = cv_data[8:]

                        if pdb_path_bytes:
                            pdb_path = pdb_path_bytes.split(b'\x00', 1)[0]
                            metadata["pdb_path"] = safe_decode(pdb_path)
                            break
                    except pefile.PEFormatError as e:
                         debug_print(f"ERROR - Could not get debug data from entry {entry_idx} "
                                   f"(AddressOfRawData=0x{entry.struct.AddressOfRawData:X}, "
                                   f"SizeOfData={entry.struct.SizeOfData}): {e}")

    except Exception as e:
        debug_print(f"ERROR - Exception during PE metadata extraction: {str(e)}")
        debug_print(traceback.format_exc())

    duration = time.time() - start_time
    debug_print(f"TRACE - Finished: extract_pe_metadata. Duration: {duration:.4f}s")
    return metadata


def extract_advanced_pe_info(pe: Any, has_decompiler: bool, force_reanalyze: bool = False) -> Dict[str, Any]:
    """
    Extracts advanced PE information such as Rich Header and TLS callbacks.

    :param pe: An initialized pefile.PE object.
    :param has_decompiler: Boolean indicating if Hex-Rays decompiler is available.
    :param force_reanalyze: If True, forces decompiler re-analysis.
    :return: Dictionary containing advanced PE information.
    """
    debug_print("TRACE - Starting: extract_advanced_pe_info")
    start_time = time.time()
    advanced_info = {
        "rich_header": {},
        "tls_callbacks": []
    }
    try:
        # Added Rich Header extraction
        try:
            rich_header_info = _extract_detailed_rich_header(pe)
            if rich_header_info:
                advanced_info['rich_header'] = rich_header_info
        except Exception as e:
            debug_print(f"Failed to extract Rich Header: {str(e)}")

        # TLS Callbacks extraction
        try:
            tls_callbacks_info = _extract_tls_callbacks_metadata(pe)
            advanced_info['tls_callbacks'] = tls_callbacks_info
            if tls_callbacks_info:
                debug_print(f"Successfully extracted {len(tls_callbacks_info)} TLS callbacks.")
        except Exception as e:
            debug_print(f"Failed to extract TLS callbacks: {str(e)}")
            advanced_info['tls_callbacks'] = []

    except Exception as e:
        debug_print(f"ERROR - Exception during advanced PE metadata extraction: {str(e)}")
        debug_print(traceback.format_exc())
    
    duration = time.time() - start_time
    debug_print(f"TRACE - Finished: extract_advanced_pe_info. Duration: {duration:.4f}s")
    
    advanced_info = _ensure_json_serializable(advanced_info)
    return advanced_info


def _ensure_json_serializable(obj):
    """
    Recursively ensures all data is JSON-serializable.
    
    Added to handle additional types including datetime, Decimal, complex numbers,
    numpy arrays, and custom IDA types.
    
    :param obj: The object to make JSON-serializable.
    :return: A JSON-serializable version of the object.
    """
    # Handle None and basic types first (most common case)
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    
    # Handle collections
    if isinstance(obj, dict):
        return {k: _ensure_json_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [_ensure_json_serializable(item) for item in obj]
    elif isinstance(obj, set):
        return [_ensure_json_serializable(item) for item in sorted(obj, key=str)]
    
    # Handle bytes
    elif isinstance(obj, bytes):
        return obj.hex().upper()
    elif isinstance(obj, bytearray):
        return bytes(obj).hex().upper()
    
    # Handle datetime objects
    elif isinstance(obj, datetime):
        return obj.isoformat()
    
    # Handle Decimal (for precise numeric values)
    try:
        from decimal import Decimal
        if isinstance(obj, Decimal):
            # Convert to float for JSON, or string for exact precision
            return float(obj)
    except ImportError:
        pass
    
    # Handle complex numbers
    if isinstance(obj, complex):
        return {"real": obj.real, "imag": obj.imag, "_type": "complex"}
    
    # Handle numpy arrays (if numpy is available)
    try:
        import numpy as np
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, (np.integer, np.floating)):
            return obj.item()
        elif isinstance(obj, np.bool_):
            return bool(obj)
    except ImportError:
        pass
    except Exception:
        # If numpy operations fail, continue to other handlers
        pass
    
    # Handle custom IDA types
    try:
        # IDA Pro types that might appear in metadata
        if hasattr(obj, '__class__') and obj.__class__.__module__.startswith('ida_'):
            # Try to extract relevant attributes
            if hasattr(obj, 'value'):
                return _ensure_json_serializable(obj.value)
            elif hasattr(obj, '__int__'):
                return int(obj)
            elif hasattr(obj, '__str__'):
                return str(obj)
    except Exception:
        pass
    
    # Handle objects with __dict__ (custom classes)
    if hasattr(obj, '__dict__'):
        try:
            # Try to serialize the object's dictionary
            return _ensure_json_serializable(obj.__dict__)
        except Exception:
            return str(obj)
    
    # Handle enums
    try:
        from enum import Enum
        if isinstance(obj, Enum):
            return obj.value
    except ImportError:
        pass
    
    # Fallback to string representation
    try:
        return str(obj)
    except Exception:
        return f"<unserializable: {type(obj).__name__}>"


def _extract_detailed_rich_header(pe):
    """
    Extracts Rich Header information.
    
    :param pe: An initialized pefile.PE object.
    :return: Dictionary containing Rich Header data or None.
    """
    rich_header_info = {
        "present": False,
        "valid": False,
        "checksum": None,
        "raw_data_hex": None,
        "tools": [],
        "total_objects": 0,
        "unique_tools": 0,
        "extraction_method": None,
        "errors": []
    }

    try:
        # Method 1: Modern pefile API
        if hasattr(pe, 'get_rich_header_hash'):
            try:
                rich_hash = pe.get_rich_header_hash()
                if rich_hash and hasattr(pe, 'rich_header') and pe.rich_header:
                    rich_header_info["present"] = True
                    rich_header_info["extraction_method"] = "pefile_new_api"
                    rich_header_info["checksum"] = rich_hash
                    
                    if hasattr(pe.rich_header, 'clear_data'):
                        clear_data = pe.rich_header.clear_data
                        if isinstance(clear_data, bytes):
                            rich_header_info["raw_data_hex"] = clear_data.hex().upper()
                    
                    if hasattr(pe.rich_header, 'entries') and pe.rich_header.entries:
                        tools_list = []
                        total_objects = 0
                        unique_tools = set()
                        
                        for entry in pe.rich_header.entries:
                            tool_info = {
                                "product_id": getattr(entry, 'id', 0),
                                "build_number": getattr(entry, 'build', 0),
                                "object_count": getattr(entry, 'count', 0),
                                "tool_name": _get_rich_tool_name(getattr(entry, 'id', 0)),
                                "combined_id": (getattr(entry, 'id', 0) << 16) | getattr(entry, 'build', 0)
                            }
                            tools_list.append(tool_info)
                            total_objects += tool_info["object_count"]
                            unique_tools.add(tool_info["product_id"])
                        
                        rich_header_info["tools"] = tools_list
                        rich_header_info["total_objects"] = total_objects
                        rich_header_info["unique_tools"] = len(unique_tools)
                        rich_header_info["valid"] = True
                    
                    return rich_header_info
            except Exception as e:
                rich_header_info["errors"].append(f"New API failed: {str(e)}")

        # Method 2: Legacy pefile API
        if hasattr(pe, 'RICH_HEADER') and pe.RICH_HEADER:
            try:
                rich_header_info["present"] = True
                rich_header_info["extraction_method"] = "pefile_old_api"
                
                if hasattr(pe.RICH_HEADER, 'checksum'):
                    rich_header_info["checksum"] = pe.RICH_HEADER.checksum
                elif hasattr(pe.RICH_HEADER, 'key'):
                    rich_header_info["checksum"] = pe.RICH_HEADER.key
                
                if hasattr(pe.RICH_HEADER, 'entries') and pe.RICH_HEADER.entries:
                    tools_list = []
                    total_objects = 0
                    unique_tools = set()
                    
                    for entry in pe.RICH_HEADER.entries:
                        if hasattr(entry, 'id') and hasattr(entry, 'build') and hasattr(entry, 'count'):
                            tool_info = {
                                "product_id": entry.id,
                                "build_number": entry.build,
                                "object_count": entry.count,
                                "tool_name": _get_rich_tool_name(entry.id),
                                "combined_id": (entry.id << 16) | entry.build
                            }
                            tools_list.append(tool_info)
                            total_objects += tool_info["object_count"]
                            unique_tools.add(tool_info["product_id"])
                    
                    rich_header_info["tools"] = tools_list
                    rich_header_info["total_objects"] = total_objects
                    rich_header_info["unique_tools"] = len(unique_tools)
                    rich_header_info["valid"] = True
                
                return rich_header_info
            except Exception as e:
                rich_header_info["errors"].append(f"Old API failed: {str(e)}")

        # Method 3: Manual parsing
        try:
            manual_rich = _parse_rich_header_manually(pe)
            if manual_rich:
                rich_header_info.update(manual_rich)
                rich_header_info["extraction_method"] = "manual_parsing"
                return rich_header_info
        except Exception as e:
            rich_header_info["errors"].append(f"Manual parsing failed: {str(e)}")

    except Exception as e:
        rich_header_info["errors"].append(f"General error: {str(e)}")

    return rich_header_info if rich_header_info["present"] else None


def _get_rich_tool_name(product_id):
    """
    Maps Rich Header product IDs to tool names.
    
    :param product_id: The product ID from Rich Header entry.
    :return: Human-readable tool name.
    """
    tool_mapping = {
        0x00: "Unknown",
        0x01: "Linker",
        0x5E: "C/C++ (1400) - VS2005",
        0x60: "LINK (1400) - VS2005",
        0x6D: "C/C++ (1500) - VS2008",
        0x6F: "LINK (1500) - VS2008",
        0x7A: "C/C++ (1600) - VS2010",
        0x7C: "LINK (1600) - VS2010",
        0x82: "C/C++ (1700) - VS2012",
        0x84: "LINK (1700) - VS2012",
        0x8C: "C/C++ (1800) - VS2013",
        0x8E: "LINK (1800) - VS2013",
        0x90: "C/C++ (1900) - VS2015",
        0x92: "LINK (1900) - VS2015",
        0x9A: "C/C++ (1910) - VS2017",
        0x9C: "LINK (1910) - VS2017",
        0xA2: "C/C++ (1912-1916) - VS2017.6-9",
        0xA4: "LINK (1912-1916) - VS2017.6-9",
        0x93: "C/C++ (1920-1929) - VS2019 (Compiler)",
        0x83: "LINK (1920-1929) - VS2019 (Linker)",
        0xAA: "C/C++ (1930+) - VS2022",
        0xAC: "LINK (1930+) - VS2022"
    }
    
    base_name = tool_mapping.get(product_id, f"Unknown_Tool_{product_id:02X}")
    
    if "C/C++" in base_name and "(Compiler)" not in base_name:
        return f"{base_name} (Compiler)"
    elif "LINK" in base_name and "(Linker)" not in base_name:
        return f"{base_name} (Linker)"
    
    return base_name


def _parse_rich_header_manually(pe):
    """
    Manually parses Rich Header from PE raw data as fallback.
    
    Handles common error cases such as:
    - Corrupted headers
    - Non-standard XOR keys
    - Truncated data
    - Invalid offsets
    
    :param pe: An initialized pefile.PE object.
    :return: Dictionary with Rich Header data or None.
    """
    rich_info = {
        "present": False,
        "valid": False,
        "signature_offset": None,
        "checksum": None,
        "errors": [],
        "warnings": []
    }
    
    try:
        # Validate PE object has raw data
        if not hasattr(pe, '__data__'):
            rich_info["errors"].append("PE object missing __data__ attribute")
            return rich_info
        
        pe_data = pe.__data__
        if not pe_data or len(pe_data) < 100:
            rich_info["errors"].append("PE data too small to contain Rich header")
            return rich_info
        
        # Search for Rich signature
        rich_signature = b'Rich'
        rich_pos = pe_data.find(rich_signature)
        
        if rich_pos == -1:
            # Not an error - some PEs don't have Rich headers (legitimate)
            return rich_info
        
        # Found Rich signature
        rich_info["present"] = True
        rich_info["signature_offset"] = rich_pos
        
        # Validate we have enough data for checksum
        if rich_pos + 8 > len(pe_data):
            rich_info["errors"].append(f"Rich header at offset {rich_pos} is truncated "
                                      f"(need 8 bytes, have {len(pe_data) - rich_pos})")
            return rich_info
        
        try:
            # Extract checksum
            checksum_bytes = pe_data[rich_pos + 4:rich_pos + 8]
            if len(checksum_bytes) != 4:
                rich_info["errors"].append(f"Checksum bytes incomplete: got {len(checksum_bytes)}, need 4")
                return rich_info
            
            checksum = struct.unpack('<I', checksum_bytes)[0]
            rich_info["checksum"] = checksum
            
            # Validate checksum is non-zero (zero is suspicious)
            if checksum == 0:
                rich_info["warnings"].append("Rich header checksum is zero (unusual)")
            
            rich_info["valid"] = True
            
            # Try to find DanS signature (start of Rich header)
            dans_signature = b'DanS'
            dans_pos = pe_data.rfind(dans_signature, 0, rich_pos)
            
            if dans_pos != -1:
                rich_info["dans_offset"] = dans_pos
                rich_info["header_size"] = rich_pos - dans_pos + 8
                
                # Try to extract and decode entries
                try:
                    # Rich header is XOR'ed with the checksum
                    xor_key = checksum
                    
                    # Data between DanS and Rich is the encoded data
                    encoded_data = pe_data[dans_pos + 16:rich_pos]  # Skip DanS + padding
                    
                    if len(encoded_data) % 8 != 0:
                        rich_info["warnings"].append(f"Encoded data length {len(encoded_data)} not multiple of 8")
                    
                    # Decode entries (format: product_id+build << 16 | count)
                    entries = []
                    for i in range(0, len(encoded_data), 8):
                        if i + 8 <= len(encoded_data):
                            try:
                                comp_id_bytes = struct.unpack('<I', encoded_data[i:i+4])[0]
                                count_bytes = struct.unpack('<I', encoded_data[i+4:i+8])[0]
                                
                                # XOR decode
                                comp_id = comp_id_bytes ^ xor_key
                                count = count_bytes ^ xor_key
                                
                                # Extract product_id and build
                                product_id = (comp_id >> 16) & 0xFFFF
                                build = comp_id & 0xFFFF
                                
                                entries.append({
                                    "product_id": product_id,
                                    "build": build,
                                    "count": count
                                })
                            except Exception as entry_error:
                                rich_info["warnings"].append(f"Failed to decode entry at offset {i}: {str(entry_error)}")
                    
                    if entries:
                        rich_info["entries"] = entries
                        rich_info["entry_count"] = len(entries)
                    
                except Exception as decode_error:
                    rich_info["warnings"].append(f"Failed to decode Rich header data: {str(decode_error)}")
            else:
                rich_info["warnings"].append("DanS signature not found before Rich (unusual but not critical)")
        
        except struct.error as e:
            rich_info["errors"].append(f"Struct unpacking failed: {str(e)}")
        except Exception as e:
            rich_info["errors"].append(f"Checksum extraction failed: {str(e)}")
        
        return rich_info
        
    except Exception as e:
        import traceback
        rich_info["errors"].append(f"Manual parsing exception: {str(e)}")
        debug_print(f"ERROR - Rich header manual parsing failed: {str(e)}")
        debug_print(traceback.format_exc())
        return rich_info


def _extract_tls_callbacks_metadata(pe):
    """
    Extracts TLS callback metadata and function names.
    
    :param pe: An initialized pefile.PE object.
    :return: List of TLS callback metadata dictionaries.
    """
    tls_callbacks = []
    
    try:
        if not (hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks):
            return tls_callbacks
        
        debug_print("Found TLS Directory.")
        callback_array_va = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
        
        if not callback_array_va:
            return tls_callbacks
        
        # Get image bases for address translation
        pe_image_base = pe.OPTIONAL_HEADER.ImageBase
        ida_image_base = ida_nalt.get_imagebase()
        
        # Convert to EA in IDA's address space
        callback_array_ea = (callback_array_va - pe_image_base) + ida_image_base
        
        ptr_size = 8 if ida_ida.inf_is_64bit() else 4
        read_ptr = ida_bytes.get_qword if ptr_size == 8 else ida_bytes.get_dword
        
        i = 0
        MAX_TLS_CALLBACKS = constants.MAX_TLS_CALLBACKS
        
        while i < MAX_TLS_CALLBACKS:
            callback_ptr_ea = callback_array_ea + i * ptr_size
            
            if not _cached_is_loaded(callback_ptr_ea):
                break
            
            callback_va = read_ptr(callback_ptr_ea)
            if callback_va == 0:
                break
            
            callback_ea = (callback_va - pe_image_base) + ida_image_base
            debug_print(f"Found TLS callback VA 0x{callback_va:X}, EA 0x{callback_ea:X}")
            
            callback_info = _extract_single_tls_callback_metadata(callback_ea, i)
            if callback_info:
                tls_callbacks.append(callback_info)
            
            i += 1
        
        if i >= MAX_TLS_CALLBACKS:
            debug_print(f"WARNING - Maximum TLS callback limit ({MAX_TLS_CALLBACKS}) reached.")
    
    except Exception as e:
        callback_va_str = f"0x{callback_array_va:X}" if 'callback_array_va' in locals() else "unknown"
        debug_print(f"ERROR - Error extracting TLS callbacks (callback_array_va={callback_va_str}, "
                   f"extracted {len(tls_callbacks)} callbacks so far): {str(e)}")
        debug_print(traceback.format_exc())
    
    return tls_callbacks


def _extract_single_tls_callback_metadata(callback_ea, index):
    """
    Extracts metadata for a single TLS callback.
    
    :param callback_ea: The EA of the TLS callback function.
    :param index: The index of this callback in the TLS array.
    :return: Dictionary containing callback metadata.
    """
    callback_info = {
        "index": index,
        "address": f"0x{callback_ea:X}",
        "rva": None,
        "function_name": None,
        "mangled_name": None,
        "demangled_name": None,
        "is_function": False,
        "function_size": 0,
        "segment_name": None,
        "segment_permissions": None,
        "has_name": False,
        "extraction_errors": []
    }
    
    try:
        # Calculate RVA
        ida_base = ida_nalt.get_imagebase()
        callback_info["rva"] = callback_ea - ida_base
        
        # Get segment information
        seg = _cached_getseg(callback_ea)
        if seg:
            callback_info["segment_name"] = ida_segment.get_segm_name(seg)
            callback_info["segment_permissions"] = {
                "read": bool(seg.perm & ida_segment.SEGPERM_READ),
                "write": bool(seg.perm & ida_segment.SEGPERM_WRITE),
                "execute": bool(seg.perm & ida_segment.SEGPERM_EXEC)
            }
        
        # Ensure IDA recognizes this as a function
        func = ida_funcs.get_func(callback_ea)
        if not func:
            if ida_funcs.add_func(callback_ea):
                func = ida_funcs.get_func(callback_ea)
        
        if func:
            callback_info["is_function"] = True
            callback_info["function_size"] = func.end_ea - func.start_ea
            
            # Extract function names
            try:
                name_info = extract_detailed_function_names(callback_ea)
                if name_info:
                    callback_info["function_name"] = name_info.get('display_name', '')
                    callback_info["mangled_name"] = name_info.get('mangled_name', '')
                    callback_info["demangled_name"] = name_info.get('long_name', '')
                    callback_info["has_name"] = bool(name_info.get('display_name'))
                
                if not callback_info["function_name"]:
                    callback_info["function_name"] = f"TlsCallback_{index}_{callback_ea:X}"
                    callback_info["mangled_name"] = callback_info["function_name"]
            
            except Exception as e:
                callback_info["extraction_errors"].append(f"Name extraction failed: {str(e)}")
                callback_info["function_name"] = f"TlsCallback_{index}_{callback_ea:X}"
        else:
            callback_info["extraction_errors"].append("Could not create function definition")
            callback_info["function_name"] = f"TlsCallback_{index}_{callback_ea:X}"
        
        # Added security metadata and pattern detection
        callback_info["ida_flags"] = ida_bytes.get_flags(callback_ea)
        callback_info["is_code"] = ida_bytes.is_code(callback_info["ida_flags"])
        callback_info["has_xrefs"] = bool(list(idautils.XrefsTo(callback_ea, 0)))
        callback_info["has_strings"] = False
        callback_info["has_crypto_constants"] = False
        callback_info["has_api_calls"] = False
        callback_info["has_anti_debug"] = False
        callback_info["suspicious_patterns"] = []
        
        # Detailed security scan for suspicious patterns
        if func:
            try:
                string_count = 0
                api_call_count = 0
                anti_debug_api_count = 0
                timing_check_count = 0
                crypto_patterns = constants.CRYPTO_CONSTANTS
                anti_debug_apis = constants.ANTI_DEBUG_APIS
                suspicious_apis_found = []
                
                # Import xref module once
                import ida_xref
                
                ea = func.start_ea
                while ea < func.end_ea and ea != ida_idaapi.BADADDR:
                    insn = ida_ua.insn_t()
                    if ida_ua.decode_insn(insn, ea):
                        # Check for crypto constants in immediate operands
                        for i in range(8):  # Check up to 8 operands
                            op = insn.ops[i]
                            if op.type == 0:  # o_void - end of operands
                                break
                            if op.type == ida_ua.o_imm and op.value in crypto_patterns:
                                callback_info["has_crypto_constants"] = True
                                callback_info["suspicious_patterns"].append(f"crypto_constant_0x{op.value:X}_at_0x{ea:X}")
                                break
                    
                    # Check for strings
                    for xref in idautils.XrefsFrom(ea, 0):
                        # String references
                        if ida_bytes.is_strlit(ida_bytes.get_flags(xref.to)):
                            string_count += 1
                        
                        # Check for API calls (especially anti-debug ones)
                        if xref.type in [ida_xref.fl_CN, ida_xref.fl_CF]:
                            api_call_count += 1
                            
                            # Get API name
                            api_name = ida_name.get_name(xref.to)
                            if api_name:
                                api_name_lower = api_name.lower()
                                
                                # Strip common prefixes
                                for prefix in ['__imp_', '_imp_', '__imp_load_', '_o_']:
                                    if api_name_lower.startswith(prefix):
                                        api_name_lower = api_name_lower[len(prefix):]
                                        break
                                
                                # Check against anti-debug API list
                                if api_name_lower in anti_debug_apis:
                                    anti_debug_api_count += 1
                                    suspicious_apis_found.append(api_name)
                                    callback_info["has_anti_debug"] = True
                                
                                # Check for timing-based anti-debug
                                if api_name_lower in ['queryperformancecounter', 'gettickcount', 'gettickcount64']:
                                    timing_check_count += 1
                    
                    next_ea = ida_bytes.next_head(ea, func.end_ea)
                    # Break if next_head returns BADADDR or same/previous address to prevent infinite loop
                    if next_ea == ida_idaapi.BADADDR or next_ea <= ea:
                        break
                    ea = next_ea
                
                callback_info["has_strings"] = string_count > 0
                callback_info["has_api_calls"] = api_call_count > 0
                callback_info["string_count"] = string_count
                callback_info["api_call_count"] = api_call_count
                callback_info["anti_debug_api_count"] = anti_debug_api_count
                callback_info["timing_check_count"] = timing_check_count
                
                if suspicious_apis_found:
                    callback_info["anti_debug_apis_found"] = suspicious_apis_found
                
                # Pattern-based suspicion scoring
                if anti_debug_api_count > 0:
                    callback_info["suspicious_patterns"].append(f"anti_debug_apis_{anti_debug_api_count}_calls")
                
                if timing_check_count >= 2:
                    callback_info["suspicious_patterns"].append("multiple_timing_checks_may_indicate_debugger_detection")
                
                if callback_info.get("has_crypto_constants") and anti_debug_api_count > 0:
                    callback_info["suspicious_patterns"].append("crypto_and_anti_debug_combination_highly_suspicious")
                
            except Exception as e:
                callback_info["extraction_errors"].append(f"Security analysis failed: {str(e)}")
        
        # Added analysis notes with security implications
        callback_info["analysis_notes"] = []
        
        if callback_info.get("has_crypto_constants"):
            callback_info["analysis_notes"].append("Contains potential cryptographic constants (encryption/decryption in TLS)")
        
        if callback_info.get("has_anti_debug"):
            severity = "HIGH" if callback_info.get("anti_debug_api_count", 0) >= 3 else "MEDIUM"
            callback_info["analysis_notes"].append(f"[{severity}] Contains anti-debugging APIs - possible evasion technique")
        
        if callback_info.get("timing_check_count", 0) >= 2:
            callback_info["analysis_notes"].append("[MEDIUM] Multiple timing checks detected - may use timing-based debugger detection")
        
        if not callback_info.get("has_name") and callback_info.get("is_function"):
            callback_info["analysis_notes"].append("[INFO] Function has no symbolic name (stripped or obfuscated)")
        
        if callback_info.get("function_size", 0) > 10000:
            callback_info["analysis_notes"].append("[INFO] Large function size may indicate complexity or obfuscation")
        
        # High-risk pattern combinations
        if (callback_info.get("has_crypto_constants") and 
            callback_info.get("has_anti_debug") and 
            not callback_info.get("has_name")):
            callback_info["analysis_notes"].append("[CRITICAL] Combination of crypto, anti-debug, and no symbols - highly suspicious TLS callback")
        
        # Threat level assessment
        threat_score = 0
        if callback_info.get("has_anti_debug"):
            threat_score += 30
        if callback_info.get("has_crypto_constants"):
            threat_score += 20
        if not callback_info.get("has_name"):
            threat_score += 10
        if callback_info.get("timing_check_count", 0) >= 2:
            threat_score += 15
        if callback_info.get("function_size", 0) > 10000:
            threat_score += 10
        
        callback_info["threat_score"] = threat_score
        if threat_score >= 50:
            callback_info["threat_level"] = "HIGH"
        elif threat_score >= 30:
            callback_info["threat_level"] = "MEDIUM"
        elif threat_score >= 15:
            callback_info["threat_level"] = "LOW"
        else:
            callback_info["threat_level"] = "MINIMAL"
        
    except Exception as e:
        callback_info["extraction_errors"].append(f"General error: {str(e)}")
        debug_print(f"ERROR - Error extracting TLS callback metadata for 0x{callback_ea:X}: {str(e)}")
    
    return callback_info


def extract_runtime_info(pe):
    """
    Extracts runtime-specific information including delay-load imports and .NET metadata.

    :param pe: An initialized pefile.PE object.
    :return: Dictionary containing runtime info.
    """
    debug_print("TRACE - Starting: extract_runtime_info")
    start_time = time.time()
    runtime_info = {
        "delay_load_imports": [],
        "is_net_assembly": False,
        "clr_metadata": {}
    }
    try:
        # Extract Delay-Load Imports
        if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
            debug_print("Found Delay-Load Import Directory.")
            for dll in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                raw_module_name = safe_decode(dll.dll)
                resolved_module_name = constants.resolve_api_set(raw_module_name)
                is_api_set = resolved_module_name != raw_module_name
                
                module_imports = {
                    "module_name": resolved_module_name,
                    "raw_module_name": raw_module_name,
                    "is_api_set": is_api_set,
                    "resolved_module": resolved_module_name if is_api_set else None,
                    "functions": []
                }
                for imp in dll.imports:
                    if imp.name:
                        name_str = safe_decode(imp.name)
                    else:
                        name_str = f"ord_{imp.ordinal}" if imp.ordinal else f"unknown_delay_import"
                    
                    # Demangle names for consistency with regular imports
                    short_demangled_name, long_demangled_name = get_raw_long_function_name(name_str)
                    
                    # If demangling failed, use the original name
                    if not short_demangled_name:
                        short_demangled_name = name_str
                    if not long_demangled_name:
                        long_demangled_name = name_str
                    
                    import_info = {
                        "address": None,  # Delay-load imports don't have fixed addresses until loaded
                        "mangled_name": name_str,
                        "function_name": safe_decode(short_demangled_name),
                        "function_signature_extended": safe_decode(long_demangled_name),
                        "ordinal": imp.ordinal,
                        "is_delay_loaded": True
                    }
                    module_imports["functions"].append(import_info)
                runtime_info["delay_load_imports"].append(module_imports)

        # Check for .NET Assembly
        if hasattr(pe, 'DIRECTORY_ENTRY_COM_DESCRIPTOR'):
            runtime_info["is_net_assembly"] = True
            debug_print("Detected .NET Assembly.")
            if hasattr(pe.DIRECTORY_ENTRY_COM_DESCRIPTOR, 'struct'):
                cor20_header = pe.DIRECTORY_ENTRY_COM_DESCRIPTOR.struct
                runtime_info["clr_metadata"] = {
                    "major_runtime_version": cor20_header.MajorRuntimeVersion,
                    "minor_runtime_version": cor20_header.MinorRuntimeVersion,
                    "flags": f"0x{cor20_header.Flags:X}",
                    "entry_point_token": f"0x{cor20_header.EntryPointToken:X}"
                }

    except Exception as e:
        debug_print(f"ERROR - Exception during runtime info extraction: {str(e)}")
        debug_print(traceback.format_exc())
            
    duration = time.time() - start_time
    debug_print(f"TRACE - Finished: extract_runtime_info. Duration: {duration:.4f}s")
    return runtime_info


def calculate_file_hashes(file_path: str) -> Optional[Dict[str, str]]:
    """
    Calculates the MD5 and SHA256 hashes of a file.

    :param file_path: The absolute path to the file.
    :return: Dictionary with 'md5' and 'sha256' hashes, or None on failure.
    """
    debug_print(f"TRACE - Starting: calculate_file_hashes for {file_path}")
    start_time = time.time()
    try:
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
                
        hashes = {
            'md5': md5_hash.hexdigest(),
            'sha256': sha256_hash.hexdigest()
        }
        duration = time.time() - start_time
        debug_print(f"TRACE - Finished: calculate_file_hashes. Duration: {duration:.4f}s")
        return hashes
    except Exception as e:
        debug_print(f"ERROR - Error calculating file hashes for '{file_path}': {str(e)}")
        return None


def _rebase_pe_entry_point(raw_rva):
    """
    Converts a raw RVA from PE header to proper VA in IDA's memory space.
    
    :param raw_rva: The raw relative virtual address or already-rebased EA
    :return: A valid EA or BADADDR if cannot be resolved
    """
    try:
        if raw_rva in (None, 0, idaapi.BADADDR):
            return idaapi.BADADDR

        # If already a loaded address, return it
        if _cached_is_loaded(raw_rva):
            return raw_rva

        # Otherwise treat as RVA and add image base
        image_base = ida_nalt.get_imagebase()
        entry_ea = image_base + raw_rva

        if not _cached_is_loaded(entry_ea):
            debug_print(f"WARNING - Rebasing failed, computed EA 0x{entry_ea:X} not mapped")
            return idaapi.BADADDR

        debug_print(f"Rebasing PE entry point: RVA 0x{raw_rva:X} + ImageBase 0x{image_base:X} = VA 0x{entry_ea:X}")
        return entry_ea

    except Exception as e:
        debug_print(f"WARNING - Failed to rebase PE entry point 0x{raw_rva:X}: {str(e)}")
        return idaapi.BADADDR


def _validate_entry_point_address(entry_ea: int) -> bool:
    """
    Helper function to validate an entry point address.
    
    :param entry_ea: The entry point address to validate
    :return: True if valid, False otherwise
    """
    try:
        if entry_ea == idaapi.BADADDR or entry_ea <= 0:
            return False
            
        # Check if in valid segment
        seg = _cached_getseg(entry_ea)
        if not seg:
            return False
            
        # Check if segment is executable
        if not (seg.perm & ida_segment.SEGPERM_EXEC):
            return False
            
        return True
    except Exception:
        return False

