"""
Call validation and confidence scoring functions for PE binary analysis.

This module validates function calls, cross-references,
and control flow to reduce false positives in analysis results.
"""

import os
from typing import Dict, Tuple, Any, Optional, List
import ida_bytes
import ida_funcs
import ida_name
import ida_segment
import ida_idaapi
import ida_xref
import ida_ua
import ida_idp
import ida_typeinf
import idautils

from . import constants
from .logging_utils import debug_print, _cached_getseg, _cached_is_loaded


# Configurable minimum confidence threshold for call validation
# Enforce minimum floor to prevent validation bypass
MIN_VALIDATION_CONF_FLOOR = 10   # Never allow validation to be effectively disabled
MIN_VALIDATION_CONF_CEILING = 100

_MIN_VALID_CALL_CONF = float(os.getenv("CALL_VALIDATION_MIN_CONF", "30"))


# Import directly from constants module
from .constants import _strip_import_prefix


def set_min_validation_conf(conf: float) -> None:
    """
    Override global minimum confidence percentage for call validation.
    
    Enforces bounds to prevent validation bypass (min: 10%, max: 100%).
    Setting confidence below 10% would effectively disable validation and allow
    invalid cross-references to pollute the database.
    
    :param conf: The minimum confidence threshold (10-100)
    :raises ValueError: If conf is outside the valid range
    """
    global _MIN_VALID_CALL_CONF
    try:
        val = float(conf)
        
        # Enforce bounds to prevent validation bypass
        if val < MIN_VALIDATION_CONF_FLOOR:
            raise ValueError(
                f"Minimum validation confidence cannot be set below {MIN_VALIDATION_CONF_FLOOR}%. "
                f"Attempted to set to {val}%. This would effectively disable validation "
                f"and allow invalid cross-references into the database."
            )
        
        if val > MIN_VALIDATION_CONF_CEILING:
            raise ValueError(
                f"Minimum validation confidence cannot exceed {MIN_VALIDATION_CONF_CEILING}%. "
                f"Attempted to set to {val}%."
            )
        
        _MIN_VALID_CALL_CONF = val
        debug_print(f"[Config] Minimum call validation confidence set to {_MIN_VALID_CALL_CONF}% "
                   f"(valid range: {MIN_VALIDATION_CONF_FLOOR}-{MIN_VALIDATION_CONF_CEILING}%)")
        
    except ValueError:
        # Re-raise ValueError with original message
        raise
    except Exception as e:
        debug_print(f"ERROR - Invalid min validation conf '{conf}': {e}")
        raise ValueError(f"Failed to set validation confidence: {e}")


def validate_function_call(source_ea: int, target_ea: int, xref_type: str, 
                          resolved_name: str = "", confidence_info: Optional[Dict[str, Any]] = None) -> Tuple[bool, float, Dict[str, Any]]:
    """
    Validates whether a detected function call is legitimate and not a false positive.
    
    :param source_ea: The source instruction address
    :param target_ea: The target function address
    :param xref_type: The type of cross-reference
    :param resolved_name: The resolved function name
    :param confidence_info: Additional confidence information from analysis
    :return: Tuple of (is_valid, confidence_score, validation_info)
    """
    try:
        validation_info = {
            'validation_checks': [],
            'warnings': [],
            'confidence_factors': []
        }
        
        confidence_score = 0.0
        
        # 1. Basic instruction validation
        instruction_valid, inst_confidence = validate_instruction_context(source_ea, target_ea, xref_type)
        if instruction_valid:
            confidence_score += constants.VALIDATION_SCORES['instruction_context_valid']
            validation_info['validation_checks'].append('instruction_context_valid')
            validation_info['confidence_factors'].append(f'instruction_confidence: {inst_confidence}')
        else:
            validation_info['warnings'].append('suspicious_instruction_context')
            
        # 2. Target address validation
        target_valid, target_confidence = validate_target_address(target_ea)
        if target_valid:
            confidence_score += constants.VALIDATION_SCORES['target_address_valid']
            validation_info['validation_checks'].append('target_address_valid')
            validation_info['confidence_factors'].append(f'target_confidence: {target_confidence}')
        else:
            validation_info['warnings'].append('invalid_target_address')
            return False, 0.0, validation_info  # Critical failure
            
        # 3. Call flow validation
        flow_valid, flow_confidence = validate_call_flow(source_ea, target_ea, xref_type)
        if flow_valid:
            confidence_score += constants.VALIDATION_SCORES['call_flow_valid']
            validation_info['validation_checks'].append('call_flow_valid')
            validation_info['confidence_factors'].append(f'flow_confidence: {flow_confidence}')
        else:
            validation_info['warnings'].append('suspicious_call_flow')
            
        # 4. Function signature validation
        signature_valid, sig_confidence = validate_function_signature(target_ea, resolved_name)
        if signature_valid:
            confidence_score += constants.VALIDATION_SCORES['function_signature_valid']
            validation_info['validation_checks'].append('function_signature_valid')
            validation_info['confidence_factors'].append(f'signature_confidence: {sig_confidence}')
        else:
            validation_info['warnings'].append('suspicious_function_signature')
            
        # 5. Context consistency validation
        context_valid, ctx_confidence = validate_context_consistency(source_ea, target_ea, resolved_name)
        if context_valid:
            confidence_score += constants.VALIDATION_SCORES['context_consistent']
            validation_info['validation_checks'].append('context_consistent')
            validation_info['confidence_factors'].append(f'context_confidence: {ctx_confidence}')
        else:
            validation_info['warnings'].append('inconsistent_context')
            
        # 6. Apply confidence boosts from specialized analysis
        if confidence_info:
            analysis_confidence = confidence_info.get('confidence', 'low')
            if analysis_confidence == 'high':
                confidence_score += constants.VALIDATION_SCORES['high_confidence_analysis']
                validation_info['confidence_factors'].append('high_confidence_analysis')
            elif analysis_confidence == 'medium':
                confidence_score += constants.VALIDATION_SCORES['medium_confidence_analysis']
                validation_info['confidence_factors'].append('medium_confidence_analysis')
                
        # 7. Apply penalties for common false positive patterns
        fp_penalty = check_false_positive_patterns(source_ea, target_ea, resolved_name)
        confidence_score -= fp_penalty
        if fp_penalty > 0:
            validation_info['warnings'].append(f'false_positive_penalty: {fp_penalty}')
            
        # Normalize confidence score
        final_confidence = min(100.0, max(0.0, confidence_score))
        
        # Determine if call is valid based on configurable threshold
        threshold = _MIN_VALID_CALL_CONF
        is_valid = final_confidence >= threshold
        
        return is_valid, final_confidence, validation_info
        
    except Exception as e:
        import traceback
        debug_print(f"ERROR - Unexpected error validating function call "
                   f"(source=0x{source_ea:X}, target=0x{target_ea:X}, type={xref_type}): {e}")
        debug_print(traceback.format_exc())
        return False, 0.0, {'error': str(e)}


def validate_instruction_context(source_ea: int, target_ea: int, xref_type: str) -> Tuple[bool, str]:
    """
    Validates the instruction context around the call site.
    
    :param source_ea: Source instruction address
    :param target_ea: Target address
    :param xref_type: Cross-reference type
    :return: Tuple of (is_valid, confidence)
    """
    try:
        # Decode the instruction
        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, source_ea):
            return False, 'invalid_instruction'
            
        # Verify it's actually a call/jump instruction
        if not (ida_idp.is_call_insn(insn) or ida_idp.is_indirect_jump_insn(insn)):
            # Allow xref metadata to indicate a valid call/jump
            if 'Call' in xref_type or 'Jump' in xref_type:
                return True, 'xref_type_indicates_call'
            return False, 'not_call_instruction'
                
        # Check for suspicious instruction patterns
        # Example: calls in the middle of other instructions (overlapping code)
        if not ida_bytes.is_head(source_ea):
            return False, 'overlapping_instruction'
            
        # Check if the instruction is in a valid code segment
        seg = _cached_getseg(source_ea)
        if not seg or not (seg.perm & ida_segment.SEGPERM_EXEC):
            return False, 'not_in_executable_segment'
            
        return True, 'valid_instruction_context'
        
    except Exception as e:
        import traceback
        debug_print(f"ERROR - Error validating instruction context "
                   f"(source=0x{source_ea:X}, target=0x{target_ea:X}): {e}")
        debug_print(traceback.format_exc())
        return False, 'validation_error'


def validate_target_address(target_ea):
    """
    Validates that the target address is a legitimate function entry point.
    
    :param target_ea: Target address to validate
    :return: Tuple of (is_valid, confidence)
    """
    try:
        # Check if address is valid
        if target_ea == ida_idaapi.BADADDR or target_ea == 0:
            return False, 'invalid_address'
            
        # Check if target is in a valid segment
        seg = _cached_getseg(target_ea)
        if not seg:
            return False, 'not_in_segment'
            
        # For code targets, must be in executable segment
        if not (seg.perm & ida_segment.SEGPERM_EXEC):
            # Could be import table or data containing function pointer
            if seg.perm & ida_segment.SEGPERM_READ:
                return True, 'data_segment_function_pointer'
            else:
                return False, 'not_executable_or_readable'
                
        # Check if there's a function at this address
        func = ida_funcs.get_func(target_ea)
        if func and func.start_ea == target_ea:
            return True, 'function_start'
        elif func and target_ea > func.start_ea:
            # Target is in the middle of a function - might be valid for some cases
            return True, 'function_interior'
            
        # Check if it's the start of code
        flags = ida_bytes.get_flags(target_ea)
        if ida_bytes.is_code(flags):
            return True, 'code_location'
            
        # Check if it's a known import
        name = ida_name.get_name(target_ea)
        if name and (name.startswith('__imp_') or 'import' in name.lower()):
            return True, 'import_location'
            
        # If we get here, it might be a false positive
        return False, 'suspicious_target'
        
    except Exception as e:
        import traceback
        debug_print(f"ERROR - Error validating target address 0x{target_ea:X}: {e}")
        debug_print(traceback.format_exc())
        return False, 'validation_error'


def validate_call_flow(source_ea: int, target_ea: int, xref_type: str) -> Tuple[bool, str]:
    """
    Validates the call flow pattern and context.
    
    :param source_ea: Source instruction address
    :param target_ea: Target address
    :param xref_type: Cross-reference type
    :return: Tuple of (is_valid, confidence)
    """
    try:
        # Check for common call flow patterns
        
        # 1. Check for valid call/return patterns
        if 'Call' in xref_type:
            # For calls, check if the next instruction exists (return point)
            # IDA 7.7+ requires the upper bound parameter; BADADDR means no limit
            next_ea = ida_bytes.next_head(source_ea, ida_idaapi.BADADDR)
            if next_ea == ida_idaapi.BADADDR:
                return False, 'no_return_point'
                
        # 2. Check for reasonable distance for direct calls
        if 'Call Near' in xref_type or 'Jump Near' in xref_type:
            distance = abs(target_ea - source_ea)
            # Suspicious if call is to very nearby address (might be data)
            if distance < 5:
                return False, 'suspiciously_close_target'
            # Very far calls might be suspicious in some contexts
            if distance > constants.SUSPICIOUS_CALL_DISTANCE:  # 256MB
                return False, 'suspiciously_far_target'
                
        # 3. Check for recursive call patterns
        source_func = ida_funcs.get_func(source_ea)
        target_func = ida_funcs.get_func(target_ea)
        if source_func and target_func and source_func.start_ea == target_func.start_ea:
            return True, 'recursive_call'  # Recursive calls are valid
            
        # 4. Check for calls to known problematic areas
        if target_ea < constants.LOW_ADDRESS_THRESHOLD:  # Very low addresses are suspicious
            return False, 'low_address_target'
            
        return True, 'valid_call_flow'
        
    except Exception as e:
        debug_print(f"ERROR - Error validating call flow "
                   f"(source=0x{source_ea:X}, target=0x{target_ea:X}, type={xref_type}): {e}")
        return False, 'validation_error'


def validate_function_signature(target_ea, resolved_name):
    """
    Validates the function signature and naming consistency.
    
    :param target_ea: Target function address
    :param resolved_name: Resolved function name
    :return: Tuple of (is_valid, confidence)
    """
    try:
        # Check for obvious dummy/placeholder names
        dummy_patterns = [
            'sub_', 'loc_', 'off_', 'byte_', 'word_', 'dword_', 'qword_',
            'unk_', 'unknown_', 'nullsub', 'j_nullsub'
        ]
        
        if any(resolved_name.startswith(pattern) for pattern in dummy_patterns):
            # These are IDA-generated names, still valid but lower confidence
            return True, 'generated_name'
            
        # Check for Windows API naming patterns
        api_patterns = [
            'CreateFile', 'ReadFile', 'WriteFile', 'CloseHandle',
            'VirtualAlloc', 'VirtualFree', 'LoadLibrary', 'GetProcAddress',
            'Nt', 'Zw', 'Rtl'
        ]
        
        if any(pattern in resolved_name for pattern in api_patterns):
            return True, 'windows_api'
            
        # Check for C++ mangled names
        if (resolved_name.startswith('?') or 
            resolved_name.startswith('_Z') or
            '@@' in resolved_name):
            return True, 'mangled_name'
            
        # Check for import names
        if resolved_name.startswith('__imp_') or 'import' in resolved_name.lower():
            return True, 'import_name'
            
        # Check function type information if available
        func = ida_funcs.get_func(target_ea)
        if func:
            # Try to get type information
            tif = ida_typeinf.tinfo_t()
            if ida_typeinf.guess_tinfo(tif, target_ea):
                if tif.is_func():
                    return True, 'has_type_info'
                    
        return True, 'basic_name_validation'
        
    except Exception as e:
        import traceback
        debug_print(f"ERROR - Error validating function signature: {e}")
        debug_print(traceback.format_exc())
        return False, 'validation_error'


def validate_context_consistency(source_ea: int, target_ea: int, resolved_name: str) -> Tuple[bool, str]:
    """
    Validates consistency of the call within its context.
    
    :param source_ea: Source instruction address
    :param target_ea: Target address
    :param resolved_name: Resolved function name
    :return: Tuple of (is_valid, confidence)
    """
    try:
        # Check for context clues around the call site
        
        # 1. Check if call is in a reasonable function context
        source_func = ida_funcs.get_func(source_ea)
        if not source_func:
            return False, 'source_not_in_function'
            
        # 2. Check for string references that might validate the call
        # Look for strings near the call that might be related to the target function
        search_range = constants.CONTEXT_SEARCH_RANGE  # Instructions to search around the call
        start_ea = max(source_func.start_ea, source_ea - search_range * 4)
        end_ea = min(source_func.end_ea, source_ea + search_range * 4)
        
        # Heuristic check; deeper analysis could inspect richer data-flow context
        for ea in range(start_ea, end_ea, 4):
            if ida_bytes.is_head(ea):
                for xref in idautils.XrefsFrom(ea):
                    if ida_bytes.is_strlit(ida_bytes.get_flags(xref.to)):
                        # Found a string reference nearby - this adds context confidence
                        return True, 'nearby_string_context'
                        
        # 3. Check for API call patterns
        if resolved_name:
            # If this looks like a Windows API call, check for typical patterns
            if any(api in resolved_name for api in ['CreateFile', 'RegOpenKey', 'GetModuleHandle']):
                # Look for typical setup patterns before API calls
                return True, 'api_call_pattern'
                
        return True, 'basic_context_validation'
        
    except Exception as e:
        debug_print(f"ERROR - Error validating context consistency "
                   f"(source=0x{source_ea:X}, target=0x{target_ea:X}): {e}")
        return False, 'validation_error'


def check_false_positive_patterns(source_ea, target_ea, resolved_name):
    """
    Checks for common false positive patterns and returns a penalty score.
    
    :param source_ea: Source instruction address
    :param target_ea: Target address  
    :param resolved_name: Resolved function name
    :return: Penalty score (0-50)
    """
    try:
        penalty = 0
        
        # 1. Check for calls to obvious data locations
        if resolved_name and any(pattern in resolved_name for pattern in ['byte_', 'word_', 'dword_', 'unk_data']):
            penalty += constants.VALIDATION_PENALTIES['obvious_data_location']
            
        # 2. Check for suspicious target addresses
        if target_ea % 4 != 0:  # Unaligned addresses are suspicious for function calls
            penalty += constants.VALIDATION_PENALTIES['unaligned_address']
            
        # 3. Check for calls to very small "functions"
        target_func = ida_funcs.get_func(target_ea)
        if target_func:
            func_size = target_func.end_ea - target_func.start_ea
            if func_size < 5:  # Very small functions might be data
                penalty += constants.VALIDATION_PENALTIES['very_small_function']
                
        # 4. Check for calls to areas with no code
        if not ida_bytes.is_code(ida_bytes.get_flags(target_ea)):
            penalty += constants.VALIDATION_PENALTIES['no_code_at_target']
            
        # 5. Check for repetitive patterns that might indicate data
        # This is a heuristic - if we see the same "call" target many times
        # it might actually be data being interpreted as code
        
        return min(50, penalty)  # Cap penalty at 50
        
    except Exception as e:
        import traceback
        debug_print(f"ERROR - Error checking false positive patterns: {e}")
        debug_print(traceback.format_exc())
        return 0


def validate_and_normalize_xref_data(xref_data: Dict[str, Any], data_type: str = "unknown") -> Dict[str, Any]:
    """
    Validates and normalizes cross-reference data for consistency across all processing paths.
    
    This function ensures uniform field naming, data types, and API-set resolution
    across all xref data structures.
    
    :param xref_data: Dictionary containing xref data to validate
    :param data_type: Type of data being validated (inbound/outbound/vtable/indirect/jump_table)
    :return: Normalized and validated xref data
    """
    try:
        # Ensure required fields are present with default values
        required_fields = {
            'extraction_type': data_type,
            'call_confidence': 50.0,
            'validation_checks': [],
            'validation_warnings': []
        }
        
        for field, default_value in required_fields.items():
            if field not in xref_data:
                xref_data[field] = default_value
        
        # Normalize numeric fields
        if 'call_confidence' in xref_data:
            try:
                xref_data['call_confidence'] = round(float(xref_data['call_confidence']), 2)
            except (ValueError, TypeError):
                xref_data['call_confidence'] = 50.0
        
        # Ensure all name fields are strings and properly processed
        name_fields = ['function_name', 'short_function_name', 'function_name_short', 
                      'function_name_long', 'function_name_mangled']
        for field in name_fields:
            if field in xref_data:
                if xref_data[field] is None:
                    xref_data[field] = ""
                else:
                    # Ensure it's a string and apply consistent post-processing
                    xref_data[field] = str(xref_data[field])
                    try:
                        xref_data[field] = _strip_import_prefix(xref_data[field])
                    except Exception:
                        pass  # Keep original if stripping fails
        
        # Normalize module names and apply API-set resolution consistently
        if 'module_name' in xref_data and xref_data['module_name']:
            try:
                # Store original module name if not already stored
                if 'module_host' not in xref_data:
                    xref_data['module_host'] = xref_data['module_name']
                
                # Apply API-set resolution
                resolved_module = constants.resolve_apiset(xref_data['module_name'])
                if resolved_module != xref_data['module_name']:
                    xref_data['module_name'] = resolved_module
                    
            except Exception as e:
                debug_print(f"WARNING - Module name normalization failed: {str(e)}")
        
        # Ensure boolean fields are proper booleans
        boolean_fields = ['is_code', 'is_tail_call', 'is_thunk_resolved', 'is_vtable_candidate',
                         'is_vtable_call', 'is_indirect_call', 'is_jump_table_target']
        for field in boolean_fields:
            if field in xref_data:
                if isinstance(xref_data[field], str):
                    xref_data[field] = xref_data[field].lower() in ('true', '1', 'yes')
                else:
                    xref_data[field] = bool(xref_data[field])
        
        # Ensure lists are properly formatted
        list_fields = ['validation_checks', 'validation_warnings']
        for field in list_fields:
            if field in xref_data:
                if not isinstance(xref_data[field], list):
                    xref_data[field] = []
        
        return xref_data
        
    except Exception as e:
        import traceback
        data_type_info = f"type={data_type}" if data_type else "type=unknown"
        debug_print(f"ERROR - Error validating xref data ({data_type_info}): {str(e)}")
        debug_print(traceback.format_exc())
        return xref_data  # Return original data if validation fails
