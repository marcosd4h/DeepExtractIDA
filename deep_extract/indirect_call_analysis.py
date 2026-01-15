"""
Indirect call and jump table resolution for PE binary analysis.

This module resolves indirect calls,
jump tables, and computed addressing modes through data flow analysis.
"""

from typing import Dict, List, Optional, Any, Tuple, Set
import ida_bytes
import ida_funcs
import ida_segment
import ida_idaapi
import ida_ida
import ida_nalt
import ida_ua
import ida_idp
import ida_lines
import idautils
try:
    import ida_allins
except ImportError:
    # Fallback for older IDA versions
    import idaapi as ida_allins
try:
    import ida_gdl
except ImportError:
    ida_gdl = None

from . import constants
from .logging_utils import debug_print, _cached_getseg
from .vtable_analysis import is_valid_function_pointer
from .thunk_analysis import resolve_thunk_target

# Import inter-procedural analysis (optional, graceful fallback if not available)
try:
    from .interprocedural_analysis import (
        resolve_indirect_call_interprocedural,
        INTERPROCEDURAL_MAX_DEPTH
    )
    HAS_INTERPROCEDURAL = True
except ImportError:
    HAS_INTERPROCEDURAL = False
    debug_print("INFO - Inter-procedural analysis module not available, using intra-procedural only")


def analyze_jump_table(instruction_ea: int) -> Tuple[List[int], float, Dict[str, Any]]:
    """
    Analyzes a potential jump table at the given instruction address.
    
    Includes confidence scoring to reduce false positives.
    
    :param instruction_ea: The address of the instruction that might use a jump table
    :return: Tuple of (targets_list, confidence_score, detection_info)
    """
    targets = []
    confidence_score = 0.0
    detection_info = {
        'method': 'unknown',
        'confidence_factors': [],
        'warnings': []
    }
    
    try:
        # Try to get switch info from IDA (highest confidence)
        si = ida_nalt.switch_info_t()
        if ida_nalt.get_switch_info(si, instruction_ea):
            # IDA detected a switch statement
            debug_print(f"TRACE - Found switch info at 0x{instruction_ea:X}")
            detection_info['method'] = 'ida_switch_info'
            confidence_score = 95.0  # High confidence for IDA-detected switches
            detection_info['confidence_factors'].append('ida_detected_switch')
            
            # Get all switch targets
            for i in range(si.get_jtable_size()):
                target_ea = si.get_jtable_element_ea(instruction_ea, i)
                if target_ea != ida_idaapi.BADADDR:
                    targets.append(target_ea)
            
            if len(targets) > 0:
                detection_info['confidence_factors'].append(f'ida_switch_targets_{len(targets)}')
            
            debug_print(f"TRACE - Switch at 0x{instruction_ea:X} has {len(targets)} targets with {confidence_score:.1f}% confidence (IDA detected)")
            
        else:
            # Manual jump table detection with confidence scoring
            targets, confidence_score, detection_info = detect_manual_jump_table(instruction_ea)
            
    except Exception as e:
        import traceback
        debug_print(f"ERROR - Error analyzing jump table at 0x{instruction_ea:X}: {str(e)}")
        debug_print(traceback.format_exc())
        detection_info['warnings'].append(f'analysis_error: {str(e)}')
    
    return targets, confidence_score, detection_info


def detect_manual_jump_table(instruction_ea):
    """
    Manually detects jump tables that IDA might have missed.
    
    Includes confidence scoring to reduce false positives.
    
    :param instruction_ea: The instruction address to analyze
    :return: Tuple of (targets_list, confidence_score, detection_info)
    """
    targets = []
    confidence_score = 0.0
    detection_info = {
        'method': 'manual',
        'confidence_factors': [],
        'warnings': []
    }
    
    try:
        # Check if this is an indirect jump instruction
        if not is_indirect_jump_instruction(instruction_ea):
            return targets, 0.0, detection_info
        
        detection_info['confidence_factors'].append('is_indirect_jump')
        confidence_score += 20.0
        
        # Look for patterns like:
        # jmp [reg*4 + table_base]
        # jmp [table_base + reg*4]
        
        # Get the operand that contains the jump target
        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, instruction_ea):
            return targets, confidence_score, detection_info
        
        if insn.Op1.type == ida_ua.o_displ or insn.Op1.type == ida_ua.o_phrase:
            # This is a displacement or phrase operand, might be a jump table
            base_addr = insn.Op1.addr if hasattr(insn.Op1, 'addr') else 0
            
            if base_addr and ida_bytes.is_mapped(base_addr):
                detection_info['confidence_factors'].append('has_mapped_base_address')
                confidence_score += 20.0
                
                # Check if base address is in a data segment (higher confidence)
                seg = _cached_getseg(base_addr)
                if seg:
                    seg_name = ida_segment.get_segm_name(seg)
                    if seg_name in ['.rdata', '.rodata', '.data']:
                        detection_info['confidence_factors'].append(f'base_in_data_segment_{seg_name}')
                        confidence_score += 20.0
                
                # Try to read potential jump table entries
                ptr_size = 8 if ida_ida.inf_is_64bit() else 4
                max_entries = constants.JUMP_TABLE_MAX_ENTRIES
                
                consecutive_misses = 0
                MAX_MISSES = constants.JUMP_TABLE_MAX_MISSES
                valid_targets_found = 0
                
                for i in range(max_entries):
                    entry_addr = base_addr + (i * ptr_size)
                    if not ida_bytes.is_mapped(entry_addr):
                        break
                    
                    if ptr_size == 8:
                        target = ida_bytes.get_qword(entry_addr)
                    else:
                        target = ida_bytes.get_dword(entry_addr)
                    
                    # Check if target looks like a valid code address
                    if target and ida_bytes.is_mapped(target) and ida_bytes.is_code(ida_bytes.get_full_flags(target)):
                        # Additional validation: check if target is in same segment as caller
                        target_seg = _cached_getseg(target)
                        caller_seg = _cached_getseg(instruction_ea)
                        
                        if target_seg and caller_seg and target_seg.start_ea == caller_seg.start_ea:
                            detection_info['confidence_factors'].append('target_in_same_segment')
                            confidence_score += 2.0  # Small boost per valid target
                        
                        targets.append(target)
                        valid_targets_found += 1
                        consecutive_misses = 0
                    else:
                        consecutive_misses += 1
                        if consecutive_misses >= MAX_MISSES:
                            # assume end of sparse table
                            break
                
                # Confidence based on number of valid targets found
                if valid_targets_found >= 5:
                    detection_info['confidence_factors'].append(f'multiple_valid_targets_{valid_targets_found}')
                    confidence_score += 30.0
                elif valid_targets_found >= 3:
                    detection_info['confidence_factors'].append(f'several_valid_targets_{valid_targets_found}')
                    confidence_score += 20.0
                elif valid_targets_found >= 1:
                    detection_info['confidence_factors'].append(f'few_valid_targets_{valid_targets_found}')
                    confidence_score += 10.0
                else:
                    detection_info['warnings'].append('no_valid_targets_found')
                
                # Cap confidence at 100
                confidence_score = min(100.0, confidence_score)
                
                debug_print(f"TRACE - Manual jump table detection at 0x{instruction_ea:X} found {len(targets)} targets with {confidence_score:.1f}% confidence")
        
    except Exception as e:
        import traceback
        debug_print(f"ERROR - Error in manual jump table detection at 0x{instruction_ea:X}: {str(e)}")
        debug_print(traceback.format_exc())
        detection_info['warnings'].append(f'detection_error: {str(e)}')
    
    return targets, confidence_score, detection_info


def is_indirect_jump_instruction(ea: int) -> bool:
    """
    Checks if the instruction at the given address is an indirect jump.
    
    :param ea: The instruction address
    :return: True if it's an indirect jump, False otherwise
    """
    try:
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea):
            return ida_idp.is_indirect_jump_insn(insn)
    except:
        pass
    return False


def analyze_indirect_calls(ea, target_addr, import_addresses=None):
    """
    Analyzes indirect calls and attempts to resolve their targets through data flow analysis.

    Supports optional inter-procedural analysis when intra-procedural analysis
    doesn't find sufficient targets.

    :param ea: The instruction address making the call
    :param target_addr: The target address being called (for indirect calls this might be BADADDR)
    :param import_addresses: Set of import addresses for context
    :return: Tuple of (is_indirect_call, resolved_targets, analysis_info)
    """
    try:
        # First check if this is an indirect call pattern
        if not is_indirect_call_pattern(ea):
            return False, [], {}

        # PHASE 1: Perform intra-procedural data flow analysis (fast, local)
        analysis_info = perform_indirect_call_dataflow(ea)
        if not analysis_info:
            return False, [], {}

        # Resolve the actual function targets using local analysis
        resolved_targets = resolve_indirect_call_targets(analysis_info, import_addresses)

        # PHASE 2: If inter-procedural analysis is available and we didn't find enough targets,
        # try deeper analysis (slower, but broader)
        confidence = analysis_info.get('confidence', 0.0)
        # Convert string confidence levels to numeric values for comparison
        if isinstance(confidence, str):
            confidence_map = {'low': 25.0, 'medium': 50.0, 'high': 75.0}
            confidence = confidence_map.get(confidence.lower(), 0.0)

        if HAS_INTERPROCEDURAL and (not resolved_targets or confidence < 50.0):
            debug_print(f"TRACE - Attempting inter-procedural analysis for indirect call at 0x{ea:X}")

            try:
                # Use inter-procedural analysis to find more targets
                interprocedural_targets, interprocedural_confidence, interprocedural_info = \
                    resolve_indirect_call_interprocedural(
                        ea,
                        analysis_info,
                        max_depth=INTERPROCEDURAL_MAX_DEPTH
                    )

                if interprocedural_targets:
                    # Merge results - prefer inter-procedural if confidence is higher
                    if interprocedural_confidence > confidence:
                        debug_print(f"TRACE - Inter-procedural analysis improved confidence: "
                                  f"{confidence:.1f}% -> {interprocedural_confidence:.1f}%")
                        resolved_targets = interprocedural_targets
                        analysis_info['method'] = 'interprocedural'
                        analysis_info['confidence'] = interprocedural_confidence
                        analysis_info['interprocedural_info'] = interprocedural_info
                    else:
                        # Combine targets from both analyses
                        combined_targets = list(set(resolved_targets + interprocedural_targets))
                        debug_print(f"TRACE - Combined intra+inter-procedural analysis: "
                                  f"{len(resolved_targets)} + {len(interprocedural_targets)} = "
                                  f"{len(combined_targets)} unique targets")
                        resolved_targets = combined_targets
                        analysis_info['method'] = 'combined'
                        analysis_info['interprocedural_info'] = interprocedural_info

            except Exception as e:
                debug_print(f"WARNING - Inter-procedural analysis failed: {str(e)}")
                # Fall back to intra-procedural results
                pass

        return True, resolved_targets, analysis_info

    except Exception as e:
        import traceback
        debug_print(f"ERROR - Error in indirect call analysis: {e}")
        debug_print(traceback.format_exc())
        return False, [], {}


def is_indirect_call_pattern(ea: int) -> bool:
    """
    Detects if an instruction represents an indirect call pattern.
    
    Common patterns:
    - call reg           ; call through register
    - call [mem]         ; call through memory location  
    - call [reg + offset]; call through memory with offset
    
    :param ea: The instruction address
    :return: True if it matches indirect call pattern, False otherwise
    """
    try:
        # Get the instruction
        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, ea):
            return False
            
        # Must be a call instruction
        if not ida_idp.is_call_insn(insn):
            return False
            
        # Check the operand type for indirect patterns
        op = insn.Op1
        
        # Direct register call: call eax
        if op.type == ida_ua.o_reg:
            return True
            
        # Memory reference call: call [address]
        if op.type == ida_ua.o_mem:
            return True
            
        # Displacement call: call [reg + offset]
        if op.type == ida_ua.o_displ:
            return True
            
        # Phrase call: call [reg + reg*scale + offset]
        if op.type == ida_ua.o_phrase:
            return True
            
        return False
        
    except Exception as e:
        import traceback
        debug_print(f"ERROR - Error detecting indirect call pattern: {e}")
        debug_print(traceback.format_exc())
        return False


def perform_indirect_call_dataflow(ea):
    """
    Performs data flow analysis to track how the indirect call target is loaded.
    
    :param ea: The call instruction address
    :return: Dictionary with data flow analysis results
    """
    try:
        analysis_info = {
            'call_type': 'unknown',
            'target_register': None,
            'target_memory': ida_idaapi.BADADDR,
            'load_instructions': [],
            'potential_targets': [],
            'confidence': 'low'
        }
        
        # Decode the call instruction
        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, ea):
            return {}
            
        op = insn.Op1
        
        # Analyze based on operand type
        if op.type == ida_ua.o_reg:
            analysis_info['call_type'] = 'register'
            analysis_info['target_register'] = op.reg
            # Track register loads
            analysis_info.update(track_register_loads(ea, op.reg))
            
        elif op.type == ida_ua.o_mem:
            analysis_info['call_type'] = 'memory'
            analysis_info['target_memory'] = op.addr
            # Analyze memory location directly
            analysis_info.update(analyze_memory_target(op.addr))
            
        elif op.type == ida_ua.o_displ:
            analysis_info['call_type'] = 'displacement'
            analysis_info['target_register'] = op.reg
            analysis_info['displacement'] = op.addr
            # Track object pointer and analyze structure
            analysis_info.update(track_displacement_loads(ea, op.reg, op.addr))
            
        elif op.type == ida_ua.o_phrase:
            analysis_info['call_type'] = 'computed'
            analysis_info['target_register'] = op.reg
            # More complex computed addressing
            analysis_info.update(track_computed_address(ea, op))
            
        return analysis_info
        
    except Exception as e:
        debug_print(f"Error in data flow analysis: {e}")
        return {}


def _apply_transform_ops(value: int, ops: List[Tuple[str, int]]) -> int:
    """Apply recorded arithmetic/bitwise transforms in forward order."""
    for op, imm in reversed(ops):
        if op == 'xor':
            value ^= imm
        elif op == 'add':
            value += imm
        elif op == 'sub':
            value -= imm
    return value


def _compute_effective_address(insn: ida_ua.insn_t, op: ida_ua.op_t) -> Optional[int]:
    """Compute an absolute address for memory operands when possible."""
    if op.type == ida_ua.o_mem and op.addr != ida_idaapi.BADADDR:
        return op.addr
    if op.type == ida_ua.o_displ:
        base_reg = ida_idp.get_reg_name(op.reg, op.dtype) or ""
        disp = ida_idaapi.as_signed(op.addr, 32)
        if base_reg.lower() in ("rip", "eip"):
            return insn.ea + insn.size + disp
    return None


def _resolve_register_base_value(ea: int, reg: int, max_depth: Optional[int] = None) -> Optional[int]:
    """Best-effort resolution of a register value to an address or immediate."""
    if max_depth is None:
        max_depth = constants.MAX_REGISTER_TRACKING_DEPTH
    current_ea = ea
    tracked_reg = reg

    for _ in range(max_depth):
        current_ea = ida_bytes.prev_head(current_ea)
        if current_ea == ida_idaapi.BADADDR:
            break

        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, current_ea):
            continue

        if insn.Op1.type != ida_ua.o_reg or insn.Op1.reg != tracked_reg:
            continue

        if insn.itype == ida_allins.NN_mov:
            if insn.Op2.type == ida_ua.o_imm:
                return insn.Op2.value
            if insn.Op2.type in (ida_ua.o_mem, ida_ua.o_displ):
                return _compute_effective_address(insn, insn.Op2)
            if insn.Op2.type == ida_ua.o_reg:
                tracked_reg = insn.Op2.reg
                continue

        if insn.itype == ida_allins.NN_lea and insn.Op2.type in (ida_ua.o_mem, ida_ua.o_displ):
            return _compute_effective_address(insn, insn.Op2)

        break

    return None


def track_register_loads(ea, target_reg, max_depth=None):
    """
    Tracks backward to find where a register was loaded with a function pointer.
    
    Uses pattern matching for common obfuscation techniques:
    - XOR with constants followed by adjustments
    - Register-to-register moves with offsets
    - Stack-based indirect loads
    - Basic arithmetic obfuscation
    
    :param ea: Starting address (the call instruction)
    :param target_reg: The register to track
    :param max_depth: Maximum number of instructions to search backward (defaults to MAX_REGISTER_TRACKING_DEPTH)
    :return: Dictionary with tracking results
    """
    if max_depth is None:
        max_depth = constants.MAX_REGISTER_TRACKING_DEPTH
    try:
        tracking_info = {
            'load_instructions': [],
            'potential_targets': [],
            'confidence': 'low',
            'obfuscation_detected': False,
            'obfuscation_patterns': []
        }
        
        current_ea = ea
        search_count = 0
        tracked_regs = {target_reg}  # Track all registers that might hold our value
        transform_ops: List[Tuple[str, int]] = []
        
        while search_count < max_depth:
            current_ea = ida_bytes.prev_head(current_ea)
            if current_ea == ida_idaapi.BADADDR:
                break
                
            search_count += 1
            
            insn = ida_ua.insn_t()
            if not ida_ua.decode_insn(insn, current_ea):
                continue
            
            # Check if this instruction modifies any of our tracked registers
            if insn.Op1.type == ida_ua.o_reg and insn.Op1.reg in tracked_regs:
                
                # MOV reg, immediate
                if (insn.itype == ida_allins.NN_mov and 
                    insn.Op2.type == ida_ua.o_imm):
                    
                    target_addr = _apply_transform_ops(insn.Op2.value, transform_ops)
                    if is_valid_function_pointer(target_addr):
                        tracking_info['potential_targets'].append(target_addr)
                        tracking_info['load_instructions'].append({
                            'address': current_ea,
                            'instruction': f"mov {ida_ua.print_operand(insn, 0)}, 0x{target_addr:X}",
                            'target': target_addr
                        })
                        tracking_info['confidence'] = 'high'
                        
                # MOV reg, [memory]
                elif (insn.itype == ida_allins.NN_mov and 
                      insn.Op2.type in (ida_ua.o_mem, ida_ua.o_displ)):
                      
                    mem_addr = _compute_effective_address(insn, insn.Op2)
                    if mem_addr is None:
                        continue
                    # Read the value from memory
                    ptr_size = 8 if ida_ida.inf_is_64bit() else 4
                    if ptr_size == 8:
                        target_addr = ida_bytes.get_qword(mem_addr)
                    else:
                        target_addr = ida_bytes.get_dword(mem_addr)
                        
                    target_addr = _apply_transform_ops(target_addr, transform_ops)
                    if is_valid_function_pointer(target_addr):
                        tracking_info['potential_targets'].append(target_addr)
                        tracking_info['load_instructions'].append({
                            'address': current_ea,
                            'instruction': f"mov {ida_ua.print_operand(insn, 0)}, [{ida_ua.print_operand(insn, 1)}]",
                            'target': target_addr,
                            'memory_source': mem_addr
                        })
                        tracking_info['confidence'] = 'medium'
                        
                # LEA reg, function_address
                elif (insn.itype == ida_allins.NN_lea and
                      insn.Op2.type in (ida_ua.o_mem, ida_ua.o_displ)):
                      
                    target_addr = _compute_effective_address(insn, insn.Op2)
                    if target_addr is None:
                        continue
                    target_addr = _apply_transform_ops(target_addr, transform_ops)
                    if is_valid_function_pointer(target_addr):
                        tracking_info['potential_targets'].append(target_addr)
                        tracking_info['load_instructions'].append({
                            'address': current_ea,
                            'instruction': f"lea {ida_ua.print_operand(insn, 0)}, {ida_ua.print_operand(insn, 1)}",
                            'target': target_addr
                        })
                        tracking_info['confidence'] = 'high'
                        
                # XOR obfuscation pattern: XOR reg, constant followed by adjustments
                elif (insn.itype == ida_allins.NN_xor and
                      insn.Op2.type == ida_ua.o_imm):
                    # Common obfuscation: XOR with a key, then ADD/SUB to get real address
                    tracking_info['obfuscation_detected'] = True
                    tracking_info['obfuscation_patterns'].append('xor_with_constant')
                    tracking_info['confidence'] = 'medium'
                    transform_ops.append(('xor', insn.Op2.value))
                    
                    tracking_info['load_instructions'].append({
                        'address': current_ea,
                        'instruction': f"xor {ida_ua.print_operand(insn, 0)}, 0x{insn.Op2.value:X}",
                        'obfuscation': 'xor_key'
                    })
                
                # ADD/SUB with register (could be de-obfuscation or offset calculation)
                elif (insn.itype in [ida_allins.NN_add, ida_allins.NN_sub] and
                      insn.Op2.type == ida_ua.o_imm):
                    tracking_info['obfuscation_patterns'].append('arithmetic_adjustment')
                    tracking_info['confidence'] = 'low'  # Ambiguous
                    transform_ops.append(('add' if insn.itype == ida_allins.NN_add else 'sub', insn.Op2.value))
                
                # Register-to-register move (extend tracking)
                elif (insn.itype == ida_allins.NN_mov and
                      insn.Op2.type == ida_ua.o_reg):
                    # Track the source register too
                    source_reg = insn.Op2.reg
                    tracked_regs.add(source_reg)
                    tracking_info['load_instructions'].append({
                        'address': current_ea,
                        'instruction': f"mov {ida_ua.print_operand(insn, 0)}, {ida_ua.print_operand(insn, 1)}",
                        'note': 'register_transfer'
                    })
                
                # If we found a definitive load, we can stop
                if tracking_info['confidence'] == 'high':
                    break
        
        # Log obfuscation detection
        if tracking_info['obfuscation_detected']:
            debug_print(f"TRACE - Obfuscation detected in indirect call at 0x{ea:X}: "
                       f"{', '.join(tracking_info['obfuscation_patterns'])}")
                    
        return tracking_info
        
    except Exception as e:
        import traceback
        debug_print(f"ERROR - Error tracking register loads: {e}")
        debug_print(traceback.format_exc())
        return {'load_instructions': [], 'potential_targets': [], 'confidence': 'low'}


def analyze_memory_target(mem_addr: int) -> Dict[str, Any]:
    """
    Analyzes a memory location that's used in an indirect call.
    
    :param mem_addr: The memory address being called through
    :return: Dictionary with analysis results
    """
    try:
        analysis_info = {
            'memory_type': 'unknown',
            'potential_targets': [],
            'confidence': 'low'
        }
        
        # Read the value from memory
        ptr_size = 8 if ida_ida.inf_is_64bit() else 4
        if ptr_size == 8:
            target_addr = ida_bytes.get_qword(mem_addr)
        else:
            target_addr = ida_bytes.get_dword(mem_addr)
            
        # Check if it's a valid function pointer
        if is_valid_function_pointer(target_addr):
            analysis_info['potential_targets'].append(target_addr)
            analysis_info['confidence'] = 'high'
            
            # Try to determine what kind of memory location this is
            seg = _cached_getseg(mem_addr)
            if seg:
                seg_name = ida_segment.get_segm_name(seg)
                if '.data' in seg_name or '.rdata' in seg_name:
                    analysis_info['memory_type'] = 'global_function_pointer'
                elif '.idata' in seg_name:
                    analysis_info['memory_type'] = 'import_table'
                else:
                    analysis_info['memory_type'] = 'static_data'
        else:
            # Check if this might be a function pointer array
            array_info = analyze_function_pointer_array(mem_addr)
            if array_info['targets']:
                analysis_info.update(array_info)
                analysis_info['memory_type'] = 'function_pointer_array'
                
        return analysis_info
        
    except Exception as e:
        import traceback
        debug_print(f"ERROR - Error analyzing memory target: {e}")
        debug_print(traceback.format_exc())
        return {'memory_type': 'unknown', 'potential_targets': [], 'confidence': 'low'}


def analyze_function_pointer_array(base_addr, max_entries=50):
    """
    Analyzes a potential function pointer array starting at base_addr.
    
    :param base_addr: Base address of the potential array
    :param max_entries: Maximum number of entries to check
    :return: Dictionary with array analysis results
    """
    try:
        array_info = {
            'targets': [],
            'array_size': 0,
            'confidence': 'low'
        }
        
        ptr_size = 8 if ida_ida.inf_is_64bit() else 4
        current_addr = base_addr
        valid_count = 0
        
        for i in range(max_entries):
            # Read the pointer value
            if ptr_size == 8:
                ptr_val = ida_bytes.get_qword(current_addr)
            else:
                ptr_val = ida_bytes.get_dword(current_addr)
                
            # Check if this looks like a valid function pointer
            if is_valid_function_pointer(ptr_val):
                array_info['targets'].append(ptr_val)
                valid_count += 1
            else:
                # If we hit 3+ consecutive invalid pointers, assume end of array
                if i > 0 and valid_count > 0:
                    break
                    
            current_addr += ptr_size
            
        array_info['array_size'] = len(array_info['targets'])
        
        # Set confidence based on how many valid pointers we found
        if array_info['array_size'] >= 3:
            array_info['confidence'] = 'high'
        elif array_info['array_size'] >= 1:
            array_info['confidence'] = 'medium'
            
        return array_info
        
    except Exception as e:
        debug_print(f"Error analyzing function pointer array: {e}")
        return {'targets': [], 'array_size': 0, 'confidence': 'low'}


def track_displacement_loads(ea: int, base_reg: int, displacement: int) -> Dict[str, Any]:
    """
    Tracks displacement-based calls like call [reg + offset].
    
    :param ea: The call instruction address
    :param base_reg: The base register
    :param displacement: The displacement/offset
    :return: Dictionary with tracking results
    """
    try:
        tracking_info = {
            'object_type': 'unknown',
            'potential_targets': [],
            'confidence': 'low'
        }
        
        # This is often a method call through an object or structure
        # Try to determine what the base register points to
        base_info = track_register_loads(ea, base_reg, max_depth=constants.MAX_REGISTER_TRACKING_DEPTH)
        
        if base_info['potential_targets']:
            # The base register points to an object/structure
            for base_target in base_info['potential_targets']:
                # Calculate the actual call target
                target_addr = base_target + displacement
                
                # Read the function pointer from the calculated address
                ptr_size = 8 if ida_ida.inf_is_64bit() else 4
                try:
                    if ptr_size == 8:
                        func_ptr = ida_bytes.get_qword(target_addr)
                    else:
                        func_ptr = ida_bytes.get_dword(target_addr)
                        
                    if is_valid_function_pointer(func_ptr):
                        tracking_info['potential_targets'].append(func_ptr)
                        tracking_info['confidence'] = 'medium'
                        tracking_info['object_type'] = 'structure_with_function_pointers'
                        
                except:
                    # Memory read failed, might not be a valid structure
                    pass
                    
        return tracking_info
        
    except Exception as e:
        debug_print(f"Error tracking displacement loads: {e}")
        return {'object_type': 'unknown', 'potential_targets': [], 'confidence': 'low'}


def track_computed_address(ea, operand):
    """
    Tracks computed addressing modes like call [reg + reg*scale + offset].
    
    :param ea: The call instruction address
    :param operand: The operand with computed addressing
    :return: Dictionary with tracking results
    """
    try:
        tracking_info = {
            'address_type': 'computed',
            'potential_targets': [],
            'confidence': 'low'
        }
        
        # This is usually an array access or switch table: base + index*scale + offset
        base_addr = _resolve_register_base_value(ea, operand.reg)
        if base_addr is not None and ida_bytes.is_mapped(base_addr):
            array_info = analyze_function_pointer_array(
                base_addr,
                max_entries=constants.JUMP_TABLE_MAX_ENTRIES
            )
            if array_info['targets']:
                tracking_info['address_type'] = 'function_pointer_table'
                tracking_info['potential_targets'] = array_info['targets']
                tracking_info['confidence'] = array_info.get('confidence', 'medium')
                return tracking_info

        tracking_info['address_type'] = 'array_or_switch_table'
        tracking_info['confidence'] = 'low'
        
        return tracking_info
        
    except Exception as e:
        debug_print(f"Error tracking computed address: {e}")
        return {'address_type': 'computed', 'potential_targets': [], 'confidence': 'low'}


def resolve_indirect_call_targets(analysis_info: Dict[str, Any], import_addresses: Optional[Set[int]] = None) -> List[int]:
    """
    Resolves the final target addresses from indirect call analysis.
    
    :param analysis_info: Dictionary with analysis results
    :param import_addresses: Set of import addresses for context
    :return: List of resolved target addresses
    """
    try:
        targets = []
        
        # Get potential targets from analysis
        potential_targets = analysis_info.get('potential_targets', [])
        
        for target_addr in potential_targets:
            # Validate the target
            if is_valid_function_pointer(target_addr):
                # Resolve thunks if needed
                resolved_target = resolve_thunk_target(target_addr)
                targets.append(resolved_target)
                
        # Remove duplicates while preserving order
        seen = set()
        unique_targets = []
        for target in targets:
            if target not in seen:
                seen.add(target)
                unique_targets.append(target)
                
        return unique_targets
        
    except Exception as e:
        import traceback
        debug_print(f"ERROR - Error resolving indirect call targets: {e}")
        debug_print(traceback.format_exc())
        return []


def track_register_loads_across_blocks(ea: int, target_reg: int, func: Any, max_blocks: int = 10) -> Dict[str, Any]:
    """
    Walk predecessor basic blocks to find potential loads for register (light data-flow).
    
    :param ea: The instruction address
    :param target_reg: The register to track
    :param func: The function object
    :param max_blocks: Maximum blocks to traverse
    :return: Dictionary with tracking results
    """
    if ida_gdl is None:
        # Fallback to simpler tracking if ida_gdl not available
        return track_register_loads(ea, target_reg, max_depth=15)
    
    tracking_info = {
        'load_instructions': [],
        'potential_targets': [],
        'confidence': 'low'
    }
    try:
        fc = ida_gdl.FlowChart(func)
        blk_of_ea = None
        for b in fc:
            if b.start_ea <= ea < b.end_ea:
                blk_of_ea = b
                break
        todo = [(blk_of_ea, 0)] if blk_of_ea else []
        visited = set()
        while todo:
            blk, dist = todo.pop(0)
            if not blk or blk in visited or dist > max_blocks:
                continue
            visited.add(blk)
            # scan block backwards if it precedes original ea else forward entire block
            scan_eas = list(idautils.Heads(blk.start_ea, blk.end_ea))
            scan_eas.sort()
            scan_eas = scan_eas[::-1]  # reverse for backward
            for ins_ea in scan_eas:
                if ins_ea >= ea and blk == blk_of_ea:
                    continue
                insn = ida_ua.insn_t()
                if not ida_ua.decode_insn(insn, ins_ea):
                    continue
                if insn.Op1.type == ida_ua.o_reg and insn.Op1.reg == target_reg:
                    # mimic same checks as basic tracker
                    if insn.itype == ida_allins.NN_mov and insn.Op2.type == ida_ua.o_imm:
                        ptr = insn.Op2.value
                        if is_valid_function_pointer(ptr):
                            tracking_info['potential_targets'].append(ptr)
                            tracking_info['confidence'] = 'medium'
                            tracking_info['load_instructions'].append({'address':ins_ea,'instruction':ida_lines.generate_disasm_line(ins_ea,0)})
                            return tracking_info
            for pred in blk.preds():
                todo.append((pred, dist+1))
    except Exception as e:
        debug_print(f"ERROR - track_register_loads_across_blocks: {e}")
    return tracking_info
