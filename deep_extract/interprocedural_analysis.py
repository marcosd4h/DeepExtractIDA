"""
Inter-procedural data flow analysis for PE binary analysis.

This module extends indirect call resolution by tracking values across function boundaries,
enabling better resolution of function pointers and computed call targets.

Design principles:
1. Lightweight - Use summary-based approach (not full symbolic execution)
2. Bounded - Limit depth and complexity to avoid performance issues
3. Practical - Focus on common patterns (parameter passing, return values)
"""

from typing import Dict, List, Optional, Any, Tuple, Set
from functools import lru_cache
from dataclasses import dataclass, field
import ida_funcs
import ida_bytes
import ida_ua
import ida_idp
import ida_idaapi
import ida_ida
import ida_xref
import idautils
try:
    import ida_allins
except ImportError:
    # Fallback for older IDA versions
    import idaapi as ida_allins

from . import constants
from .logging_utils import debug_print, _cached_getseg


# Configuration constants
INTERPROCEDURAL_MAX_DEPTH = 3           # Maximum call chain depth to analyze
INTERPROCEDURAL_MAX_CALLEES = 5        # Max callees to analyze per function
INTERPROCEDURAL_MAX_CALLERS = 5        # Max callers to analyze per function
INTERPROCEDURAL_CACHE_SIZE = 1000      # LRU cache size for function summaries


@dataclass
class FunctionSummary:
    """
    Summary of a function's behavior relevant to data flow analysis.
    
    Tracks:
    - What parameters are used for indirect calls
    - What values are returned (constants, parameters, etc.)
    - What global variables are accessed
    """
    function_ea: int
    
    # Parameter usage
    uses_parameter_as_func_ptr: Set[int] = field(default_factory=set)  # Set of param indices
    
    # Return value analysis
    returns_constant: bool = False
    return_constant_value: Optional[int] = None
    returns_parameter: bool = False
    return_parameter_index: Optional[int] = None
    returns_global: bool = False
    return_global_address: Optional[int] = None
    
    # Indirect call patterns
    makes_indirect_call_from_param: Set[int] = field(default_factory=set)
    makes_indirect_call_from_global: Set[int] = field(default_factory=set)
    
    # Analysis metadata
    analysis_depth: int = 0
    is_complete: bool = True
    analysis_warnings: List[str] = field(default_factory=list)


@lru_cache(maxsize=INTERPROCEDURAL_CACHE_SIZE)
def analyze_function_summary(func_ea: int, max_depth: int = 1) -> FunctionSummary:
    """
    Analyze a function and create a summary of its data flow behavior.
    
    This is the core of inter-procedural analysis - it builds reusable summaries
    that can be combined to track values across function boundaries.
    
    Args:
        func_ea: Function start address
        max_depth: How deep to recursively analyze callees (0 = this function only)
    
    Returns:
        FunctionSummary with analyzed behavior
    """
    summary = FunctionSummary(function_ea=func_ea, analysis_depth=max_depth)
    
    try:
        func = ida_funcs.get_func(func_ea)
        if not func:
            summary.is_complete = False
            summary.analysis_warnings.append("function_not_found")
            return summary
        
        # Track register values through the function
        register_sources = {}  # reg_name -> (source_type, source_value)
        
        # Analyze each instruction in the function
        for ea in idautils.FuncItems(func.start_ea):
            insn = ida_ua.insn_t()
            if not ida_ua.decode_insn(insn, ea):
                continue
            
            # Detect indirect call patterns
            if ida_idp.is_call_insn(insn):
                op = insn.Op1
                
                # call reg - indirect call through register
                if op.type == ida_ua.o_reg:
                    reg_name = ida_idp.get_reg_name(op.reg, op.dtype)
                    if reg_name in register_sources:
                        source_type, source_value = register_sources[reg_name]
                        
                        if source_type == 'parameter':
                            summary.makes_indirect_call_from_param.add(source_value)
                        elif source_type == 'global':
                            summary.makes_indirect_call_from_global.add(source_value)
                
                # call [mem] - indirect call through memory
                elif op.type == ida_ua.o_mem:
                    if op.addr != ida_idaapi.BADADDR:
                        summary.makes_indirect_call_from_global.add(op.addr)
            
            # Track register assignments to detect parameter usage
            # Common patterns:
            # mov reg, [rsp+offset]     ; load parameter from stack
            # mov reg, rcx/rdx/r8/r9    ; use register parameter (x64)
            # mov reg, [global]         ; load from global variable
            
            if insn.itype in [ida_allins.NN_mov, ida_allins.NN_lea]:
                # Destination operand (what's being assigned to)
                dst_op = insn.Op1
                src_op = insn.Op2
                
                if dst_op.type == ida_ua.o_reg:
                    dst_reg = ida_idp.get_reg_name(dst_op.reg, dst_op.dtype)
                    
                    # Check if source is a parameter
                    if _is_parameter_access(insn, src_op, func):
                        param_idx = _estimate_parameter_index(insn, src_op)
                        register_sources[dst_reg] = ('parameter', param_idx)
                        summary.uses_parameter_as_func_ptr.add(param_idx)
                    
                    # Check if source is a global variable
                    elif src_op.type == ida_ua.o_mem:
                        if src_op.addr != ida_idaapi.BADADDR:
                            register_sources[dst_reg] = ('global', src_op.addr)
                    
                    # Check if source is a constant
                    elif src_op.type == ida_ua.o_imm:
                        register_sources[dst_reg] = ('constant', src_op.value)
            
            # Analyze return instructions
            if insn.itype in [ida_allins.NN_retn, ida_allins.NN_retf]:
                # On x86/x64, return value is typically in rax/eax
                return_reg = 'rax' if ida_ida.inf_is_64bit() else 'eax'
                
                if return_reg in register_sources:
                    source_type, source_value = register_sources[return_reg]
                    
                    if source_type == 'constant':
                        summary.returns_constant = True
                        summary.return_constant_value = source_value
                    elif source_type == 'parameter':
                        summary.returns_parameter = True
                        summary.return_parameter_index = source_value
                    elif source_type == 'global':
                        summary.returns_global = True
                        summary.return_global_address = source_value
        
        # If requested, recursively analyze callees (bounded depth)
        if max_depth > 0:
            _analyze_callees_recursively(summary, func, max_depth - 1)
        
    except Exception as e:
        import traceback
        debug_print(f"ERROR - Error analyzing function summary for 0x{func_ea:X}: {str(e)}")
        debug_print(traceback.format_exc())
        summary.is_complete = False
        summary.analysis_warnings.append(f'exception: {str(e)}')
    
    return summary


def resolve_indirect_call_interprocedural(
    call_ea: int,
    immediate_context: Dict[str, Any],
    max_depth: int = INTERPROCEDURAL_MAX_DEPTH
) -> Tuple[List[int], float, Dict[str, Any]]:
    """
    Resolve an indirect call using inter-procedural analysis.
    
    This function extends local dataflow analysis by looking at:
    1. If the function pointer comes from a parameter, trace backwards to callers
    2. If it comes from a return value, trace forwards to callees
    3. If it comes from a global, analyze all writers to that global
    
    Args:
        call_ea: Address of the indirect call instruction
        immediate_context: Results from intra-procedural analysis
        max_depth: Maximum depth for inter-procedural tracking
    
    Returns:
        Tuple of (resolved_targets, confidence, analysis_info)
    """
    resolved_targets = []
    confidence = 0.0
    analysis_info = {
        'method': 'interprocedural',
        'depth_used': 0,
        'functions_analyzed': [],
        'confidence_factors': [],
        'warnings': []
    }
    
    try:
        # Get the function containing this call
        caller_func = ida_funcs.get_func(call_ea)
        if not caller_func:
            analysis_info['warnings'].append('caller_function_not_found')
            return resolved_targets, 0.0, analysis_info
        
        # Analyze the caller function
        caller_summary = analyze_function_summary(caller_func.start_ea, max_depth=1)
        analysis_info['functions_analyzed'].append(hex(caller_func.start_ea))
        
        # Check what pattern is being used for the indirect call
        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, call_ea):
            return resolved_targets, 0.0, analysis_info
        
        # STRATEGY 1: If call uses a parameter, trace back to callers
        if _indirect_call_uses_parameter(insn, immediate_context):
            param_idx = _get_parameter_index_from_context(immediate_context)
            
            if param_idx is not None:
                analysis_info['confidence_factors'].append(f'traces_parameter_{param_idx}')
                
                # Find all callers and check what they pass
                targets_from_callers = _trace_parameter_to_callers(
                    caller_func.start_ea,
                    param_idx,
                    max_depth
                )
                
                if targets_from_callers:
                    resolved_targets.extend(targets_from_callers)
                    confidence += 70.0
                    analysis_info['confidence_factors'].append(
                        f'resolved_{len(targets_from_callers)}_from_callers'
                    )
        
        # STRATEGY 2: If call uses a global variable, find all writers
        if _indirect_call_uses_global(insn, immediate_context):
            global_addr = _get_global_address_from_context(immediate_context)
            
            if global_addr:
                analysis_info['confidence_factors'].append(f'traces_global_0x{global_addr:X}')
                
                targets_from_global = _find_function_pointers_written_to_global(
                    global_addr,
                    max_depth
                )
                
                if targets_from_global:
                    resolved_targets.extend(targets_from_global)
                    confidence += 80.0  # Global writes are usually more reliable
                    analysis_info['confidence_factors'].append(
                        f'resolved_{len(targets_from_global)}_from_global_writers'
                    )
        
        # STRATEGY 3: If call uses return value from another call, trace forward
        if _indirect_call_uses_call_result(insn, immediate_context):
            callee_addr = _get_callee_address_from_context(immediate_context)
            
            if callee_addr:
                analysis_info['confidence_factors'].append(f'traces_return_from_0x{callee_addr:X}')
                
                callee_summary = analyze_function_summary(callee_addr, max_depth=1)
                analysis_info['functions_analyzed'].append(hex(callee_addr))
                
                if callee_summary.returns_constant and callee_summary.return_constant_value:
                    resolved_targets.append(callee_summary.return_constant_value)
                    confidence += 90.0  # Constant returns are very reliable
                    analysis_info['confidence_factors'].append('constant_return_value')
                
                elif callee_summary.returns_global and callee_summary.return_global_address:
                    # Recursively trace the global
                    targets_from_global = _find_function_pointers_written_to_global(
                        callee_summary.return_global_address,
                        max_depth - 1
                    )
                    if targets_from_global:
                        resolved_targets.extend(targets_from_global)
                        confidence += 60.0
        
        # Validate all resolved targets
        validated_targets = []
        for target in resolved_targets:
            if _is_valid_function_target(target):
                validated_targets.append(target)
            else:
                analysis_info['warnings'].append(f'invalid_target_0x{target:X}')
        
        # Update confidence based on validation
        if validated_targets:
            validation_ratio = len(validated_targets) / len(resolved_targets)
            confidence *= validation_ratio
        
        analysis_info['depth_used'] = max_depth
        
        return validated_targets, min(100.0, confidence), analysis_info
        
    except Exception as e:
        import traceback
        debug_print(f"ERROR - Inter-procedural analysis failed: {str(e)}")
        debug_print(traceback.format_exc())
        analysis_info['warnings'].append(f'exception: {str(e)}')
        return [], 0.0, analysis_info


def _is_parameter_access(insn: ida_ua.insn_t, operand: ida_ua.op_t, func: ida_funcs.func_t) -> bool:
    """Check if operand accesses a function parameter."""
    # Stack-based parameter: [rsp+offset] or [rbp+offset]
    if operand.type == ida_ua.o_displ:
        base_reg = ida_idp.get_reg_name(operand.reg, operand.dtype)
        if base_reg in ['rsp', 'esp', 'rbp', 'ebp']:
            # Positive offsets from rsp/rbp typically indicate parameters
            return operand.addr > 0
    
    # Register parameters (x64 calling convention: rcx, rdx, r8, r9)
    if operand.type == ida_ua.o_reg:
        reg_name = ida_idp.get_reg_name(operand.reg, operand.dtype)
        if reg_name in ['rcx', 'rdx', 'r8', 'r9', 'ecx', 'edx']:
            return True
    
    return False


def _estimate_parameter_index(insn: ida_ua.insn_t, operand: ida_ua.op_t) -> int:
    """Estimate which parameter index (0-based) this operand represents."""
    if operand.type == ida_ua.o_reg:
        reg_name = ida_idp.get_reg_name(operand.reg, operand.dtype)
        # x64 register parameters
        param_map = {'rcx': 0, 'ecx': 0, 'rdx': 1, 'edx': 1, 'r8': 2, 'r9': 3}
        return param_map.get(reg_name, -1)
    
    elif operand.type == ida_ua.o_displ:
        # Estimate from stack offset (rough heuristic)
        offset = operand.addr
        ptr_size = 8 if ida_ida.inf_is_64bit() else 4
        return int(offset // ptr_size)
    
    return -1


def _analyze_callees_recursively(summary: FunctionSummary, func: ida_funcs.func_t, remaining_depth: int):
    """Recursively analyze callees to build richer summaries."""
    if remaining_depth <= 0:
        return
    
    callee_count = 0
    for ea in idautils.FuncItems(func.start_ea):
        if callee_count >= INTERPROCEDURAL_MAX_CALLEES:
            summary.analysis_warnings.append('max_callees_reached')
            break
        
        # Find call instructions
        for xref in idautils.XrefsFrom(ea, 0):
            if xref.type in [ida_xref.fl_CF, ida_xref.fl_CN]:  # Call flow
                callee_func = ida_funcs.get_func(xref.to)
                if callee_func:
                    callee_summary = analyze_function_summary(
                        callee_func.start_ea,
                        max_depth=remaining_depth - 1
                    )
                    callee_count += 1
                    # Could aggregate callee patterns here if needed


def _trace_parameter_to_callers(func_ea: int, param_idx: int, max_depth: int) -> List[int]:
    """Trace a parameter back through callers to find possible values."""
    targets = []
    
    if max_depth <= 0:
        return targets
    
    # Find all callers
    caller_count = 0
    for xref in idautils.XrefsTo(func_ea, 0):
        if caller_count >= INTERPROCEDURAL_MAX_CALLERS:
            break
        
        if xref.type in [ida_xref.fl_CF, ida_xref.fl_CN]:  # Call flow
            call_ea = xref.frm
            
            # Analyze what value is passed as this parameter at the call site
            passed_value = _analyze_argument_at_call_site(call_ea, param_idx)
            
            if passed_value and _is_valid_function_target(passed_value):
                targets.append(passed_value)
            
            caller_count += 1
    
    return targets


def _find_function_pointers_written_to_global(global_addr: int, max_depth: int) -> List[int]:
    """Find all function pointers written to a global variable."""
    targets = []
    
    # Find all writes to this global
    for xref in idautils.DataRefsTo(global_addr):
        # Check if this is a write operation
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, xref):
            # Look for mov [global], value patterns
            if insn.itype == ida_allins.NN_mov and insn.Op2.type == ida_ua.o_imm:
                value = insn.Op2.value
                if _is_valid_function_target(value):
                    targets.append(value)
    
    return targets


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


def _resolve_memory_operand(insn: ida_ua.insn_t, operand: ida_ua.op_t) -> Optional[int]:
    """Resolve a memory operand to an absolute address."""
    if operand.type == ida_ua.o_mem and operand.addr != ida_idaapi.BADADDR:
        return operand.addr
    if operand.type == ida_ua.o_displ:
        base_reg = ida_idp.get_reg_name(operand.reg, operand.dtype) or ""
        disp = ida_idaapi.as_signed(operand.addr, 32)
        if base_reg.lower() in ("rip", "eip"):
            return insn.ea + insn.size + disp
    return None


def _track_register_value_at_call(call_ea: int, reg_name: str, max_depth: int = 40) -> Optional[int]:
    """Track a register value backwards from a call site."""
    current_ea = call_ea
    tracked_reg = reg_name.lower()
    transform_ops: List[Tuple[str, int]] = []
    # Compute lower search bound: function start or a safe fallback
    func = ida_funcs.get_func(call_ea)
    minea = func.start_ea if func else 0

    for _ in range(max_depth):
        current_ea = ida_bytes.prev_head(current_ea, minea)
        if current_ea == ida_idaapi.BADADDR:
            break

        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, current_ea):
            continue

        if insn.Op1.type != ida_ua.o_reg:
            continue

        dst_reg = (ida_idp.get_reg_name(insn.Op1.reg, insn.Op1.dtype) or "").lower()
        if dst_reg != tracked_reg:
            continue

        if insn.itype == ida_allins.NN_xor and insn.Op2.type == ida_ua.o_imm:
            transform_ops.append(('xor', insn.Op2.value))
            continue

        if insn.itype == ida_allins.NN_add and insn.Op2.type == ida_ua.o_imm:
            transform_ops.append(('add', insn.Op2.value))
            continue

        if insn.itype == ida_allins.NN_sub and insn.Op2.type == ida_ua.o_imm:
            transform_ops.append(('sub', insn.Op2.value))
            continue

        if insn.itype == ida_allins.NN_xor and insn.Op2.type == ida_ua.o_reg and insn.Op2.reg == insn.Op1.reg:
            return _apply_transform_ops(0, transform_ops)

        if insn.itype == ida_allins.NN_mov:
            if insn.Op2.type == ida_ua.o_imm:
                return _apply_transform_ops(insn.Op2.value, transform_ops)
            if insn.Op2.type == ida_ua.o_reg:
                tracked_reg = (ida_idp.get_reg_name(insn.Op2.reg, insn.Op2.dtype) or "").lower()
                continue
            if insn.Op2.type in (ida_ua.o_mem, ida_ua.o_displ):
                mem_addr = _resolve_memory_operand(insn, insn.Op2)
                if mem_addr is not None and ida_bytes.is_mapped(mem_addr):
                    ptr_size = 8 if ida_ida.inf_is_64bit() else 4
                    if ptr_size == 8:
                        value = ida_bytes.get_qword(mem_addr)
                    else:
                        value = ida_bytes.get_dword(mem_addr)
                    return _apply_transform_ops(value, transform_ops)

        if insn.itype == ida_allins.NN_lea and insn.Op2.type in (ida_ua.o_mem, ida_ua.o_displ):
            mem_addr = _resolve_memory_operand(insn, insn.Op2)
            if mem_addr is not None:
                return _apply_transform_ops(mem_addr, transform_ops)

        break

    return None


def _track_stack_argument(call_ea: int, stack_offset: int, max_depth: int = 40) -> Optional[int]:
    """Track stack argument written to [rsp+offset] or [rbp+offset]."""
    current_ea = call_ea
    # Compute lower search bound: function start or a safe fallback
    func = ida_funcs.get_func(call_ea)
    minea = func.start_ea if func else 0
    for _ in range(max_depth):
        current_ea = ida_bytes.prev_head(current_ea, minea)
        if current_ea == ida_idaapi.BADADDR:
            break

        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, current_ea):
            continue

        if insn.itype != ida_allins.NN_mov:
            continue

        if insn.Op1.type == ida_ua.o_displ:
            base_reg = ida_idp.get_reg_name(insn.Op1.reg, insn.Op1.dtype) or ""
            if base_reg.lower() in ("rsp", "rbp") and insn.Op1.addr == stack_offset:
                if insn.Op2.type == ida_ua.o_imm:
                    return insn.Op2.value
                if insn.Op2.type == ida_ua.o_reg:
                    reg_name = ida_idp.get_reg_name(insn.Op2.reg, insn.Op2.dtype) or ""
                    return _track_register_value_at_call(current_ea, reg_name, max_depth=max_depth)
                if insn.Op2.type in (ida_ua.o_mem, ida_ua.o_displ):
                    mem_addr = _resolve_memory_operand(insn, insn.Op2)
                    if mem_addr is not None:
                        return mem_addr

    return None


def _track_pushed_arguments(call_ea: int, param_idx: int, max_depth: int = 40) -> Optional[int]:
    """Track x86-style pushed arguments (right-to-left)."""
    current_ea = call_ea
    pushed_values: List[Optional[int]] = []
    # Compute lower search bound: function start or a safe fallback
    func = ida_funcs.get_func(call_ea)
    minea = func.start_ea if func else 0

    for _ in range(max_depth):
        current_ea = ida_bytes.prev_head(current_ea, minea)
        if current_ea == ida_idaapi.BADADDR:
            break

        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, current_ea):
            continue

        if insn.itype == ida_allins.NN_push:
            if insn.Op1.type == ida_ua.o_imm:
                pushed_values.append(insn.Op1.value)
            elif insn.Op1.type == ida_ua.o_reg:
                reg_name = ida_idp.get_reg_name(insn.Op1.reg, insn.Op1.dtype) or ""
                pushed_values.append(_track_register_value_at_call(current_ea, reg_name, max_depth=max_depth))
            elif insn.Op1.type in (ida_ua.o_mem, ida_ua.o_displ):
                mem_addr = _resolve_memory_operand(insn, insn.Op1)
                pushed_values.append(mem_addr)

            if len(pushed_values) > param_idx + 2:
                break

    if param_idx < len(pushed_values):
        return pushed_values[param_idx]
    return None


def _analyze_argument_at_call_site(call_ea: int, param_idx: int) -> Optional[int]:
    """Analyze what value is passed as a specific parameter at a call site."""
    try:
        ptr_size = 8 if ida_ida.inf_is_64bit() else 4

        if ida_ida.inf_is_64bit():
            param_regs = {0: "rcx", 1: "rdx", 2: "r8", 3: "r9"}
            if param_idx in param_regs:
                return _track_register_value_at_call(call_ea, param_regs[param_idx])

            stack_offset = 0x20 + max(0, param_idx - 4) * ptr_size
            return _track_stack_argument(call_ea, stack_offset)

        # x86: arguments typically pushed right-to-left
        return _track_pushed_arguments(call_ea, param_idx)

    except Exception:
        return None


def _is_parameter_register(operand: ida_ua.op_t, param_idx: int) -> bool:
    """Check if operand is the register for a specific parameter."""
    if operand.type != ida_ua.o_reg:
        return False
    
    reg_name = ida_idp.get_reg_name(operand.reg, operand.dtype)
    param_map = {0: ['rcx', 'ecx'], 1: ['rdx', 'edx'], 2: ['r8'], 3: ['r9']}
    
    return reg_name in param_map.get(param_idx, [])


def _is_valid_function_target(addr: int) -> bool:
    """Validate that an address is a legitimate function entry point."""
    if addr == ida_idaapi.BADADDR or addr == 0:
        return False
    
    if not ida_bytes.is_mapped(addr):
        return False
    
    seg = _cached_getseg(addr)
    if not seg or not (seg.perm & 1):  # Must be executable
        return False
    
    # Check if there's a function or code at this address
    flags = ida_bytes.get_full_flags(addr)
    if not ida_bytes.is_code(flags):
        return False
    
    return True


def _indirect_call_uses_parameter(insn: ida_ua.insn_t, context: Dict) -> bool:
    """Check if indirect call uses a parameter."""
    return context.get('source_type') == 'parameter'


def _indirect_call_uses_global(insn: ida_ua.insn_t, context: Dict) -> bool:
    """Check if indirect call uses a global variable."""
    return context.get('source_type') == 'global'


def _indirect_call_uses_call_result(insn: ida_ua.insn_t, context: Dict) -> bool:
    """Check if indirect call uses a return value from another call."""
    return context.get('source_type') == 'call_result'


def _get_parameter_index_from_context(context: Dict) -> Optional[int]:
    """Extract parameter index from analysis context."""
    return context.get('parameter_index')


def _get_global_address_from_context(context: Dict) -> Optional[int]:
    """Extract global address from analysis context."""
    return context.get('global_address')


def _get_callee_address_from_context(context: Dict) -> Optional[int]:
    """Extract callee address from analysis context."""
    return context.get('callee_address')


def clear_interprocedural_caches():
    """Clear all inter-procedural analysis caches. Call between analysis sessions."""
    analyze_function_summary.cache_clear()
    debug_print("Inter-procedural analysis caches cleared")


__all__ = [
    'FunctionSummary',
    'analyze_function_summary',
    'resolve_indirect_call_interprocedural',
    'clear_interprocedural_caches',
    'INTERPROCEDURAL_MAX_DEPTH',
]
