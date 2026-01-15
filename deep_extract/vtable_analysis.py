"""
VTable detection and C++ class reconstruction for PE binary analysis.

Vtable analysis for understanding C++ virtual
function tables, class hierarchies, and polymorphic method calls.
"""

import time
from typing import Dict, List, Optional, Any, Tuple, Set
import ida_bytes
import ida_funcs
import ida_name
import ida_segment
import ida_idaapi
import ida_ida
import ida_lines
import ida_ua
import ida_idp
try:
    import ida_allins
except ImportError:
    # Fallback for older IDA versions
    import idaapi as ida_allins

from . import constants
from .logging_utils import debug_print, _cached_getseg
from .name_extraction import get_function_name_at

def _resolve_vtable_entry(ea: int, ptr_size: int) -> Optional[Dict[str, Any]]:
    """
    Reads a pointer at a given address and resolves it to a function or address.

    This is a helper for vtable analysis. It reads a memory location, gets the name
    of the function at the target address, and returns a structured dictionary
    with details about the vtable slot.

    :param ea: The effective address of the vtable slot.
    :param ptr_size: The size of a pointer (4 or 8 bytes).
    :return: A dictionary with details about the resolved vtable entry, or None on error.
    """
    try:
        read_ptr = ida_bytes.get_qword if ptr_size == 8 else ida_bytes.get_dword
        target_addr = read_ptr(ea)

        disasm = ida_lines.generate_disasm_line(ea, 0)
        disasm = ida_lines.tag_remove(disasm) if disasm else ""

        name_info = get_function_name_at(target_addr) if target_addr and target_addr != 0 else None
        
        if name_info:
            resolved_name = name_info['long']
        elif target_addr and target_addr != 0:
            resolved_name = f"0x{target_addr:X}"
        else:
            resolved_name = "NULL"


        return {
            "slot_ea": f"0x{ea:X}",
            "points_to_ea": f"0x{target_addr:X}" if target_addr else "NULL",
            "points_to_name": resolved_name,
            "name_info": name_info,
            "disassembly": disasm
        }
    except Exception as e:
        debug_print(f"ERROR - [VTable Context] Error reading pointer at 0x{ea:X}: {e}")
        return None


def get_vtable_context(vtable_slot_ea: int) -> List[Dict[str, Any]]:
    """
    Extracts the context around a potential vtable slot to aid in class reconstruction.

    It reads a number of pointers before and after the given address, resolves them,
    and returns a list of potential virtual functions in the vicinity. This helps
    identify the full layout of a vtable.

    :param vtable_slot_ea: The effective address of a suspected vtable entry.
    :return: A list of dictionaries, where each dictionary represents a vtable slot.
    """
    debug_print(f"TRACE - Starting: get_vtable_context for 0x{vtable_slot_ea:X}")
    start_time = time.time()
    context = []
    
    ptr_size = 8 if ida_ida.inf_is_64bit() else 4

    try:
        pointers_before = 5
        pointers_after = 10

        seg = _cached_getseg(vtable_slot_ea)
        if not seg:
            debug_print(f"[VTable Context] Could not get segment for address 0x{vtable_slot_ea:X}")
            return context

        seg_start = seg.start_ea
        seg_end = seg.end_ea

        # Process pointers before the target slot
        for i in range(pointers_before, 0, -1):
            current_ea = vtable_slot_ea - (i * ptr_size)
            if current_ea < seg_start:
                continue
            
            entry = _resolve_vtable_entry(current_ea, ptr_size)
            if entry:
                entry["is_target_slot"] = False
                context.append(entry)

        # Process the target slot itself
        target_entry = _resolve_vtable_entry(vtable_slot_ea, ptr_size)
        if target_entry:
            target_entry["is_target_slot"] = True
            context.append(target_entry)

        # Process pointers after the target slot
        for i in range(1, pointers_after + 1):
            current_ea = vtable_slot_ea + (i * ptr_size)
            if current_ea >= seg_end:
                break
            
            entry = _resolve_vtable_entry(current_ea, ptr_size)
            if entry:
                entry["is_target_slot"] = False
                context.append(entry)
                
    except Exception as vtable_err:
        debug_print(f"ERROR - [VTable Context] Error processing context: {vtable_err}")
    
    duration = time.time() - start_time
    debug_print(f"TRACE - Finished: get_vtable_context for 0x{vtable_slot_ea:X}. Duration: {duration:.4f}s")
    return context


def analyze_vtable_calls(target_ea: int, target_addr: int, import_addresses: Optional[Set[int]] = None) -> Tuple[bool, List[int], Dict[str, Any]]:
    """
    Analyzes vtable calls and resolves virtual function targets.
    
    :param target_ea: The instruction address making the call
    :param target_addr: The target address being called
    :param import_addresses: Set of import addresses for context
    :return: Tuple of (is_vtable_call, resolved_targets, vtable_info)
    """
    try:
        # Avoid vtable analysis for explicit import targets
        if import_addresses and target_addr in import_addresses:
            return False, [], {}

        # Check if this looks like a vtable call pattern
        if not is_vtable_call_pattern(target_ea, target_addr):
            return False, [], {}
            
        # Analyze the vtable structure
        vtable_info = analyze_vtable_structure(target_ea, target_addr)
        if not vtable_info:
            return False, [], {}
            
        # Resolve the actual function targets from the vtable
        resolved_targets = resolve_vtable_targets(vtable_info)
        
        return True, resolved_targets, vtable_info
        
    except Exception as e:
        import traceback
        debug_print(f"ERROR - Error in vtable call analysis: {e}")
        debug_print(traceback.format_exc())
        return False, [], {}


def is_vtable_call_pattern(ea, target_addr):
    """
    Detects if an instruction represents a vtable call pattern.
    
    Common patterns:
    - call [reg + offset]     ; call through vtable
    - call [reg + reg*scale + offset]
    - call dword ptr [eax+4]
    """
    try:
        # Get the instruction
        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, ea):
            return False
            
        # Must be a call instruction
        if not ida_idp.is_call_insn(insn):
            return False
            
        # Check for indirect call through memory
        op = insn.Op1
        if op.type == ida_ua.o_displ or op.type == ida_ua.o_phrase:
            # This is an indirect call through memory - potential vtable call
            
            # Check if the displacement suggests vtable access
            if op.type == ida_ua.o_displ and op.addr != ida_idaapi.BADADDR:
                # Look for patterns like [reg + small_offset] where offset is multiple of pointer size
                ptr_size = 8 if ida_ida.inf_is_64bit() else 4
                if op.addr % ptr_size == 0 and op.addr < constants.MAX_VTABLE_OFFSET:  # Reasonable vtable offset
                    return True
                    
            # Check for computed indirect calls [reg + reg*scale + offset]
            if op.type == ida_ua.o_phrase:
                return True
                
        return False
        
    except Exception as e:
        import traceback
        debug_print(f"ERROR - Error detecting vtable pattern: {e}")
        debug_print(traceback.format_exc())
        return False


def analyze_vtable_structure(ea: int, target_addr: int) -> Dict[str, Any]:
    """
    Analyzes the vtable structure to understand the virtual function layout.
    
    :param ea: The call instruction address
    :param target_addr: The target being called
    :return: Dictionary with vtable analysis results
    """
    try:
        vtable_info = {
            'vtable_addr': ida_idaapi.BADADDR,
            'vtable_offset': 0,
            'object_reg': None,
            'method_offset': 0,
            'vtable_size': 0,
            'method_addrs': []
        }
        
        # Decode the call instruction
        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, ea):
            return {}
            
        op = insn.Op1
        
        # Analyze the operand to extract vtable information
        if op.type == ida_ua.o_displ:
            # Pattern: call [reg + offset]
            vtable_info['object_reg'] = op.reg
            vtable_info['method_offset'] = op.addr
            
            # Try to find the vtable base address through data flow analysis
            vtable_base = find_vtable_base_address(ea, op.reg)
            if vtable_base != ida_idaapi.BADADDR:
                vtable_info['vtable_addr'] = vtable_base
                vtable_info['vtable_size'] = analyze_vtable_size(vtable_base)
                vtable_info['method_addrs'] = extract_vtable_methods(vtable_base, vtable_info['vtable_size'])
                
        elif op.type == ida_ua.o_phrase:
            # More complex addressing mode
            vtable_info['object_reg'] = op.reg
            method_offset = 0
            if hasattr(op, 'addr') and op.addr not in (0, ida_idaapi.BADADDR):
                method_offset = op.addr
            elif hasattr(op, 'specval') and op.specval not in (0, ida_idaapi.BADADDR):
                method_offset = op.specval
            vtable_info['method_offset'] = method_offset if method_offset != 0 else None

            vtable_base = find_vtable_base_address(ea, op.reg)
            if vtable_base != ida_idaapi.BADADDR:
                vtable_info['vtable_addr'] = vtable_base
                vtable_info['vtable_size'] = analyze_vtable_size(vtable_base)
                vtable_info['method_addrs'] = extract_vtable_methods(vtable_base, vtable_info['vtable_size'])
                
        return vtable_info
        
    except Exception as e:
        import traceback
        debug_print(f"ERROR - Error analyzing vtable structure: {e}")
        debug_print(traceback.format_exc())
        return {}


def find_vtable_base_address(ea, obj_reg):
    """
    Attempts to find the vtable base address by analyzing data flow.
    
    :param ea: The call instruction address  
    :param obj_reg: The register holding the object pointer
    :return: Vtable base address or BADADDR
    """
    try:
        # Look backward through instructions to find vtable loading
        search_limit = constants.VTABLE_SEARCH_LIMIT
        current_ea = ea
        
        for i in range(search_limit):
            current_ea = ida_bytes.prev_head(current_ea)
            if current_ea == ida_idaapi.BADADDR:
                break
                
            insn = ida_ua.insn_t()
            if not ida_ua.decode_insn(insn, current_ea):
                continue
                
            # Look for MOV reg, [obj_reg] - loading vtable pointer
            if (insn.itype == ida_allins.NN_mov and 
                insn.Op1.type == ida_ua.o_reg and
                insn.Op2.type == ida_ua.o_displ and 
                insn.Op2.reg == obj_reg):
                
                # This might be loading the vtable pointer
                # The vtable is typically at offset 0 of the object
                if insn.Op2.addr == 0:
                    # Try to resolve the actual vtable address
                    return resolve_memory_reference(current_ea, insn.Op2)
                    
            # Look for LEA reg, vtable_symbol
            elif (insn.itype == ida_allins.NN_lea and
                  insn.Op1.type == ida_ua.o_reg and
                  insn.Op1.reg == obj_reg):
                if insn.Op2.type == ida_ua.o_mem:
                    return insn.Op2.addr
                    
        return ida_idaapi.BADADDR
        
    except Exception as e:
        debug_print(f"Error finding vtable base: {e}")
        return ida_idaapi.BADADDR


def _resolve_register_value(ea: int, reg: int) -> int:
    """Best-effort resolution of a register value by scanning backwards."""
    try:
        current_ea = ea
        tracked_reg = reg
        search_limit = constants.VTABLE_SEARCH_LIMIT
        frame_regs = {"rbp", "ebp", "rsp", "esp"}

        for _ in range(search_limit):
            current_ea = ida_bytes.prev_head(current_ea)
            if current_ea == ida_idaapi.BADADDR:
                break

            insn = ida_ua.insn_t()
            if not ida_ua.decode_insn(insn, current_ea):
                continue

            if insn.Op1.type != ida_ua.o_reg or insn.Op1.reg != tracked_reg:
                continue

            # Stop if the target register is the stack/frame pointer
            reg_name = ida_idp.get_reg_name(tracked_reg, insn.Op1.dtype) or ""
            if reg_name.lower() in frame_regs:
                return ida_idaapi.BADADDR

            if insn.itype == ida_allins.NN_mov:
                if insn.Op2.type == ida_ua.o_imm:
                    return insn.Op2.value
                if insn.Op2.type in (ida_ua.o_mem, ida_ua.o_displ):
                    eff = resolve_memory_reference(current_ea, insn.Op2)
                    if eff != ida_idaapi.BADADDR:
                        return eff
                if insn.Op2.type == ida_ua.o_reg:
                    tracked_reg = insn.Op2.reg
                    continue

            if insn.itype == ida_allins.NN_lea and insn.Op2.type in (ida_ua.o_mem, ida_ua.o_displ):
                eff = _compute_effective_address(insn, insn.Op2)
                if eff != ida_idaapi.BADADDR:
                    return eff

            break
    except Exception:
        return ida_idaapi.BADADDR

    return ida_idaapi.BADADDR


def _compute_effective_address(insn: ida_ua.insn_t, operand: Any) -> int:
    """Compute an absolute address for memory operands when possible."""
    if operand.type == ida_ua.o_mem:
        return operand.addr
    if operand.type == ida_ua.o_displ:
        base_reg = ida_idp.get_reg_name(operand.reg, operand.dtype) or ""
        disp = ida_idaapi.as_signed(operand.addr, 32)
        if base_reg.lower() in ("rip", "eip"):
            return insn.ea + insn.size + disp
    return ida_idaapi.BADADDR


def resolve_memory_reference(ea: int, operand: Any) -> int:
    """
    Resolves a memory reference to get the actual address.
    
    :param ea: Instruction address
    :param operand: The memory operand
    :return: Resolved address or BADADDR
    """
    try:
        if operand.type == ida_ua.o_mem:
            return operand.addr
        elif operand.type == ida_ua.o_displ:
            insn = ida_ua.insn_t()
            if not ida_ua.decode_insn(insn, ea):
                return ida_idaapi.BADADDR

            base_reg = ida_idp.get_reg_name(operand.reg, operand.dtype) or ""
            disp = ida_idaapi.as_signed(operand.addr, 32)

            if base_reg.lower() in ("rip", "eip"):
                eff_addr = insn.ea + insn.size + disp
            else:
                base_val = _resolve_register_value(ea, operand.reg)
                if base_val == ida_idaapi.BADADDR:
                    return ida_idaapi.BADADDR
                eff_addr = base_val + disp

            if not ida_bytes.is_mapped(eff_addr):
                return ida_idaapi.BADADDR

            ptr_size = 8 if ida_ida.inf_is_64bit() else 4
            if ptr_size == 8:
                return ida_bytes.get_qword(eff_addr)
            return ida_bytes.get_dword(eff_addr)
        return ida_idaapi.BADADDR
        
    except Exception:
        return ida_idaapi.BADADDR


def analyze_vtable_size(vtable_addr: int) -> int:
    """
    Determines the size of a vtable by analyzing the function pointer array.
    
    :param vtable_addr: Address of the vtable
    :return: Number of entries in the vtable
    """
    try:
        if vtable_addr == ida_idaapi.BADADDR:
            return 0
            
        ptr_size = 8 if ida_ida.inf_is_64bit() else 4
        size = 0
        current_addr = vtable_addr
        
        # Scan the vtable until we hit invalid pointers
        max_entries = constants.JUMP_TABLE_MAX_ENTRIES
        
        for i in range(max_entries):
            # Read the pointer value
            if ptr_size == 8:
                ptr_val = ida_bytes.get_qword(current_addr)
            else:
                ptr_val = ida_bytes.get_dword(current_addr)
                
            # Check if this looks like a valid function pointer
            if not is_valid_function_pointer(ptr_val):
                break
                
            size += 1
            current_addr += ptr_size
            
        return size
        
    except Exception as e:
        import traceback
        debug_print(f"ERROR - Error analyzing vtable size: {e}")
        debug_print(traceback.format_exc())
        return 0


def is_valid_function_pointer(addr: int) -> bool:
    """
    Checks if an address looks like a valid function pointer.
    
    :param addr: Address to check
    :return: True if it looks like a valid function pointer
    """
    try:
        if addr == 0 or addr == ida_idaapi.BADADDR:
            return False
            
        # Check if it's in a valid code segment
        seg = _cached_getseg(addr)
        if not seg:
            return False
            
        # Check if segment is executable
        if not (seg.perm & ida_segment.SEGPERM_EXEC):
            return False
            
        # Check if there's a function at this address
        func = ida_funcs.get_func(addr)
        if func:
            return True
            
        # Check if it's the start of code
        flags = ida_bytes.get_flags(addr)
        if ida_bytes.is_code(flags):
            return True
            
        return False
        
    except Exception:
        return False


def extract_vtable_methods(vtable_addr, vtable_size):
    """
    Extracts the method addresses from a vtable.
    
    :param vtable_addr: Address of the vtable
    :param vtable_size: Number of entries in the vtable  
    :return: List of method addresses
    """
    try:
        methods = []
        if vtable_addr == ida_idaapi.BADADDR or vtable_size == 0:
            return methods
            
        ptr_size = 8 if ida_ida.inf_is_64bit() else 4
        current_addr = vtable_addr
        
        for i in range(vtable_size):
            # Read the function pointer
            if ptr_size == 8:
                method_addr = ida_bytes.get_qword(current_addr)
            else:
                method_addr = ida_bytes.get_dword(current_addr)
                
            if is_valid_function_pointer(method_addr):
                methods.append(method_addr)
                
            current_addr += ptr_size
            
        return methods
        
    except Exception as e:
        debug_print(f"Error extracting vtable methods: {e}")
        return []


def resolve_vtable_targets(vtable_info: Dict[str, Any]) -> List[int]:
    """
    Resolves the actual function targets from vtable information.
    
    :param vtable_info: Dictionary with vtable analysis results
    :return: List of resolved target addresses
    """
    try:
        targets = []
        
        if not vtable_info or vtable_info.get('vtable_addr') == ida_idaapi.BADADDR:
            return targets
            
        method_offset = vtable_info.get('method_offset', 0)
        vtable_addr = vtable_info['vtable_addr']
        
        # Calculate the specific method address
        ptr_size = 8 if ida_ida.inf_is_64bit() else 4
        if method_offset is None:
            return [addr for addr in vtable_info.get('method_addrs', []) if is_valid_function_pointer(addr)]
        method_slot = method_offset // ptr_size
        
        methods = vtable_info.get('method_addrs', [])
        if method_slot < len(methods):
            target_addr = methods[method_slot]
            if is_valid_function_pointer(target_addr):
                targets.append(target_addr)
                
        return targets
        
    except Exception as e:
        import traceback
        debug_print(f"ERROR - Error resolving vtable targets: {e}")
        debug_print(traceback.format_exc())
        return []
