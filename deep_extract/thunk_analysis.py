"""
Thunk resolution utilities for PE binary analysis.
"""

from typing import Optional
import ida_funcs
import idc
import ida_idaapi
import ida_ua
import ida_idp

from . import constants
from .logging_utils import debug_print

# --- Thunk resolution configuration ---
_DEFAULT_THUNK_DEPTH = constants.DEFAULT_THUNK_DEPTH

def set_max_thunk_depth(depth: int) -> None:
    """Allow external scripts to override the maximum thunk-chase depth."""
    global _DEFAULT_THUNK_DEPTH
    try:
        depth_int = int(depth)
        if depth_int > 0:
            _DEFAULT_THUNK_DEPTH = depth_int
            debug_print(f"INFO - Thunk chase depth overridden -> {_DEFAULT_THUNK_DEPTH}")
    except Exception as e:
        debug_print(f"WARNING - Invalid thunk depth '{depth}': {e}")

def _get_max_thunk_depth() -> int:
    """Internal helper – determine the current configured thunk chase depth."""
    return _DEFAULT_THUNK_DEPTH

def resolve_thunk_target(thunk_ea: int, max_depth: Optional[int] = None) -> int:
    """
    Resolves a thunk function to its final target by following the chain.
    
    Decodes instructions to resolve thunks more reliably
    instead of blindly reading operands.
    """
    if max_depth is None:
        max_depth = _get_max_thunk_depth()
    visited = set()
    current_ea = thunk_ea

    for _ in range(max_depth):
        if current_ea in visited:
            debug_print(f"TRACE - Thunk cycle detected at 0x{current_ea:X}. Stopping resolution.")
            break
        visited.add(current_ea)

        func = ida_funcs.get_func(current_ea)
        if not func or not (func.flags & ida_funcs.FUNC_THUNK):
            break

        # Check if IDA can resolve it automatically (newer API)
        if hasattr(ida_funcs, 'calc_thunk_target'):
            target = ida_funcs.calc_thunk_target(current_ea)
            if target != ida_idaapi.BADADDR:
                current_ea = target
                continue

        # Manual resolution with instruction decoding
        first_insn_ea = func.start_ea
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, first_insn_ea):
            # Check if it's a branch instruction (JMP or CALL)
            if ida_idp.is_indirect_jump_insn(insn) or ida_idp.is_call_insn(insn) or insn.itype == ida_idp.NN_jmp:
                # Target is usually in the first operand
                if insn.Op1.type in [ida_ua.o_near, ida_ua.o_far, ida_ua.o_mem]:
                    target = insn.Op1.addr
                    if target != ida_idaapi.BADADDR:
                        current_ea = target
                        continue
                elif insn.Op1.type == ida_ua.o_reg:
                    # Register jump - hard to resolve statically without data flow
                    break
            else:
                # Not a simple branch thunk (maybe complex logic), stop here
                break
        else:
            # Failed to decode
            break
            
        break

    return current_ea
