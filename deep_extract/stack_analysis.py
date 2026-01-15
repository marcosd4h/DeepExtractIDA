"""
Stack frame analysis utilities for PE binary analysis.
"""

import time
from typing import Dict, Any, Optional

import ida_funcs
import ida_typeinf
import ida_frame
import ida_name
import idautils
import ida_ua
import ida_idp
import ida_bytes
import ida_idaapi
try:
    import ida_allins
except ImportError:
    # Fallback for older IDA versions
    import idaapi as ida_allins

from .logging_utils import debug_print

def extract_stack_frame_info(function_ea: int) -> Optional[Dict[str, Any]]:
    """
    Extracts information about a function's stack frame.
    
    Detects stack canaries by analyzing instructions for security cookie
    checks, rather than just relying on variable names.
    """
    debug_print(f"TRACE - Starting: extract_stack_frame_info for 0x{function_ea:X}")
    start_time = time.time()
    try:
        func = ida_funcs.get_func(function_ea)
        if not func:
            return None

        frame_info: Dict[str, Any] = {
            "local_vars_size": int(getattr(func, "frsize", 0) or 0),
            "args_size": 0,
            "has_canary": False,
            "saved_regs_size": int(getattr(func, "frregs", 0) or 0),
            "exception_handler": False,
            "frame_pointer_present": bool(func.flags & ida_funcs.FUNC_FRAME),
        }

        # If available, check whether the function has EH metadata (e.g. pdata/unwind info).
        if hasattr(ida_funcs, "FUNC_EH"):
            frame_info["exception_handler"] = bool(func.flags & ida_funcs.FUNC_EH)

        # Calculate arguments size (best-effort; leave 0 if we can't infer it)
        args_size = 0
        tif = ida_typeinf.tinfo_t()
        if ida_typeinf.guess_tinfo(tif, func.start_ea):
            if tif and hasattr(tif, "is_func") and tif.is_func():
                funcdata = ida_typeinf.func_type_data_t()
                if tif.get_func_details(funcdata):
                    for i in range(funcdata.size()):
                        arg = funcdata[i]
                        if arg.type:
                            arg_size = arg.type.get_size()
                            if arg_size is not None and arg_size != -1:
                                args_size += arg_size
        frame_info["args_size"] = args_size

        # 1. Check stack variables for cookie names (legacy/fast check)
        frame_tif = ida_typeinf.tinfo_t()
        if ida_frame.get_func_frame(frame_tif, func):
            frame_udt = ida_typeinf.udt_type_data_t()
            if frame_tif.get_udt_details(frame_udt):
                for i in range(frame_udt.size()):
                    member = frame_udt[i]
                    if member.name and ("SecurityCookie" in member.name or "canary" in member.name):
                        frame_info["has_canary"] = True
                        break
        
        # 2. Instruction analysis for canary checks
        if not frame_info["has_canary"]:
            # Look for calls to security_check_cookie or XOR interactions with stack
            # Common epilogue pattern: mov rcx, [rbp+cookie]; xor rcx, rbp; call __security_check_cookie
            cookie_reference_seen = False
            recent_frame_loads = {}
            frame_regs = {"rbp", "ebp", "rsp", "esp"}

            def _is_frame_displ(op: ida_ua.op_t) -> bool:
                if op.type != ida_ua.o_displ:
                    return False
                base_reg = ida_idp.get_reg_name(op.reg, op.dtype) or ""
                return base_reg.lower() in frame_regs

            for ea in idautils.FuncItems(func.start_ea):
                insn = ida_ua.insn_t()
                if not ida_ua.decode_insn(insn, ea):
                    continue
                
                # Check for call to __security_check_cookie
                if ida_idp.is_call_insn(insn):
                    # Resolve call target
                    target_ea = insn.Op1.addr
                    if target_ea:
                        name = ida_name.get_name(target_ea)
                        if name and ("security_check_cookie" in name or "stack_chk_fail" in name):
                            frame_info["has_canary"] = True
                            break

                # Detect global cookie references (e.g., __security_cookie, __stack_chk_guard)
                for op in insn.ops:
                    if op.type == ida_ua.o_void:
                        break
                    if op.type == ida_ua.o_mem and op.addr != ida_idaapi.BADADDR:
                        name = ida_name.get_name(op.addr)
                        if name and ("security_cookie" in name or "stack_chk_guard" in name):
                            cookie_reference_seen = True
                            break
                            
                # Check for XOR with likely cookie value (stack/frame relative)
                # XOR reg, [ebp+var] where var is the cookie
                if insn.itype == ida_allins.NN_xor:
                    if insn.Op1.type == ida_ua.o_reg and _is_frame_displ(insn.Op2):
                        frame_info["has_canary"] = True
                        break
                    if insn.Op2.type == ida_ua.o_reg and _is_frame_displ(insn.Op1):
                        frame_info["has_canary"] = True
                        break
                    if insn.Op1.type == ida_ua.o_reg and insn.Op2.type == ida_ua.o_reg:
                        reg1 = (ida_idp.get_reg_name(insn.Op1.reg, insn.Op1.dtype) or "").lower()
                        reg2 = (ida_idp.get_reg_name(insn.Op2.reg, insn.Op2.dtype) or "").lower()
                        if reg1 in frame_regs and reg2 in recent_frame_loads:
                            frame_info["has_canary"] = True
                            break
                        if reg2 in frame_regs and reg1 in recent_frame_loads:
                            frame_info["has_canary"] = True
                            break

                # Track loads from the frame to correlate with XOR against frame pointer
                if insn.itype in (ida_allins.NN_mov, ida_allins.NN_lea):
                    if insn.Op1.type == ida_ua.o_reg and _is_frame_displ(insn.Op2):
                        reg_name = ida_idp.get_reg_name(insn.Op1.reg, insn.Op1.dtype)
                        if reg_name:
                            recent_frame_loads[reg_name.lower()] = ea
                        
            # 3. Check function flags
            if func.flags & ida_funcs.FUNC_FRAME:
                # FUNC_FRAME doesn't guarantee a canary, but it helps qualify cookie references
                if cookie_reference_seen and not (func.flags & ida_funcs.FUNC_LIB):
                    frame_info["has_canary"] = True

        duration = time.time() - start_time
        debug_print(f"TRACE - Finished: extract_stack_frame_info for 0x{function_ea:X}. Duration: {duration:.4f}s")
        return frame_info
    except Exception as e:
        import traceback
        debug_print(f"ERROR - Failed to extract stack frame info for function at 0x{function_ea:X}: {e}")
        debug_print(traceback.format_exc())
        return None
