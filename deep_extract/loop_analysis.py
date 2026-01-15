"""
Loop detection utilities for PE binary analysis.

This module uses Tarjan's strongly connected components (SCC) algorithm for
O(V+E) loop detection and supports configurable limits with logging for large
functions.
"""

from typing import Dict, List, Tuple, Any, Optional
import ida_funcs
import ida_bytes
import ida_ua
import ida_idp
try:
    import ida_gdl
    HAS_LOOP_DETECTOR = True
except ImportError:
    HAS_LOOP_DETECTOR = False

from .logging_utils import debug_print
from . import constants


def extract_loop_analysis(function_ea: int, 
                         quantity_limit: bool = True, 
                         chunk_quantity: Optional[int] = None,
                         config: Optional[Any] = None) -> Dict[str, Any]:
    """
    Analyzes the control flow graph of a function to identify all loops using
    Tarjan's strongly connected components (SCC) algorithm for O(V+E) complexity.
    
    Supports configurable limits and logging when large functions are skipped.

    :param function_ea: The starting effective address of the function.
    :param quantity_limit: A flag to limit analysis on huge functions.
    :param chunk_quantity: The block count threshold to trigger the limit.
                          If None, uses DEFAULT_LOOP_BLOCK_LIMIT from constants.
    :param config: Optional AnalysisConfig object to get limit from config.
    :return: A dictionary containing the loops found and a count of them.
    """
    if not HAS_LOOP_DETECTOR:
        return {"error": "ida_gdl module not available", "loops": [], "loop_count": 0}
    
    # Determine chunk quantity limit
    if chunk_quantity is None:
        # Try to get from config first
        if config and hasattr(config, 'loop_block_limit'):
            chunk_quantity = config.loop_block_limit
        else:
            # Fall back to constant
            chunk_quantity = constants.DEFAULT_LOOP_BLOCK_LIMIT
    
    try:
        func = ida_funcs.get_func(function_ea)
        if not func:
            return {"error": "Function not found.", "loops": [], "loop_count": 0}

        f = ida_gdl.FlowChart(func)
        
        # Logging for large functions
        if quantity_limit and f.size > chunk_quantity:
            func_name = ida_funcs.get_func_name(function_ea) or f"sub_{function_ea:X}"
            
            # Determine severity of skip
            if f.size > constants.LOOP_ANALYSIS_WARNING_THRESHOLD:
                # This is a notably large function - log as warning
                debug_print(f"WARNING - Skipping loop analysis for large function '{func_name}' "
                           f"at 0x{function_ea:X}: {f.size} basic blocks exceeds limit of {chunk_quantity}. "
                           f"Large functions may contain security-critical loops. "
                           f"Consider increasing limit or analyzing this function manually.")
            else:
                # Just informational
                debug_print(f"INFO - Skipping loop analysis for function '{func_name}' "
                           f"at 0x{function_ea:X}: {f.size} basic blocks exceeds limit of {chunk_quantity}.")
            
            return {
                "loops": [], 
                "loop_count": 0, 
                "skipped": True, 
                "reason": "block_limit_exceeded",
                "block_count": f.size,
                "limit": chunk_quantity,
                "function_name": func_name
            }
        
        block_id = {}
        id_to_block = {}
        successors = {}
        
        for idx, block in enumerate(f):
            key = (block.start_ea, block.end_ea)
            block_id[key] = idx
            id_to_block[idx] = key
            successors[idx] = []
        
        for block in f:
            key = (block.start_ea, block.end_ea)
            src_id = block_id[key]
            for succ in block.succs():
                succ_key = (succ.start_ea, succ.end_ea)
                if succ_key in block_id:
                    successors[src_id].append(block_id[succ_key])
        
        n = len(block_id)
        predecessors = {idx: [] for idx in block_id.values()}
        for src_id, succs in successors.items():
            for dst_id in succs:
                predecessors[dst_id].append(src_id)

        entry_id = None
        for block in f:
            if block.start_ea <= func.start_ea < block.end_ea:
                entry_id = block_id[(block.start_ea, block.end_ea)]
                break

        # Compute SCCs for fallback (irreducible loops)
        index_counter = [0]
        stack = []
        lowlinks = [0] * n
        indices = [-1] * n
        on_stack = [False] * n
        sccs = []

        def strongconnect(v):
            indices[v] = index_counter[0]
            lowlinks[v] = index_counter[0]
            index_counter[0] += 1
            stack.append(v)
            on_stack[v] = True

            for w in successors[v]:
                if indices[w] == -1:
                    strongconnect(w)
                    lowlinks[v] = min(lowlinks[v], lowlinks[w])
                elif on_stack[w]:
                    lowlinks[v] = min(lowlinks[v], indices[w])

            if lowlinks[v] == indices[v]:
                scc = []
                while True:
                    w = stack.pop()
                    on_stack[w] = False
                    scc.append(w)
                    if w == v:
                        break
                if len(scc) > 1:
                    sccs.append(scc)
                elif len(scc) == 1:
                    v_node = scc[0]
                    if v_node in successors[v_node]:
                        sccs.append(scc)

        for v in range(n):
            if indices[v] == -1:
                strongconnect(v)

        # Dominator-based back edges for natural loop detection
        dominators = None
        back_edges = []
        if entry_id is not None:
            dominators = {v: set(range(n)) for v in range(n)}
            dominators[entry_id] = {entry_id}

            changed = True
            while changed:
                changed = False
                for v in range(n):
                    if v == entry_id:
                        continue
                    preds = predecessors.get(v, [])
                    if not preds:
                        new_dom = {v}
                    else:
                        new_dom = set(range(n))
                        for p in preds:
                            new_dom &= dominators[p]
                        new_dom.add(v)
                    if new_dom != dominators[v]:
                        dominators[v] = new_dom
                        changed = True

            for u in range(n):
                for v in successors[u]:
                    if v in dominators[u]:
                        back_edges.append((u, v))

        # Build natural loops from back edges; fall back to SCCs if needed
        loop_sets = []
        if back_edges:
            loops_by_nodes = {}
            for u, v in back_edges:
                loop_nodes = {u, v}
                work = [u]
                while work:
                    m = work.pop()
                    for p in predecessors.get(m, []):
                        if p not in loop_nodes:
                            loop_nodes.add(p)
                            if p != v:
                                work.append(p)
                key = frozenset(loop_nodes)
                if key not in loops_by_nodes:
                    loops_by_nodes[key] = loop_nodes
            loop_sets = list(loops_by_nodes.values())
        else:
            loop_sets = [set(scc) for scc in sccs]

        # Compute nesting levels based on loop containment
        nesting_levels = []
        for i, loop_nodes in enumerate(loop_sets):
            level = 0
            for j, other in enumerate(loop_sets):
                if i == j:
                    continue
                if loop_nodes.issubset(other) and loop_nodes != other:
                    level += 1
            nesting_levels.append(level)

        def _count_back_edges(loop_nodes: set) -> int:
            if back_edges:
                return sum(1 for u, v in back_edges if u in loop_nodes and v in loop_nodes)
            visited = set()
            stack_set = set()
            count = 0

            def dfs(node_id):
                nonlocal count
                visited.add(node_id)
                stack_set.add(node_id)
                for succ_id in successors[node_id]:
                    if succ_id not in loop_nodes:
                        continue
                    if succ_id not in visited:
                        dfs(succ_id)
                    elif succ_id in stack_set:
                        count += 1
                stack_set.remove(node_id)

            for node_id in loop_nodes:
                if node_id not in visited:
                    dfs(node_id)
            return count

        # Loop Analysis: Metrics & Behavior
        processed_loops = []
        for loop_idx, loop_nodes in enumerate(loop_sets):
            # Basic structural metrics
            num_blocks = len(loop_nodes)

            # Analyze contents of the loop blocks
            instruction_count = 0
            has_calls = False
            memory_access = False
            exit_edges = 0

            # Traverse all blocks in the loop
            for node_id in loop_nodes:
                # Get block address range
                start_ea, end_ea = id_to_block[node_id]
                
                # Instruction analysis
                # Iterate instructions in the block
                head = start_ea
                while head < end_ea:
                    instruction_count += 1
                    
                    # Decode instruction for detailed analysis
                    insn = ida_ua.insn_t()
                    if ida_ua.decode_insn(insn, head):
                        # Check for calls
                        if ida_idp.is_call_insn(insn):
                            has_calls = True
                        
                        # Check for memory access (heuristic for common x86/x64 mem operands)
                        if not memory_access:
                            # Check operands for memory reference
                            for op in insn.ops:
                                if op.type == ida_ua.o_void: break
                                if op.type in (ida_ua.o_mem, ida_ua.o_phrase, ida_ua.o_displ):
                                    memory_access = True
                                    break
                    
                    head = ida_bytes.next_head(head, end_ea)
                
                # Edge analysis (Exits)
                for succ_id in successors[node_id]:
                    if succ_id not in loop_nodes:
                        exit_edges += 1

            # Estimate Complexity
            # High: Many blocks or many instructions
            if num_blocks > 10 or instruction_count > 100:
                complexity = "high"
            elif num_blocks > 3 or instruction_count > 20:
                complexity = "medium"
            else:
                complexity = "low"
            
            # Is Infinite?
            # Heuristic: If there are NO exit edges, it's likely an infinite loop 
            # (or a function that never returns, e.g. calls exit())
            is_infinite = (exit_edges == 0)

            # Cyclomatic Complexity of the loop body
            # E - N + 2P. Here P=1 (connected component).
            # We need internal edges count (E) and nodes (N=num_blocks).
            # Let's count internal edges exactly.
            internal_edges = 0
            for node_id in loop_nodes:
                for succ_id in successors[node_id]:
                    if succ_id in loop_nodes:
                        internal_edges += 1
            
            cyclomatic = internal_edges - num_blocks + 2
            
            back_edges_count = _count_back_edges(loop_nodes)

            processed_loops.append({
                "complexity": complexity,
                "block_count": num_blocks,
                "instruction_count": instruction_count,
                "has_function_calls": has_calls,
                "memory_access": memory_access,
                "is_infinite": is_infinite,
                "exit_condition_count": exit_edges,
                "cyclomatic_complexity": cyclomatic,
                "back_edges": back_edges_count,
                "nesting_level": nesting_levels[loop_idx] if loop_idx < len(nesting_levels) else 0,
            })

        return {"loops": processed_loops, "loop_count": len(processed_loops)}
    except Exception as e:
        debug_print(f"ERROR - [Loop Analysis] for 0x{function_ea:X}: {str(e)}")
        return {"error": str(e), "loops": [], "loop_count": 0}

