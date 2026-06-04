"""
Call Analysis Module

Implements function call detection and call graph construction.
This is essential for taint analysis to track data flow between functions.
"""

import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger('OPM.binary_analysis')


@dataclass
class CallSite:
    """A function call site."""
    address: int              # Address of the call instruction
    caller: str               # Calling function name
    callee: str               # Called function name
    callee_addr: int          # Address of called function
    is_indirect: bool = False # Whether this is an indirect call
    arguments: List[int] = field(default_factory=list)  # Argument registers/offsets


@dataclass
class CallGraph:
    """Call graph representation."""
    # call_site_addr -> CallSite
    call_sites: Dict[int, CallSite] = field(default_factory=dict)
    # caller_name -> set of callee_names
    callers: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    # callee_name -> set of caller_names
    callees: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    # function_name -> list of call sites in that function
    function_calls: Dict[str, List[CallSite]] = field(default_factory=lambda: defaultdict(list))


def analyze_calls(binary_path: str, cfg: Any) -> CallGraph:
    """
    Analyze function calls in the binary.

    Args:
        binary_path: Path to the binary
        cfg: Control flow graph

    Returns:
        CallGraph with call information
    """
    logger.info("Analyzing function calls")

    call_graph = CallGraph()

    # Get function addresses for lookup (internal functions)
    func_addr_to_name = {}
    for func_name, func in cfg.functions.items():
        func_addr_to_name[func.address] = func_name

    # Also add external/library functions from angr's knowledge base
    # These are typically at higher addresses (0x500000+ for Windows PE)
    if hasattr(cfg, 'angr_cfg') and cfg.angr_cfg is not None:
        for addr, func in cfg.angr_cfg.functions.items():
            if addr not in func_addr_to_name:
                func_addr_to_name[addr] = func.name

    # Analyze each function
    for func_name, func in cfg.functions.items():
        _analyze_function_calls(func, func_name, func_addr_to_name, call_graph)

    logger.info(f"Call analysis complete: {len(call_graph.call_sites)} call sites, "
                f"{len(call_graph.callers)} callers, {len(call_graph.callees)} callees")

    return call_graph


def _analyze_function_calls(
    func: Any,
    func_name: str,
    func_addr_to_name: Dict[int, str],
    call_graph: CallGraph
):
    """Analyze calls in a single function."""
    # Check each block for call instructions
    for block in func.blocks:
        # Look for call patterns in the block
        # In x86/x64, CALL instruction is 0xE8 (relative) or 0xFF (indirect)

        # For Windows PE, we need to check the block's successors
        # If a successor is a function entry point, it's likely a call
        for succ_addr in block.successors:
            if succ_addr in func_addr_to_name:
                callee_name = func_addr_to_name[succ_addr]

                # Skip self-calls
                if callee_name == func_name:
                    continue

                # Create call site
                call_site = CallSite(
                    address=block.address,  # Approximate - real implementation would find exact call instruction
                    caller=func_name,
                    callee=callee_name,
                    callee_addr=succ_addr,
                    is_indirect=False
                )

                # Add to call graph
                call_graph.call_sites[block.address] = call_site
                call_graph.callers[func_name].add(callee_name)
                call_graph.callees[callee_name].add(func_name)
                call_graph.function_calls[func_name].append(call_site)


def get_callers(call_graph: CallGraph, func_name: str) -> Set[str]:
    """Get all functions that call the given function."""
    # callees maps callee -> set of callers
    return call_graph.callees.get(func_name, set())


def get_callees(call_graph: CallGraph, func_name: str) -> Set[str]:
    """Get all functions called by the given function."""
    # callers maps caller -> set of callees
    return call_graph.callers.get(func_name, set())


def get_call_path(call_graph: CallGraph, source: str, sink: str) -> Optional[List[str]]:
    """
    Find a call path from source to sink function.

    Args:
        call_graph: Call graph
        source: Source function name
        sink: Sink function name

    Returns:
        List of function names forming the path, or None if no path exists
    """
    # BFS to find path
    visited = set()
    queue = [(source, [source])]

    while queue:
        current, path = queue.pop(0)

        if current == sink:
            return path

        if current in visited:
            continue
        visited.add(current)

        # Get callees
        for callee in get_callees(call_graph, current):
            if callee not in visited:
                queue.append((callee, path + [callee]))

    return None


def get_call_depth(call_graph: CallGraph, func_name: str) -> int:
    """Get the maximum call depth from the given function."""
    visited = set()

    def _dfs(name: str, depth: int) -> int:
        if name in visited:
            return depth
        visited.add(name)

        max_depth = depth
        for callee in get_callees(call_graph, name):
            max_depth = max(max_depth, _dfs(callee, depth + 1))

        visited.remove(name)
        return max_depth

    return _dfs(func_name, 0)


def is_library_function(func_name: str) -> bool:
    """Check if a function is a library function."""
    # Common C library functions
    lib_funcs = {
        'printf', 'fprintf', 'sprintf', 'snprintf',
        'scanf', 'fscanf', 'sscanf',
        'strcpy', 'strncpy', 'strcat', 'strncat',
        'strlen', 'strcmp', 'strncmp',
        'memcpy', 'memmove', 'memset', 'memcmp',
        'malloc', 'calloc', 'realloc', 'free',
        'fopen', 'fclose', 'fread', 'fwrite',
        'getchar', 'gets', 'fgets', 'puts', 'fputs',
        'system', 'popen', 'exec',
        'exit', 'abort', 'atexit',
        'signal', 'raise',
    }
    return func_name in lib_funcs


def get_source_functions() -> Set[str]:
    """Get set of known source functions (input sources)."""
    return {
        'getchar', 'gets', 'scanf', 'fscanf', 'sscanf',
        'fgets', 'gets_s', 'scanf_s',
        'read', 'recv', 'recvfrom', 'recvmsg',
        'getenv', 'getlogin', 'getpwuid',
        'fread', 'fgetc', 'getc', 'getw',
        'getline', 'getdelim',
    }


def get_sink_functions() -> Set[str]:
    """Get set of known sink functions (dangerous operations)."""
    return {
        'strcpy', 'strncpy', 'strcat', 'strncat',
        'sprintf', 'snprintf', 'vsprintf', 'vsnprintf',
        'printf', 'fprintf', 'vprintf', 'vfprintf',
        'system', 'popen', 'exec', 'execl', 'execlp',
        'execle', 'execv', 'execvp', 'execvpe',
        'malloc', 'calloc', 'realloc', 'free',
        'memcpy', 'memmove', 'memset',
        'gets',
    }


def get_propagation_functions() -> Dict[str, str]:
    """
    Get functions that propagate taint.
    Returns dict of function_name -> taint_propagation_type
    """
    return {
        'strcpy': 'propagate',     # Both args propagate
        'strncpy': 'propagate',    # Both args propagate
        'strcat': 'propagate',     # Both args propagate
        'memcpy': 'propagate',     # Both args propagate
        'memmove': 'propagate',    # Both args propagate
        'sprintf': 'propagate',    # Format string + args propagate
        'snprintf': 'propagate',   # Format string + args propagate
        'printf': 'sink_only',     # Only format string is sink
        'fprintf': 'sink_only',    # Only format string is sink
        'strlen': 'propagate',     # Input propagates to return
        'strcmp': 'no_propagate',  # Comparison, no propagation
        'strncmp': 'no_propagate', # Comparison, no propagation
    }


def print_call_graph_summary(call_graph: CallGraph):
    """Print a summary of the call graph."""
    print("\n" + "=" * 60)
    print("CALL GRAPH SUMMARY")
    print("=" * 60)
    print(f"Total call sites: {len(call_graph.call_sites)}")
    print(f"Functions with callers: {len(call_graph.callers)}")
    print(f"Functions with callees: {len(call_graph.callees)}")

    # Find source and sink functions
    sources = get_source_functions()
    sinks = get_sink_functions()

    found_sources = set()
    found_sinks = set()

    for func_name in call_graph.callees.keys():
        if func_name in sources:
            found_sources.add(func_name)
        if func_name in sinks:
            found_sinks.add(func_name)

    print(f"\nSource functions found: {found_sources}")
    print(f"Sink functions found: {found_sinks}")

    # Find call paths
    if found_sources and found_sinks:
        print("\nPotential taint paths:")
        for source in found_sources:
            for sink in found_sinks:
                path = get_call_path(call_graph, source, sink)
                if path:
                    print(f"  {' -> '.join(path)}")

    print("=" * 60)
