"""
CFG Recovery Module

Implements: Binary → CFGRecovery → CFG
From infra.txt: "CFG Recovery (angr CFGFast)"

This module handles:
1. Recovering control flow graphs from binaries
2. Function detection and analysis
3. Basic block identification
"""

import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger('OPM.binary_analysis')

# Lazy import
_angr = None


def _get_angr():
    """Lazy import of angr."""
    global _angr
    if _angr is None:
        try:
            import angr
            _angr = angr
        except ImportError:
            raise ImportError("angr not installed. Install with: pip install angr")
    return _angr


@dataclass
class BasicBlock:
    """Represents a basic block in the CFG."""
    address: int
    size: int
    instructions: List[Dict[str, Any]] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)
    jumpkind: Optional[str] = None


@dataclass
class Function:
    """Represents a function in the binary."""
    name: str
    address: int
    size: int
    blocks: List[BasicBlock] = field(default_factory=list)
    is_plt: bool = False
    is_syscall: bool = False
    num_args: int = 0


@dataclass
class CFG:
    """Control Flow Graph container."""
    binary_path: str
    arch: str
    entry_point: int
    functions: Dict[str, Function] = field(default_factory=dict)
    blocks: Dict[int, BasicBlock] = field(default_factory=dict)
    edges: List[Tuple[int, int, str]] = field(default_factory=list)  # (src, dst, jumpkind)
    angr_cfg: Any = None  # Raw angr CFG


def recover_cfg(binary_path: str) -> CFG:
    """
    Recover control flow graph from a binary.

    Args:
        binary_path: Path to the binary file

    Returns:
        CFG object containing the recovered control flow graph
    """
    angr = _get_angr()

    logger.info(f"Recovering CFG from: {binary_path}")

    # Load binary
    proj = angr.Project(binary_path, auto_load_libs=False)

    # Recover CFG using CFGFast
    cfg_analysis = proj.analyses.CFGFast()

    logger.info(f"  Architecture: {proj.arch.name}")
    logger.info(f"  Entry point: {hex(proj.entry)}")

    # Build CFG structure
    cfg = CFG(
        binary_path=binary_path,
        arch=proj.arch.name,
        entry_point=proj.entry,
        angr_cfg=cfg_analysis
    )

    # Process functions
    for func_addr, func in cfg_analysis.functions.items():
        if func.is_plt or func.is_syscall:
            continue

        function = _process_function(func, cfg_analysis)
        cfg.functions[func.name] = function

        # Store blocks
        for block in function.blocks:
            cfg.blocks[block.address] = block

    # Build edges
    for func in cfg.functions.values():
        for block in func.blocks:
            for succ_addr in block.successors:
                cfg.edges.append((block.address, succ_addr, block.jumpkind or 'unknown'))

    logger.info(f"  Recovered {len(cfg.functions)} functions, "
                f"{len(cfg.blocks)} blocks, {len(cfg.edges)} edges")

    return cfg


def recover_cfg_function(binary_path: str, function_name: str) -> Optional[Function]:
    """
    Recover CFG for a specific function.

    Args:
        binary_path: Path to the binary file
        function_name: Name of the function

    Returns:
        Function object or None if not found
    """
    angr = _get_angr()

    logger.info(f"Recovering CFG for function '{function_name}' from: {binary_path}")

    # Load binary
    proj = angr.Project(binary_path, auto_load_libs=False)

    # Recover CFG
    cfg_analysis = proj.analyses.CFGFast()

    # Find function
    for func_addr, func in cfg_analysis.functions.items():
        if func.name == function_name:
            return _process_function(func, cfg_analysis)

    logger.warning(f"Function '{function_name}' not found")
    return None


def _process_function(func, cfg_analysis) -> Function:
    """Process an angr function into our Function structure."""
    function = Function(
        name=func.name,
        address=func.addr,
        size=func.size,
        is_plt=func.is_plt,
        is_syscall=func.is_syscall,
    )

    # Process blocks
    for block in func.blocks:
        basic_block = BasicBlock(
            address=block.addr,
            size=block.size,
        )

        # Get successors from CFG
        node = cfg_analysis.model.get_node(block.addr)
        if node is not None:
            for succ in cfg_analysis.graph.successors(node):
                basic_block.successors.append(succ.addr)

            for pred in cfg_analysis.graph.predecessors(node):
                basic_block.predecessors.append(pred.addr)

        # Get jump kind
        if node is not None:
            for succ in cfg_analysis.graph.successors(node):
                edge_data = cfg_analysis.graph.get_edge_data(node, succ)
                if edge_data and 'jumpkind' in edge_data:
                    basic_block.jumpkind = edge_data['jumpkind']
                    break

        function.blocks.append(basic_block)

    return function


def get_function_addresses(cfg: CFG) -> List[int]:
    """Get list of all function addresses."""
    return [func.address for func in cfg.functions.values()]


def get_function_by_addr(cfg: CFG, address: int) -> Optional[Function]:
    """Find function by address."""
    for func in cfg.functions.values():
        if func.address == address:
            return func
    return None


def get_block_by_addr(cfg: CFG, address: int) -> Optional[BasicBlock]:
    """Find basic block by address."""
    return cfg.blocks.get(address)


def get_successors(cfg: CFG, block_addr: int) -> List[int]:
    """Get successor blocks."""
    block = cfg.blocks.get(block_addr)
    if block:
        return block.successors
    return []


def get_predecessors(cfg: CFG, block_addr: int) -> List[int]:
    """Get predecessor blocks."""
    block = cfg.blocks.get(block_addr)
    if block:
        return block.predecessors
    return []


def get_function_blocks(cfg: CFG, function_name: str) -> List[BasicBlock]:
    """Get all blocks in a function."""
    func = cfg.functions.get(function_name)
    if func:
        return func.blocks
    return []


def get_cfg_stats(cfg: CFG) -> Dict[str, Any]:
    """Get statistics about the CFG."""
    total_blocks = len(cfg.blocks)
    total_edges = len(cfg.edges)
    total_functions = len(cfg.functions)

    # Compute average blocks per function
    avg_blocks = total_blocks / total_functions if total_functions > 0 else 0

    # Find functions with most blocks
    func_sizes = [(f.name, len(f.blocks)) for f in cfg.functions.values()]
    func_sizes.sort(key=lambda x: x[1], reverse=True)

    return {
        'total_functions': total_functions,
        'total_blocks': total_blocks,
        'total_edges': total_edges,
        'avg_blocks_per_function': avg_blocks,
        'largest_functions': func_sizes[:10],
    }


def export_cfg_dot(cfg: CFG, output_path: str):
    """Export CFG to DOT format for visualization."""
    lines = ['digraph CFG {']
    lines.append('  node [shape=box];')

    # Add nodes
    for addr, block in cfg.blocks.items():
        label = f"0x{addr:x}\\n{block.size} bytes"
        lines.append(f'  "0x{addr:x}" [label="{label}"];')

    # Add edges
    for src, dst, jk in cfg.edges:
        style = 'solid' if jk != 'Ijk_Call' else 'dashed'
        lines.append(f'  "0x{src:x}" -> "0x{dst:x}" [style={style}];')

    lines.append('}')

    with open(output_path, 'w') as f:
        f.write('\n'.join(lines))

    logger.info(f"CFG exported to: {output_path}")


# Example usage
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python cfg_recovery.py <binary_path> [--export-dot output.dot]")
        sys.exit(1)

    binary = sys.argv[1]
    export_dot = None

    if '--export-dot' in sys.argv:
        idx = sys.argv.index('--export-dot')
        if idx + 1 < len(sys.argv):
            export_dot = sys.argv[idx + 1]

    try:
        cfg = recover_cfg(binary)

        # Print stats
        stats = get_cfg_stats(cfg)
        print(f"\nCFG Statistics:")
        print(f"  Functions: {stats['total_functions']}")
        print(f"  Blocks: {stats['total_blocks']}")
        print(f"  Edges: {stats['total_edges']}")
        print(f"  Avg blocks/function: {stats['avg_blocks_per_function']:.1f}")

        print(f"\nLargest functions:")
        for name, size in stats['largest_functions'][:5]:
            print(f"  {name}: {size} blocks")

        # Export if requested
        if export_dot:
            export_cfg_dot(cfg, export_dot)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
