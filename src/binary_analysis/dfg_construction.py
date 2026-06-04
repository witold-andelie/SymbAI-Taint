"""
DFG Construction Module

Implements: VEX IR + CFG → DFGConstruction → DFG
From infra.txt: "DFG Construction"

This module handles:
1. Constructing data flow graphs from VEX IR
2. Tracking register and memory dependencies
3. Building use-def chains
"""

import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger('OPM.binary_analysis')


@dataclass
class DFGNode:
    """Node in the data flow graph."""
    id: int
    address: int
    operation: str  # 'register_read', 'register_write', 'memory_read', 'memory_write', 'operation'
    operand: Optional[str] = None  # Register name or memory address
    value: Optional[Any] = None
    size: int = 0
    block_addr: int = 0


@dataclass
class DFGEdge:
    """Edge in the data flow graph."""
    source: int  # Node ID
    target: int  # Node ID
    type: str  # 'data_flow', 'address_flow', 'control_flow'
    label: Optional[str] = None


@dataclass
class DFG:
    """Data Flow Graph container."""
    nodes: Dict[int, DFGNode] = field(default_factory=dict)
    edges: List[DFGEdge] = field(default_factory=list)
    # Adjacency lists for fast lookup
    successors: Dict[int, List[int]] = field(default_factory=lambda: defaultdict(list))
    predecessors: Dict[int, List[int]] = field(default_factory=lambda: defaultdict(list))
    # Register definitions
    reg_defs: Dict[str, List[int]] = field(default_factory=lambda: defaultdict(list))
    # Memory definitions
    mem_defs: Dict[int, List[int]] = field(default_factory=lambda: defaultdict(list))
    # Next node ID
    _next_id: int = 0

    def add_node(self, node: DFGNode) -> int:
        """Add a node and return its ID."""
        node.id = self._next_id
        self._next_id += 1
        self.nodes[node.id] = node
        return node.id

    def add_edge(self, source: int, target: int, edge_type: str, label: Optional[str] = None):
        """Add an edge between nodes."""
        edge = DFGEdge(source=source, target=target, type=edge_type, label=label)
        self.edges.append(edge)
        self.successors[source].append(target)
        self.predecessors[target].append(source)

    def get_node(self, node_id: int) -> Optional[DFGNode]:
        """Get node by ID."""
        return self.nodes.get(node_id)

    def get_successors(self, node_id: int) -> List[DFGNode]:
        """Get successor nodes."""
        return [self.nodes[nid] for nid in self.successors.get(node_id, []) if nid in self.nodes]

    def get_predecessors(self, node_id: int) -> List[DFGNode]:
        """Get predecessor nodes."""
        return [self.nodes[nid] for nid in self.predecessors.get(node_id, []) if nid in self.nodes]


def construct_dfg(vex_ir: Any, cfg: Any) -> DFG:
    """
    Construct data flow graph from VEX IR and CFG.

    Args:
        vex_ir: VEX IR container (from vex_lift module)
        cfg: Control Flow Graph (from cfg_recovery module)

    Returns:
        DFG object containing the data flow graph
    """
    logger.info("Constructing DFG from VEX IR and CFG")

    dfg = DFG()

    # Process each function
    for func_name, func in vex_ir.functions.items():
        _process_function_dfg(func, dfg, cfg)

    logger.info(f"  DFG constructed: {len(dfg.nodes)} nodes, {len(dfg.edges)} edges")
    return dfg


def construct_function_dfg(vex_ir: Any, function_name: str) -> Optional[DFG]:
    """
    Construct DFG for a specific function.

    Args:
        vex_ir: VEX IR container
        function_name: Name of the function

    Returns:
        DFG for the function or None if not found
    """
    logger.info(f"Constructing DFG for function: {function_name}")

    func = vex_ir.functions.get(function_name)
    if func is None:
        logger.warning(f"Function '{function_name}' not found")
        return None

    dfg = DFG()
    _process_function_dfg(func, dfg, None)

    logger.info(f"  Function DFG: {len(dfg.nodes)} nodes, {len(dfg.edges)} edges")
    return dfg


def _process_function_dfg(func: Any, dfg: DFG, cfg: Any):
    """Process a function and add its nodes/edges to the DFG."""
    # Track register and memory state
    reg_state: Dict[int, int] = {}  # register offset -> last node ID
    mem_state: Dict[int, int] = {}  # memory address -> last node ID

    # Process each block in order
    for block in func.blocks:
        _process_block_dfg(block, dfg, reg_state, mem_state)


def _process_block_dfg(block: Any, dfg: DFG, reg_state: Dict[int, int], mem_state: Dict[int, int]):
    """Process a basic block and add nodes/edges to the DFG."""
    irsb = block.irsb

    if irsb is None:
        return

    # Process each IR statement
    for stmt in irsb.statements:
        _process_statement(stmt, block.address, dfg, reg_state, mem_state, irsb)


def _process_statement(stmt: Any, block_addr: int, dfg: DFG,
                       reg_state: Dict[int, int], mem_state: Dict[int, int], irsb: Any = None):
    """Process an IR statement and add to DFG."""
    stmt_type = type(stmt).__name__

    # Handle different statement types
    if stmt_type == 'Put':
        # Register write: Put(offset, data)
        offset = stmt.offset
        data_node_id = _process_expression(stmt.data, block_addr, dfg, reg_state, mem_state)

        # Get size safely
        size = 0
        if irsb and hasattr(stmt.data, 'result_size'):
            try:
                size = stmt.data.result_size(irsb.tyenv)
            except:
                size = 0

        node = DFGNode(
            id=0,  # Will be assigned
            address=block_addr,
            operation='register_write',
            operand=f"reg_{offset}",
            size=size,
            block_addr=block_addr
        )
        node_id = dfg.add_node(node)
        dfg.reg_defs[f"reg_{offset}"].append(node_id)

        # Add data flow edge
        if data_node_id is not None:
            dfg.add_edge(data_node_id, node_id, 'data_flow')

        # Add flow from previous definition
        if offset in reg_state:
            dfg.add_edge(reg_state[offset], node_id, 'data_flow', 'redefinition')

        reg_state[offset] = node_id

    elif stmt_type == 'Store':
        # Memory write: Store(addr, data)
        addr_node_id = _process_expression(stmt.addr, block_addr, dfg, reg_state, mem_state)
        data_node_id = _process_expression(stmt.data, block_addr, dfg, reg_state, mem_state)

        # Get size safely
        size = 0
        if irsb and hasattr(stmt.data, 'result_size'):
            try:
                size = stmt.data.result_size(irsb.tyenv)
            except:
                size = 0

        node = DFGNode(
            id=0,
            address=block_addr,
            operation='memory_write',
            size=size,
            block_addr=block_addr
        )
        node_id = dfg.add_node(node)

        # Add address and data flow edges
        if addr_node_id is not None:
            dfg.add_edge(addr_node_id, node_id, 'address_flow')
        if data_node_id is not None:
            dfg.add_edge(data_node_id, node_id, 'data_flow')

    elif stmt_type == 'IMark':
        # Instruction marker - skip
        pass

    elif stmt_type == 'AbiHint':
        # ABI hint - skip
        pass

    elif stmt_type == 'CAS':
        # Compare-and-swap
        node = DFGNode(
            id=0,
            address=block_addr,
            operation='cas',
            block_addr=block_addr
        )
        node_id = dfg.add_node(node)

    elif stmt_type == 'LLSC':
        # Load-linked/store-conditional
        node = DFGNode(
            id=0,
            address=block_addr,
            operation='llsc',
            block_addr=block_addr
        )
        node_id = dfg.add_node(node)


def _process_expression(expr: Any, block_addr: int, dfg: DFG,
                        reg_state: Dict[int, int], mem_state: Dict[int, int]) -> Optional[int]:
    """Process an IR expression and return node ID."""
    if expr is None:
        return None

    expr_type = type(expr).__name__

    if expr_type == 'RdTmp':
        # Read from temporary - skip for now
        return None

    elif expr_type == 'Get':
        # Register read: Get(offset, ty)
        offset = expr.offset

        node = DFGNode(
            id=0,
            address=block_addr,
            operation='register_read',
            operand=f"reg_{offset}",
            block_addr=block_addr
        )
        node_id = dfg.add_node(node)

        # Add flow from last definition
        if offset in reg_state:
            dfg.add_edge(reg_state[offset], node_id, 'data_flow')

        return node_id

    elif expr_type == 'Load':
        # Memory read: Load(addr, ty)
        addr_node_id = _process_expression(expr.addr, block_addr, dfg, reg_state, mem_state)

        node = DFGNode(
            id=0,
            address=block_addr,
            operation='memory_read',
            block_addr=block_addr
        )
        node_id = dfg.add_node(node)

        if addr_node_id is not None:
            dfg.add_edge(addr_node_id, node_id, 'address_flow')

        return node_id

    elif expr_type == 'Const':
        # Constant value
        node = DFGNode(
            id=0,
            address=block_addr,
            operation='constant',
            value=expr.con.value if hasattr(expr, 'con') else None,
            block_addr=block_addr
        )
        return dfg.add_node(node)

    elif expr_type == 'Binop':
        # Binary operation
        left_id = _process_expression(expr.args[0], block_addr, dfg, reg_state, mem_state)
        right_id = _process_expression(expr.args[1], block_addr, dfg, reg_state, mem_state)

        node = DFGNode(
            id=0,
            address=block_addr,
            operation=f'binop_{expr.op}',
            block_addr=block_addr
        )
        node_id = dfg.add_node(node)

        if left_id is not None:
            dfg.add_edge(left_id, node_id, 'data_flow')
        if right_id is not None:
            dfg.add_edge(right_id, node_id, 'data_flow')

        return node_id

    elif expr_type == 'Unop':
        # Unary operation
        arg_id = _process_expression(expr.args[0], block_addr, dfg, reg_state, mem_state)

        node = DFGNode(
            id=0,
            address=block_addr,
            operation=f'unop_{expr.op}',
            block_addr=block_addr
        )
        node_id = dfg.add_node(node)

        if arg_id is not None:
            dfg.add_edge(arg_id, node_id, 'data_flow')

        return node_id

    elif expr_type == 'ITE':
        # If-then-else
        cond_id = _process_expression(expr.cond, block_addr, dfg, reg_state, mem_state)
        true_id = _process_expression(expr.iftrue, block_addr, dfg, reg_state, mem_state)
        false_id = _process_expression(expr.iffalse, block_addr, dfg, reg_state, mem_state)

        node = DFGNode(
            id=0,
            address=block_addr,
            operation='ite',
            block_addr=block_addr
        )
        node_id = dfg.add_node(node)

        if cond_id is not None:
            dfg.add_edge(cond_id, node_id, 'control_flow')
        if true_id is not None:
            dfg.add_edge(true_id, node_id, 'data_flow')
        if false_id is not None:
            dfg.add_edge(false_id, node_id, 'data_flow')

        return node_id

    else:
        # Unknown expression type
        return None


def get_dfg_stats(dfg: DFG) -> Dict[str, Any]:
    """Get statistics about the DFG."""
    node_types = defaultdict(int)
    edge_types = defaultdict(int)

    for node in dfg.nodes.values():
        node_types[node.operation] += 1

    for edge in dfg.edges:
        edge_types[edge.type] += 1

    return {
        'total_nodes': len(dfg.nodes),
        'total_edges': len(dfg.edges),
        'node_types': dict(node_types),
        'edge_types': dict(edge_types),
        'register_definitions': len(dfg.reg_defs),
        'memory_definitions': len(dfg.mem_defs),
    }


def export_dfg_dot(dfg: DFG, output_path: str):
    """Export DFG to DOT format for visualization."""
    lines = ['digraph DFG {']
    lines.append('  node [shape=ellipse];')

    # Add nodes
    for node_id, node in dfg.nodes.items():
        label = f"{node.operation}"
        if node.operand:
            label += f"\\n{node.operand}"
        if node.value is not None:
            label += f"\\n={node.value}"
        lines.append(f'  "{node_id}" [label="{label}"];')

    # Add edges
    for edge in dfg.edges:
        style = 'solid' if edge.type == 'data_flow' else 'dashed'
        color = 'black' if edge.type == 'data_flow' else 'red'
        label = edge.label or edge.type
        lines.append(f'  "{edge.source}" -> "{edge.target}" [style={style}, color={color}, label="{label}"];')

    lines.append('}')

    with open(output_path, 'w') as f:
        f.write('\n'.join(lines))

    logger.info(f"DFG exported to: {output_path}")


# Example usage
if __name__ == "__main__":
    import sys
    from .vex_lift import lift_binary
    from .cfg_recovery import recover_cfg

    if len(sys.argv) < 2:
        print("Usage: python dfg_construction.py <binary_path> [--export-dot output.dot]")
        sys.exit(1)

    binary = sys.argv[1]
    export_dot = None

    if '--export-dot' in sys.argv:
        idx = sys.argv.index('--export-dot')
        if idx + 1 < len(sys.argv):
            export_dot = sys.argv[idx + 1]

    try:
        # Lift to VEX IR
        vex_ir = lift_binary(binary)

        # Recover CFG
        cfg = recover_cfg(binary)

        # Construct DFG
        dfg = construct_dfg(vex_ir, cfg)

        # Print stats
        stats = get_dfg_stats(dfg)
        print(f"\nDFG Statistics:")
        print(f"  Nodes: {stats['total_nodes']}")
        print(f"  Edges: {stats['total_edges']}")
        print(f"  Node types: {stats['node_types']}")
        print(f"  Edge types: {stats['edge_types']}")

        # Export if requested
        if export_dot:
            export_dfg_dot(dfg, export_dot)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
