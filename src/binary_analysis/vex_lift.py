"""
VEX IR Lifting Module

Implements: Binary → CodeLifting → VEX IR
From infra.txt: "Code Lifting (angr / VEX)"

This module handles:
1. Loading binaries using angr
2. Lifting machine code to VEX IR
3. Extracting IR blocks for analysis
"""

import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger('OPM.binary_analysis')

# Lazy imports for angr (heavy dependency)
_angr = None
_pyvex = None


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


def _get_pyvex():
    """Lazy import of pyvex."""
    global _pyvex
    if _pyvex is None:
        try:
            import pyvex
            _pyvex = pyvex
        except ImportError:
            raise ImportError("pyvex not installed. Install with: pip install pyvex")
    return _pyvex


@dataclass
class VEXBlock:
    """Represents a VEX IR basic block."""
    address: int
    size: int
    irsb: Any  # pyvex IRSB
    statements: List[Any] = field(default_factory=list)
    jump_target: Optional[int] = None
    jump_kind: Optional[str] = None


@dataclass
class VEXFunction:
    """Represents a function lifted to VEX IR."""
    name: str
    address: int
    blocks: List[VEXBlock] = field(default_factory=list)
    cfg: Optional[Any] = None


@dataclass
class VEXIR:
    """Container for VEX IR data."""
    binary_path: str
    arch: str
    entry_point: int
    functions: Dict[str, VEXFunction] = field(default_factory=dict)
    blocks: Dict[int, VEXBlock] = field(default_factory=dict)
    project: Any = None


def lift_binary(binary_path: str) -> VEXIR:
    """
    Lift an entire binary to VEX IR.

    Args:
        binary_path: Path to the binary file

    Returns:
        VEXIR container with lifted IR
    """
    angr = _get_angr()

    logger.info(f"Loading binary: {binary_path}")

    # Load binary with angr
    proj = angr.Project(binary_path, auto_load_libs=False)

    # Get architecture info
    arch_name = proj.arch.name
    entry = proj.entry

    logger.info(f"  Architecture: {arch_name}")
    logger.info(f"  Entry point: {hex(entry)}")

    # Create VEXIR container
    vex_ir = VEXIR(
        binary_path=binary_path,
        arch=arch_name,
        entry_point=entry,
        project=proj
    )

    # Lift all functions
    cfg = proj.analyses.CFGFast()
    for func_addr, func in cfg.functions.items():
        if func.is_plt or func.is_syscall:
            continue

        vex_func = _lift_function(proj, func)
        vex_ir.functions[func.name] = vex_func

        # Store blocks
        for block in vex_func.blocks:
            vex_ir.blocks[block.address] = block

    logger.info(f"  Lifted {len(vex_ir.functions)} functions, "
                f"{len(vex_ir.blocks)} blocks")

    return vex_ir


def lift_function(binary_path: str, function_name: str) -> Optional[VEXFunction]:
    """
    Lift a specific function to VEX IR.

    Args:
        binary_path: Path to the binary file
        function_name: Name of the function to lift

    Returns:
        VEXFunction or None if not found
    """
    angr = _get_angr()

    logger.info(f"Lifting function '{function_name}' from: {binary_path}")

    # Load binary
    proj = angr.Project(binary_path, auto_load_libs=False)

    # Get CFG
    cfg = proj.analyses.CFGFast()

    # Find function
    for func_addr, func in cfg.functions.items():
        if func.name == function_name:
            return _lift_function(proj, func)

    logger.warning(f"Function '{function_name}' not found")
    return None


def _lift_function(proj, func) -> VEXFunction:
    """Lift a single function to VEX IR."""
    pyvex = _get_pyvex()

    vex_func = VEXFunction(
        name=func.name,
        address=func.addr
    )

    # Lift each basic block
    for block in func.blocks:
        try:
            # Lift to VEX IR
            irsb = pyvex.lift(
                block.bytes,
                addr=block.addr,
                arch=proj.arch
            )

            # Extract statements
            statements = []
            for stmt in irsb.statements:
                statements.append(stmt)

            # Get jump info
            jump_target = None
            jump_kind = None
            if irsb.jumpkind:
                jump_kind = str(irsb.jumpkind)
                if hasattr(irsb, 'next'):
                    try:
                        jump_target = irsb.next.con.value
                    except (AttributeError, TypeError):
                        pass

            vex_block = VEXBlock(
                address=block.addr,
                size=block.size,
                irsb=irsb,
                statements=statements,
                jump_target=jump_target,
                jump_kind=jump_kind
            )

            vex_func.blocks.append(vex_block)

        except Exception as e:
            logger.warning(f"Failed to lift block at {hex(block.addr)}: {e}")

    return vex_func


def get_ir_statements(vex_block: VEXBlock) -> List[Dict[str, Any]]:
    """
    Extract IR statements from a VEX block.

    Args:
        vex_block: VEX block to extract from

    Returns:
        List of statement dictionaries
    """
    statements = []

    for i, stmt in enumerate(vex_block.statements):
        stmt_info = {
            'index': i,
            'type': type(stmt).__name__,
            'address': vex_block.address,
        }

        # Extract statement-specific info
        if hasattr(stmt, 'offset'):
            stmt_info['offset'] = stmt.offset
        if hasattr(stmt, 'data'):
            stmt_info['data'] = str(stmt.data)
        if hasattr(stmt, 'addr'):
            stmt_info['addr'] = stmt.addr

        statements.append(stmt_info)

    return statements


def get_expressions(vex_block: VEXBlock) -> List[Dict[str, Any]]:
    """
    Extract IR expressions from a VEX block.

    Args:
        vex_block: VEX block to extract from

    Returns:
        List of expression dictionaries
    """
    pyvex = _get_pyvex()
    expressions = []

    # Walk the IR tree
    def walk_expr(expr, depth=0):
        if expr is None:
            return

        expr_info = {
            'type': type(expr).__name__,
            'tag': str(expr.tag) if hasattr(expr, 'tag') else None,
            'depth': depth,
        }

        if hasattr(expr, 'con'):
            expr_info['constant'] = expr.con.value
        if hasattr(expr, 'offset'):
            expr_info['offset'] = expr.offset

        expressions.append(expr_info)

        # Recurse into child expressions
        if hasattr(expr, 'child_expressions'):
            for child in expr.child_expressions:
                walk_expr(child, depth + 1)

    # Walk expressions in each statement
    for stmt in vex_block.statements:
        if hasattr(stmt, 'data'):
            walk_expr(stmt.data)
        if hasattr(stmt, 'addr'):
            walk_expr(stmt.addr)

    return expressions


# Example usage
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python vex_lift.py <binary_path> [function_name]")
        sys.exit(1)

    binary = sys.argv[1]
    func_name = sys.argv[2] if len(sys.argv) > 2 else None

    try:
        if func_name:
            func = lift_function(binary, func_name)
            if func:
                print(f"Function: {func.name} at {hex(func.address)}")
                print(f"Blocks: {len(func.blocks)}")
                for block in func.blocks:
                    print(f"  Block at {hex(block.address)}: {len(block.statements)} statements")
        else:
            vex_ir = lift_binary(binary)
            print(f"Binary: {vex_ir.binary_path}")
            print(f"Architecture: {vex_ir.arch}")
            print(f"Functions: {len(vex_ir.functions)}")
            print(f"Blocks: {len(vex_ir.blocks)}")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
