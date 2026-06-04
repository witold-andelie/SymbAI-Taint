"""
Type Metadata Injector

Implements: VEX IR + CFG + DFG + TypeRecoveryOutput → TypeMetadataInjection → TypedIR
From infra.txt: "Type Metadata Injection"

This module handles injecting type metadata into the IR to create
a type-augmented representation for guided symbolic execution.
"""

import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger('OPM.typed_ir')


@dataclass
class TypedVariable:
    """A variable with type information."""
    name: str
    address: int
    type_name: str
    is_pointer: bool = False
    is_buffer: bool = False
    size: int = 0
    confidence: float = 0.0
    source: str = 'unknown'
    # Memory location
    stack_offset: Optional[int] = None
    register: Optional[str] = None
    global_addr: Optional[int] = None


@dataclass
class TypedBlock:
    """A basic block with type information."""
    address: int
    size: int
    variables: List[TypedVariable] = field(default_factory=list)
    type_annotations: Dict[int, str] = field(default_factory=dict)  # addr -> type


@dataclass
class TypedFunction:
    """A function with type information."""
    name: str
    address: int
    blocks: List[TypedBlock] = field(default_factory=list)
    parameters: List[TypedVariable] = field(default_factory=list)
    return_type: Optional[str] = None
    local_variables: List[TypedVariable] = field(default_factory=list)


@dataclass
class TypedIR:
    """Type-augmented intermediate representation."""
    binary_path: str
    functions: Dict[str, TypedFunction] = field(default_factory=dict)
    # Type metadata
    variable_types: Dict[str, str] = field(default_factory=dict)
    pointer_map: Dict[int, bool] = field(default_factory=dict)
    buffer_map: Dict[int, bool] = field(default_factory=dict)
    # Original IR references
    vex_ir: Any = None
    cfg: Any = None
    dfg: Any = None
    type_recovery_output: Any = None


def inject_type_metadata(
    vex_ir: Any,
    cfg: Any,
    dfg: Any,
    type_recovery_output: Dict[str, Any]
) -> TypedIR:
    """
    Inject type metadata into IR.

    Args:
        vex_ir: VEX IR container
        cfg: Control Flow Graph
        dfg: Data Flow Graph
        type_recovery_output: Type recovery output from GNN

    Returns:
        TypedIR with injected type metadata
    """
    logger.info("Injecting type metadata into IR")

    typed_ir = TypedIR(
        binary_path=vex_ir.binary_path if hasattr(vex_ir, 'binary_path') else '',
        vex_ir=vex_ir,
        cfg=cfg,
        dfg=dfg,
        type_recovery_output=type_recovery_output
    )

    # Process each function
    for func_name, func in cfg.functions.items():
        typed_func = _process_function(func, type_recovery_output.get(func_name))
        typed_ir.functions[func_name] = typed_func

        # Collect type information
        for var in typed_func.parameters + typed_func.local_variables:
            typed_ir.variable_types[var.name] = var.type_name
            if var.global_addr is not None:
                typed_ir.pointer_map[var.global_addr] = var.is_pointer
                typed_ir.buffer_map[var.global_addr] = var.is_buffer

    # Fold in all GNN predictions directly, decoupled from CFG name/address matching
    # (DWARF low_pc vs angr's PIE-rebased addresses don't line up by name). This is the
    # authoritative record of the GNN's per-variable types for downstream consumers.
    for fname, out in (type_recovery_output or {}).items():
        for pred in getattr(out, 'predictions', []):
            key = f"{fname}:{pred.variable_name}"
            typed_ir.variable_types[key] = pred.predicted_type
            is_buf = pred.predicted_type in ('array', 'pointer', 'char*')
            loc = pred.details.get('location') if getattr(pred, 'details', None) else None
            if isinstance(loc, (tuple, list)) and len(loc) == 2 and loc[0] == 'cfa':
                typed_ir.buffer_map[loc[1]] = is_buf
                typed_ir.pointer_map[loc[1]] = pred.predicted_type in ('pointer', 'char*')

    logger.info(f"Type injection complete: {len(typed_ir.functions)} functions, "
                f"{len(typed_ir.variable_types)} typed variables")

    return typed_ir


def _process_function(func: Any, type_output: Any) -> TypedFunction:
    """Process a function and inject type information."""
    typed_func = TypedFunction(
        name=func.name,
        address=func.address
    )

    # Create type map from recovery output
    type_map = {}
    if type_output is not None:
        for pred in type_output.predictions if hasattr(type_output, 'predictions') else []:
            type_map[pred.variable_name] = {
                'type': pred.predicted_type,
                'confidence': pred.confidence,
                'source': pred.source,
            }

    # Register GNN-predicted variables directly (they are DWARF-located), since the
    # block-level IR variable extraction below is a stub. Names are function-qualified.
    if type_output is not None:
        for pred in getattr(type_output, 'predictions', []):
            loc = pred.details.get('location') if getattr(pred, 'details', None) else None
            is_cfa = isinstance(loc, (tuple, list)) and len(loc) == 2 and loc[0] == 'cfa'
            is_reg = isinstance(loc, (tuple, list)) and len(loc) == 2 and loc[0] == 'reg'
            typed_func.local_variables.append(TypedVariable(
                name=f"{func.name}:{pred.variable_name}",
                address=func.address,
                type_name=pred.predicted_type,
                is_pointer=pred.predicted_type in ('pointer', 'char*'),
                is_buffer=pred.predicted_type in ('array', 'pointer', 'char*'),
                confidence=pred.confidence,
                source=pred.source,
                stack_offset=loc[1] if is_cfa else None,
                register=str(loc[1]) if is_reg else None,
            ))

    # Process blocks
    for block in func.blocks:
        typed_block = TypedBlock(
            address=block.address,
            size=block.size
        )

        # Analyze block for variables
        variables = _extract_variables_from_block(block, type_map)
        typed_block.variables = variables

        # Separate parameters and locals
        for var in variables:
            if var.name.startswith('param_') or var.name.startswith('arg_'):
                typed_func.parameters.append(var)
            else:
                typed_func.local_variables.append(var)

        typed_func.blocks.append(typed_block)

    return typed_func


def _extract_variables_from_block(block: Any, type_map: Dict[str, Any]) -> List[TypedVariable]:
    """Extract variables from a basic block."""
    variables = []

    # This is a simplified version - real implementation would
    # analyze the IR to find variable accesses

    # Look for stack accesses (common for local variables)
    if hasattr(block, 'size'):
        # Create placeholder variables for demonstration
        # Real implementation would parse IR statements
        pass

    return variables


def get_variable_type(typed_ir: TypedIR, var_name: str) -> Optional[str]:
    """Get type of a variable."""
    return typed_ir.variable_types.get(var_name)


def is_pointer(typed_ir: TypedIR, address: int) -> bool:
    """Check if an address is a pointer."""
    return typed_ir.pointer_map.get(address, False)


def is_buffer(typed_ir: TypedIR, address: int) -> bool:
    """Check if an address is a buffer."""
    return typed_ir.buffer_map.get(address, False)


def get_typed_variables(typed_ir: TypedIR, function_name: str) -> List[TypedVariable]:
    """Get all typed variables in a function."""
    func = typed_ir.functions.get(function_name)
    if func is None:
        return []
    return func.parameters + func.local_variables


def get_function_signatures(typed_ir: TypedIR) -> Dict[str, Dict[str, Any]]:
    """Get function signatures with type information."""
    signatures = {}

    for func_name, func in typed_ir.functions.items():
        signatures[func_name] = {
            'name': func.name,
            'address': func.address,
            'parameters': [
                {
                    'name': p.name,
                    'type': p.type_name,
                    'is_pointer': p.is_pointer,
                }
                for p in func.parameters
            ],
            'return_type': func.return_type,
            'local_variables': len(func.local_variables),
        }

    return signatures


def export_typed_ir(typed_ir: TypedIR, output_path: str):
    """Export typed IR to file."""
    import json

    data = {
        'binary_path': typed_ir.binary_path,
        'functions': {
            name: {
                'name': func.name,
                'address': func.address,
                'parameters': [
                    {
                        'name': v.name,
                        'type': v.type_name,
                        'is_pointer': v.is_pointer,
                        'is_buffer': v.is_buffer,
                    }
                    for v in func.parameters
                ],
                'local_variables': [
                    {
                        'name': v.name,
                        'type': v.type_name,
                        'is_pointer': v.is_pointer,
                        'is_buffer': v.is_buffer,
                    }
                    for v in func.local_variables
                ],
            }
            for name, func in typed_ir.functions.items()
        },
        'variable_types': typed_ir.variable_types,
    }

    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)

    logger.info(f"Typed IR exported to: {output_path}")


def get_typed_ir_stats(typed_ir: TypedIR) -> Dict[str, Any]:
    """Get statistics about the typed IR."""
    total_vars = len(typed_ir.variable_types)
    total_pointers = sum(1 for v in typed_ir.pointer_map.values() if v)
    total_buffers = sum(1 for v in typed_ir.buffer_map.values() if v)

    type_counts = {}
    for t in typed_ir.variable_types.values():
        type_counts[t] = type_counts.get(t, 0) + 1

    return {
        'total_functions': len(typed_ir.functions),
        'total_variables': total_vars,
        'total_pointers': total_pointers,
        'total_buffers': total_buffers,
        'type_distribution': type_counts,
    }


# Example usage
if __name__ == "__main__":
    print("Type Injector Module")
    print("This module is used as part of the OPM pipeline.")
