"""
Path Prioritizer Module

Implements: TypedIR + TypeRecoveryOutput → PathPrioritization
From infra.txt: "Type-Aware Path Prioritization (lightweight rule-based strategy)"

This module prioritizes execution paths based on type information
to improve taint analysis efficiency.
"""

import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger('OPM.symbolic_exec')


@dataclass
class ExecutionPath:
    """Represents an execution path."""
    id: int
    blocks: List[int] = field(default_factory=list)  # Block addresses
    priority: float = 0.0
    is_feasible: bool = True
    is_prioritized: bool = False
    # Type-related information
    has_pointer_operations: bool = False
    has_buffer_operations: bool = False
    has_type_mismatch: bool = False
    # Taint-related information
    has_source: bool = False
    has_sink: bool = False
    taint_propagation_score: float = 0.0


@dataclass
class PathPrioritizer:
    """Prioritizes execution paths based on type information."""
    typed_ir: Any = None
    type_recovery_output: Any = None
    paths: List[ExecutionPath] = field(default_factory=list)
    # Priority rules
    rules: Dict[str, float] = field(default_factory=lambda: {
        'has_source': 10.0,
        'has_sink': 10.0,
        'has_pointer_operations': 5.0,
        'has_buffer_operations': 8.0,
        'has_type_mismatch': 15.0,
        'path_length': 0.1,
        'taint_propagation': 20.0,
    })

    def prioritize(self) -> List[ExecutionPath]:
        """Prioritize all paths."""
        logger.info(f"Prioritizing {len(self.paths)} paths")

        for path in self.paths:
            path.priority = self._calculate_priority(path)

        # Sort by priority (higher is better)
        self.paths.sort(key=lambda p: p.priority, reverse=True)

        # Mark top paths as prioritized
        top_k = min(10, len(self.paths))
        for i in range(top_k):
            self.paths[i].is_prioritized = True

        logger.info(f"Prioritization complete: top path priority = {self.paths[0].priority if self.paths else 0}")
        return self.paths

    def _calculate_priority(self, path: ExecutionPath) -> float:
        """Calculate priority score for a path."""
        score = 0.0

        # Apply rules
        if path.has_source:
            score += self.rules['has_source']
        if path.has_sink:
            score += self.rules['has_sink']
        if path.has_pointer_operations:
            score += self.rules['has_pointer_operations']
        if path.has_buffer_operations:
            score += self.rules['has_buffer_operations']
        if path.has_type_mismatch:
            score += self.rules['has_type_mismatch']

        # Path length bonus
        score += len(path.blocks) * self.rules['path_length']

        # Taint propagation bonus
        score += path.taint_propagation_score * self.rules['taint_propagation']

        return score


def prioritize_paths(
    typed_ir: Any,
    type_recovery_output: Dict[str, Any]
) -> List[ExecutionPath]:
    """
    Prioritize execution paths based on type information.

    Args:
        typed_ir: Type-augmented IR
        type_recovery_output: Type recovery output

    Returns:
        List of prioritized execution paths
    """
    logger.info("Starting path prioritization")

    prioritizer = PathPrioritizer(
        typed_ir=typed_ir,
        type_recovery_output=type_recovery_output
    )

    # Generate paths from CFG
    paths = _generate_paths(typed_ir)
    prioritizer.paths = paths

    # Analyze paths for type-related properties
    _analyze_paths(paths, typed_ir, type_recovery_output)

    # Prioritize
    prioritized_paths = prioritizer.prioritize()

    logger.info(f"Path prioritization complete: {len(prioritized_paths)} paths")
    return prioritized_paths


def _generate_paths(typed_ir: Any) -> List[ExecutionPath]:
    """Generate execution paths from CFG."""
    paths = []

    if typed_ir is None or not hasattr(typed_ir, 'cfg'):
        return paths

    cfg = typed_ir.cfg
    if cfg is None:
        return paths

    # Simple path generation: DFS from entry points
    visited = set()
    path_id = 0

    for func_name, func in cfg.functions.items():
        if not func.blocks:
            continue

        # Start from first block
        start_block = func.blocks[0].address
        if start_block in visited:
            continue

        # DFS to generate paths
        path = _dfs_generate_path(cfg, start_block, visited, path_id)
        if path:
            paths.append(path)
            path_id += 1

    return paths


def _dfs_generate_path(cfg: Any, start_addr: int, visited: Set[int], path_id: int) -> Optional[ExecutionPath]:
    """Generate a path using DFS."""
    path = ExecutionPath(id=path_id)
    stack = [start_addr]

    while stack:
        addr = stack.pop()

        if addr in visited:
            continue

        visited.add(addr)
        path.blocks.append(addr)

        # Get successors
        block = cfg.blocks.get(addr)
        if block and block.successors:
            for succ in block.successors:
                if succ not in visited:
                    stack.append(succ)

    return path if path.blocks else None


def _analyze_paths(
    paths: List[ExecutionPath],
    typed_ir: Any,
    type_recovery_output: Dict[str, Any]
):
    """Analyze paths for type-related properties."""
    if typed_ir is None:
        return

    for path in paths:
        for block_addr in path.blocks:
            # Check for pointer operations
            if _has_pointer_operations(block_addr, typed_ir):
                path.has_pointer_operations = True

            # Check for buffer operations
            if _has_buffer_operations(block_addr, typed_ir):
                path.has_buffer_operations = True

            # Check for type mismatches
            if _has_type_mismatch(block_addr, typed_ir, type_recovery_output):
                path.has_type_mismatch = True


def _has_pointer_operations(block_addr: int, typed_ir: Any) -> bool:
    """Check if a block has pointer operations."""
    # Simplified check
    if hasattr(typed_ir, 'pointer_map'):
        return any(typed_ir.pointer_map.values())
    return False


def _has_buffer_operations(block_addr: int, typed_ir: Any) -> bool:
    """Check if a block has buffer operations."""
    # Simplified check
    if hasattr(typed_ir, 'buffer_map'):
        return any(typed_ir.buffer_map.values())
    return False


def _has_type_mismatch(block_addr: int, typed_ir: Any, type_recovery_output: Dict[str, Any]) -> bool:
    """Check if a block has type mismatches."""
    # Simplified check - would need actual type analysis
    return False


def get_path_statistics(paths: List[ExecutionPath]) -> Dict[str, Any]:
    """Get statistics about execution paths."""
    if not paths:
        return {
            'total_paths': 0,
            'prioritized_paths': 0,
            'avg_path_length': 0,
        }

    total_paths = len(paths)
    prioritized_paths = sum(1 for p in paths if p.is_prioritized)
    avg_length = sum(len(p.blocks) for p in paths) / total_paths

    paths_with_source = sum(1 for p in paths if p.has_source)
    paths_with_sink = sum(1 for p in paths if p.has_sink)
    paths_with_pointer = sum(1 for p in paths if p.has_pointer_operations)
    paths_with_buffer = sum(1 for p in paths if p.has_buffer_operations)

    return {
        'total_paths': total_paths,
        'prioritized_paths': prioritized_paths,
        'avg_path_length': avg_length,
        'paths_with_source': paths_with_source,
        'paths_with_sink': paths_with_sink,
        'paths_with_pointer_ops': paths_with_pointer,
        'paths_with_buffer_ops': paths_with_buffer,
    }


# Example usage
if __name__ == "__main__":
    print("Path Prioritizer Module")
    print("This module is used as part of the OPM pipeline.")
