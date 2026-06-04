"""
Type-Guided Symbolic Executor

Implements: Type-Guided Symbolic Execution
From infra.txt: "Type-Guided Symbolic Execution (using symbolic execution APIs)"

This module performs symbolic execution guided by type information
to improve taint analysis precision.
"""

import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger('OPM.symbolic_exec')

# Lazy import for angr
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
class SymbolicState:
    """Symbolic execution state."""
    address: int
    constraints: List[Any] = field(default_factory=list)
    memory: Dict[int, Any] = field(default_factory=dict)
    registers: Dict[str, Any] = field(default_factory=dict)
    # Type information
    typed_variables: Dict[str, Any] = field(default_factory=dict)
    # Taint information
    tainted_vars: Set[str] = field(default_factory=set)


@dataclass
class ExecutionResult:
    """Result of symbolic execution."""
    states: List[SymbolicState] = field(default_factory=list)
    paths: List[List[int]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    # Hard evidence (formatted path constraints / parameter ranges) for the LLM
    constraint_evidence: List[str] = field(default_factory=list)
    # Statistics
    num_states: int = 0
    num_paths: int = 0
    execution_time: float = 0.0


@dataclass
class TypeGuidedExecutor:
    """Executes symbolic execution guided by type information."""
    binary_path: str = ''
    typed_ir: Any = None
    max_steps: int = 1000
    solver_timeout: int = 1000  # milliseconds
    max_states: int = 100

    def execute(self, paths: List[Any]) -> ExecutionResult:
        """
        Execute symbolic execution on given paths.

        Args:
            paths: List of execution paths to explore

        Returns:
            ExecutionResult with states and paths
        """
        logger.info(f"Starting type-guided symbolic execution on {len(paths)} paths")

        result = ExecutionResult()

        # Extractor turns LIVE angr states into "hard evidence" for the LLM.
        # Created here so it is reused across all paths; degrades to None if unavailable.
        try:
            from .constraint_extractor import create_constraint_extractor
            extractor = create_constraint_extractor()
        except Exception as e:
            logger.debug(f"Constraint extractor unavailable: {e}")
            extractor = None

        try:
            angr = _get_angr()

            # Load binary
            proj = angr.Project(self.binary_path, auto_load_libs=False)

            # Execute each path
            for path in paths:
                states = self._execute_path(proj, path, extractor, result.constraint_evidence)
                result.states.extend(states)
                result.paths.append(path.blocks if hasattr(path, 'blocks') else [])

            result.num_states = len(result.states)
            result.num_paths = len(result.paths)

        except Exception as e:
            logger.error(f"Symbolic execution failed: {e}")
            result.errors.append(str(e))

        logger.info(f"Execution complete: {result.num_states} states, {result.num_paths} paths")
        return result

    def _execute_path(self, proj: Any, path: Any,
                      extractor: Any = None,
                      evidence_sink: Optional[List[str]] = None) -> List[SymbolicState]:
        """Execute symbolic execution on a single path.

        While each angr state is still live (its solver is available), extract path
        constraints / parameter ranges as hard evidence and append the formatted blocks
        to ``evidence_sink``. This is the only point where the real solver exists, so the
        extraction must happen here rather than later in the pipeline.
        """
        states = []

        if not hasattr(path, 'blocks') or not path.blocks:
            return states

        try:
            # Create initial state
            entry_addr = path.blocks[0]
            state = proj.factory.blank_state(addr=entry_addr)
            func_label = f"func_{hex(entry_addr)}"

            # Apply type-guided constraints
            if self.typed_ir:
                state = self._apply_type_constraints(state, path)

            # Execute
            simgr = proj.factory.simgr(state)

            for i, block_addr in enumerate(path.blocks):
                if i >= self.max_steps:
                    break

                # Step
                simgr.step()

                # Check for states
                if not simgr.active:
                    break

                # Get symbolic state
                for active_state in simgr.active[:self.max_states]:
                    sym_state = self._create_symbolic_state(active_state, block_addr)
                    states.append(sym_state)

                    # Extract hard evidence from the LIVE state (solver still attached)
                    if extractor is not None and evidence_sink is not None:
                        try:
                            ev = extractor.extract_constraints(active_state, func_label)
                            if ev.constraints or ev.param_ranges or ev.dangerous_patterns:
                                block = extractor.format_for_llm(ev)
                                if block and block not in evidence_sink:
                                    evidence_sink.append(block)
                        except Exception as e:
                            logger.debug(f"Constraint extraction failed at {hex(block_addr)}: {e}")

        except Exception as e:
            logger.warning(f"Path execution failed: {e}")

        return states

    def _apply_type_constraints(self, state: Any, path: Any) -> Any:
        """Apply type-guided constraints to state."""
        if self.typed_ir is None:
            return state

        # Apply constraints based on type information
        # This would add type-related constraints to guide execution

        return state

    def _create_symbolic_state(self, angr_state: Any, address: int) -> SymbolicState:
        """Create SymbolicState from angr state."""
        sym_state = SymbolicState(address=address)

        # Extract constraints
        try:
            sym_state.constraints = list(angr_state.solver.constraints)
        except:
            pass

        # Extract register values
        try:
            for reg_name in ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp']:
                try:
                    val = angr_state.registers.load(reg_name)
                    sym_state.registers[reg_name] = val
                except:
                    pass
        except:
            pass

        return sym_state


def execute_guided(
    typed_ir: Any,
    paths: List[Any],
    max_steps: int = 1000,
    solver_timeout: int = 1000
) -> Dict[str, Any]:
    """
    Execute type-guided symbolic execution.

    Args:
        typed_ir: Type-augmented IR
        paths: Execution paths to explore
        max_steps: Maximum execution steps per path
        solver_timeout: Solver timeout in milliseconds

    Returns:
        Dictionary with execution results
    """
    logger.info("Starting type-guided symbolic execution")

    binary_path = typed_ir.binary_path if hasattr(typed_ir, 'binary_path') else ''

    executor = TypeGuidedExecutor(
        binary_path=binary_path,
        typed_ir=typed_ir,
        max_steps=max_steps,
        solver_timeout=solver_timeout
    )

    result = executor.execute(paths)

    return {
        'state': result.states[0] if result.states else None,
        'paths': result.paths,
        'states': result.states,
        'constraint_evidence': result.constraint_evidence,
        'num_states': result.num_states,
        'num_paths': result.num_paths,
        'errors': result.errors,
    }


def get_execution_statistics(result: ExecutionResult) -> Dict[str, Any]:
    """Get statistics about execution results."""
    return {
        'total_states': result.num_states,
        'total_paths': result.num_paths,
        'errors': len(result.errors),
        'avg_constraints_per_state': (
            sum(len(s.constraints) for s in result.states) / result.num_states
            if result.num_states > 0 else 0
        ),
    }


# Example usage
if __name__ == "__main__":
    print("Type-Guided Symbolic Executor Module")
    print("This module is used as part of the OPM pipeline.")
