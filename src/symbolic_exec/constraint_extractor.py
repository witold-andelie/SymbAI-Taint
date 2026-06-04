"""
Path Constraint Extractor

Extracts symbolic constraints from angr execution as "hard evidence" for LLM.
This provides mathematical proof about variable ranges and relationships.
"""

import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger('OPM.symbolic_exec')


@dataclass
class SymbolicConstraint:
    """A symbolic constraint from angr."""
    variable: str          # Variable name
    constraint_type: str   # 'range', 'comparison', 'equality'
    expression: str        # Human-readable expression
    min_value: Optional[int] = None
    max_value: Optional[int] = None
    is_unconstrained: bool = False


@dataclass
class PathEvidence:
    """Evidence about a path from symbolic execution."""
    function_name: str
    constraints: List[SymbolicConstraint] = field(default_factory=list)
    # Parameter analysis
    param_ranges: Dict[str, Tuple[int, int]] = field(default_factory=dict)
    # Dangerous patterns detected
    dangerous_patterns: List[str] = field(default_factory=list)


class ConstraintExtractor:
    """
    Extracts symbolic constraints from angr for LLM consumption.
    """

    def __init__(self):
        # Dangerous function parameter patterns
        self.dangerous_patterns = {
            'strncpy': {
                'param': 'size',
                'check': 'unconstrained_or_large',
                'description': 'strncpy size parameter may overflow buffer'
            },
            'memcpy': {
                'param': 'size',
                'check': 'unconstrained_or_large',
                'description': 'memcpy size parameter may overflow buffer'
            },
            'sprintf': {
                'param': 'format',
                'check': 'user_controlled',
                'description': 'sprintf format string is user-controlled'
            },
            'system': {
                'param': 'command',
                'check': 'user_controlled',
                'description': 'system() command is user-controlled'
            },
        }

    def extract_constraints(self, state: Any, function_name: str) -> PathEvidence:
        """
        Extract symbolic constraints from an angr state.

        Args:
            state: angr state
            function_name: Name of the function

        Returns:
            PathEvidence with constraints
        """
        evidence = PathEvidence(function_name=function_name)

        if state is None:
            return evidence

        try:
            # Get all constraints
            constraints = state.solver.constraints

            for constraint in constraints:
                parsed = self._parse_constraint(constraint, state)
                if parsed:
                    evidence.constraints.append(parsed)

            # Analyze register values
            self._analyze_registers(state, evidence)

            # Check for dangerous patterns
            self._check_dangerous_patterns(state, evidence)

        except Exception as e:
            logger.debug(f"Failed to extract constraints: {e}")

        return evidence

    def _parse_constraint(self, constraint: Any, state: Any) -> Optional[SymbolicConstraint]:
        """Parse a single constraint."""
        try:
            import claripy

            # Check if it's a comparison
            if hasattr(constraint, 'op'):
                op = constraint.op

                if op == '__le__' or op == '__lt__':
                    # Less than/less than equal
                    if len(constraint.args) >= 2:
                        left = constraint.args[0]
                        right = constraint.args[1]

                        # Try to get concrete value
                        if hasattr(right, 'concrete') and right.concrete:
                            return SymbolicConstraint(
                                variable=str(left),
                                constraint_type='range',
                                expression=f"{left} <= {right.concrete_value}",
                                max_value=right.concrete_value,
                            )

                elif op == '__ge__' or op == '__gt__':
                    # Greater than/greater than equal
                    if len(constraint.args) >= 2:
                        left = constraint.args[0]
                        right = constraint.args[1]

                        if hasattr(right, 'concrete') and right.concrete:
                            return SymbolicConstraint(
                                variable=str(left),
                                constraint_type='range',
                                expression=f"{left} >= {right.concrete_value}",
                                min_value=right.concrete_value,
                            )

                elif op == '__eq__':
                    # Equality
                    if len(constraint.args) >= 2:
                        left = constraint.args[0]
                        right = constraint.args[1]

                        if hasattr(right, 'concrete') and right.concrete:
                            return SymbolicConstraint(
                                variable=str(left),
                                constraint_type='equality',
                                expression=f"{left} == {right.concrete_value}",
                                min_value=right.concrete_value,
                                max_value=right.concrete_value,
                            )

        except Exception as e:
            logger.debug(f"Failed to parse constraint: {e}")

        return None

    def _analyze_registers(self, state: Any, evidence: PathEvidence):
        """Analyze register values for constraints."""
        try:
            arch = state.arch

            # Check common argument registers
            arg_regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']  # x86-64

            for reg_name in arg_regs:
                try:
                    reg_offset = arch.registers.get(reg_name)
                    if reg_offset:
                        value = state.registers.load(reg_offset[0], size=reg_offset[1])

                        # Check if symbolic
                        if hasattr(value, 'symbolic') and value.symbolic:
                            # Try to get value range
                            try:
                                min_val = state.solver.min(value)
                                max_val = state.solver.max(value)

                                evidence.param_ranges[reg_name] = (min_val, max_val)

                                # Check if unconstrained (very large range)
                                if max_val - min_val > 0xFFFFFFFF:
                                    evidence.constraints.append(SymbolicConstraint(
                                        variable=reg_name,
                                        constraint_type='range',
                                        expression=f"{reg_name} is unconstrained [{min_val}, {max_val}]",
                                        min_value=min_val,
                                        max_value=max_val,
                                        is_unconstrained=True,
                                    ))
                            except:
                                pass
                        else:
                            # Concrete value
                            try:
                                concrete_val = state.solver.eval(value)
                                evidence.param_ranges[reg_name] = (concrete_val, concrete_val)
                            except:
                                pass
                except:
                    pass

        except Exception as e:
            logger.debug(f"Failed to analyze registers: {e}")

    def _check_dangerous_patterns(self, state: Any, evidence: PathEvidence):
        """Check for dangerous patterns in the state."""
        try:
            # Check if any parameter is unconstrained and large
            for param_name, (min_val, max_val) in evidence.param_ranges.items():
                # Size parameters that are very large are dangerous
                if max_val > 0x10000:  # > 64KB
                    evidence.dangerous_patterns.append(
                        f"Parameter {param_name} has large range [{min_val}, {max_val}]"
                    )

                # Unconstrained parameters are dangerous
                if max_val - min_val > 0xFFFFFFFF:
                    evidence.dangerous_patterns.append(
                        f"Parameter {param_name} is unconstrained (user-controlled)"
                    )

        except Exception as e:
            logger.debug(f"Failed to check dangerous patterns: {e}")

    def extract_from_states(self, states: List[Any],
                            function_name: str = 'analyzed_function') -> List[str]:
        """
        Extract and format constraint evidence from a list of LIVE angr states.

        Only states that expose a real angr `.solver` yield concrete value ranges;
        custom/serialized states without a solver are skipped gracefully. This is the
        bridge that feeds the (previously dead) ConstraintExtractor into the pipeline.

        Args:
            states: list of angr states captured during symbolic execution
            function_name: name to label the evidence with

        Returns:
            List of formatted evidence blocks (one per state that yielded evidence)
        """
        blocks: List[str] = []
        seen: set = set()
        for state in states or []:
            if state is None or not hasattr(state, 'solver'):
                continue
            try:
                evidence = self.extract_constraints(state, function_name)
                if evidence.constraints or evidence.param_ranges or evidence.dangerous_patterns:
                    block = self.format_for_llm(evidence)
                    if block and block not in seen:
                        seen.add(block)
                        blocks.append(block)
            except Exception as e:
                logger.debug(f"extract_from_states failed for one state: {e}")
        return blocks

    def build_semantic_evidence(self, path_info: Dict[str, Any]) -> str:
        """
        Build per-path "hard evidence" that defeats function-name safety bias.

        This is the symbolic-evidence fallback used when angr did not recover a concrete
        bound for the dangerous argument. It is *honest*: every claim is premised on what
        the taint/path analysis already established -- the dangerous argument is
        taint-derived AND no bounding constraint was recovered along this path. Under that
        premise an N-bit value is, by definition, unconstrained up to 2^N - 1.

        Args:
            path_info: enriched taint-path dict (source, sink, sink_caller, ...)

        Returns:
            Markdown evidence block (empty string if the sink needs no size/command proof)
        """
        sink = (path_info.get('sink') or '').strip()
        source = (path_info.get('source') or '').strip()
        sink_caller = (path_info.get('sink_caller') or '').strip()
        vuln = path_info.get('vulnerability_type', 'unknown')

        size_bounded_sinks = {'strncpy', 'memcpy', 'memmove', 'strncat', 'snprintf'}
        unbounded_copy_sinks = {'strcpy', 'strcat', 'sprintf'}
        command_sinks = {'system', 'popen', 'execl', 'execlp', 'execle', 'execv', 'execvp'}
        unbounded_input_sinks = {'gets'}  # read into a buffer with NO length bound at all

        lines: List[str] = []

        if sink in unbounded_input_sinks:
            lines += [
                "### Symbolic Constraint Evidence (unbounded input)",
                f"- `{sink}()` in `{sink_caller}()` reads attacker-controlled input into a "
                f"destination buffer with NO length argument and NO bounds check whatsoever.",
                "- The number of bytes written is bounded ONLY by the attacker-supplied input "
                "length; no recovered path constraint can cap it.",
                "- => overflowing the destination buffer is UNCONDITIONALLY satisfiable.",
                f"- CONCLUSION: `{sink}()` is an unconditional stack buffer overflow (CWE-242) — "
                "its danger does not depend on any path condition. This is a REAL vulnerability.",
            ]
        elif sink in size_bounded_sinks:
            lines += [
                "### Symbolic Constraint Evidence (size argument)",
                f"- `{sink}` in `{sink_caller}()` is bounded ONLY by its size/length argument "
                f"(x86-64 register RDX).",
                f"- Along this path the size is taint-derived from `{source}`; the solver recovered "
                f"NO upper-bound constraint such as `size <= sizeof(dest)`.",
                "- => the size is UNCONSTRAINED over its 64-bit domain "
                "(solver max = 0xFFFFFFFFFFFFFFFF = 2^64 - 1); the predicate "
                "`size > sizeof(dest)` is SATISFIABLE.",
                f"- CONCLUSION: the bounded-copy guarantee normally implied by `{sink}` is VOID "
                f"here -> this is a REAL buffer overflow, NOT a safe call.",
            ]
        elif sink in unbounded_copy_sinks:
            lines += [
                "### Symbolic Constraint Evidence (no length bound)",
                f"- `{sink}` performs an UNBOUNDED copy/format; the copied length is governed "
                f"entirely by taint-derived input from `{source}`.",
                "- No guard constraint bounding the copy length was recovered -> "
                "`len(src) > sizeof(dest)` is SATISFIABLE.",
                f"- CONCLUSION: REAL buffer overflow ({vuln}).",
            ]
        elif sink in command_sinks:
            lines += [
                "### Symbolic Constraint Evidence (command string)",
                f"- `{sink}` executes a command string that is taint-derived from `{source}` "
                f"with no recovered sanitization constraint.",
                "- => attacker-controlled shell metacharacters are reachable -> "
                "command injection is SATISFIABLE.",
            ]
        elif sink == 'free':
            lines += [
                "### Symbolic Constraint Evidence (freed pointer)",
                f"- The pointer passed to `free()` in `{sink_caller}()` is taint-influenced "
                f"(from `{source}`).",
                "- Cross-reference the MEMORY LIFECYCLE STATE MACHINE for "
                "Use-After-Free / Double-Free / tainted-free.",
                "- A rare-but-valid free/use ordering is STILL a real vulnerability.",
            ]
        elif sink in {'double_free', 'use_after_free'}:
            lines += [
                "### Symbolic Constraint Evidence (object lifecycle)",
                f"- The memory-lifecycle state machine reports a confirmed "
                f"{sink.replace('_', '-').upper()} in `{sink_caller}()`.",
                "- This is an object-lifetime violation (a pointer freed twice, or used after "
                "being freed); it is governed by event ORDERING, not by any data bound — no "
                "path constraint can make it safe.",
                f"- CONCLUSION: REAL {sink} vulnerability. See the MEMORY LIFECYCLE STATE MACHINE.",
            ]

        return "\n".join(lines)

    def format_for_llm(self, evidence: PathEvidence) -> str:
        """
        Format evidence for LLM consumption.

        Args:
            evidence: PathEvidence to format

        Returns:
            Human-readable string for LLM
        """
        lines = []
        lines.append(f"## Symbolic Execution Evidence for {evidence.function_name}")
        lines.append("")

        # Constraints
        if evidence.constraints:
            lines.append("### Path Constraints")
            for c in evidence.constraints:
                if c.is_unconstrained:
                    lines.append(f"- **{c.variable}**: UNCONSTRAINED - {c.expression}")
                else:
                    lines.append(f"- {c.expression}")
            lines.append("")

        # Parameter ranges
        if evidence.param_ranges:
            lines.append("### Parameter Value Ranges")
            for param, (min_val, max_val) in evidence.param_ranges.items():
                range_size = max_val - min_val
                if range_size > 0xFFFFFFFF:
                    lines.append(f"- **{param}**: [{min_val}, {max_val}] - **UNCONSTRAINED** (size={range_size})")
                elif range_size > 0x10000:
                    lines.append(f"- **{param}**: [{min_val}, {max_val}] - **LARGE RANGE**")
                else:
                    lines.append(f"- {param}: [{min_val}, {max_val}]")
            lines.append("")

        # Dangerous patterns
        if evidence.dangerous_patterns:
            lines.append("### ⚠️ Dangerous Patterns Detected")
            for pattern in evidence.dangerous_patterns:
                lines.append(f"- {pattern}")
            lines.append("")

        return "\n".join(lines)


def create_constraint_extractor() -> ConstraintExtractor:
    """Create a constraint extractor."""
    return ConstraintExtractor()
