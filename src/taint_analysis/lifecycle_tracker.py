"""
Memory Lifecycle Tracker

Implements state machine primitives for tracking object lifecycle:
- Allocation (malloc, calloc, realloc)
- Taint Input (gets, scanf, etc.)
- Deallocation (free)
- Use-After-Free detection

This helps identify real vulnerability patterns even when they're rare in business logic.
"""

import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger('OPM.taint_analysis')


class LifecycleState(Enum):
    """States in the memory lifecycle state machine."""
    UNALLOCATED = "unallocated"
    ALLOCATED = "allocated"
    TAINTED = "tainted"
    FREED = "freed"
    USE_AFTER_FREE = "use_after_free"


class LifecycleEvent(Enum):
    """Events in the memory lifecycle state machine."""
    ALLOCATE = "allocate"        # malloc, calloc, realloc
    TAINT_INPUT = "taint_input"  # gets, scanf, read
    DEALLOCATE = "deallocate"    # free
    USE = "use"                  # any operation on the pointer
    DEREFERENCE = "dereference"  # read/write through pointer


# State transition table
TRANSITIONS = {
    (LifecycleState.UNALLOCATED, LifecycleEvent.ALLOCATE): LifecycleState.ALLOCATED,
    (LifecycleState.UNALLOCATED, LifecycleEvent.TAINT_INPUT): LifecycleState.TAINTED,
    (LifecycleState.ALLOCATED, LifecycleEvent.TAINT_INPUT): LifecycleState.TAINTED,
    (LifecycleState.ALLOCATED, LifecycleEvent.DEALLOCATE): LifecycleState.FREED,
    (LifecycleState.ALLOCATED, LifecycleEvent.USE): LifecycleState.ALLOCATED,
    (LifecycleState.TAINTED, LifecycleEvent.DEALLOCATE): LifecycleState.FREED,
    (LifecycleState.TAINTED, LifecycleEvent.USE): LifecycleState.TAINTED,
    (LifecycleState.FREED, LifecycleEvent.USE): LifecycleState.USE_AFTER_FREE,
    (LifecycleState.FREED, LifecycleEvent.DEALLOCATE): LifecycleState.FREED,  # Double free
    (LifecycleState.FREED, LifecycleEvent.DEREFERENCE): LifecycleState.USE_AFTER_FREE,
}


@dataclass
class LifecycleRecord:
    """Record of a pointer's lifecycle."""
    pointer: str                    # Pointer identifier (register or address)
    state: LifecycleState = LifecycleState.UNALLOCATED
    events: List[Tuple[LifecycleEvent, str, int]] = field(default_factory=list)  # (event, function, address)
    taint_source: Optional[str] = None
    allocated_size: Optional[int] = None
    freed_by: Optional[str] = None


@dataclass
class LifecycleVulnerability:
    """A vulnerability detected by lifecycle tracking."""
    vuln_type: str                  # 'use_after_free', 'double_free', 'tainted_free'
    pointer: str
    description: str
    evidence: List[str] = field(default_factory=list)
    confidence: float = 1.0


class LifecycleTracker:
    """
    Tracks memory lifecycle to detect UAF, double-free, and tainted-free.
    """

    def __init__(self):
        # Track pointer states
        self.pointers: Dict[str, LifecycleRecord] = {}

        # Allocation functions
        self.alloc_funcs = {'malloc', 'calloc', 'realloc', 'mmap'}
        # Deallocation functions
        self.dealloc_funcs = {'free', 'munmap'}
        # Taint input functions
        self.taint_funcs = {'gets', 'scanf', 'fgets', 'read', 'recv', 'getchar'}

        # Detected vulnerabilities
        self.vulnerabilities: List[LifecycleVulnerability] = []

    def track_call(self, caller: str, callee: str, args: List[Any], address: int):
        """
        Track a function call for lifecycle analysis.

        Args:
            caller: Calling function name
            callee: Called function name
            args: Function arguments
            address: Call address
        """
        # Check if it's an allocation
        if callee in self.alloc_funcs:
            self._track_allocation(callee, caller, args, address)

        # Check if it's a deallocation
        elif callee in self.dealloc_funcs:
            self._track_deallocation(callee, caller, args, address)

        # Check if it's a taint input
        elif callee in self.taint_funcs:
            self._track_taint_input(callee, caller, args, address)

        # Check for explicit UAF patterns:
        # - free(ptr) followed by use(ptr) in the SAME function
        # This is handled by checking freed pointers in subsequent calls
        self._check_uaf_after_free(callee, caller, args, address)

    def _scope_key(self, caller: str) -> str:
        """Identify the buffer tracked for a function scope.

        Binary call sites arrive WITHOUT the freed pointer's identity (args is empty),
        so we cannot match a free() to a specific allocation by argument. We instead
        approximate ONE tracked buffer per CALLER function. This keeps each function's
        malloc/taint/free lifecycle independent. The previous implementation keyed
        allocations by call-site address but then freed/tainted EVERY tracked pointer
        on any free(), which fabricated cross-function double-frees (revio finding).
        """
        return f"{caller or 'unknown'}::buffer"

    def _track_allocation(self, func: str, caller: str, args: List[Any], address: int):
        """Track memory allocation (scoped to the calling function)."""
        ptr_name = self._scope_key(caller)

        record = LifecycleRecord(
            pointer=ptr_name,
            state=LifecycleState.ALLOCATED,
            events=[(LifecycleEvent.ALLOCATE, caller, address)],
            allocated_size=args[0] if args else None,
        )

        self.pointers[ptr_name] = record
        logger.debug(f"Tracked allocation in scope {caller}")

    def _track_deallocation(self, func: str, caller: str, args: List[Any], address: int):
        """Track memory deallocation for THIS scope's pointer only.

        A double-free is reported ONLY when the same scope's pointer is freed again,
        not when some unrelated pointer happens to already be FREED.
        """
        key = self._scope_key(caller)
        record = self.pointers.get(key)
        if record is None:
            # free() with no tracked allocation in this scope: start a record so a
            # genuine later double-free in the same scope can still be detected.
            record = LifecycleRecord(pointer=key, state=LifecycleState.UNALLOCATED)
            self.pointers[key] = record

        if record.state == LifecycleState.FREED:
            # The pointer owned by this scope is freed a second time -> real double free.
            self.vulnerabilities.append(LifecycleVulnerability(
                vuln_type='double_free',
                pointer=key,
                description=f"Double free in {caller}",
                evidence=[
                    f"First freed by: {record.freed_by}",
                    f"Second free in: {caller} at {hex(address)}",
                ],
            ))
            logger.warning(f"Double free detected in {caller}")
            record.events.append((LifecycleEvent.DEALLOCATE, caller, address))
            return

        # Normal first free: transition this scope's record to FREED.
        new_state = TRANSITIONS.get((record.state, LifecycleEvent.DEALLOCATE))
        if new_state:
            record.state = new_state
            record.freed_by = caller
            record.events.append((LifecycleEvent.DEALLOCATE, caller, address))

    def _track_taint_input(self, func: str, caller: str, args: List[Any], address: int):
        """Track taint input into THIS scope's buffer only."""
        key = self._scope_key(caller)
        record = self.pointers.get(key)
        if record is None:
            # taint into a stack buffer with no prior malloc in this scope
            record = LifecycleRecord(pointer=key, state=LifecycleState.UNALLOCATED)
            self.pointers[key] = record

        new_state = TRANSITIONS.get((record.state, LifecycleEvent.TAINT_INPUT))
        if new_state:
            record.state = new_state
            record.taint_source = func
            record.events.append((LifecycleEvent.TAINT_INPUT, caller, address))

    # Functions that READ/use a pointer argument (a use of a freed buffer => UAF)
    use_funcs = {'printf', 'fprintf', 'sprintf', 'snprintf', 'puts', 'fputs',
                 'strcpy', 'strncpy', 'strcat', 'strncat', 'memcpy', 'memmove', 'strlen'}

    def _check_uaf_after_free(self, func: str, caller: str, args: List[Any], address: int):
        """Detect use-after-free: a read/use of THIS scope's buffer after it was freed.

        Relies on call sites being processed in program (address) order so a use is only
        flagged when this scope's record is already in the FREED state. Approximates one
        buffer per function scope (no argument resolution available from the call graph).
        """
        if func not in self.use_funcs:
            return
        key = self._scope_key(caller)
        record = self.pointers.get(key)
        if record is not None and record.state == LifecycleState.FREED:
            self.vulnerabilities.append(LifecycleVulnerability(
                vuln_type='use_after_free',
                pointer=key,
                description=f"Use-after-free in {caller}",
                evidence=[
                    f"Pointer freed by {record.freed_by}, then used via {func}() at {hex(address)}",
                ],
            ))
            logger.warning(f"Use-after-free detected in {caller}")
            record.state = LifecycleState.USE_AFTER_FREE  # avoid duplicate reports

    def _track_use(self, func: str, caller: str, args: List[Any], address: int):
        """Track pointer use."""
        # Only detect UAF if the pointer is used AFTER being freed
        # Not just because it was freed at some point
        pass  # Skip generic use tracking - only detect explicit UAF patterns

    def get_vulnerabilities(self) -> List[LifecycleVulnerability]:
        """Get all detected vulnerabilities."""
        return self.vulnerabilities

    def format_for_llm(self) -> str:
        """
        Format lifecycle analysis for LLM consumption.

        Returns:
            Human-readable string describing lifecycle issues
        """
        lines = []
        lines.append("## Memory Lifecycle Analysis")
        lines.append("")

        if not self.vulnerabilities:
            lines.append("No lifecycle vulnerabilities detected.")
            return "\n".join(lines)

        lines.append("### ⚠️ Lifecycle Vulnerabilities Detected")
        lines.append("")

        for vuln in self.vulnerabilities:
            lines.append(f"**{vuln.vuln_type.upper()}**: {vuln.description}")
            for evidence in vuln.evidence:
                lines.append(f"  - {evidence}")
            lines.append("")

        # State machine summary
        lines.append("### Pointer State Summary")
        for ptr_name, record in self.pointers.items():
            if record.state != LifecycleState.UNALLOCATED:
                events_str = " -> ".join([e[0].value for e in record.events])
                lines.append(f"- {ptr_name}: {record.state.value} [{events_str}]")

        return "\n".join(lines)


class TaintedFreeDetector:
    """
    Detects tainted-free vulnerabilities:
    When taint data controls the address being freed.
    """

    def __init__(self):
        self.tainted_pointers: Set[str] = set()

    def check_tainted_free(self, free_arg: Any, taint_state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Check if a free() call receives a tainted pointer.

        Args:
            free_arg: The argument to free()
            taint_state: Current taint state

        Returns:
            Vulnerability info if detected
        """
        # Check if the pointer is tainted
        if self._is_tainted(free_arg, taint_state):
            return {
                'type': 'tainted_free',
                'description': 'free() called with tainted pointer - potential arbitrary free',
                'confidence': 0.9,
                'evidence': 'Taint data controls the pointer being freed',
            }
        return None

    def _is_tainted(self, value: Any, taint_state: Dict[str, Any]) -> bool:
        """Check if a value is tainted."""
        # Simplified check
        tainted_vars = taint_state.get('tainted_vars', {})
        return str(value) in tainted_vars


def create_lifecycle_tracker() -> LifecycleTracker:
    """Create a lifecycle tracker."""
    return LifecycleTracker()


def create_tainted_free_detector() -> TaintedFreeDetector:
    """Create a tainted-free detector."""
    return TaintedFreeDetector()
