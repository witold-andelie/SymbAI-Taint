"""
Source-Sink Checker Module

Implements: TaintState + ExecutionPaths + TaintSpec → SourceSinkChecking → TaintTrace
From infra.txt: "Source-Sink Checking"

This module checks for taint flows from sources to sinks.
"""

import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger('OPM.taint_analysis')


@dataclass
class TaintTrace:
    """A trace of taint flow from source to sink."""
    source: str
    sink: str
    source_location: Optional[int] = None
    sink_location: Optional[int] = None
    propagation_path: List[str] = field(default_factory=list)
    is_vulnerable: bool = False
    vulnerability_type: Optional[str] = None
    confidence: float = 1.0


@dataclass
class SourceSinkChecker:
    """Checks for taint flows from sources to sinks."""
    taint_spec: Dict[str, Any] = field(default_factory=dict)
    taint_state: Dict[str, Any] = field(default_factory=dict)

    def check(self, execution_paths: List[Any]) -> List[TaintTrace]:
        """
        Check for source-sink taint flows.

        Args:
            execution_paths: Execution paths to check

        Returns:
            List of taint traces
        """
        logger.info(f"Checking source-sink flows in {len(execution_paths)} paths")

        traces = []

        # Get sources and sinks from spec
        sources = {s['name'] for s in self.taint_spec.get('sources', [])}
        sinks = {s['name'] for s in self.taint_spec.get('sinks', [])}

        # Check each path
        for path in execution_paths:
            path_traces = self._check_path(path, sources, sinks)
            traces.extend(path_traces)

        logger.info(f"Source-sink checking complete: {len(traces)} traces found")
        return traces

    def _check_path(self, path: Any, sources: Set[str], sinks: Set[str]) -> List[TaintTrace]:
        """Check a single path for source-sink flows."""
        traces = []

        if not hasattr(path, 'blocks'):
            return traces

        # Track taint flow along path
        current_taint = {}  # variable -> source
        current_source = None

        for block_addr in path.blocks:
            # Check for source calls
            if self._is_source_call(block_addr, sources):
                current_source = block_addr

            # Check for sink calls
            if self._is_sink_call(block_addr, sinks):
                if current_source is not None:
                    # Found a source-sink flow
                    trace = TaintTrace(
                        source=str(current_source),
                        sink=str(block_addr),
                        source_location=current_source,
                        sink_location=block_addr,
                        is_vulnerable=self._check_vulnerability(current_source, block_addr),
                    )
                    traces.append(trace)

        return traces

    def _is_source_call(self, block_addr: int, sources: Set[str]) -> bool:
        """Check if a block calls a source function."""
        # Simplified check - would need actual call analysis
        return False

    def _is_sink_call(self, block_addr: int, sinks: Set[str]) -> bool:
        """Check if a block calls a sink function."""
        # Simplified check - would need actual call analysis
        return False

    def _check_vulnerability(self, source: Any, sink: Any) -> bool:
        """Check if a source-sink flow represents a vulnerability."""
        # Check against known vulnerability patterns
        sink_sinks = self.taint_spec.get('sinks', [])
        for sink_spec in sink_sinks:
            if sink_spec.get('type') in ['buffer_overflow', 'format_string', 'command_injection']:
                return True
        return False


def check_source_sink(
    taint_state: Dict[str, Any],
    execution_paths: List[Any],
    taint_spec: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Check for source-sink taint flows.

    Args:
        taint_state: Current taint state
        execution_paths: Execution paths to check
        taint_spec: Taint specification

    Returns:
        List of taint trace dictionaries
    """
    logger.info("Starting source-sink checking")

    checker = SourceSinkChecker(
        taint_spec=taint_spec,
        taint_state=taint_state
    )

    traces = checker.check(execution_paths)

    # Convert to dictionary format
    result = [
        {
            'source': trace.source,
            'sink': trace.sink,
            'source_location': trace.source_location,
            'sink_location': trace.sink_location,
            'propagation_path': trace.propagation_path,
            'is_vulnerable': trace.is_vulnerable,
            'vulnerability_type': trace.vulnerability_type,
            'confidence': trace.confidence,
        }
        for trace in traces
    ]

    logger.info(f"Source-sink checking complete: {len(result)} traces")
    return result


def get_vulnerability_summary(traces: List[TaintTrace]) -> Dict[str, Any]:
    """Get summary of vulnerabilities found."""
    total_traces = len(traces)
    vulnerable_traces = sum(1 for t in traces if t.is_vulnerable)

    vuln_types = {}
    for trace in traces:
        if trace.vulnerability_type:
            vuln_types[trace.vulnerability_type] = vuln_types.get(trace.vulnerability_type, 0) + 1

    return {
        'total_traces': total_traces,
        'vulnerable_traces': vulnerable_traces,
        'vulnerability_types': vuln_types,
        'vulnerability_rate': vulnerable_traces / total_traces if total_traces > 0 else 0,
    }


# Example usage
if __name__ == "__main__":
    print("Source-Sink Checker Module")
    print("This module is used as part of the OPM pipeline.")
