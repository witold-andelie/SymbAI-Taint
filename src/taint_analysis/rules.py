"""
Taint Rules Module

Defines taint specifications and rules for taint analysis.
"""

import json
import os
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger('OPM.taint_analysis')


@dataclass
class TaintSource:
    """Definition of a taint source."""
    name: str
    type: str  # 'input', 'network', 'environment', 'file'
    description: str = ''
    return_type: str = 'void*'


@dataclass
class TaintSink:
    """Definition of a taint sink."""
    name: str
    type: str  # 'buffer_overflow', 'format_string', 'command_injection', 'memory', 'use_after_free'
    description: str = ''
    vulnerable_args: List[int] = field(default_factory=lambda: [0])


@dataclass
class TaintRule:
    """A taint propagation rule."""
    operation: str  # 'assign', 'add', 'sub', 'call', etc.
    propagates: bool = True
    description: str = ''


@dataclass
class TaintSpec:
    """Complete taint specification."""
    sources: List[TaintSource] = field(default_factory=list)
    sinks: List[TaintSink] = field(default_factory=list)
    rules: List[TaintRule] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'sources': [
                {
                    'name': s.name,
                    'type': s.type,
                    'description': s.description,
                    'return_type': s.return_type,
                }
                for s in self.sources
            ],
            'sinks': [
                {
                    'name': s.name,
                    'type': s.type,
                    'description': s.description,
                    'vulnerable_args': s.vulnerable_args,
                }
                for s in self.sinks
            ],
            'rules': [
                {
                    'operation': r.operation,
                    'propagates': r.propagates,
                    'description': r.description,
                }
                for r in self.rules
            ],
        }


def load_taint_spec(spec_path: str) -> TaintSpec:
    """
    Load taint specification from file.

    Args:
        spec_path: Path to specification file (JSON)

    Returns:
        TaintSpec object
    """
    if not os.path.exists(spec_path):
        raise FileNotFoundError(f"Taint spec not found: {spec_path}")

    logger.info(f"Loading taint spec from: {spec_path}")

    with open(spec_path, 'r') as f:
        data = json.load(f)

    return parse_taint_spec(data)


def parse_taint_spec(data: Dict[str, Any]) -> TaintSpec:
    """
    Parse taint specification from dictionary.

    Args:
        data: Specification dictionary

    Returns:
        TaintSpec object
    """
    spec = TaintSpec()

    # Parse sources
    for source_data in data.get('sources', []):
        source = TaintSource(
            name=source_data.get('name', ''),
            type=source_data.get('type', 'input'),
            description=source_data.get('description', ''),
            return_type=source_data.get('return_type', 'void*'),
        )
        spec.sources.append(source)

    # Parse sinks
    for sink_data in data.get('sinks', []):
        sink = TaintSink(
            name=sink_data.get('name', ''),
            type=sink_data.get('type', 'unknown'),
            description=sink_data.get('description', ''),
            vulnerable_args=sink_data.get('vulnerable_args', [0]),
        )
        spec.sinks.append(sink)

    # Parse rules
    for rule_data in data.get('rules', []):
        rule = TaintRule(
            operation=rule_data.get('operation', ''),
            propagates=rule_data.get('propagates', True),
            description=rule_data.get('description', ''),
        )
        spec.rules.append(rule)

    return spec


def get_default_taint_spec() -> TaintSpec:
    """Get default taint specification."""
    spec = TaintSpec()

    # Common sources
    spec.sources = [
        TaintSource(name='getchar', type='input', return_type='int'),
        TaintSource(name='gets', type='input', return_type='char*'),
        TaintSource(name='scanf', type='input', return_type='int'),
        TaintSource(name='fgets', type='input', return_type='char*'),
        TaintSource(name='read', type='input', return_type='ssize_t'),
        TaintSource(name='recv', type='network', return_type='ssize_t'),
        TaintSource(name='recvfrom', type='network', return_type='ssize_t'),
        TaintSource(name='getenv', type='environment', return_type='char*'),
    ]

    # Common sinks
    spec.sinks = [
        TaintSink(name='strcpy', type='buffer_overflow', vulnerable_args=[0, 1]),
        TaintSink(name='strncpy', type='buffer_overflow', vulnerable_args=[0, 1]),
        TaintSink(name='strcat', type='buffer_overflow', vulnerable_args=[0, 1]),
        TaintSink(name='strncat', type='buffer_overflow', vulnerable_args=[0, 1]),
        TaintSink(name='sprintf', type='format_string', vulnerable_args=[0, 1]),
        TaintSink(name='snprintf', type='format_string', vulnerable_args=[0, 2]),
        TaintSink(name='printf', type='format_string', vulnerable_args=[0]),
        TaintSink(name='fprintf', type='format_string', vulnerable_args=[1]),
        TaintSink(name='system', type='command_injection', vulnerable_args=[0]),
        TaintSink(name='popen', type='command_injection', vulnerable_args=[0]),
        TaintSink(name='execl', type='command_injection', vulnerable_args=[0]),
        TaintSink(name='execlp', type='command_injection', vulnerable_args=[0]),
        TaintSink(name='execle', type='command_injection', vulnerable_args=[0]),
        TaintSink(name='execv', type='command_injection', vulnerable_args=[0]),
        TaintSink(name='execvp', type='command_injection', vulnerable_args=[0]),
        TaintSink(name='malloc', type='memory'),
        TaintSink(name='calloc', type='memory'),
        TaintSink(name='realloc', type='memory'),
        TaintSink(name='free', type='use_after_free'),
        TaintSink(name='memcpy', type='buffer_overflow', vulnerable_args=[0, 1]),
        TaintSink(name='memmove', type='buffer_overflow', vulnerable_args=[0, 1]),
        TaintSink(name='memset', type='buffer_overflow', vulnerable_args=[0]),
    ]

    # Propagation rules
    spec.rules = [
        TaintRule(operation='assign', propagates=True, description='Direct assignment'),
        TaintRule(operation='add', propagates=True, description='Addition'),
        TaintRule(operation='sub', propagates=True, description='Subtraction'),
        TaintRule(operation='mul', propagates=True, description='Multiplication'),
        TaintRule(operation='div', propagates=False, description='Division (may not propagate)'),
        TaintRule(operation='call', propagates=True, description='Function call'),
        TaintRule(operation='return', propagates=True, description='Return value'),
    ]

    return spec


def save_taint_spec(spec: TaintSpec, output_path: str):
    """Save taint specification to file."""
    logger.info(f"Saving taint spec to: {output_path}")

    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)

    with open(output_path, 'w') as f:
        json.dump(spec.to_dict(), f, indent=2)

    logger.info(f"Taint spec saved")


def is_source(spec: TaintSpec, function_name: str) -> bool:
    """Check if a function is a taint source."""
    return any(s.name == function_name for s in spec.sources)


def is_sink(spec: TaintSpec, function_name: str) -> bool:
    """Check if a function is a taint sink."""
    return any(s.name == function_name for s in spec.sinks)


def get_source_type(spec: TaintSpec, function_name: str) -> Optional[str]:
    """Get the type of a taint source."""
    for source in spec.sources:
        if source.name == function_name:
            return source.type
    return None


def get_sink_type(spec: TaintSpec, function_name: str) -> Optional[str]:
    """Get the type of a taint sink."""
    for sink in spec.sinks:
        if sink.name == function_name:
            return sink.type
    return None


def get_vulnerable_args(spec: TaintSpec, function_name: str) -> List[int]:
    """Get vulnerable argument indices for a sink function."""
    for sink in spec.sinks:
        if sink.name == function_name:
            return sink.vulnerable_args
    return []


# Example usage
if __name__ == "__main__":
    import sys

    # Generate default taint spec
    spec = get_default_taint_spec()

    output_path = sys.argv[1] if len(sys.argv) > 1 else "taint_spec.json"
    save_taint_spec(spec, output_path)

    print(f"Taint spec saved to: {output_path}")
    print(f"  Sources: {len(spec.sources)}")
    print(f"  Sinks: {len(spec.sinks)}")
    print(f"  Rules: {len(spec.rules)}")
