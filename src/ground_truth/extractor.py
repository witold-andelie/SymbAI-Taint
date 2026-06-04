"""
Ground Truth Extractor

Extracts ground truth information from C source code for evaluation.
Uses DWARF debug info and source code analysis.
"""

import os
import re
import json
import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from pathlib import Path
from dataclasses import dataclass, field

logger = logging.getLogger('OPM.ground_truth')


@dataclass
class VariableInfo:
    """Information about a variable from source code."""
    name: str
    type_name: str
    is_pointer: bool = False
    is_array: bool = False
    is_buffer: bool = False
    line_number: int = 0
    function: Optional[str] = None


@dataclass
class FunctionInfo:
    """Information about a function from source code."""
    name: str
    return_type: str
    parameters: List[Dict[str, str]] = field(default_factory=list)
    line_number: int = 0
    is_source: bool = False
    is_sink: bool = False


@dataclass
class TaintPath:
    """A taint propagation path from source to sink."""
    source: str
    sink: str
    path: List[str] = field(default_factory=list)
    line_numbers: List[int] = field(default_factory=list)
    annotated: bool = False   # came from an explicit // @vuln: source-code annotation


@dataclass
class GroundTruth:
    """Ground truth data extracted from source code."""
    source_file: str
    functions: List[FunctionInfo] = field(default_factory=list)
    variables: List[VariableInfo] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    sinks: List[str] = field(default_factory=list)
    taint_paths: List[TaintPath] = field(default_factory=list)
    vulnerable_paths: List[TaintPath] = field(default_factory=list)
    types: Dict[str, str] = field(default_factory=dict)


# Common source functions (input sources)
SOURCE_FUNCTIONS = {
    'getchar', 'gets', 'scanf', 'fscanf', 'sscanf',
    'fgets', 'gets_s', 'scanf_s',
    'read', 'recv', 'recvfrom', 'recvmsg',
    'getenv', 'getlogin', 'getpwuid',
    'fread', 'fgetc', 'getc', 'getw',
    'getline', 'getdelim',
}

# Common sink functions (dangerous operations)
SINK_FUNCTIONS = {
    'strcpy', 'strncpy', 'strcat', 'strncat',
    'sprintf', 'snprintf', 'vsprintf', 'vsnprintf',
    'printf', 'fprintf', 'vprintf', 'vfprintf',
    'system', 'popen', 'exec', 'execl', 'execlp',
    'execle', 'execv', 'execvp', 'execvpe',
    'malloc', 'calloc', 'realloc', 'free',
    'memcpy', 'memmove', 'memset',
    'gets',  # Also a source
    'scanf', 'fscanf', 'sscanf',  # Also sources
}

# Dangerous patterns
DANGEROUS_PATTERNS = [
    (r'gets\s*\(', 'buffer_overflow', 'gets() is always unsafe'),
    (r'strcpy\s*\(', 'buffer_overflow', 'strcpy() without length check'),
    (r'strcat\s*\(', 'buffer_overflow', 'strcat() without length check'),
    (r'sprintf\s*\(', 'format_string', 'sprintf() without length check'),
    (r'printf\s*\([^"\'"]', 'format_string', 'printf() with non-literal format'),
    (r'system\s*\(', 'command_injection', 'system() executes shell commands'),
    (r'exec\w*\s*\(', 'command_injection', 'exec() family executes commands'),
    (r'malloc\s*\([^)]*\)', 'memory', 'Dynamic memory allocation'),
    (r'free\s*\(', 'use_after_free', 'free() - check for use-after-free'),
]


def _strip_comments(code: str) -> str:
    """Blank out C // and /* */ comments while preserving line structure (line numbers
    and function spans stay valid). Prevents commented-out calls like
    `// vuln_popen(x);` from being parsed as real calls — that previously fabricated
    argv taint into never-called dead functions (false expected paths).
    Note: does not special-case `//` inside string literals (none in the test set).
    """
    code = re.sub(r'/\*.*?\*/', lambda m: re.sub(r'[^\n]', ' ', m.group(0)), code, flags=re.DOTALL)
    code = re.sub(r'//[^\n]*', lambda m: ' ' * len(m.group(0)), code)
    return code


def extract_ground_truth(source_path: str) -> Dict[str, Any]:
    """
    Extract ground truth from a C source file.

    Args:
        source_path: Path to the C source file

    Returns:
        Dictionary containing ground truth data
    """
    source_path = os.path.abspath(source_path)
    if not os.path.exists(source_path):
        raise FileNotFoundError(f"Source file not found: {source_path}")

    logger.info(f"Extracting ground truth from: {source_path}")

    # Read source code
    with open(source_path, 'r', encoding='utf-8', errors='ignore') as f:
        raw_source = f.read()
    # Parse explicit vuln annotations from the RAW source BEFORE comments are stripped.
    annotated_paths = extract_annotations(raw_source)
    source_code = _strip_comments(raw_source)
    lines = source_code.split('\n')

    # Extract information
    functions = extract_functions(source_code, lines)
    variables = extract_variables(source_code, lines)
    sources = identify_sources(functions, lines)
    sinks = identify_sinks(functions, lines)
    taint_paths = identify_taint_paths(source_code, lines, sources, sinks)
    taint_paths += identify_lifecycle_vulns(lines, _compute_function_spans(lines))
    taint_paths += annotated_paths
    types = extract_types(variables)

    # Build ground truth
    ground_truth = {
        'source_file': source_path,
        'functions': [
            {
                'name': f.name,
                'return_type': f.return_type,
                'parameters': f.parameters,
                'line_number': f.line_number,
                'is_source': f.is_source,
                'is_sink': f.is_sink,
            }
            for f in functions
        ],
        'variables': [
            {
                'name': v.name,
                'type_name': v.type_name,
                'is_pointer': v.is_pointer,
                'is_array': v.is_array,
                'is_buffer': v.is_buffer,
                'line_number': v.line_number,
                'function': v.function,
            }
            for v in variables
        ],
        'sources': sources,
        'sinks': sinks,
        'taint_paths': [
            {
                'source': p.source,
                'sink': p.sink,
                'path': p.path,
                'line_numbers': p.line_numbers,
            }
            for p in taint_paths
        ],
        'vulnerable_paths': [
            {
                'source': p.source,
                'sink': p.sink,
                'path': p.path,
                'line_numbers': p.line_numbers,
            }
            for p in taint_paths
            if _is_vulnerable_path(p)
        ],
        'types': types,
    }

    logger.info(f"Extracted: {len(functions)} functions, {len(variables)} variables, "
                f"{len(sources)} sources, {len(sinks)} sinks, "
                f"{len(taint_paths)} taint paths")

    return ground_truth


def extract_from_source(source_code: str) -> Dict[str, Any]:
    """
    Extract ground truth from source code string.

    Args:
        source_code: C source code string

    Returns:
        Dictionary containing ground truth data
    """
    source_code = _strip_comments(source_code)
    lines = source_code.split('\n')
    functions = extract_functions(source_code, lines)
    variables = extract_variables(source_code, lines)
    sources = identify_sources(functions, lines)
    sinks = identify_sinks(functions, lines)
    taint_paths = identify_taint_paths(source_code, lines, sources, sinks)
    taint_paths += identify_lifecycle_vulns(lines, _compute_function_spans(lines))
    types = extract_types(variables)

    return {
        'functions': functions,
        'variables': variables,
        'sources': sources,
        'sinks': sinks,
        'taint_paths': taint_paths,
        'types': types,
    }


def extract_functions(source_code: str, lines: List[str]) -> List[FunctionInfo]:
    """Extract function definitions from source code."""
    functions = []

    # Pattern for function definitions
    # Matches: type name(params) {
    func_pattern = re.compile(
        r'^(\w[\w\s\*]+?)\s+'  # Return type
        r'(\w+)\s*'  # Function name
        r'\(([^)]*)\)\s*'  # Parameters
        r'\{',  # Opening brace
        re.MULTILINE
    )

    for match in func_pattern.finditer(source_code):
        return_type = match.group(1).strip()
        func_name = match.group(2).strip()
        params_str = match.group(3).strip()

        # Skip main and common boilerplate
        if func_name in {'main', '_start', '__libc_csu_init', '__libc_csu_fini'}:
            continue

        # Parse parameters
        parameters = []
        if params_str and params_str != 'void':
            for param in params_str.split(','):
                param = param.strip()
                if param:
                    parts = param.rsplit(None, 1)
                    if len(parts) == 2:
                        parameters.append({
                            'type': parts[0].strip(),
                            'name': parts[1].strip().lstrip('*'),
                        })
                    elif len(parts) == 1:
                        parameters.append({
                            'type': parts[0].strip(),
                            'name': '',
                        })

        # Find line number
        line_number = source_code[:match.start()].count('\n') + 1

        # Check if source or sink
        is_source = func_name in SOURCE_FUNCTIONS
        is_sink = func_name in SINK_FUNCTIONS

        functions.append(FunctionInfo(
            name=func_name,
            return_type=return_type,
            parameters=parameters,
            line_number=line_number,
            is_source=is_source,
            is_sink=is_sink,
        ))

    return functions


def extract_variables(source_code: str, lines: List[str]) -> List[VariableInfo]:
    """Extract variable declarations from source code."""
    variables = []

    # Pattern for variable declarations
    # Matches: type name; or type name = ...; or type name[...];
    var_pattern = re.compile(
        r'^\s*'
        r'(?:const\s+|volatile\s+|static\s+|extern\s+)*'  # Qualifiers
        r'([\w\s\*]+?)\s+'  # Type
        r'(\*?\s*\w+)'  # Variable name (may have pointer *)
        r'(?:\s*\[[\w\s]*\])?'  # Optional array size
        r'(?:\s*=.*?)?\s*;',  # Optional initializer
        re.MULTILINE
    )

    current_function = None
    func_pattern = re.compile(r'(\w+)\s*\([^)]*\)\s*\{')

    for i, line in enumerate(lines, 1):
        # Track current function
        func_match = func_pattern.search(line)
        if func_match:
            current_function = func_match.group(1)

        # Look for variable declarations
        var_match = var_pattern.match(line)
        if var_match:
            type_name = var_match.group(1).strip()
            var_name = var_match.group(2).strip().lstrip('*')

            # Skip common non-variable patterns
            if type_name in {'if', 'else', 'while', 'for', 'return', 'switch', 'case'}:
                continue

            # Determine variable properties
            is_pointer = '*' in var_match.group(2) or '*' in type_name
            is_array = '[' in line
            is_buffer = is_array or (is_pointer and 'char' in type_name.lower())

            variables.append(VariableInfo(
                name=var_name,
                type_name=type_name,
                is_pointer=is_pointer,
                is_array=is_array,
                is_buffer=is_buffer,
                line_number=i,
                function=current_function,
            ))

    return variables


def identify_sources(functions: List[FunctionInfo], lines: List[str]) -> List[str]:
    """Identify source functions (input sources)."""
    sources = set()

    # From function definitions
    for func in functions:
        if func.is_source:
            sources.add(func.name)

    # From function calls in code
    if SOURCE_FUNCTIONS:
        source_pattern = re.compile(r'\b(' + '|'.join(SOURCE_FUNCTIONS) + r')\s*\(')
        for line in lines:
            match = source_pattern.search(line)
            if match:
                sources.add(match.group(1))

    # Check for argv usage (common source in C programs)
    argv_pattern = re.compile(r'argv\[\d+\]')
    for line in lines:
        if argv_pattern.search(line):
            sources.add('argv')
            break

    return list(sources)


def identify_sinks(functions: List[FunctionInfo], lines: List[str]) -> List[str]:
    """Identify sink functions (dangerous operations)."""
    sinks = set()

    # From function definitions
    for func in functions:
        if func.is_sink:
            sinks.add(func.name)

    # From function calls in code
    sink_pattern = re.compile(r'\b(' + '|'.join(SINK_FUNCTIONS) + r')\s*\(')
    for line in lines:
        match = sink_pattern.search(line)
        if match:
            sinks.add(match.group(1))

    return list(sinks)


def _compute_function_spans(lines: List[str]) -> List[Tuple[str, int, int]]:
    """Compute (function_name, start_line, end_line) spans via brace counting.

    Scope awareness is essential: without it, a variable named ``buffer`` tainted by
    ``gets`` in one function poisons every other function's local ``buffer`` (the old
    global var->source map), fabricating phantom paths like gets->free / gets->strncpy
    across unrelated functions. Spans let us confine taint to its real scope.
    """
    spans: List[Tuple[str, int, int]] = []
    func_def = re.compile(r'^\s*[\w\*\s]+?\b(\w+)\s*\([^;{]*\)\s*\{')
    n = len(lines)
    idx = 0
    while idx < n:
        line = lines[idx]
        m = func_def.match(line)
        # avoid matching calls/control-flow (e.g. "if (...)") as definitions
        if m and m.group(1) not in {'if', 'else', 'for', 'while', 'switch', 'return', 'sizeof'}:
            depth = line.count('{') - line.count('}')
            start = idx + 1
            j = idx
            while depth > 0 and j + 1 < n:
                j += 1
                depth += lines[j].count('{') - lines[j].count('}')
            spans.append((m.group(1), start, j + 1))
            idx = j + 1
        else:
            idx += 1
    return spans


def _param_names(signature_line: str) -> List[str]:
    """Extract parameter variable names from a function signature line."""
    names: List[str] = []
    pm = re.search(r'\(([^)]*)\)', signature_line)
    if not pm:
        return names
    params = pm.group(1).strip()
    if not params or params == 'void':
        return names
    for part in params.split(','):
        part = part.strip()
        if not part:
            continue
        token = part.rsplit(None, 1)[-1]           # last token is the name
        token = token.lstrip('*')                   # drop pointer stars
        token = re.sub(r'\[.*$', '', token)         # drop array brackets
        if token:
            names.append(token)
    return names


def identify_taint_paths(
    source_code: str,
    lines: List[str],
    sources: List[str],
    sinks: List[str]
) -> List[TaintPath]:
    """Identify potential taint propagation paths (SCOPE-AWARE).

    Taint is tracked PER FUNCTION so a local variable tainted in one function cannot
    leak its source label to a same-named local in another function. Cross-function
    flow is modeled explicitly: a function called with a tainted argument has its
    parameters marked tainted (propagated to a fixpoint), and sinks inside that
    function are then attributed to the incoming source.
    """
    paths: List[TaintPath] = []

    spans = _compute_function_spans(lines)
    if not spans:
        return paths
    func_names = {name for name, _, _ in spans}

    src_alt = '|'.join(re.escape(s) for s in sources) if sources else None
    sink_alt = '|'.join(re.escape(s) for s in sinks) if sinks else None

    source_assign = re.compile(r'(\w+)\s*=\s*(' + src_alt + r')\s*\(') if src_alt else None
    source_call = re.compile(r'\b(' + src_alt + r')\s*\(\s*&?\s*(\w+)') if src_alt else None
    argv_assign = re.compile(r'(\w+)\s*=\s*argv\s*\[\s*\d+\s*\]')
    sink_call = re.compile(r'\b(' + sink_alt + r')\s*\(\s*&?\s*(\w+)') if sink_alt else None
    call_pat = re.compile(r'\b(\w+)\s*\(\s*&?\s*(\w+)')

    # scope_taint[func][var] = source_label, populated only from in-scope evidence
    scope_taint: Dict[str, Dict[str, str]] = {name: {} for name, _, _ in spans}

    # ---- Pass 1: local sources within each function scope ----
    for name, s, e in spans:
        local = scope_taint[name]
        for ln in range(s, e + 1):
            line = lines[ln - 1]
            if source_assign:
                m = source_assign.search(line)
                if m:
                    local[m.group(1)] = m.group(2)
            if source_call:
                m = source_call.search(line)
                if m:
                    local[m.group(2)] = m.group(1)   # gets(buffer) -> buffer tainted by gets
            m = argv_assign.search(line)
            if m:
                local[m.group(1)] = 'argv'

    # ---- Pass 2: interprocedural taint into callee parameters (fixpoint) ----
    param_taint: Dict[str, str] = {}
    for _ in range(4):
        changed = False
        for name, s, e in spans:
            for ln in range(s, e + 1):
                line = lines[ln - 1]
                for m in call_pat.finditer(line):
                    callee, arg = m.group(1), m.group(2)
                    if callee in func_names and callee != name:
                        src = scope_taint[name].get(arg) or param_taint.get(name)
                        if src and param_taint.get(callee) != src:
                            param_taint[callee] = src
                            changed = True
        if not changed:
            break

    # fold incoming param taint into each callee's parameter variable names
    for name, s, e in spans:
        if name in param_taint:
            for pname in _param_names(lines[s - 1]):
                scope_taint[name].setdefault(pname, param_taint[name])

    # ---- Pass 3: sinks attributed to in-scope taint only ----
    for name, s, e in spans:
        local = scope_taint[name]
        for ln in range(s, e + 1):
            line = lines[ln - 1]
            if not sink_call:
                continue
            for m in sink_call.finditer(line):
                sink_func, arg = m.group(1), m.group(2)
                source = None
                if arg in local:
                    source = local[arg]
                elif name in param_taint:
                    # tainted data may be a non-first argument (e.g. strcpy(dest, input));
                    # attribute to the source flowing into this function's scope
                    source = param_taint[name]
                if source:
                    paths.append(TaintPath(
                        source=source,
                        sink=sink_func,
                        path=[source, arg, name, sink_func],
                        line_numbers=[ln],
                    ))

    return paths


def identify_lifecycle_vulns(lines: List[str], spans: List[Tuple[str, int, int]]) -> List[TaintPath]:
    """Detect double-free and use-after-free per function scope (object-lifecycle vulns).

    These are memory-safety bugs the data-flow source->sink view cannot express. We emit
    them as (function_name, vuln_type) entries so the set-based metric can credit the
    analyzer's lifecycle detector (which reports the same normalized pair).
    """
    vulns: List[TaintPath] = []
    free_pat = re.compile(r'\bfree\s*\(\s*&?\s*(\w+)')
    use_funcs = {'printf', 'fprintf', 'sprintf', 'snprintf', 'puts', 'fputs',
                 'strcpy', 'strncpy', 'strcat', 'strncat', 'memcpy', 'memmove', 'strlen'}
    use_call_pat = re.compile(r'\b(' + '|'.join(use_funcs) + r')\s*\(')

    for name, s, e in spans:
        if name == 'main':
            continue
        freed: Dict[str, List[int]] = {}
        for ln in range(s, e + 1):
            for m in free_pat.finditer(lines[ln - 1]):
                freed.setdefault(m.group(1), []).append(ln)
        if not freed:
            continue

        # double-free: the same variable freed two or more times in the function
        for var, lns in freed.items():
            if len(lns) >= 2:
                vulns.append(TaintPath(source=name, sink='double_free',
                                       path=[name, var, 'double_free'], line_numbers=lns))

        # use-after-free: the freed variable is read by a use-function after its free
        for var, lns in freed.items():
            first_free = min(lns)
            for ln in range(first_free + 1, e + 1):
                line = lines[ln - 1]
                if use_call_pat.search(line) and re.search(r'\b' + re.escape(var) + r'\b', line):
                    vulns.append(TaintPath(source=name, sink='use_after_free',
                                           path=[name, var, 'use_after_free'],
                                           line_numbers=[first_free, ln]))
                    break

    return vulns


def extract_types(variables: List[VariableInfo]) -> Dict[str, str]:
    """Extract type information from variables."""
    types = {}
    for var in variables:
        types[var.name] = var.type_name
    return types


def extract_annotations(raw_source: str) -> List[TaintPath]:
    """Parse explicit vulnerability annotations from source comments.

    Format (case-insensitive):  // @vuln: <type> <source> -> <sink>
    e.g.  // @vuln: buffer_overflow argv -> store_record

    Lets a benchmark/demo program declare the ground-truth path for a custom
    (non-libc) sink that the name/pattern-based extractor cannot recognise.
    """
    paths = []
    pat = re.compile(r'@vuln:\s*(\w+)\s+(\w+)\s*->\s*(\w+)', re.IGNORECASE)
    for i, line in enumerate(raw_source.split('\n'), start=1):
        m = pat.search(line)
        if m:
            _vtype, source, sink = m.group(1), m.group(2), m.group(3)
            paths.append(TaintPath(source=source, sink=sink,
                                   path=[source, sink], line_numbers=[i],
                                   annotated=True))
            logger.info(f"Annotated ground-truth path: {source} -> {sink} ({_vtype})")
    return paths


def _is_vulnerable_path(path: TaintPath) -> bool:
    """Check if a taint path represents a vulnerability."""
    if getattr(path, 'annotated', False):
        return True
    vulnerable_sinks = {'strcpy', 'strcat', 'sprintf', 'gets', 'system', 'exec'}
    return path.sink in vulnerable_sinks


# Example usage
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python extractor.py <source_file>")
        sys.exit(1)

    source = sys.argv[1]

    try:
        gt = extract_ground_truth(source)
        print(json.dumps(gt, indent=2, default=str))
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
