"""
Taint Engine V2 - Real Implementation

This module implements actual taint propagation with:
1. Function call tracking
2. Data flow analysis
3. Source-sink path detection
"""

import os
import logging
import re
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger('OPM.taint_analysis')


# Pure format-string sinks and the register that holds their FORMAT argument (x86-64).
# (sprintf/snprintf are NOT here: they are buffer-overflow sinks regardless of format.)
_FORMAT_ARG_REG = {'printf': 'rdi', 'fprintf': 'rsi'}


def _format_arg_is_rodata(proj: Any, block_addr: int, reg: str,
                          ro_range: Tuple[int, int]) -> Optional[bool]:
    """Inspect a call block: is the FORMAT register loaded from a .rodata literal?

    Returns True (last write to reg is `lea reg, [rip+disp]` into .rodata => literal
    format), False (reg written by a non-literal mov/etc. => attacker-controlled), or
    None (undeterminable -> caller should treat conservatively as NOT literal).
    """
    try:
        insns = proj.factory.block(block_addr).capstone.insns
    except Exception:
        return None
    reg32 = 'e' + reg[1:]
    verdict: Optional[bool] = None
    for insn in insns:
        op = insn.op_str
        dest = op.split(',')[0].strip()
        if dest not in (reg, reg32):
            continue
        if insn.mnemonic == 'lea' and 'rip' in op:
            m = re.search(r'\[rip\s*([+-])\s*(0x[0-9a-fA-F]+)\]', op)
            if m:
                disp = int(m.group(2), 16) * (1 if m.group(1) == '+' else -1)
                target = insn.address + insn.size + disp
                verdict = (ro_range[0] <= target < ro_range[1])
            else:
                verdict = None
        else:
            verdict = False  # mov/xor/etc. into the format register -> not a literal
    return verdict


def detect_literal_format_printf(binary_path: str, call_graph: Any) -> Set[Tuple[str, str]]:
    """Find (caller, callee) where EVERY printf/fprintf call uses a .rodata literal format.

    Such calls (e.g. printf("Buffer: %s", x)) are NOT format-string vulnerabilities, so the
    taint engine should not report them. Conservative: a function is only listed when every
    one of its printf/fprintf sites is provably a literal; any tainted or undeterminable
    site keeps the sink.
    """
    result: Set[Tuple[str, str]] = set()
    try:
        import angr  # noqa: F401
        proj = __import__('angr').Project(binary_path, auto_load_libs=False)
        ro_sec = proj.loader.main_object.sections_map.get('.rodata')
        if ro_sec is None:
            return result
        ro_range = (ro_sec.min_addr, ro_sec.max_addr)

        groups: Dict[Tuple[str, str], List[Any]] = defaultdict(list)
        for _addr, cs in call_graph.call_sites.items():
            if getattr(cs, 'callee', None) in _FORMAT_ARG_REG:
                groups[(cs.caller, cs.callee)].append(cs)

        for (caller, callee), sites in groups.items():
            reg = _FORMAT_ARG_REG[callee]
            verdicts = [_format_arg_is_rodata(proj, cs.address, reg, ro_range) for cs in sites]
            # all sites provably literal (True) -> safe to drop; otherwise keep
            if verdicts and all(v is True for v in verdicts):
                result.add((caller, callee))
    except Exception as e:
        logger.debug(f"Literal-format printf detection unavailable: {e}")
    return result


@dataclass
class TaintSource:
    """Represents a taint source (input function)."""
    function_name: str
    call_site_addr: int
    caller_function: str
    tainted_args: List[int] = field(default_factory=lambda: [0])  # Which args are tainted


@dataclass
class TaintSink:
    """Represents a taint sink (dangerous function)."""
    function_name: str
    call_site_addr: int
    caller_function: str
    vulnerable_args: List[int] = field(default_factory=lambda: [0])  # Which args are dangerous


@dataclass
class TaintPath:
    """A complete taint path from source to sink."""
    source: TaintSource
    sink: TaintSink
    propagation_path: List[str] = field(default_factory=list)  # Function names in path
    confidence: float = 1.0
    vulnerability_type: str = ''


@dataclass
class TaintState:
    """Current taint state during analysis."""
    # Tainted variables: (function_name, var_name) -> taint_source
    tainted_vars: Dict[Tuple[str, str], TaintSource] = field(default_factory=dict)
    # Tainted registers: (function_name, reg_offset) -> taint_source
    tainted_regs: Dict[Tuple[str, int], TaintSource] = field(default_factory=dict)
    # Tainted memory: (function_name, addr) -> taint_source
    tainted_memory: Dict[Tuple[str, int], TaintSource] = field(default_factory=dict)


@dataclass
class TaintEngineV2:
    """Real taint analysis engine."""
    # Source functions and their taint behavior
    source_functions: Dict[str, List[int]] = field(default_factory=lambda: {
        'getchar': [0],      # Returns tainted value
        'gets': [0],         # Arg 0 is tainted buffer
        'scanf': [1],        # Args after format string are tainted
        'fscanf': [2],       # Args after format string are tainted
        'sscanf': [2],       # Args after format string are tainted
        'fgets': [0],        # Arg 0 is tainted buffer
        'read': [1],         # Arg 1 is tainted buffer
        'recv': [1],         # Arg 1 is tainted buffer
        'recvfrom': [1],     # Arg 1 is tainted buffer
        'getenv': [0],       # Returns tainted string
        'getlogin': [0],     # Returns tainted string
        'getpwuid': [0],     # Returns tainted struct
    })

    # Additional sources that are not function calls
    # These are tracked through the binary analysis
    additional_sources: Set[str] = field(default_factory=lambda: {
        'main',  # main's argv is a source
    })

    # Sink functions and their vulnerable arguments
    sink_functions: Dict[str, List[int]] = field(default_factory=lambda: {
        'strcpy': [0, 1],    # Both args vulnerable
        'strncpy': [0, 1],   # Both args vulnerable
        'strcat': [0, 1],    # Both args vulnerable
        'strncat': [0, 1],   # Both args vulnerable
        'sprintf': [0, 1],   # Buffer and format string
        'snprintf': [0, 2],  # Buffer and format string
        'printf': [0],       # Format string
        'fprintf': [1],      # Format string
        'vprintf': [0],      # Format string
        'vfprintf': [1],     # Format string
        'system': [0],       # Command string
        'popen': [0],        # Command string
        'execl': [0],        # Command string
        'execlp': [0],       # Command string
        'execle': [0],       # Command string
        'execv': [0],        # Command string
        'execvp': [0],       # Command string
        'malloc': [0],       # Size can be tainted (heap overflow)
        'calloc': [0, 1],    # Size can be tainted
        'realloc': [1],      # Size can be tainted
        'free': [0],         # Pointer can be tainted (use-after-free)
        'gets': [0],         # Buffer can be tainted
    })

    # Propagation functions
    propagation_functions: Dict[str, str] = field(default_factory=lambda: {
        'strcpy': 'propagate',
        'strncpy': 'propagate',
        'strcat': 'propagate',
        'memcpy': 'propagate',
        'memmove': 'propagate',
        'sprintf': 'propagate',
        'snprintf': 'propagate',
        'strlen': 'propagate',
        'malloc': 'propagate',  # malloc returns tainted pointer
        'calloc': 'propagate',  # calloc returns tainted pointer
        'realloc': 'propagate', # realloc returns tainted pointer
    })

    # Analysis results
    sources_found: List[TaintSource] = field(default_factory=list)
    sinks_found: List[TaintSink] = field(default_factory=list)
    taint_paths: List[TaintPath] = field(default_factory=list)

    def analyze(self, binary_path: str, cfg: Any, call_graph: Any,
                taint_spec: Optional[Dict[str, Any]] = None,
                symbolic_results: Optional[Dict[str, Any]] = None,
                type_recovery_output: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform taint analysis on the binary.

        Args:
            binary_path: Path to the binary
            cfg: Control flow graph
            call_graph: Call graph
            taint_spec: Optional taint specification from AI Orchestrator
            symbolic_results: Optional results from symbolic execution
            type_recovery_output: Optional per-function GNN type predictions (Stage 6)

        Returns:
            Analysis results
        """
        logger.info("Starting taint analysis V2")
        self.type_recovery_output = type_recovery_output or {}

        # Update sources and sinks from taint_spec if provided
        if taint_spec:
            self._update_from_taint_spec(taint_spec)

        # Step 1: Find all source calls
        self._find_sources(call_graph)

        # Step 2: Find all sink calls (with GNN if available)
        self._find_sinks_enhanced(call_graph, cfg)

        # Step 2b: type-driven sink candidates (env-gated; off by default so existing
        # name/structure-based behavior is unchanged). Targets fully-stripped binaries
        # where custom buffer-handling functions have no recognizable name.
        if os.environ.get('OPM_TYPE_SINKS') == '1':
            self._find_sinks_by_types(call_graph)

        # Step 2.5: drop printf/fprintf sinks whose format string is a .rodata literal
        # (a conservative static guard for the classic format-string ambiguity).
        self._drop_literal_format_sinks(binary_path, call_graph)

        # Step 3: Find taint paths from sources to sinks
        self._find_taint_paths(call_graph)

        # Step 3.5: drop data-flow paths inside functions unreachable from main (dead
        # code). Lifecycle vulns are added later (Step 7) and are intentionally exempt.
        self._filter_unreachable_paths(call_graph)

        # Step 4: Filter paths using symbolic execution results
        if symbolic_results:
            self._filter_with_symbolic_results(symbolic_results)

        # Step 5: Filter paths using trained model (if available)
        self._filter_paths_with_model()

        # Step 6: Validate with counterfactual analysis
        self._validate_with_counterfactual()

        # Step 7: Track memory lifecycle for UAF detection
        self._track_lifecycle(call_graph)

        logger.info(f"Taint analysis complete: {len(self.sources_found)} sources, "
                    f"{len(self.sinks_found)} sinks, {len(self.taint_paths)} paths")

        return self._get_results()

    def _track_lifecycle(self, call_graph: Any):
        """Track memory lifecycle for UAF and double-free detection."""
        logger.info("Tracking memory lifecycle")

        try:
            from .lifecycle_tracker import create_lifecycle_tracker
            tracker = create_lifecycle_tracker()

            # Track all function calls. Sort by address so the lifecycle state machine
            # sees alloc/free events in program order (addresses increase with program
            # order within a function) -> a real double-free (free then free in the same
            # scope) is detected even if the call-site dict is unordered.
            if call_graph and hasattr(call_graph, 'call_sites'):
                for addr, call_site in sorted(call_graph.call_sites.items()):
                    caller = call_site.caller if hasattr(call_site, 'caller') else ''
                    callee = call_site.callee if hasattr(call_site, 'callee') else ''
                    tracker.track_call(caller, callee, [], addr)

            # Get vulnerabilities
            vulns = tracker.get_vulnerabilities()
            if vulns:
                logger.info(f"  Found {len(vulns)} lifecycle vulnerabilities")
                # Add lifecycle vulns to taint paths
                for vuln in vulns:
                    # Create a synthetic taint path for lifecycle vulns.
                    # Normalize the source to the function name (scope key is 'func::buffer')
                    # so the detected pair (func, vuln_type) can match the ground-truth
                    # lifecycle entry produced by the extractor.
                    from .taint_engine_v2 import TaintSource, TaintSink, TaintPath
                    vuln_func = vuln.pointer.split('::')[0]
                    source = TaintSource(
                        function_name=vuln_func,
                        call_site_addr=0,
                        caller_function=vuln_func,
                        tainted_args=[0]
                    )
                    sink = TaintSink(
                        function_name=vuln.vuln_type,
                        call_site_addr=0,
                        caller_function=vuln_func,
                        vulnerable_args=[0]
                    )
                    path = TaintPath(
                        source=source,
                        sink=sink,
                        propagation_path=['lifecycle'],
                        vulnerability_type=vuln.vuln_type,
                        confidence=vuln.confidence,
                    )
                    self.taint_paths.append(path)

            # Store lifecycle analysis for LLM context
            self._lifecycle_analysis = tracker.format_for_llm()

        except Exception as e:
            logger.debug(f"Lifecycle tracking not available: {e}")
            self._lifecycle_analysis = ""

    def _filter_with_symbolic_results(self, symbolic_results: Dict[str, Any]):
        """Filter paths using symbolic execution results."""
        logger.info("  Filtering paths with symbolic execution results")

        feasible_paths = symbolic_results.get('feasible_paths', [])
        if not feasible_paths:
            logger.info("  No feasible paths from symbolic execution, keeping all")
            return

        # Get feasible function names from symbolic execution
        feasible_functions = set()
        for path in feasible_paths:
            if hasattr(path, 'blocks'):
                for block in path.blocks:
                    # Get function name from block address
                    feasible_functions.add(block)
            elif isinstance(path, dict):
                for block in path.get('blocks', []):
                    feasible_functions.add(block)

        # Get states from symbolic execution
        states = symbolic_results.get('states', [])
        logger.info(f"  Symbolic execution: {len(feasible_paths)} paths, {len(states)} states")

        # Filter taint paths - keep only those with feasible execution
        filtered_paths = []
        for path_info in self.taint_paths:
            # Get source and sink callers
            if isinstance(path_info, dict):
                source_caller = path_info.get('source_caller', '')
                sink_caller = path_info.get('sink_caller', '')
            else:
                source_caller = path_info.source.caller_function if hasattr(path_info, 'source') else ''
                sink_caller = path_info.sink.caller_function if hasattr(path_info, 'sink') else ''

            # Keep path if both source and sink functions are in feasible paths
            # For now, keep all paths as symbolic execution doesn't provide function-level info
            filtered_paths.append(path_info)

        logger.info(f"  Symbolic filtering: {len(self.taint_paths)} -> {len(filtered_paths)} paths")
        self.taint_paths = filtered_paths

    def _update_from_taint_spec(self, taint_spec: Dict[str, Any]):
        """Update source and sink functions from taint specification."""
        logger.info("Updating from taint specification")

        # Update sources
        if 'sources' in taint_spec:
            for source in taint_spec['sources']:
                if isinstance(source, str):
                    # Add to source functions if not already present
                    if source not in self.source_functions:
                        self.source_functions[source] = [0]  # Default: first arg is tainted
                        logger.debug(f"  Added source: {source}")

        # Update sinks
        if 'sinks' in taint_spec:
            for sink in taint_spec['sinks']:
                if isinstance(sink, str):
                    # Add to sink functions if not already present
                    if sink not in self.sink_functions:
                        self.sink_functions[sink] = [0]  # Default: first arg is vulnerable
                        logger.debug(f"  Added sink: {sink}")

        logger.info(f"  Updated: {len(self.source_functions)} sources, {len(self.sink_functions)} sinks")

    def _filter_paths_with_model(self):
        """Filter taint paths using heuristic rules and type information."""
        logger.info("  Filtering paths with heuristic rules and type info")

        filtered_paths = []
        for path_info in self.taint_paths:
            # Handle both dict and TaintPath objects
            if isinstance(path_info, dict):
                source = path_info.get('source', '')
                sink = path_info.get('sink', '')
                source_caller = path_info.get('source_caller', '')
                sink_caller = path_info.get('sink_caller', '')
            else:
                # TaintPath object
                source = path_info.source.function_name if hasattr(path_info.source, 'function_name') else ''
                sink = path_info.sink.function_name if hasattr(path_info.sink, 'function_name') else ''
                source_caller = path_info.source.caller_function if hasattr(path_info.source, 'caller_function') else ''
                sink_caller = path_info.sink.caller_function if hasattr(path_info.sink, 'caller_function') else ''

            # Rule 1: If source and sink are in the same function, it's a TP
            if source_caller == sink_caller:
                filtered_paths.append(path_info)
                continue

            # Rule 2: If source is 'argv' (from main), it's likely a TP
            if source == 'argv':
                filtered_paths.append(path_info)
                continue

            # Rule 3: Type-based filtering
            # If sink is 'free' and source is not a pointer allocator, it's likely FP
            if sink == 'free' and source not in {'malloc', 'calloc', 'realloc'}:
                # Check if source allocates memory
                logger.debug(f"  Type filter: {source} -> {sink} (source not allocator)")
                continue

            # Rule 4: If sink is 'printf' and source is not a format string, it's likely FP
            if sink == 'printf' and source not in {'gets', 'scanf', 'getchar', 'fgets'}:
                # printf with user input is only dangerous if it's a format string
                logger.debug(f"  Type filter: {source} -> {sink} (not format string source)")
                continue

            # Rule 5: If source is a real input function and is called from main,
            # then taint flows through main to all other functions
            real_sources = {'gets', 'scanf', 'getchar', 'fgets', 'recv', 'read'}
            if source in real_sources:
                # Allow if source and sink are in the same function
                if source_caller == sink_caller:
                    filtered_paths.append(path_info)
                    continue
                # Allow if sink is a dangerous function
                dangerous_sinks = {'strcpy', 'strcat', 'sprintf', 'system', 'gets'}
                if sink in dangerous_sinks:
                    filtered_paths.append(path_info)
                    continue
                # Skip other cross-function flows
                logger.debug(f"  Skipping cross-function path: {source}({source_caller}) -> {sink}({sink_caller})")
                continue

            # Rule 6: If source is not a real input function, it's likely a FP
            # unless source and sink are in the same function
            if source_caller == sink_caller:
                filtered_paths.append(path_info)
                continue

        logger.info(f"  Filtered {len(self.taint_paths)} -> {len(filtered_paths)} paths")
        self.taint_paths = filtered_paths

    def _find_sources(self, call_graph: Any):
        """Find all source function calls."""
        logger.info("Finding source function calls")

        # Track which functions are called from main
        main_callees = set()
        for call_site_addr, call_site in call_graph.call_sites.items():
            if call_site.caller == 'main':
                main_callees.add(call_site.callee)

        for call_site_addr, call_site in call_graph.call_sites.items():
            if call_site.callee in self.source_functions:
                source = TaintSource(
                    function_name=call_site.callee,
                    call_site_addr=call_site_addr,
                    caller_function=call_site.caller,
                    tainted_args=self.source_functions[call_site.callee]
                )
                self.sources_found.append(source)
                logger.debug(f"Found source: {call_site.callee} in {call_site.caller}")

        # Also consider functions called from main as potential sources
        # because main's argv is a source
        for callee in main_callees:
            if callee not in self.source_functions:
                # Check if this function calls any sink
                has_sink = False
                for call_site_addr, call_site in call_graph.call_sites.items():
                    if call_site.caller == callee and call_site.callee in self.sink_functions:
                        has_sink = True
                        break

                if has_sink:
                    # Consider this function as a source (via main's argv)
                    source = TaintSource(
                        function_name='argv',
                        call_site_addr=0,
                        caller_function=callee,
                        tainted_args=[0]  # argv[1] is tainted
                    )
                    self.sources_found.append(source)
                    logger.debug(f"Found source: argv via {callee}")

        logger.info(f"Found {len(self.sources_found)} source calls")

    def _find_sinks(self, call_graph: Any):
        """Find all sink function calls."""
        logger.info("Finding sink function calls")

        # Track unique sinks to avoid duplicates
        seen_sinks = set()

        for call_site_addr, call_site in call_graph.call_sites.items():
            callee = call_site.callee
            caller = call_site.caller

            # Check if callee is a known sink
            if callee in self.sink_functions:
                key = (callee, caller)
                if key not in seen_sinks:
                    seen_sinks.add(key)
                    sink = TaintSink(
                        function_name=callee,
                        call_site_addr=call_site_addr,
                        caller_function=caller,
                        vulnerable_args=self.sink_functions[callee]
                    )
                    self.sinks_found.append(sink)
                    logger.debug(f"Found sink: {callee} in {caller}")

            # Also check if caller is a user-defined sink (from LLM)
            # This handles cases like vulnerable_strcpy -> strcpy
            if caller in self.sink_functions and caller not in seen_sinks:
                # Check if this function calls any dangerous function
                for inner_addr, inner_cs in call_graph.call_sites.items():
                    if inner_cs.caller == caller and inner_cs.callee in self.sink_functions:
                        key = (caller, caller)
                        if key not in seen_sinks:
                            seen_sinks.add(key)
                            sink = TaintSink(
                                function_name=caller,
                                call_site_addr=call_site_addr,
                                caller_function=caller,
                                vulnerable_args=self.sink_functions.get(caller, [0])
                            )
                            self.sinks_found.append(sink)
                            logger.debug(f"Found user-defined sink: {caller}")
                            break

        logger.info(f"Found {len(self.sinks_found)} sink calls")

    def _find_sinks_enhanced(self, call_graph: Any, cfg: Any = None):
        """Find sinks using GNN detector if available."""
        logger.info("Finding sink function calls (enhanced)")

        # Try GNN detector first
        try:
            from .gnn_sink_detector import create_gnn_sink_detector
            gnn_detector = create_gnn_sink_detector()

            # Use GNN to detect sinks
            detected = gnn_detector.detect_sinks(call_graph, cfg)

            for sink_info in detected:
                sink = TaintSink(
                    function_name=sink_info['function'],
                    call_site_addr=sink_info['address'],
                    caller_function=sink_info['caller'],
                    vulnerable_args=self.sink_functions.get(sink_info['function'], [0])
                )
                self.sinks_found.append(sink)

            logger.info(f"GNN detected {len(detected)} sinks")

        except Exception as e:
            logger.debug(f"GNN sink detection not available: {e}")
            # Fallback to rule-based
            self._find_sinks(call_graph)

    def _find_sinks_by_types(self, call_graph: Any):
        """Add type-driven sink candidates from GNN type recovery.

        Targets the fully-stripped case: a custom function whose name is gone
        (sub_xxxx) but whose parameters the GNN typed as char*/buffer and which
        looks like a buffer-copy (>=2 buffer-ish vars). Name/structure-based
        detection misses these; the GNN's recovered types are the only signal.

        Conservative on purpose (still gated by downstream taint-path + symbolic +
        LLM adjudication, so a flagged-but-benign function won't be reported unless
        a tainted path actually reaches it).
        """
        tro = getattr(self, 'type_recovery_output', {}) or {}
        if not getattr(self, 'type_buffer_sinks', None):
            self.type_buffer_sinks = set()
        if not tro:
            logger.info("Type-driven sinks: no type info available")
            return

        graph_funcs = set()
        for cs in call_graph.call_sites.values():
            graph_funcs.add(cs.callee)
            graph_funcs.add(cs.caller)

        seen = {(s.function_name, s.caller_function) for s in self.sinks_found}
        existing_src = {(s.function_name, s.caller_function) for s in self.sources_found}
        added = 0
        new_sink_callers = set()
        for fname, out in tro.items():
            # libc sources/sinks are already handled by name; skip them here
            if fname in self.sink_functions or fname in self.source_functions:
                continue
            if fname not in graph_funcs:
                continue
            buf_vars = [p for p in getattr(out, 'predictions', [])
                        if getattr(p, 'predicted_type', None) in ('char*', 'pointer', 'array')]
            # require >=2 buffer-ish typed vars (dst+src style copy signature)
            if len(buf_vars) < 2:
                continue
            caller, addr = None, 0
            for a, cs in call_graph.call_sites.items():
                if cs.callee == fname:
                    caller, addr = cs.caller, a
                    break
            if caller is None or (fname, caller) in seen:
                continue
            seen.add((fname, caller))
            self.sinks_found.append(TaintSink(
                function_name=fname, call_site_addr=addr,
                caller_function=caller, vulnerable_args=[0]))
            self.type_buffer_sinks.add(fname)
            new_sink_callers.add(caller)
            added += 1
            logger.debug(f"Type-based sink candidate: {fname} "
                         f"({len(buf_vars)} buffer/ptr vars from GNN)")

        # Register an argv source in each caller of a type-based sink that is reachable
        # from main, so a taint path (argv -> custom buffer sink) can actually form.
        for caller in new_sink_callers:
            reachable = caller == 'main' or self._is_called_from_main(caller, call_graph)
            if reachable and ('argv', caller) not in existing_src:
                self.sources_found.append(TaintSource(
                    function_name='argv', call_site_addr=0,
                    caller_function=caller, tainted_args=[0]))
                existing_src.add(('argv', caller))

        logger.info(f"Type-driven sinks: {added} candidate(s) from GNN types")

    def _drop_literal_format_sinks(self, binary_path: str, call_graph: Any):
        """Remove printf/fprintf sinks whose format argument is a .rodata literal.

        Such calls (printf("...%s", x)) are not format-string vulnerabilities. The guard
        is conservative: a (caller, callee) is dropped only when EVERY one of its call
        sites is provably a literal, so real format-string bugs (printf(tainted)) survive.
        """
        try:
            literal = detect_literal_format_printf(binary_path, call_graph)
        except Exception as e:
            logger.debug(f"Literal-format filter skipped: {e}")
            return
        if not literal:
            return
        before = len(self.sinks_found)
        self.sinks_found = [
            s for s in self.sinks_found
            if (s.caller_function, s.function_name) not in literal
        ]
        dropped = before - len(self.sinks_found)
        if dropped:
            logger.info(f"  Literal-format printf guard: dropped {dropped} non-vuln sink(s)")

    def _validate_with_counterfactual(self):
        """Validate taint paths using counterfactual analysis."""
        logger.info("Validating paths with counterfactual analysis")

        try:
            from .counterfactual import create_counterfactual_validator
            validator = create_counterfactual_validator()

            # Convert taint paths to dict format
            path_dicts = []
            for path in self.taint_paths:
                path_dict = {
                    'source': path.source.function_name if hasattr(path, 'source') else '',
                    'sink': path.sink.function_name if hasattr(path, 'sink') else '',
                    'source_caller': path.source.caller_function if hasattr(path, 'source') else '',
                    'sink_caller': path.sink.caller_function if hasattr(path, 'sink') else '',
                }
                path_dicts.append(path_dict)

            # Validate
            valid_paths, filtered_paths = validator.validate_paths(path_dicts)

            # Update taint paths (keep only valid ones)
            if filtered_paths:
                # Create set of filtered path keys
                filtered_keys = set()
                for fp in filtered_paths:
                    key = (fp['source'], fp['sink'], fp['source_caller'], fp['sink_caller'])
                    filtered_keys.add(key)

                # Filter original paths
                self.taint_paths = [
                    p for p in self.taint_paths
                    if (p.source.function_name, p.sink.function_name,
                        p.source.caller_function, p.sink.caller_function) not in filtered_keys
                ]

                logger.info(f"Counterfactual validation filtered {len(filtered_paths)} paths")

        except Exception as e:
            logger.debug(f"Counterfactual validation not available: {e}")

    def _find_taint_paths(self, call_graph: Any):
        """Find taint paths from sources to sinks."""
        logger.info("Finding taint paths")

        # Get all source and sink callers
        source_callers = {s.caller_function for s in self.sources_found}
        sink_callers = {s.caller_function for s in self.sinks_found}

        # Build a map of function -> (sources, sinks)
        func_sources = defaultdict(list)
        func_sinks = defaultdict(list)

        for source in self.sources_found:
            func_sources[source.caller_function].append(source)
        for sink in self.sinks_found:
            func_sinks[sink.caller_function].append(sink)

        # Find paths within the same function (most precise)
        for func_name in set(func_sources.keys()) | set(func_sinks.keys()):
            sources = func_sources.get(func_name, [])
            sinks = func_sinks.get(func_name, [])

            if sources and sinks:
                # Function has both sources and sinks
                for source in sources:
                    for sink in sinks:
                        # Scope guard: a sink that is itself an input source (gets/scanf)
                        # only forms a real path with ITSELF as the source — the fresh input
                        # IS the taint. Don't pair it with a different source such as the
                        # synthetic argv (removes FP argv->gets while keeping gets->gets).
                        if (sink.function_name in self.source_functions
                                and source.function_name != sink.function_name):
                            continue
                        taint_path = TaintPath(
                            source=source,
                            sink=sink,
                            propagation_path=[func_name],
                            vulnerability_type=self._get_vulnerability_type(sink.function_name)
                        )
                        self.taint_paths.append(taint_path)
                        logger.info(f"Found taint path (same function): {source.function_name} -> {sink.function_name}")

        # Find paths through call graph (source caller -> sink caller)
        for source in self.sources_found:
            for sink in self.sinks_found:
                # Skip if same function (already handled)
                if source.caller_function == sink.caller_function:
                    continue

                # Find path in call graph
                path = self._find_path(source, sink, call_graph)
                if path:
                    # Verify the path is valid (source and sink are actually called)
                    if self._verify_path(source, sink, path, call_graph):
                        taint_path = TaintPath(
                            source=source,
                            sink=sink,
                            propagation_path=path,
                            vulnerability_type=self._get_vulnerability_type(sink.function_name)
                        )
                        self.taint_paths.append(taint_path)
                        logger.info(f"Found taint path: {source.function_name} -> {sink.function_name}")

        # Find paths through main (argv is a source for all functions called from main)
        if 'main' in source_callers or any(s.function_name == 'argv' for s in self.sources_found):
            # All functions called from main can have tainted args from argv
            for sink in self.sinks_found:
                if sink.caller_function != 'main':
                    # Scope guard: a "sink" that is itself an input SOURCE (gets/scanf/...)
                    # does NOT consume argv — it reads fresh input into a local buffer. Its
                    # danger is already captured by the same-function source->sink path, so
                    # do not fabricate an argv-> path into it (removes FP argv->gets).
                    if sink.function_name in self.source_functions:
                        continue
                    # Check if this function is called from main
                    if self._is_called_from_main(sink.caller_function, call_graph):
                        # Create a path from argv through main to this function
                        source = TaintSource(
                            function_name='argv',
                            call_site_addr=0,
                            caller_function='main',
                            tainted_args=[0]
                        )
                        taint_path = TaintPath(
                            source=source,
                            sink=sink,
                            propagation_path=['main', sink.caller_function],
                            vulnerability_type=self._get_vulnerability_type(sink.function_name)
                        )
                        # Check if not already added
                        if not self._path_exists(taint_path):
                            self.taint_paths.append(taint_path)
                            logger.info(f"Found taint path (via main): argv -> {sink.function_name}")

        # Find paths where source is in one function and sink is in another
        # Both called from main with the same tainted argument
        # ONLY if the source function's caller passes tainted data to the sink function
        for source in self.sources_found:
            if source.caller_function != 'main':
                # Scope guard: a local-input source (gets/scanf/...) writes into a buffer
                # LOCAL to source.caller_function; that buffer does not flow through main to
                # a sibling function. Only the shared argv taint reaches siblings, and that
                # is already covered by the 'via main' block above (removes FP gets->strcpy).
                if source.function_name in self.source_functions and source.function_name != 'argv':
                    continue
                for sink in self.sinks_found:
                    # A sink that is itself an input source (gets/scanf) does not consume the
                    # incoming argv taint — skip it here too (removes FP argv->gets siblings).
                    if sink.function_name in self.source_functions:
                        continue
                    if sink.caller_function != 'main' and sink.caller_function != source.caller_function:
                        # Check if main passes the same tainted argument to both functions
                        if self._main_passes_same_tainted_arg(source.caller_function, sink.caller_function, call_graph):
                            taint_path = TaintPath(
                                source=source,
                                sink=sink,
                                propagation_path=[source.caller_function, 'main', sink.caller_function],
                                vulnerability_type=self._get_vulnerability_type(sink.function_name)
                            )
                            # Check if not already added
                            if not self._path_exists(taint_path):
                                self.taint_paths.append(taint_path)
                                logger.info(f"Found taint path (cross-function): {source.function_name} -> {sink.function_name}")

        logger.info(f"Found {len(self.taint_paths)} taint paths")

    def _main_passes_same_tainted_arg(self, func1: str, func2: str, call_graph: Any) -> bool:
        """
        Check if main passes the same tainted argument to both functions.
        This is a heuristic - we assume that if both functions are called from main
        and one of them has a source, the tainted data might flow between them.
        """
        # Get all calls from main to func1
        func1_calls = []
        for call_site_addr, call_site in call_graph.call_sites.items():
            if call_site.caller == 'main' and call_site.callee == func1:
                func1_calls.append(call_site)

        # Get all calls from main to func2
        func2_calls = []
        for call_site_addr, call_site in call_graph.call_sites.items():
            if call_site.caller == 'main' and call_site.callee == func2:
                func2_calls.append(call_site)

        # If both functions are called from main, assume they might share tainted data
        # This is a conservative heuristic to reduce false positives
        if func1_calls and func2_calls:
            # Check if the calls are close together in the code (likely sharing the same argument)
            # For now, we'll be more conservative and only allow paths where:
            # 1. The source function has a source (like gets)
            # 2. The sink function is called AFTER the source function
            # 3. Both functions take the same argument (argv[1])

            # Simple heuristic: if func1 is called before func2, and func1 has a source,
            # then tainted data might flow from func1 to func2
            if func1_calls[0].address < func2_calls[0].address:
                return True

        return False

    def _verify_path(self, source: TaintSource, sink: TaintSink, path: List[str], call_graph: Any) -> bool:
        """Verify that a taint path is valid."""
        # Check that each function in the path actually calls the next
        for i in range(len(path) - 1):
            caller = path[i]
            callee = path[i + 1]

            # Check if caller calls callee
            found = False
            for call_site_addr, call_site in call_graph.call_sites.items():
                if call_site.caller == caller and call_site.callee == callee:
                    found = True
                    break

            if not found:
                return False

        return True

    def _is_called_from_main(self, func_name: str, call_graph: Any) -> bool:
        """Check if a function is called from main (directly or indirectly)."""
        from ..binary_analysis.call_analysis import get_callers
        callers = get_callers(call_graph, func_name)
        return 'main' in callers

    def _path_exists(self, new_path: TaintPath) -> bool:
        """Check if a path already exists."""
        for existing in self.taint_paths:
            if (existing.source.caller_function == new_path.source.caller_function and
                existing.sink.function_name == new_path.sink.function_name and
                existing.sink.caller_function == new_path.sink.caller_function):
                return True
        return False

    def _reachable_from_main(self, call_graph: Any) -> Set[str]:
        """Functions reachable from main via the call-graph callee closure."""
        reachable: Set[str] = set()
        if not hasattr(call_graph, 'callers'):
            return reachable
        stack = ['main']
        while stack:
            fn = stack.pop()
            if fn in reachable:
                continue
            reachable.add(fn)
            for callee in call_graph.callers.get(fn, set()):
                if callee not in reachable:
                    stack.append(callee)
        return reachable

    def _filter_unreachable_paths(self, call_graph: Any):
        """Drop data-flow taint paths whose sink lives in a function not reachable from
        main. An entry-point (argv) taint analysis must not report source->sink flows in
        dead code (e.g. functions commented out of main). Lifecycle vulns are added after
        this stage, so they are unaffected.
        """
        reachable = self._reachable_from_main(call_graph)
        if not reachable or reachable == {'main'}:
            return  # broken/empty call graph -> don't risk dropping everything
        kept = [p for p in self.taint_paths
                if getattr(getattr(p, 'sink', None), 'caller_function', '') in reachable]
        dropped = len(self.taint_paths) - len(kept)
        if dropped:
            logger.info(f"  Reachability filter: dropped {dropped} dead-code path(s)")
        self.taint_paths = kept

    def _find_path(
        self,
        source: TaintSource,
        sink: TaintSink,
        call_graph: Any
    ) -> Optional[List[str]]:
        """
        Find a path from source's caller to sink's caller.

        Args:
            source: Taint source
            sink: Taint sink
            call_graph: Call graph

        Returns:
            List of function names forming the path, or None
        """
        source_caller = source.caller_function
        sink_caller = sink.caller_function

        # If source and sink are in the same function
        if source_caller == sink_caller:
            return [source_caller]

        # Find path in call graph
        from ..binary_analysis.call_analysis import get_call_path, get_callers

        # Direct path
        path = get_call_path(call_graph, source_caller, sink_caller)
        if path:
            return path

        # Try reverse path (sink caller -> source caller)
        path = get_call_path(call_graph, sink_caller, source_caller)
        if path:
            return list(reversed(path))

        # Check if both are called from main or a common caller
        source_callers = get_callers(call_graph, source_caller)
        sink_callers = get_callers(call_graph, sink_caller)

        # Add the function itself to the callers set
        source_callers.add(source_caller)
        sink_callers.add(sink_caller)

        # Find common callers
        common = source_callers & sink_callers
        if common:
            # Return path through common caller
            common_caller = common.pop()
            return [source_caller, common_caller, sink_caller]

        return None

    def _get_vulnerability_type(self, sink_name: str) -> str:
        """Get vulnerability type for a sink function."""
        vuln_types = {
            'strcpy': 'buffer_overflow',
            'strncpy': 'buffer_overflow',
            'strcat': 'buffer_overflow',
            'strncat': 'buffer_overflow',
            'sprintf': 'format_string',
            'snprintf': 'format_string',
            'printf': 'format_string',
            'fprintf': 'format_string',
            'vprintf': 'format_string',
            'vfprintf': 'format_string',
            'system': 'command_injection',
            'popen': 'command_injection',
            'execl': 'command_injection',
            'execlp': 'command_injection',
            'execle': 'command_injection',
            'execv': 'command_injection',
            'execvp': 'command_injection',
        }
        if sink_name in vuln_types:
            return vuln_types[sink_name]
        # GNN type-driven buffer sinks (custom functions) → buffer overflow
        if sink_name in getattr(self, 'type_buffer_sinks', set()):
            return 'buffer_overflow'
        return 'unknown'

    def _get_results(self) -> Dict[str, Any]:
        """Get analysis results with enriched context for LLM."""
        taint_paths_enriched = []
        for p in self.taint_paths:
            # Build enriched path info with call stack and parameter context
            path_info = {
                'source': p.source.function_name,
                'source_caller': p.source.caller_function,
                'source_address': p.source.call_site_addr,
                'sink': p.sink.function_name,
                'sink_caller': p.sink.caller_function,
                'sink_address': p.sink.call_site_addr,
                'path': p.propagation_path,
                'vulnerability_type': p.vulnerability_type,
                'confidence': p.confidence,
                # Enriched context for LLM
                'call_stack_depth': len(p.propagation_path),
                'is_same_function': p.source.caller_function == p.sink.caller_function,
                'source_tainted_args': p.source.tainted_args,
                'sink_vulnerable_args': p.sink.vulnerable_args,
                # Build call chain description
                'call_chain': self._build_call_chain(p),
                # Parameter flow description
                'param_flow': self._build_param_flow(p),
            }
            taint_paths_enriched.append(path_info)

        return {
            'sources': [
                {
                    'function': s.function_name,
                    'caller': s.caller_function,
                    'address': s.call_site_addr,
                    'tainted_args': s.tainted_args,
                }
                for s in self.sources_found
            ],
            'sinks': [
                {
                    'function': s.function_name,
                    'caller': s.caller_function,
                    'address': s.call_site_addr,
                    'vulnerable_args': s.vulnerable_args,
                }
                for s in self.sinks_found
            ],
            'taint_paths': taint_paths_enriched,
            'summary': {
                'total_sources': len(self.sources_found),
                'total_sinks': len(self.sinks_found),
                'total_paths': len(self.taint_paths),
                'vulnerability_types': self._count_vulnerability_types(),
            },
            # Lifecycle analysis for LLM context
            'lifecycle_analysis': getattr(self, '_lifecycle_analysis', ''),
        }

    def _count_vulnerability_types(self) -> Dict[str, int]:
        """Count vulnerabilities by type."""
        counts = defaultdict(int)
        for path in self.taint_paths:
            counts[path.vulnerability_type] += 1
        return dict(counts)

    def _build_call_chain(self, path: TaintPath) -> str:
        """Build a human-readable call chain description for LLM."""
        source = path.source
        sink = path.sink
        propagation = path.propagation_path

        # Build call chain
        chain_parts = []

        # Source function call
        if source.caller_function != 'main':
            chain_parts.append(f"[Depth 1] main() calls {source.caller_function}()")

        # Source call
        chain_parts.append(f"[Depth {len(chain_parts)+1}] {source.caller_function}() calls {source.function_name}() [SOURCE: tainted input]")

        # Intermediate functions
        for i, func in enumerate(propagation):
            if func != source.caller_function and func != sink.caller_function:
                chain_parts.append(f"[Depth {len(chain_parts)+1}] {func}()")

        # Sink call
        if sink.caller_function != source.caller_function:
            chain_parts.append(f"[Depth {len(chain_parts)+1}] {sink.caller_function}() calls {sink.function_name}() [SINK: {path.vulnerability_type}]")

        return " -> ".join(chain_parts)

    def _build_param_flow(self, path: TaintPath) -> str:
        """Build parameter flow description for LLM."""
        source = path.source
        sink = path.sink

        # Describe parameter flow
        flow_parts = []

        # Source taints specific arguments
        if source.tainted_args:
            args_str = ", ".join([f"arg{i}" for i in source.tainted_args])
            flow_parts.append(f"{source.function_name}() taints {args_str}")

        # Flow through call chain
        if path.propagation_path:
            flow_parts.append(f"Taint propagates through: {' -> '.join(path.propagation_path)}")

        # Sink receives tainted data
        if sink.vulnerable_args:
            args_str = ", ".join([f"arg{i}" for i in sink.vulnerable_args])
            flow_parts.append(f"{sink.function_name}() receives tainted data in {args_str}")

        return "; ".join(flow_parts) if flow_parts else "Direct flow"


def run_taint_analysis(
    binary_path: str,
    cfg: Any,
    call_graph: Any,
    taint_spec: Optional[Dict[str, Any]] = None,
    symbolic_results: Optional[Dict[str, Any]] = None,
    type_recovery_output: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Run taint analysis on a binary.

    Args:
        binary_path: Path to the binary
        cfg: Control flow graph
        call_graph: Call graph
        taint_spec: Optional taint specification from AI Orchestrator
        symbolic_results: Optional results from symbolic execution

    Returns:
        Taint analysis results
    """
    engine = TaintEngineV2()
    return engine.analyze(binary_path, cfg, call_graph, taint_spec, symbolic_results,
                          type_recovery_output)
