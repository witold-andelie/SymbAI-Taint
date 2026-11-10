# SymbAI-Taint — Internal Reference

> **Detailed architecture, modules, and file call relationships.**

---

## Table of Contents
1. [Architecture in detail](#1-architecture-in-detail)
2. [Pipeline stages in detail](#2-pipeline-stages-in-detail)
3. [Core modules](#3-core-modules)
4. [File call relationships](#4-file-call-relationships)
5. [Data-flow diagrams](#5-data-flow-diagrams)
6. [Configuration](#6-configuration)
7. [API](#7-api)
8. [Known issues](#8-known-issues)

---

## 1. Architecture in detail

### 1.1 Object/Process overview
The system is described in terms of objects and processes:

**Objects**: Binary Program, VEX IR, CFG, DFG, TypeRecoveryOutput, TypedIR, TaintSpecification,
ExecutionPaths, TaintTraces, AnalysisReport.

**Processes**: Compilation, CodeLifting, CFGRecovery, DFGConstruction, GNNSemanticInference,
TypeMetadataInjection, PathPrioritization, SymbolicExecution, TaintPropagation, SourceSinkChecking,
Evaluation, ReportGeneration.

### 1.2 Core innovations
1. **GNN type recovery**: recover variable types from binaries with a graph neural network.
2. **LLM orchestrator**: use an LLM for adjudication/decisions.
3. **Soft-threshold decision**: balance precision and recall.
4. **Chain-of-thought reasoning**: multi-stage analysis.

### 1.3 Precision methodology contributions (v9–v12, all 6 programs at 100/100/100)
5. **Scope-aware ground truth and taint engine** (`ground_truth/extractor.py`,
   `taint_analysis/taint_engine_v2.py`): per-function taint tracking; GT's `identify_taint_paths` works per
   function scope (Pass 1 local sources / Pass 2 inter-procedural fixpoint over parameters / Pass 3 attribute
   only in-scope taint); 4 cross-function guards in the taint engine (an input source used as a sink only
   pairs with itself; local input sources do not cross sibling functions). Eliminates the phantom
   false-negatives/positives from mis-linking same-named variables across scopes.
6. **Reviving reasoning-model adjudication** (`orchestrator/llm_client.py`): a reasoning model's hidden
   tokens count against `max_tokens`; at 1024 the visible JSON is truncated, `_parse_json_response` fails,
   and adjudication silently defaults to 0.5. Raised to **4096** + tolerant regex parsing + JSON decision
   field (`is_feasible`/`score`) placed first + actually injecting `lifecycle_analysis`.
7. **Symbolic hard evidence** (`symbolic_exec/constraint_extractor.py::build_semantic_evidence`): inject
   "hard facts" by sink type — unconstrained strncpy size (solver max = 2⁶⁴−1), unconditional gets stack
   overflow (CWE-242), double_free/UAF lifecycle violations — to stabilize LLM adjudication and remove
   temperature jitter.
8. **Object-lifecycle state-machine scoring** (`taint_analysis/lifecycle_tracker.py`,
   `extractor.identify_lifecycle_vulns`): real UAF detection (use after free); double-free/UAF aligned on
   both GT and analyzer sides by `(function, defect type)`, so memory-safety bugs a flat data-flow
   model cannot express count as TP.
9. **printf format-string .rodata guard** (`taint_engine_v2.detect_literal_format_printf`): disassemble
   printf/fprintf call blocks with angr and check whether the format-argument register (printf→RDI,
   fprintf→RSI) points to `.rodata` via `lea reg,[rip+disp]`
   (`sections_map['.rodata'].min_addr/max_addr`). **Conservative**: downgrade only when *all* call sites of a
   `(caller, callee)` are proven literal; real `printf(tainted)` is always kept.
10. **Dead-code handling** (`extractor._strip_comments`, `taint_engine_v2._filter_unreachable_paths`): GT
    strips C comments (so commented-out calls are not treated as real); the analyzer drops data-flow paths in
    functions unreachable from `main` (lifecycle bugs exempt).

---

## 2. Pipeline stages in detail

### Stage 0: LLM Orchestration
- **Function**: initialize the LLM orchestrator, generate a taint specification.
- **Files**: `orchestrator/orchestrator.py::AIOrchestrator.analyze_binary()`,
  `orchestrator/llm_client.py`, `orchestrator/decision_engine.py`.
- **Output**: TaintSpec, ExecutionStrategy.

### Stage 1: Compilation and Stripping
- **Function**: compile C source to ELF, strip debug symbols.
- **Files**: `compilation/compiler.py::compile_source()`, `compilation/stripper.py::strip_binary()`.
- **Input/Output**: SourceCode → Binary (stripped) + Binary (debug, `-g`).

### Stage 2: Ground Truth Extraction
- **Function**: extract expected sources/sinks/taint paths from source.
- **Files**: `ground_truth/extractor.py::extract_ground_truth()` (extract_functions / extract_variables /
  identify_sources / identify_sinks / identify_taint_paths / extract_annotations).
- **Input/Output**: SourceCode → GroundTruth (sources, sinks, taint_paths, types).

### Stage 3: Code Lifting
- **Files**: `binary_analysis/vex_lift.py::lift_binary()` (angr load + pyvex lift). Binary → VEX IR.

### Stage 4: CFG Recovery
- **Files**: `binary_analysis/cfg_recovery.py::recover_cfg()` (angr CFGFast). Binary → CFG.

### Stage 5: DFG Construction + Call Graph
- **Files**: `binary_analysis/dfg_construction.py::construct_dfg()`,
  `binary_analysis/call_analysis.py::analyze_calls()`. VEX IR, CFG → DFG, CallGraph.

### Stage 6: GNN-Based Type Recovery (truly integrated)
- **Function**: recover variable types (char*/f32*/array/struct) with TYGR's **official GlowGNN model**. The
  earlier local `gat_model.pt` was a zero-feature shell and is deprecated.
- **Files**:
  - `type_recovery/inference.py::recover_types() → _recover_with_gnn()`: **subprocess** call into the
    version-faithful `tygr-orig` env (torch1.8/PyG1.7/angr-9.0.7491) to run the official model's predict;
    `_btype_to_str()` converts TYGR btypes to OPM type strings; assembles `TypeRecoveryOutput`. Env vars
    `TYGR_MODEL`/`TYGR_PYTHON` override; falls back to the self-trained model → heuristics. **PIE base
    alignment** maps DWARF low_pc to real CFG functions via `mapped_base`.
  - `pipeline.py`: Stage 1 keeps the unstripped `-g` binary `state.binary_debug`; Stage 6 feeds it to the
    GNN (TYGR locates variables via DWARF).
- **Input/Output**: binary_debug(-g), CFG, DFG → TypeRecoveryOutput (per-variable types + buffer/pointer
  labels). See [GNN_INTEGRATION.md](GNN_INTEGRATION.md), [VERSION_COMPAT.md](VERSION_COMPAT.md).

### Stage 7: Type Metadata Injection
- **Files**: `typed_ir/type_injector.py::inject_type_metadata()`, `typed_ir/ir_types.py`. → TypedIR.

### Stage 8: Path Prioritization + Heuristic Pruning
- **Files**: `symbolic_exec/path_prioritizer.py::prioritize_paths()`,
  `symbolic_exec/heuristic_pruning.py::create_pruner()`. → ExecutionPaths.

### Stage 9: Type-Guided Symbolic Execution
- **Files**: `symbolic_exec/guided_executor.py::execute_guided()`,
  `symbolic_exec/constraint_extractor.py`. → SymbolicState, ExecutionPaths.

### Stage 10: Automated Taint Propagation
- **Files**: `taint_analysis/taint_engine_v2.py::run_taint_analysis()`:
  - `_find_sources()` / `_find_sinks_enhanced()`
  - `_find_sinks_by_types()`: **GNN type-driven sink detection** (`OPM_TYPE_SINKS=1`, off by default) —
    promote nameless + GNN-typed-char*-buffer custom functions to sinks and inject an argv source for their
    main-reachable callers.
  - `_find_taint_paths()` / `_filter_with_symbolic_results()` / `_filter_paths_with_model()` /
    `_validate_with_counterfactual()` / `_track_lifecycle()`.
- **Input/Output**: Binary, CFG, CallGraph, TaintSpec, SymbolicResults, TypeRecoveryOutput → TaintState.

### Stage 11: Source-Sink Checking (with LLM)
- **Files**: `pipeline.py::_stage_source_sink_checking()` (`_build_symbolic_evidence()` builds GNN attention
  report + calls requiring validation + GNN type information + angr path constraints), then
  `orchestrator/llm_client.py::analyze_taint_path_cot()` (CoT + soft threshold). → TaintTrace.

### Stage 12: Evaluation
- **Files**: `evaluation/metrics.py::compute_metrics()` (P/R/F1, TP/FP/FN). → EvaluationMetrics.

### Stage 13: Report Generation
- **Files**: `evaluation/reporter.py::generate_report()` (JSON + Markdown). → Report.

---

## 3. Core modules

### 3.1 LLM Orchestrator
- **Files**: `src/orchestrator/`. Generates the taint spec, adjudicates paths, does CoT reasoning.
- **Key classes**: `AIOrchestrator`, `LLMClient` (OpenAI-compatible), `DecisionEngine`.
- **LLM configuration**:
```python
llm_api_base = os.environ.get('MIMO_API_BASE', 'https://api.openai.com/v1')
llm_api_key  = os.environ.get('MIMO_API_KEY', '')   # read from env var; never hardcode/commit a key
llm_model    = os.environ.get('MIMO_MODEL', '<your-model>')
max_tokens   = 4096   # critical: a reasoning model's hidden tokens count here; 1024 truncates the JSON
```
> When running several programs concurrently, use **different keys** (via `MIMO_API_KEY`) to avoid
> rate/region-limit contention.

### 3.2 GNN Type Recovery (TYGR GlowGNN, integrated)
- **File**: `src/type_recovery/inference.py`.
- Recovers per-variable types with TYGR's **official pretrained GlowGNN** (real TYDA training), called as a
  subprocess into an isolated `tygr-orig` conda env (pinned to torch1.8/PyG1.7/angr-9.0.7491). PIE base
  alignment attaches types to real CFG functions and folds them into TypedIR. Type-driven sink detection
  (`OPM_TYPE_SINKS`, off by default) recovers custom buffer sinks missed by name/structure heuristics.
- **Key functions**: `_recover_with_gnn()`, `_btype_to_str()`.
- **Model**: official `tygr_original/model/MODEL_base/x64.O0.base.model` (external dependency, obtain it
  yourself); self-trained fallback `output/tygr/model_stable.model` (Acc 0.887). The old
  `data/models/gat_model.pt` was a zero-feature shell and is deprecated.

### 3.3 Taint Analysis Engine
- **Files**: `src/taint_analysis/`. Finds sources/sinks, builds taint paths, filters FPs, validates paths.
- **Key classes**: `TaintEngineV2`, `GNNSinkDetector`, `LifecycleTracker`, `CounterfactualValidator`.

### 3.4 Symbolic Execution
- **Files**: `src/symbolic_exec/`. Symbolic execution, path prioritization, constraint extraction,
  heuristic pruning.
- **Key classes**: `TypeGuidedExecutor`, `PathPrioritizer`, `HeuristicPathPruner`, `ConstraintExtractor`.

---

## 4. File call relationships

### 4.1 Main pipeline call chain
```
src/pipeline.py
├── src/compilation/{compiler,stripper}.py
├── src/ground_truth/extractor.py
├── src/binary_analysis/{vex_lift,cfg_recovery,dfg_construction,call_analysis}.py
├── src/type_recovery/{inference,attention_report}.py
├── src/typed_ir/type_injector.py
├── src/symbolic_exec/{path_prioritizer,heuristic_pruning,guided_executor}.py
├── src/taint_analysis/{taint_engine_v2,gnn_sink_detector,lifecycle_tracker}.py
├── src/orchestrator/{orchestrator,llm_client}.py
└── src/evaluation/{metrics,reporter}.py
```

### 4.2 Taint analysis call chain
```
taint_engine_v2.py
├── _find_sources(call_graph)
├── _find_sinks_enhanced(call_graph, cfg)  └── gnn_sink_detector.py
├── _find_sinks_by_types(call_graph)        # GNN type-driven (OPM_TYPE_SINKS=1)
├── _find_taint_paths(call_graph)
├── _filter_with_symbolic_results(symbolic_results)
├── _filter_paths_with_model()
├── _validate_with_counterfactual()         └── counterfactual.py
├── _track_lifecycle(call_graph)            └── lifecycle_tracker.py
└── _get_results()
```

### 4.3 LLM call chain
```
pipeline.py
└── _stage_source_sink_checking()
    ├── _build_symbolic_evidence()
    │   ├── attention_report.py
    │   ├── call_graph (functions requiring validation)
    │   ├── type_recovery_output (GNN types)
    │   └── symbolic_results (angr path constraints)
    └── llm_client.py::analyze_taint_path_cot() → generate(prompt, system_prompt)
```

---

## 5. Data-flow diagrams

### 5.1 Main data flow
```
SourceCode
    ├──→ Compilation ──→ Binary ──→ CodeLifting ──→ VEX IR
    ├──→ GroundTruth                 CFGRecovery ──→ CFG
    │                                DFGConstruction ──→ DFG
    │                                GNN Type Recovery ──→ TypeRecoveryOutput
    │                                TypeMetadataInjection ──→ TypedIR
    │                                PathPrioritization ──→ ExecutionPaths
    │                                SymbolicExecution ──→ SymbolicState
    │                                TaintPropagation ──→ TaintState
    │                                SourceSinkChecking ──→ TaintTrace
    └────────────────────────────→ Evaluation ──→ Metrics ──→ ReportGeneration ──→ Report
```

### 5.2 LLM-integration data flow
```
TaintState (taint_paths)
    ▼
Build Symbolic Evidence
    ├── GNN Attention Report
    ├── Call Graph (functions requiring validation)
    ├── Type Information (GNN)
    └── Angr Path Constraints
    ▼
LLM CoT Analysis (syntactic → semantic → constraint satisfiability → final score)
    ▼
Soft-Threshold Decision (confidence >= 0.3)
    ▼
Validated TaintTrace
```

---

## 6. Configuration

### 6.1 OPMConfig
```python
@dataclass
class OPMConfig:
    compiler: str = "gcc"
    compile_flags: list = ["-g", "-O0"]
    strip_binary: bool = True
    max_symbolic_steps: int = 1000
    solver_timeout: int = 1000
    max_states: int = 100
    gnn_model_path: Optional[str] = None
    confidence_threshold: float = 0.7
    output_dir: str = "./output"
    verbose: bool = True
```

### 6.2 OrchestratorConfig
```python
@dataclass
class OrchestratorConfig:
    use_llm: bool = True
    llm_provider: str = 'openai'
    llm_api_base: str = 'https://api.openai.com/v1'  # override via MIMO_API_BASE
    llm_api_key: str = ''   # read from MIMO_API_KEY env var; never hardcode/commit
    llm_model: str = '<your-model>'
```

---

## 7. API

### 7.1 Main pipeline
```python
from src.pipeline import OPMPipeline, OPMConfig
config = OPMConfig(output_dir='./output')
pipeline = OPMPipeline(config)
result = pipeline.run('path/to/source.c')
# result contains: taint_traces, metrics, summary
```

### 7.2 Individual modules
```python
from src.ground_truth import extract_ground_truth
gt = extract_ground_truth('source.c')

from src.binary_analysis import recover_cfg
cfg = recover_cfg('binary.stripped')

from src.taint_analysis import run_taint_analysis
results = run_taint_analysis(binary, cfg, call_graph, taint_spec)

from src.evaluation import compute_metrics
metrics = compute_metrics(taint_traces, ground_truth)
```

---

## 8. Known Issues

### 8.1 API limits
- **451 error**: an OpenAI-compatible endpoint may return 451 (cross-border/region restriction). Use a
  retry mechanism, a different region/endpoint, or a different provider.

### 8.2 Performance
- **Slow LLM calls**: ~15–40 s per path. Mitigation: soft threshold to reduce the number of validated paths.

### 8.3 Accuracy — ✅ resolved (all 6 programs 100/100/100)
- The earlier "missed" gets→free / gets→strncpy were **phantom ground truth** (same-named variables
  mis-linked across scopes), not real misses; the analyzer already identified the real source as argv.
- **Root causes**: ① phantom GT; ② LLM adjudication silently defaulting to 0.5 due to reasoning-model token
  truncation. See §1.3 and `docs/STATUS.md`.
- **Fix**: scope-aware GT/engine + max_tokens=4096 tolerant parsing + lifecycle scoring + printf .rodata
  guard + dead-code filtering.

### 8.4 Runtime environment
- **WSL memory**: angr is memory-hungry; on a memory-constrained WSL run **one program at a time** (the
  printf guard loads angr once more, so concurrency can OOM). Increase WSL memory in `.wslconfig` to support
  concurrency (this project uses 6 GB + 8 GB swap).

---

## Appendix: Glossary
| Term | Meaning |
|---|---|
| CFG | Control Flow Graph |
| DFG | Data Flow Graph |
| VEX IR | Valgrind EXpression intermediate representation |
| GNN | Graph Neural Network |
| TYGR | Type recovery using GNNs (sefcom/TYGR) |
| CoT | Chain-of-Thought |
| UAF | Use-After-Free |
| FP / FN / TP | False Positive / False Negative / True Positive |
| LLM | Large Language Model |
