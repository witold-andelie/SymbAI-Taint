# OPM Architecture Documentation

## Overview

The OPM (AI-Enhanced Automated Taint Analysis) system implements a complete pipeline for analyzing stripped binaries to detect security vulnerabilities. The architecture follows the OPM model described in `infra.txt`.

## Pipeline Stages

### Stage 1: Compilation and Stripping
**Module**: `src/compilation/`

**Objects**:
- SourceCode (input)
- Binary (output)

**Processes**:
- `compiler.compile_source()`: Compiles C source to ELF binary
- `stripper.strip_binary()`: Strips debug symbols

**Flow**:
```
SourceCode → Compilation → Binary
```

---

### Stage 2: Ground Truth Extraction
**Module**: `src/ground_truth/`

**Objects**:
- SourceCode (input)
- GroundTruth (output)

**Processes**:
- `extractor.extract_ground_truth()`: Extracts expected sources, sinks, and taint paths

**Flow**:
```
SourceCode → GroundTruthExtraction → GroundTruth
```

**Ground Truth Contents**:
- Expected source functions
- Expected sink functions
- Expected taint paths (**scope-aware**: per-function taint tracking)
- Expected lifecycle vulns: double-free / use-after-free as `(function, vuln_type)`
- Variable types
- Vulnerable paths

> Comments are stripped first (`_strip_comments`) so commented-out calls are not
> parsed as real calls (which previously fabricated taint into dead functions).

---

### Stage 3: Code Lifting
**Module**: `src/binary_analysis/vex_lift.py`

**Objects**:
- Binary (input)
- VEX IR (output)

**Processes**:
- `vex_lift.lift_binary()`: Lifts binary to VEX IR using angr/pyvex

**Flow**:
```
Binary → CodeLifting → VEX IR
```

---

### Stage 4: CFG Recovery
**Module**: `src/binary_analysis/cfg_recovery.py`

**Objects**:
- Binary (input)
- CFG (output)

**Processes**:
- `cfg_recovery.recover_cfg()`: Recovers control flow graph using angr CFGFast

**Flow**:
```
Binary → CFGRecovery → CFG
```

---

### Stage 5: DFG Construction
**Module**: `src/binary_analysis/dfg_construction.py`

**Objects**:
- VEX IR (input)
- CFG (input)
- DFG (output)

**Processes**:
- `dfg_construction.construct_dfg()`: Constructs data flow graph

**Flow**:
```
VEX IR + CFG → DFGConstruction → DFG
```

---

### Stage 6: GNN-Based Type Recovery
**Module**: `src/type_recovery/`

**Objects**:
- CFG (input)
- DFG (input)
- TypeRecoveryOutput (output)

**Processes**:
- `inference.recover_types()`: Recovers types using GNN (TYGR)

**Flow**:
```
CFG + DFG → GNNSemanticInference → TypeRecoveryOutput
```

**Type Recovery Output**:
- Variable types
- Pointer/buffer labels
- Function signature hints
- Confidence scores

---

### Stage 7: Type Metadata Injection
**Module**: `src/typed_ir/`

**Objects**:
- VEX IR (input)
- CFG (input)
- DFG (input)
- TypeRecoveryOutput (input)
- TypedIR (output)

**Processes**:
- `type_injector.inject_type_metadata()`: Injects type metadata into IR

**Flow**:
```
VEX IR + CFG + DFG + TypeRecoveryOutput → TypeMetadataInjection → TypedIR
```

---

### Stage 8: Path Prioritization
**Module**: `src/symbolic_exec/path_prioritizer.py`

**Objects**:
- TypedIR (input)
- TypeRecoveryOutput (input)
- ExecutionPaths (output)

**Processes**:
- `path_prioritizer.prioritize_paths()`: Prioritizes paths based on type info

**Flow**:
```
TypedIR + TypeRecoveryOutput → PathPrioritization → ExecutionPaths
```

---

### Stage 9: Type-Guided Symbolic Execution
**Module**: `src/symbolic_exec/guided_executor.py`

**Objects**:
- TypedIR (input)
- ExecutionPaths (input)
- SymbolicState (output)
- ExecutionPaths (updated output)

**Processes**:
- `guided_executor.execute_guided()`: Executes symbolic execution guided by types

**Flow**:
```
TypedIR + ExecutionPaths → TypeGuidedSymbolicExecution → SymbolicState + ExecutionPaths
```

---

### Stage 10: Taint Propagation
**Module**: `src/taint_analysis/taint_engine.py`

**Objects**:
- ExecutionPaths (input)
- TaintSpec (input)
- TypedIR (input)
- TaintState (output)

**Processes**:
- `taint_engine.propagate_taint()`: Propagates taint through execution paths

**Flow**:
```
ExecutionPaths + TaintSpec + TypedIR → TaintPropagation → TaintState
```

---

### Stage 11: Source-Sink Checking
**Module**: `src/taint_analysis/source_sink.py`

**Objects**:
- TaintState (input)
- ExecutionPaths (input)
- TaintSpec (input)
- TaintTrace (output)

**Processes**:
- `source_sink.check_source_sink()`: Checks for source-sink taint flows

**Flow**:
```
TaintState + ExecutionPaths + TaintSpec → SourceSinkChecking → TaintTrace
```

---

### Stage 12: Evaluation
**Module**: `src/evaluation/metrics.py`

**Objects**:
- TaintTrace (input)
- GroundTruth (input)
- EvaluationMetrics (output)

**Processes**:
- `metrics.compute_metrics()`: Computes precision, recall, F1-score

**Flow**:
```
TaintTrace + GroundTruth → Evaluation → EvaluationMetrics
```

---

### Stage 13: Report Generation
**Module**: `src/evaluation/reporter.py`

**Objects**:
- TaintTrace (input)
- EvaluationMetrics (input)
- Report (output)

**Processes**:
- `reporter.generate_report()`: Generates analysis report

**Flow**:
```
TaintTrace + EvaluationMetrics → ReportGeneration → Report
```

---

## Data Structures

### Core Objects

| Object | Description |
|--------|-------------|
| SourceCode | C source file |
| Binary | Compiled ELF binary |
| GroundTruth | Expected analysis results |
| VEX IR | Intermediate representation |
| CFG | Control flow graph |
| DFG | Data flow graph |
| TypeRecoveryOutput | GNN type predictions |
| TypedIR | Type-augmented IR |
| SymbolicState | Symbolic execution state |
| ExecutionPaths | Set of execution paths |
| TaintState | Current taint state |
| TaintTrace | Source-to-sink taint flow |
| EvaluationMetrics | Precision, recall, F1 |
| Report | Final analysis report |

---

## Module Dependencies

```
pipeline.py
├── compilation/
│   ├── compiler.py
│   └── stripper.py
├── ground_truth/
│   ├── extractor.py
│   └── validator.py
├── binary_analysis/
│   ├── vex_lift.py
│   ├── cfg_recovery.py
│   └── dfg_construction.py
├── type_recovery/
│   ├── inference.py
│   └── dataset.py
├── typed_ir/
│   ├── type_injector.py
│   └── ir_types.py
├── symbolic_exec/
│   ├── guided_executor.py
│   └── path_prioritizer.py
├── taint_analysis/
│   ├── taint_engine.py
│   ├── source_sink.py
│   └── rules.py
└── evaluation/
    ├── metrics.py
    └── reporter.py
```

---

## External Dependencies

- **angr**: Binary analysis framework
- **claripy**: SMT solver
- **pyvex**: VEX IR lifting
- **pyelftools**: ELF/DWARF parsing
- **networkx**: Graph algorithms
- **PyTorch**: Deep learning framework
- **PyTorch Geometric**: Graph neural networks

---

## TYGR Integration (GNN Type Recovery)

GNN-based type recovery integrates [TYGR](https://github.com/sefcom/TYGR)'s **GlowGNN** model.
Implementation lives in the vendored `tygr_original/` (gitignored). See
[GNN_INTEGRATION.md](GNN_INTEGRATION.md) and [VERSION_COMPAT.md](VERSION_COMPAT.md) for full detail.

How it works:
- **glow featurization**: angr symbolic execution builds a "glow" computation graph (nodes = values/ops,
  edges = VEX operation classes); the GlowGNN does message passing to predict each variable's type.
- **Official model**: we use TYGR's pretrained `model/MODEL_base/x64.O0.base.model` (trained on the real
  TYDA dataset → rich types: `char*`, `f32*`, `array`, `struct`).
- **Two-environment design**: the official model is pinned to torch1.8/PyG1.7/angr-9.0.7491, so it runs in a
  faithful **`tygr-orig`** conda env. OPM (in `angr-env`) calls it via **subprocess** — the envs are decoupled.

Integration points:
1. `src/type_recovery/inference.py::_recover_with_gnn()` — subprocess to `tygr-orig` python → `src.index predict`
   → loads var_dict → `_btype_to_str()` → assembles `TypeRecoveryOutput` (per-variable types + buffer/pointer labels).
   Override model/interpreter via env vars `TYGR_MODEL` / `TYGR_PYTHON`. Falls back to synthetic model, then heuristics.
2. `src/pipeline.py` — Stage 1 keeps the unstripped `-g` binary (`state.binary_debug`); Stage 6 feeds it to the GNN
   (TYGR locates variables via DWARF; the GNN predicts their types).
3. **PIE base alignment** — DWARF `low_pc` is mapped to angr's rebased function addresses via `mapped_base`,
   so types attach to the correct CFG functions.
4. `src/typed_ir/type_injector.py` — folds GNN predictions into `TypedIR.variable_types` / buffer / pointer maps.

Note: TYGR uses DWARF to *locate* variables; running on a fully-DWARF-less binary needs a preceding
variable-recovery pass (a known next step). The analysis (CFG/DFG/taint) binary may be fully stripped.

---

## Configuration

### OPMConfig

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
    taint_spec_path: Optional[str] = None
    output_dir: str = "./output"
    verbose: bool = True
```

### TaintSpec

```python
{
    'sources': [
        {'name': 'getchar', 'type': 'input'},
        {'name': 'gets', 'type': 'input'},
        ...
    ],
    'sinks': [
        {'name': 'strcpy', 'type': 'buffer_overflow'},
        {'name': 'printf', 'type': 'format_string'},
        ...
    ],
    'propagation_rules': [
        {'op': 'assign', 'propagates': True},
        ...
    ]
}
```

---

## Precision Methodology (v9–v12: 6/6 programs at 100/100/100)

The headline taint analysis (Stages 10–11) is implemented by `taint_analysis/taint_engine_v2.py`
(the legacy `taint_engine.py` is a fallback). Key precision/recall enhancements:

1. **Scope-aware GT & taint engine** — taint is tracked per function scope on both sides;
   cross-function guards prevent an input-source function (gets/scanf) acting as a sink from
   pairing with anything but itself, and stop local-buffer source taint leaking to sibling
   functions. (Removes phantom `gets→free`, `gets→strncpy`, `argv→gets`, `gets→strcpy`.)
2. **Reasoning-model LLM verdict** — mimo-v2.5-pro's hidden reasoning tokens count against
   `max_tokens`; raised to 4096 with truncation-tolerant parsing and decision-fields-first JSON.
3. **Symbolic hard evidence** (`constraint_extractor.build_semantic_evidence`) — unconstrained
   strncpy size (solver max 2⁶⁴−1), gets unconditional overflow (CWE-242), lifecycle violations.
4. **Object-lifecycle state machine** (`lifecycle_tracker.py`) — real double-free / use-after-free
   detection, scored as `(function, vuln_type)` to match the extractor.
5. **printf `.rodata` format-string guard** (`detect_literal_format_printf`) — angr disassembles
   printf/fprintf call sites; if the format register (RDI/RSI) is `lea reg,[rip+disp]` into
   `.rodata`, the call is a literal format and dropped. Conservative: real `printf(tainted)` kept.
6. **Dead-code handling** — `_strip_comments` in the extractor; `_filter_unreachable_paths`
   drops data-flow paths in functions unreachable from `main` (lifecycle vulns exempt).

> **Note**: `taint_engine_v2` and the printf guard each load angr; with WSL limited to 1.9 GB
> (no swap), run **one pipeline at a time** to avoid OOM.
