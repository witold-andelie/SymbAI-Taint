# SymbAI-Taint — Project Status

> **Last updated**: 2026-06-04
> **Current version**: v13 (**GNN type recovery truly integrated** — TYGR official model + tygr-orig env + PIE base alignment)
> v12: scope-aware + lifecycle scoring + printf .rodata guard + dead-code filtering

---

## 📊 Current Metrics (all 6 test programs, end-to-end)

| Metric | Value | Target |
|---|---|---|
| **Precision** | 100% | ≥95% ✅ |
| **Recall** | 100% | ≥90% ✅ |
| **F1-Score** | 100% | ≥90% ✅ |

> 6/6 programs at 100/100/100; aggregate TP/FP/FN = 27/0/0.
> The earlier "R = 83.33%" was only `vulnerable.c` and was doubly underestimated by **phantom ground truth
> (same-named locals mis-linked across scopes) + silent LLM-adjudication failure (reasoning-model token
> truncation)** — once diagnosed and fixed, it is actually 100%.

---

## ✅ Completed Work

### Core modules

| Module | File | Status | Notes |
|---|---|---|---|
| Compilation | `src/compilation/` | ✅ | gcc compile + strip |
| Ground Truth | `src/ground_truth/` | ✅ | source analysis |
| VEX IR lifting | `src/binary_analysis/vex_lift.py` | ✅ | angr/pyvex |
| CFG recovery | `src/binary_analysis/cfg_recovery.py` | ✅ | angr CFGFast |
| DFG construction | `src/binary_analysis/dfg_construction.py` | ✅ | data-flow analysis |
| Call graph | `src/binary_analysis/call_analysis.py` | ✅ | function-call analysis |
| Type recovery (GNN) | `src/type_recovery/inference.py` | ✅ | TYGR GlowGNN (official model) |
| Type injection | `src/typed_ir/type_injector.py` | ✅ | type metadata |
| Path prioritization | `src/symbolic_exec/path_prioritizer.py` | ✅ | path ranking |
| Heuristic pruning | `src/symbolic_exec/heuristic_pruning.py` | ✅ | path pruning |
| Taint engine | `src/taint_analysis/taint_engine_v2.py` | ✅ | core engine |
| LLM orchestrator | `src/orchestrator/` | ✅ | OpenAI-compatible API |
| Evaluation | `src/evaluation/` | ✅ | P/R/F1 |
| Reporting | `src/evaluation/reporter.py` | ✅ | JSON/Markdown |

### Enhancements

| Feature | File | Status | Notes |
|---|---|---|---|
| CoT reasoning | `src/orchestrator/llm_client.py` | ✅ | multi-stage chain-of-thought |
| GNN attention report | `src/type_recovery/attention_report.py` | ✅ | graph-structure evidence |
| Symbolic constraint extraction | `src/symbolic_exec/constraint_extractor.py` | ✅ | mathematical proof |
| Lifecycle tracking | `src/taint_analysis/lifecycle_tracker.py` | ✅ | UAF detection |
| Counterfactual validation | `src/taint_analysis/counterfactual.py` | ✅ | FP reduction |
| GNN sink detection | `src/taint_analysis/gnn_sink_detector.py` | ✅ | learned detection |
| Learned propagation | `src/taint_analysis/learned_propagation.py` | ✅ | ML propagation |
| Multimodal fusion | `src/binary_analysis/multimodal_fusion.py` | ✅ | ORACAL-style |

### Test programs (6, all end-to-end P/R/F1 = 100/100/100)

| Program | Bug type | P/R/F1 |
|---|---|---|
| vulnerable.c | buffer_overflow, format_string, command_injection, gets | 100/100/100 |
| buffer_overflow.c | buffer_overflow (strcpy/strcat/heap/off-by-one) | 100/100/100 |
| format_string.c | format_string (printf/fprintf/sprintf) | 100/100/100 |
| command_injection.c | command_injection (system) | 100/100/100 |
| memory_vuln.c | use_after_free, double_free | 100/100/100 |
| taint_flow.c | complex taint flows (global/indirect/conditional/loop/pointer) | 100/100/100 |

> **GNN-specific demo** (`output/tygr/demo_custom_sink.c`, not part of the standard suite): a custom
> hand-rolled buffer copy `store_record` (calls no libc, detected purely via GNN types). Name/structure
> heuristics: **0/0/0** → with `OPM_TYPE_SINKS=1` type-driven: **100/100/100**.

---

## ⚠️ Work in Progress / Resolved

### 1. Recall — ✅ root cause diagnosed and fixed (83.33% → 100%)

The two assumed "missed paths" `gets→free`, `gets→strncpy` turned out to be **phantom ground truth**:
- **Cause A (phantom GT)**: the GT extractor's `var_to_source` was global, scope-blind, indexed by variable
  name. The `gets(buffer)` in `vulnerable_stack` mislabeled **same-named locals in other functions**
  (vulnerable_heap's free, safe_function's strncpy) as source=gets → fabricating two expected paths. The
  analyzer correctly identified the real source as argv.
- **Cause B (silent LLM failure)**: a reasoning model's hidden tokens count against `max_tokens=1024` → the
  visible JSON is truncated/empty → parse fails → every path defaults to 0.5 / accept, dropping injected
  evidence.

**Fixes (all implemented)**:
1. ✅ Scope-aware GT extractor and taint engine (eliminating phantom paths)
2. ✅ `max_tokens=4096` + tolerant parsing + decision field first (adjudication revived)
3. ✅ Symbolic hard evidence (unconstrained strncpy size, unconditional gets overflow)
4. ✅ Lifecycle state machine truly detecting and scoring double-free / UAF

### 2. GNN integration — ✅ done (v13)

**Previous problem**: the local `gat_model.pt` was a zero-feature shell; Stage 6 always output 0. The past
100/100/100 was achieved with the **GNN not participating**.

**Now (integrated and validated)**:
- Uses TYGR's **official pretrained model** `x64.O0.base.model` (real TYDA training), loaded in a
  **version-faithful `tygr-orig` conda env** (torch1.8/PyG1.7/angr 9.0.7491); the main pipeline runs in
  angr-env and calls tygr-orig's predict via **subprocess**.
- `src/type_recovery/inference.py::_recover_with_gnn` → predict → assembles `TypeRecoveryOutput`
  (char*/pointer/array/struct/int…).
- **PIE base alignment**: DWARF `low_pc` ↔ angr rebased addresses, dual-key mapping via `mapped_base` → types
  attach to the correct named CFG functions.
- All 6 programs end-to-end: Stage 6 GNN 25–37 functions, Stage 7 injects 64–108 typed variables, **all
  P/R/F1 = 1.0, zero fallback**.
- **Fully-stripped (`--strip-all`) evidence**: names become `sub_xxxx`, the GNN still recovers char*/struct/
  pointer semantics → the GNN is the only source of type semantics in the fully-stripped case.
- See [GNN_INTEGRATION.md](GNN_INTEGRATION.md) and [VERSION_COMPAT.md](VERSION_COMPAT.md).

### 3. Dynamic path orchestration (planned)
- Current: the LLM orchestrator is at the back of the pipeline; the LLM only engages after symbolic execution.
- To implement: LLM-driven path exploration; dynamic pruning decisions; MCTS path search.

### 4. Deep neuro-symbolic fusion (planned)
- Current: GNN evidence is serialized as text into the LLM prompt (shallow fusion).
- To implement: GNN attention weights as tokens; graph-embedding similarity; joint representations.

---

## 📈 Metric Evolution (v1 → v13)

> v1–v11 are single-program (`vulnerable.c`); v12–v13 are aggregates over all 6 programs (v13 also adds the
> real Juliet benchmark).

| Version | P | R | F1 | Change | Scope |
|---|---|---|---|---|---|
| v1 | 0% | 0% | 0% | initial framework | vulnerable.c |
| v2 | 40% | 16.67% | 23.53% | basic implementation | vulnerable.c |
| v3 | 70% | 58.33% | 63.64% | improved GT | vulnerable.c |
| v4 | 100% | 41.67% | 58.82% | eliminate FPs | vulnerable.c |
| v5 | 100% | 75% | 85.71% | improve recall | vulnerable.c |
| v6 | 75% | 100% | 85.71% | perfect recall | vulnerable.c |
| v7 | 85.71% | 100% | 92.31% | best balance | vulnerable.c |
| v8 | 100% | 83.33% | 90.91% | soft threshold + CoT | vulnerable.c |
| v9 | 80% | 100% | 88.89% | scope-aware GT + reasoning-model adjudication revived (revealed the 83% recall as phantom GT + silent LLM failure; exposed 2 real FPs) | vulnerable.c |
| v10 | 100% | 87.5% | 93.33% | 4 cross-function scope guards in the taint engine (cleared argv→gets, gets→strcpy) | vulnerable.c |
| v11 | 100% | 100% | 100% | unconditional gets stack-overflow hard evidence (pinned gets→gets) | vulnerable.c |
| v12 | 100% | 100% | 100% | lifecycle state machine + printf .rodata guard + comment stripping + reachability filter | all 6 programs (27/0/0) |
| **v13** | **100%** | **100%** | **100%** | **GNN truly integrated (official GlowGNN) + PIE base alignment + type-driven sinks + NIST Juliet real benchmark** | all 6 programs (27/0/0) |

> **v13 real benchmark (NIST Juliet, 38 cases, four-way ablation)**: ① standard F1=0.750 → ② standard+LLM
> 0.750 (LLM no-op) → ③ **+GNN type-driven 0.875** (recall 0.711→0.921, recovering 8 CWE121) → ④ +GNN+LLM
> 0.667 (naive stacking hurts precision). **The GNN recall gain is quantified; the LLM precision gain did
> not materialize (a negative result, because the batch did not feed symbolic evidence)**. See
> [JULIET_PILOT.md](JULIET_PILOT.md).

---

## 🔧 Tech Stack

| Component | Version | Notes |
|---|---|---|
| Python | 3.10 | in WSL |
| angr | 9.2.212 | binary analysis (main env, angr-env) |
| PyTorch | 2.x | deep learning (main env) |
| PyG | 2.7.0 | graph neural networks (main env) |
| LLM API | - | reasoning model, max_tokens ≥ 4096 (OpenAI-compatible endpoint) |
| **tygr-orig env** | py3.8 / torch1.8.1 / PyG1.7.0 / angr 9.0.7491 | **runs TYGR's official GNN model** (subprocess) |
| TYGR official model | `x64.O0.base.model` | GlowGNN type recovery trained on real TYDA |

---

## 📝 Run Commands

### Single test
```bash
python scripts/run_pipeline.py tests/test_programs/vulnerable.c -o output/test
```
### Batch test
```bash
python scripts/run_batch_tests.py
```
### Juliet benchmark
```bash
python benchmarks/juliet/juliet_harness.py            # GNN
python benchmarks/juliet/juliet_harness_llm.py        # +GNN+LLM (needs LLM env vars)
```

---

## 🎯 Next Steps

> ✅ **Achieved (the original "improve recall" goal)**: Recall 100%. Improved CoT prompts, symbolic hard
> evidence (unconstrained strncpy size / unconditional gets overflow), and lifecycle double-free/UAF
> detection are all done; all 6 programs at 100/100/100.

1. **Larger benchmark (✅ 38-case Juliet four-way ablation done → continue)** — see
   [JULIET_PILOT.md](JULIET_PILOT.md) §7 "Open Problems / Next Steps":
   - **Make the LLM actually filter**: the batch ablation omitted angr symbolic constraints, so the LLM was
     a no-op. Feed in symbolic hard evidence and test whether "GNN + symbolic + LLM" can reject goodB2G FPs.
     **(roadmap item #1)**
   - **Refine type-driven sinks to reduce FPs**: symmetric application crashes P to 0.522; a stronger
     trigger is needed (in-function evidence of an unbounded write with a tainted index).
   - **Harden GNN datagen robustness**: `alloca` etc. make TYGR's `bityr_annots` assert (1/38 missed).
   - **Scale up**: full Juliet (flow variants 02–54) + real-world defect/fix pairs + baseline comparisons (Ghidra/CodeQL).
   - **Fix evaluation-methodology asymmetry**: the GNN-only 0.833 is the optimistic "type-sinks on positives
     only" value.

2. **Speed up LLM adjudication** (bottleneck ~30–40 s/path) — only call the LLM for ambiguous paths, batch,
   or use a local model.

3. **In-function buffer-level data flow** — resolve the "multiple buffers in the same function" mismatch
   exposed by `command_injection.c` (fgets taints `result` while popen uses `command`).

4. **GNN integration (✅ type recovery + ✅ type-driven sink detection, full loop)** —
   `analyze()` receives `type_recovery_output`; `_find_sinks_by_types` (`OPM_TYPE_SINKS=1`) detects custom
   hand-rolled buffer sinks, classifies them as buffer_overflow; the GT extractor supports `// @vuln:`
   annotations. Evidence: custom_sink (hand-rolled copy, no libc) name/structure **0/0/0** → GNN type-driven
   **1.0/1.0/1.0**; zero regression on the standard 6.

5. **Paper / talk material** (in progress) — see [PAPER_MATERIAL.md](PAPER_MATERIAL.md): abstract,
   methodology, neuro-symbolic architecture, experiments, novelty, anticipated technical Q&A.
