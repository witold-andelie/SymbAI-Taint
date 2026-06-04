# SymbAI-Taint: AI-Enhanced Automated Taint Analysis for Stripped Binaries

> A neuro-symbolic vulnerability-discovery pipeline that combines **GNN-based type recovery**,
> **symbolic-execution hard evidence**, and **LLM adjudication** for taint analysis on stripped binaries.

## ✨ Latest Progress (v13: GNN truly integrated + real-benchmark evaluation)

- ✅ **GNN type recovery is now genuinely integrated.** We use the official pretrained **GlowGNN**
  model from [TYGR](https://github.com/sefcom/TYGR) (trained on the real TYDA dataset, producing rich
  `char* / f32* / array / struct` types), invoked from the main pipeline as a subprocess running inside a
  version-faithful `tygr-orig` environment. The previous `gat_model.pt` was an empty, zero-feature shell.
- ✅ **Real third-party benchmark pilot (NIST Juliet, 38 cases).** Standard detection reaches F1 = 0.750
  (R = 0.711); adding GNN type-driven sink detection raises recall to **0.921** (F1 = 0.875). See
  [JULIET_PILOT.md](docs/JULIET_PILOT.md).
- ✅ **Irreplaceable value of GNN, demonstrated.** After full stripping (`--strip-all`), function names
  are gone, yet the GNN still recovers type semantics; a custom hand-rolled buffer sink goes from 0/0/0 to
  P/R/F1 = 1.0 once type-driven detection is enabled.

| Benchmark | Precision | Recall | F1 |
|---|---|---|---|
| 6 hand-written test programs (end-to-end) | 100% | 100% | 100% (27/0/0) |
| **NIST Juliet, 38 cases (standard)** | 0.794 | 0.711 | 0.750 |
| **NIST Juliet, 38 cases (+GNN type-driven)** | 0.833 | **0.921** | **0.875** |

> The 100% on the 6 hand-written programs only validates that the components cooperate correctly (a toy
> benchmark is not externally valid); the **Juliet numbers honestly drop to realistic levels** and
> **quantify the value added by the GNN** — a far more credible scientific result.

## 📚 Documentation Map

| Document | Contents |
|---|---|
| [GNN_INTEGRATION.md](docs/GNN_INTEGRATION.md) | Full write-up of the GNN type-recovery integration (architecture / data flow / usage) |
| [VERSION_COMPAT.md](docs/VERSION_COMPAT.md) | Reproducing the `tygr-orig` environment + dependency pitfalls |
| [JULIET_PILOT.md](docs/JULIET_PILOT.md) | NIST Juliet real-benchmark pilot (method / results / reproduction) |
| [IMPLEMENTATION_LOG.md](docs/IMPLEMENTATION_LOG.md) | Detailed implementation log / technical decisions / pitfalls |
| [PAPER_MATERIAL.md](docs/PAPER_MATERIAL.md) | Paper / talk material + anticipated technical Q&A |
| [STATUS.md](docs/STATUS.md) | Project status, metric evolution, module inventory |
| [architecture.md](docs/architecture.md) | System architecture |

## 🏗️ System Architecture (13-stage pipeline)

```
Source / Binary
 1  Compile & strip      gcc -g  →  keep -g copy (for type recovery) + stripped copy (for analysis)
 2  Ground Truth         extract expected vulnerabilities from source (scope-aware; evaluation only)
 3  Code lifting         angr  →  VEX IR
 4  CFG recovery         angr CFGFast
 5  DFG + call graph     data-flow + function calls
 6  GNN type recovery    ★ TYGR GlowGNN (official model)  →  per-variable char* / ptr / array / struct
 7  Type injection       inject type metadata into TypedIR (PIE base-aligned to real functions)
 8  Symbolic execution   angr / claripy, path prioritization + heuristic pruning
 9  Taint analysis       ★ scope-aware source-sink + object-lifecycle state machine (UAF / double-free)
10  Source-sink paths    path enumeration + reachability filtering + .rodata format-string guard
11  LLM adjudication     ★ reasoning-model CoT over symbolic hard evidence + soft threshold
12  Evaluation           Precision / Recall / F1 against ground truth
13  Reporting            JSON / Markdown
```
★ = the three core "intelligent" components.

## 📁 Project Layout

```
SymbAI-Taint/                          # <PROJECT_ROOT>
├── src/                               # main source
│   ├── pipeline.py                    # main 13-stage pipeline
│   ├── compilation/                   # compiler + stripper
│   ├── ground_truth/                  # ground-truth extraction (scope-aware, // @vuln annotations)
│   ├── binary_analysis/               # VEX lift, CFG, DFG, call graph
│   ├── type_recovery/                 # GNN type recovery (inference.py: _recover_with_gnn)
│   ├── typed_ir/                      # type injection
│   ├── symbolic_exec/                 # guided execution, prioritization, constraint extraction
│   ├── taint_analysis/                # taint engine v2, lifecycle tracker, type-driven sinks
│   ├── orchestrator/                  # LLM orchestrator + client (OpenAI-compatible)
│   └── evaluation/                    # metrics + reporter
│
├── tygr_original/                     # TYGR (+ official models) — external dependency, NOT redistributed
├── tests/test_programs/               # 6 hand-written C test programs (all 100/100/100)
├── benchmarks/juliet/                 # NIST Juliet real-benchmark pilot (harness / cases / results)
├── output/tygr/                       # GNN reproduction scripts (env build / demos / recovery notes)
├── scripts/                           # run_pipeline.py, run_batch_tests.py, evaluate.py, ...
└── docs/                              # documentation
```

## 🚀 Quick Start

### Requirements
- **OS**: Linux, or Windows + WSL2 (developed on Ubuntu 20.04)
- **Python**: 3.10 (conda recommended)
- **Core deps**: angr 9.2.x, pyvex, claripy, PyTorch, PyTorch-Geometric
- **LLM**: any **OpenAI-compatible** chat/completions endpoint
- **Memory**: ≥ 4 GB recommended for the analysis environment (angr is memory-hungry)

### 1) Install
```bash
conda create -n symbai python=3.10 -y
conda activate symbai
git clone https://github.com/witold-andelie/SymbAI-Taint.git
cd SymbAI-Taint
pip install -r requirements.txt
```

### 2) Configure the LLM (environment variables — never hardcode keys)
```bash
export MIMO_API_BASE="https://<your-openai-compatible-endpoint>/v1"
export MIMO_API_KEY="<your-api-key>"
export MIMO_MODEL="<model-name>"
```
> If you use a **reasoning model**, its hidden reasoning tokens count against `max_tokens`; this project
> already sets 4096 — do not lower it (otherwise the visible JSON gets truncated).

### 3) Configure TYGR GNN type recovery (optional external dependency)
Type recovery uses the official GlowGNN model from **[TYGR](https://github.com/sefcom/TYGR)**. TYGR is not
redistributed here (see [Acknowledgments & License](#-acknowledgments--license)). The official model is
**pinned to TYGR's original stack** (torch 1.8 / PyG 1.7 / angr-pyvex 9.0.7491), so a dedicated
`tygr-orig` environment is reproduced and called as a subprocess:
```bash
git clone https://github.com/sefcom/TYGR.git tygr_original    # under <PROJECT_ROOT>/tygr_original
bash output/tygr/build_orig_env.sh                            # builds the conda env `tygr-orig`
# Override model / interpreter via env vars if needed:
#   TYGR_MODEL=<...x64.O0.base.model>   TYGR_PYTHON=<.../envs/tygr-orig/bin/python>
```
See [VERSION_COMPAT.md](docs/VERSION_COMPAT.md) and [GNN_INTEGRATION.md](docs/GNN_INTEGRATION.md) for the
full procedure and dependency pitfalls.
> Without TYGR, type recovery **gracefully falls back** to a self-trained model, then to heuristics, and
> the main pipeline still runs. Type-driven sink detection is enabled with `OPM_TYPE_SINKS=1` (off by default).

### 4) Run
```bash
# Single program (end-to-end: compile → binary analysis → symbolic execution → taint → evaluation)
python scripts/run_pipeline.py tests/test_programs/vulnerable.c -o output/test
# All 6 test programs
python scripts/run_batch_tests.py
```
> ⚠️ One program takes ~5–15 min (the bottleneck is per-path LLM adjudication). On memory-constrained
> machines, run **one program at a time**.

## 📈 Metric Evolution (v1 → v13)

> v1–v11 are single-program (`vulnerable.c`); v12–v13 are aggregates over all 6 programs (v13 also adds
> the real Juliet benchmark).

| Version | P | R | F1 | Change | Scope |
|---|---|---|---|---|---|
| v1–v8 | — | — | 0 → 90.9% | bootstrap → soft threshold + CoT | vulnerable.c |
| v9 | 80% | 100% | 88.9% | scope-aware GT + reasoning-model adjudication revived | vulnerable.c |
| v10 | 100% | 87.5% | 93.3% | 4 cross-function scope guards in the taint engine | vulnerable.c |
| v11 | 100% | 100% | 100% | unconditional `gets` stack-overflow hard evidence | vulnerable.c |
| v12 | 100% | 100% | 100% | lifecycle state machine + printf .rodata guard + comment stripping + reachability filter | all 6 programs (27/0/0) |
| **v13** | **100%** | **100%** | **100%** | **GNN truly integrated (official GlowGNN) + PIE base alignment + type-driven sinks + real-benchmark evaluation** | all 6 programs (27/0/0) |

**v13 still keeps 6/6 programs at 100/100/100** (GNN enabled, zero regression).

### v13 in detail: from "components are correct" to "credible on real data"

Through v12 the project was tuned on 6 hand-written programs, so the **100% only proves the fixes are
correct and cannot be extrapolated**. v13 does two things that make the result credible:

**① The GNN went from an empty shell to a working core** (before, the 6-program 100% was achieved with
the GNN not participating at all):
- Integrates the official pretrained **GlowGNN** model (real TYDA data → char*/f32*/array/struct), invoked
  via subprocess inside a version-faithful `tygr-orig` environment.
- **PIE base alignment**: DWARF `low_pc` ↔ angr's rebased function addresses, so types attach to the right
  CFG functions.
- **Type-driven sink detection** (`OPM_TYPE_SINKS`): recovers custom buffer sinks that name/structure
  heuristics miss.

**② Real third-party benchmark (NIST Juliet, 38 cases), four-way ablation** — the numbers honestly drop,
and the GNN's value is quantified (LLM endpoint: FreeModel `gpt-5.4-mini`; the MiMo endpoint was blocked by
451 cross-border isolation):

| Configuration | Precision | Recall | F1 |
|---|---|---|---|
| ① Standard (name / structure) | 0.794 | 0.711 | 0.750 |
| ② Standard + LLM adjudication | 0.794 | 0.711 | 0.750 (no change) |
| **③ + GNN type-driven** | 0.833 | **0.921** | **0.875** |
| ④ + GNN type-driven + LLM | 0.522 | 0.921 | 0.667 ⬇ |

> **The GNN recall gain is real** (③): recall 0.711 → 0.921 (recovering 8 CWE121 stack overflows that
> name matching misses). **The LLM precision gain did not materialize in this configuration (a negative
> result)**: in ② the LLM is a no-op, and ④ naive stacking hurts precision. The root cause is that the
> batch ablation fed the LLM only GNN-type evidence, **without the angr symbolic constraints** (the hard
> evidence needed to tell "safe" from "dangerous" sinks). **We report the negative result openly**:
> a full neuro-symbolic + LLM evaluation, type-sink precision refinement, and scaling up are explicit next
> steps (see [JULIET_PILOT.md](docs/JULIET_PILOT.md) §7 "Open Problems").

## 🧪 Methodological Contributions (v9–v13)

1. **Scope-aware ground truth and taint engine** — per-function taint tracking that eliminates the
   "phantom" false negatives/positives caused by mis-linking same-named local variables across scopes.
2. **Reviving reasoning-model adjudication** — a reasoning model's hidden tokens count against
   `max_tokens`; at 1024 the visible JSON is truncated and adjudication silently defaults to 0.5. Fixed by
   raising to 4096 + tolerant parsing + putting the decision field first.
3. **Object-lifecycle state machine** — models double-free / use-after-free (which a flat source→sink
   model cannot express) and aligns them on both GT and analyzer sides by `(function, vulnerability type)`.
4. **printf format-string .rodata guard** — disassembles printf/fprintf call sites with angr and checks
   whether the format-argument register points to a `.rodata` literal; conservatively downgrades only when
   fully proven literal, always keeping real `printf(tainted)`.
5. **Comment stripping + reachability filtering** — GT strips C comments; the analyzer drops data-flow
   paths in code unreachable from `main`.
6. **(v13) Engineering the GNN type-recovery integration** — the official GlowGNN is pinned to
   torch 1.8 / PyG 1.7 / angr-pyvex 9.0.7491 (cross-version pickle + a VEX edge vocabulary locked at
   `edge_dim = 44`); solved with an isolated `tygr-orig` environment + subprocess boundary, plus **PIE base
   alignment**.
7. **(v13) Type-driven sink detection** — promotes nameless, GNN-typed-`char*`-buffer custom functions to
   sink candidates and builds taint paths, recovering detections missed by name/structure heuristics
   (fully stripped + hand-rolled buffer-copy scenarios); GT supports `// @vuln:` annotations.
8. **(v13) Real-benchmark evaluation method** — uses Juliet's good/bad structure + `OMITGOOD/OMITBAD`
   macros to compile positive/negative binaries; positives should be detected and negatives not; honestly
   exposes the metric drop and the GNN's incremental recall.

## 🧭 Project Status & Open Problems (Roadmap)

> **This is an in-progress research project (WIP), not a final state.** The 6 hand-written programs at
> 100/100/100 only validate component cooperation; a 38-case Juliet pilot has been run (metrics honestly
> drop). Generality still requires **larger-scale** evaluation. See
> [JULIET_PILOT.md](docs/JULIET_PILOT.md) §7 "Open Problems / Next Steps":

1. **Make the LLM actually filter** — the batch ablation omitted angr symbolic constraints, so the LLM was
   a no-op. Next: feed the symbolic hard evidence into batch adjudication and test whether
   "GNN + symbolic + LLM" can reject the goodB2G false positives. **(roadmap item #1)**
2. **Refine type-driven sinks to reduce FPs** — symmetric application crashes precision (0.522); a stronger
   trigger is needed (evidence of an unbounded write with a tainted index inside the function).
3. **Harden GNN datagen robustness** — `alloca` and some dynamic stack allocations make TYGR's
   `bityr_annots` assertion fail (1/38 missed here).
4. **Scale up** — full Juliet (flow variants 02–54, inter-procedural/inter-file) + real CVE binaries +
   baseline comparisons (e.g., Ghidra/CodeQL).
5. **Fix the evaluation-methodology asymmetry** — the GNN-only 0.833 is optimistic ("type-sinks on
   positives only").
6. **True fully-stripped evaluation** — the pilot analyzes `-g` binaries; an end-to-end `--strip-all` run
   would best demonstrate the GNN's irreplaceable value.

## 🙏 Acknowledgments & License

### Acknowledgments / References
The GNN type-recovery component is based on and references **[TYGR (sefcom/TYGR)](https://github.com/sefcom/TYGR)**
— *TYGR: Type Inference on Stripped Binaries using Graph Neural Networks*.

> ⚠️ **Important**: the TYGR repository has **no license file**, which under copyright law defaults to
> **"All Rights Reserved"** and is therefore **not redistributable**. This repository does **not** contain
> TYGR code; obtain it yourself from the official repository (see [Quick Start §3](#3-configure-tygr-gnn-type-recovery-optional-external-dependency)).
> We reference it only in an academic sense.

Other referenced work: DIRTY, ORACAL, VISION (binary semantics / vulnerability detection).

### License
This project's own code is released under the **Apache License 2.0** (see `LICENSE`). Note that the license
covers only this repository's own code and does **not** extend to external dependencies such as TYGR.
