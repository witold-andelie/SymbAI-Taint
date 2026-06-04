# Implementation Log

> A detailed record of the implementation process, technical decisions, and pitfalls of genuinely
> integrating **GNN type recovery** into the taint-analysis pipeline and validating it on a real benchmark.
> Organized by topic (roughly chronological). Companion docs:
> [GNN_INTEGRATION](GNN_INTEGRATION.md) · [VERSION_COMPAT](VERSION_COMPAT.md) · [JULIET_PILOT](JULIET_PILOT.md) · [PAPER_MATERIAL](PAPER_MATERIAL.md).

---

## 0. The starting truth
- Stage 6 "GNN type recovery" previously relied on a local `gat_model.pt` that was a **zero-feature shell**;
  inference always returned 0. The past 100/100/100 on the 6 programs was achieved with the **GNN not
  participating**.
- Decision: use [TYGR](https://github.com/sefcom/TYGR) (USENIX Sec '24 GlowGNN) to implement real type
  recovery.

## 1. Adapting TYGR to the modern environment (Path A, self-training fallback)
TYGR depends on the 2021 angr/torch/PyG stack; running it directly in the modern `angr-env` crashes.
Patches applied to the local `tygr_original/` (gitignored):
- `analysis/angr/sim_exec.py`, `ast_graph.py`: `state.solver.BVV/BVS` → `cp.BVV/BVS` (new angr removed
  `SimSolver.BVV`). Before the fix, datagen reported `Source #functions: 0`.
- `predict.py`, `test.py`: wrap `torch.load(...)` in try/except (torch 2 defaults `weights_only=True` and
  rejects whole-object pickle; torch 1.8 lacks the arg).
- `train.py`: remove `ReduceLROnPlateau(verbose=)`; `utils/learn.py`: divide-by-zero guards on metrics.
- `methods/glow/predict.py`: new `generate_glow_inputs_no_parallel` (serial, bypassing the multiprocessing
  Pool's angr RuntimeDb crash).
- `methods/glow/model.py`: `edge_dim` from hardcoded `44` → `num_edge_ops` (dynamic). **Root cause**: the
  old pyvex edge vocabulary was exactly 44; modern pyvex has more → otherwise training `index out of bounds
  for size 44`.

### 1.1 Self-training pitfalls
- The pretrained model (PyG 1.7 whole-object pickle) fails to deserialize under PyG 2.7 (`Inspector._cls`)
  → abandoned at the time, switched to self-training.
- A self-built synthetic C corpus (80 files / ~720 functions). **The real cause of "training hangs"**: the
  default batch is **OOM-killed** on a 4 GB WSL (dmesg `Out of memory: Killed process`, RSS 3.6 GB). The
  `0/7` progress bar with 0 processed was exactly this. **Fix: `--batch_size 1`** (memory → ~2 GB).
- Result: self-trained model test Acc 0.8875 (`output/tygr/model_stable.model`), kept only as a fallback.

## 2. Using the official model (Path B, final primary path)
A co-author pointed out the official model is already open-sourced in the repo's `model/`, so self-training
is unnecessary. But the official model is **pinned** to torch 1.8 / PyG 1.7 / angr-pyvex **9.0.7491** (both
cross-version pickle and the feature vocabulary lock at edge_dim=44).
- **Solution**: reproduce an isolated conda env **`tygr-orig`**; the main pipeline calls it via
  **subprocess**. Scripts: `output/tygr/build_orig_env.sh` + `req_rest.txt`.
- **Dependency pitfalls** (in order of appearance):
  1. `capstone` too new → `module 'capstone' has no attribute 'CS_ARCH_ARM64'` (5.x renamed it) →
     downgrade to **4.0.2**.
  2. `protobuf` too new → downgrade to **3.20.3**.
  3. missing `sympy`/`z3`/`pysmt` etc. → `req_rest.txt` pins them all (incl. numpy 1.22 / networkx 2.5.1 /
     numba 0.53.1 / pandas 1.2.4).
  4. CUDA 10.2 cannot run a 40-series GPU → use CPU pytorch (inference ~10 it/s is enough).
- **Verified**: the official `x64.O0.base.model` loads (GlowGNN); predict produces precise types like
  **char*/f32*/array/struct** (far beyond the self-trained int/char*/array).

## 3. Integrating into the pipeline
- `src/type_recovery/inference.py::_recover_with_gnn`: subprocess calls the tygr-orig python to run the
  official model's predict → `_btype_to_str` (pointer→char*/pointer, array→array) → assembles
  `TypeRecoveryOutput`. Env vars `TYGR_MODEL`/`TYGR_PYTHON` override; fallback self-trained → heuristics.
- **Binary-path pitfall**: the subprocess runs with `cwd=tygr_original`, so the binary path must be made
  **absolute** (otherwise relative paths fail to resolve, rc=1 → fallback).
- `src/pipeline.py`: Stage 1 keeps the unstripped `-g` binary as `state.binary_debug`; Stage 6 feeds it to
  the GNN (TYGR locates variables via DWARF, the GNN predicts their types).
- `src/typed_ir/type_injector.py`: the original `_extract_variables_from_block` was a stub (always 0 typed).
  Changed to **fold GNN predictions directly** into `variable_types`/buffer/pointer maps (86 typed variables).
- **PIE base alignment**: GNN uses DWARF `low_pc` (0x1149), angr uses PIE-rebased addresses (0x401149+). Read
  the base from `cfg.angr_cfg.project.loader.main_object.mapped_base` and map by both absolute and
  (address − base) offset → types attach to the right CFG functions
  (`vuln_use_after_free → pointer/struct/char*`). Verification `output/tygr/verify_base_align.py`.

## 4. Validating the GNN's irreplaceable value
- **Fully-stripped demo** (`output/tygr/demo_fullstrip.py`): after `strip --strip-all`, names become
  `sub_xxxx`; the GNN still recovers char*/struct/pointer (even `main`'s argc/argv).
- **Type-driven sink detection** (`OPM_TYPE_SINKS=1`, off by default → 6-program zero regression):
  - `taint_engine_v2.py::_find_sinks_by_types`: promote "nameless + GNN-typed char* buffer (≥2) + present in
    the call graph" custom functions to sinks, classify as buffer_overflow, and inject an argv source for
    their main-reachable callers → form taint paths.
  - GT annotation: `ground_truth/extractor.py::extract_annotations` parses `// @vuln: <type> <source> ->
    <sink>` before comments are stripped.
  - Demo `output/tygr/demo_custom_sink.c` (a `store_record` doing a hand-rolled while-copy, calling no libc):
    off → **0/0/0**; on → `argv→store_record`, **P/R/F1 = 1.0**.

## 5. Real benchmark pilot: NIST Juliet
- 38 cases (CWE121/122/134/78), compiling positive/negative binaries via good/bad + `OMITGOOD/OMITBAD`
  macros as GT. Harness `benchmarks/juliet/juliet_harness.py`.
- **Engineering pitfalls**: ① loops/variables inside WSL inline `bash -c` get eaten → use script files /
  Python throughout; ② `pkill -f "git clone.*juliet"` matched its own command line → self-kill; ③ cloning to
  `/mnt/d` (DrvFs) writing 50k small files is extremely slow → clone to the WSL native fs `~/juliet_repo`;
  ④ a killed half-clone left **544 MB** behind, nearly committed by accident.
- **Result**: phase 1 standard P=0.794 R=0.711 F1=0.750; **phase 2 +GNN type-driven P=0.833 R=0.921
  F1=0.875**. The GNN recovered 8 CWE121 stack overflows missed by name matching.
- **Honest limitations**: 1 alloca+fgets case makes TYGR datagen `bityr_annots` assert (non-BV location) →
  GNN fallback; 2 vprintf cases are format strings (out of type-sink scope); negatives goodB2G produce 7 FPs
  (P < 1).

## 5.1 GNN × LLM ablation (negative result + experimental limitation)
- **Endpoint pitfall**: the MiMo endpoint returned **451 cross-border isolation** ("Allow Cross-border
  Access" not enabled) → switched to FreeModel (`gpt-5.4-mini`, OpenAI-compatible, models listable via
  `/v1/models`).
- **Harness**: `juliet_harness_llm.py` (type-sinks on symmetrically) / `juliet_harness_llm_clean.py`
  (standard detection). Reuses OPM's `analyze_taint_path_cot`, feeding GNN types as evidence and adjudicating
  each path; "detected" = at least one path survives adjudication (threshold 0.3, early-exit on first
  survivor).
- **Four-way result**: standard F1=0.750 → standard+LLM 0.750 (LLM **no-op**: filtered 0/7 FPs, killed 0/27
  TPs) → +GNN type-sink 0.875 → +GNN+LLM **0.667** (symmetric type-sinks create FPs on negatives that the LLM
  fails to filter → precision collapses to 0.522).
- **Key limitation (honest)**: to save time, the batch fed the LLM **only GNN-type evidence, not the full
  pipeline's angr symbolic constraints** (`_build_symbolic_evidence` block 4, which needs Stage 8). So it
  proves "LLM + types-only = useless," not "LLM is useless." This is roadmap item #1 (JULIET_PILOT §7).

## 6. Cross-cutting lessons
- **The reasoning model's hidden tokens count against `max_tokens`**: at 1024 the visible JSON is truncated
  to empty → adjudication silently fails (defaulting every path to 0.5 / accept). Fix: `max_tokens ≥ 4096`
  + tolerant parsing.
- **WSL memory**: on a 16 GB machine (Windows uses ~14 GB), WSL is capped at 6 GB + 8 GB swap (disk-backed
  OOM safety net that does not compete for RAM).
- **WSL `/tmp` is cleared on idle shutdown** (tmpfs) → write intermediate files to a persistent path
  (`output/`).
- **Two coexisting conda environments**: angr-env (modern, main pipeline) + tygr-orig (reproduced, official
  GNN), bridged by subprocess, mutually isolated.
