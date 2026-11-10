# Version Compatibility & Environment Reproduction (TYGR ↔ SymbAI-Taint)

> GNN type recovery is based on [TYGR (sefcom/TYGR)](https://github.com/sefcom/TYGR) (2024 paper,
> GNN type inference on stripped binaries). TYGR depends on a **2021-era** angr / PyTorch / PyTorch-Geometric
> stack. This document records the **version differences**, the **final choice** between two paths, and a
> complete **environment-reproduction pitfall list**.
>
> **TL;DR**: we ultimately took **Path B — reproduce TYGR's original environment (`tygr-orig`) and use the
> official pretrained model directly**, while keeping **Path A — self-training in the adapted modern
> environment** as a fallback. Both paths work.

---

## 1. Version Comparison

| Component | TYGR original (`tygr_original/environment.yml`, 2021) | SymbAI-Taint modern env (angr-env) |
|---|---|---|
| Python | 3.8.10 | 3.10 / 3.11 |
| angr / pyvex / claripy / cle / archinfo | **9.0.7491** | 9.2.212 (latest) |
| **PyTorch** | **1.8.1** (cuda 10.2) | **2.x (cpu)** |
| **torch-geometric** | **1.7.0** | **2.7.0** |
| torch-scatter / torch-sparse | 2.0.6 / 0.6.9 | (with PyG 2.7) |
| capstone | 4.0.2 | 5.x/6.x |
| protobuf | 3.17.x | 4.x+ |

**Two fundamental gaps**:
1. **PyG 1.7 → 2.7**: spans several major versions; internal class layout changed completely → the official
   model (whole-object pickle) cannot be deserialized across versions.
2. **angr/pyvex 9.0.7491 → 9.2.x**: the VEX operation vocabulary changed → modern datagen produces graph
   edge features whose dimension mismatches the model's training (`index out of bounds for size 44`).

> Conclusion: the official model is **pinned to angr/pyvex 9.0.7491 + PyG 1.7** — both due to pickle and the
> feature vocabulary. To use it, the entire stack must be faithfully reproduced.

---

## 2. Path B (final primary path): reproduce `tygr-orig`, use the official model

Official pretrained models live in `tygr_original/model/MODEL_base/` (by arch/opt level: `x64.O0.base.model`,
`x64.O1...`, `aarch64.*`, `arm32.*`, `mips.*`, `x86.*`). We build an isolated conda env **`tygr-orig`**
dedicated to running the official model's predict; the main pipeline stays in `angr-env` and calls it via
**subprocess**. The two coexist without contamination.

### 2.1 One-click reproduction
Script: `output/tygr/build_orig_env.sh` (+ `output/tygr/req_rest.txt`). Equivalent:
```bash
conda create -y -n tygr-orig python=3.8.10
# pytorch 1.8.1 CPU (cuda 10.2 cannot run 40-series GPUs; CPU is fast enough for inference)
conda run -n tygr-orig pip install torch==1.8.1+cpu torchvision==0.9.1+cpu torchaudio==0.8.1 \
    -f https://download.pytorch.org/whl/torch_stable.html
# PyG 1.7.0 stack (must match the torch-1.8.1+cpu prebuilt wheels)
conda run -n tygr-orig pip install torch-scatter==2.0.6 torch-sparse==0.6.9 \
    -f https://data.pyg.org/whl/torch-1.8.1+cpu.html
conda run -n tygr-orig pip install torch-geometric==1.7.0
# angr family 9.0.7491 (the exact versions the official model's features depend on)
conda run -n tygr-orig pip install angr==9.0.7491 archinfo==9.0.7491 claripy==9.0.7491 \
    cle==9.0.7491 pyvex==9.0.7491
# remaining pinned dependencies (the glow code depends on old APIs)
conda run -n tygr-orig pip install -r output/tygr/req_rest.txt
```

### 2.2 Pitfall list (already pinned in the scripts / `req_rest.txt`)

| Pitfall | Symptom | Fix |
|---|---|---|
| **capstone too new** | `module 'capstone' has no attribute 'CS_ARCH_ARM64'` (5.x renamed it to `CS_ARCH_AARCH64`; angr 9.0.7491 still uses the old name); triggered when loading the model (the pickle chain imports angr) | downgrade to **`capstone==4.0.2`** |
| **protobuf too new** | "Downgrade the protobuf package to 3.20.x or lower" (angr-generated code incompatible with 4.x) | downgrade to **`protobuf==3.20.3`** |
| **missing sympy etc.** | loading the model triggers `import src.methods.glow` → `ModuleNotFoundError: sympy`/`z3`/`pysmt`... | `req_rest.txt` installs them all at once (incl. sympy/z3-solver/pysmt/networkx 2.5.1/numba 0.53.1/pandas 1.2.4) |
| **torch.load weights_only** | `tygr_original/src/{predict,test}.py` used `weights_only=False` (a torch 2 arg); torch 1.8 lacks it → `TypeError` | wrapped in try/except (works in both envs) |
| **CUDA 10.2 useless** | `environment.yml` pins cudatoolkit 10.2, which cannot run 40-series GPUs | use **CPU** pytorch; inference ~10 it/s is enough |

### 2.3 Verify the environment
```bash
cd tygr_original
# 1) Can the official model load?
conda run -n tygr-orig python -c "import torch; print(type(torch.load('model/MODEL_base/x64.O0.base.model', map_location='cpu')).__name__)"
# → GlowGNN
# 2) Can it produce types for a DWARF-carrying binary?
conda run -n tygr-orig python -m src.index predict -v model/MODEL_base/x64.O0.base.model <-g binary> /tmp/out.pkl
# → per-variable types: char* / f32* / array<void> / struct ...
```

---

## 3. Path A (fallback): self-training in the modern environment

In case the official model is ever unusable, we also made TYGR's **datagen / train / predict run in the
modern angr-env** and self-trained a model.

### 3.1 Modern-environment patches (applied to `tygr_original/`, gitignored)
| File | Change | Reason |
|---|---|---|
| `src/analysis/angr/sim_exec.py`, `ast_graph.py` | `state.solver.BVV/BVS` → `cp.BVV/BVS` (claripy) | new angr removed `SimSolver.BVV`; old-env claripy also has `BVV`, so it works in **both** |
| `src/predict.py`, `src/test.py` | wrap `torch.load(...)` in try/except (weights_only) | torch 2 defaults `weights_only=True`, rejecting whole-object pickle; torch 1.8 lacks the arg |
| `src/train.py` | remove `ReduceLROnPlateau(verbose=)` | torch 2.x removed that argument |
| `src/utils/learn.py` | divide-by-zero guards on precision/recall/accuracy | zero denominators on small datasets |
| `src/methods/glow/predict.py` | new `generate_glow_inputs_no_parallel` (serial) | the multiprocessing Pool's angr RuntimeDb crashes in the modern env |
| `src/methods/glow/model.py` | `edge_dim` from hardcoded `44` → `num_edge_ops` (dynamic) | modern pyvex has >44 edge ops → otherwise training `index out of bounds`. **Only affects newly built models, not loading the official model** |

### 3.2 Self-training procedure & result
- A self-built synthetic C corpus (80 files / ~720 functions / diverse types) → `output/tygr/ctr|cva|cte.pkl`.
- Training **key**: `--batch_size 1` (the default batch is **OOM-killed** on a 4 GB WSL, confirmed by
  dmesg; batch_size=1 uses ~2 GB).
- Result: held-out test **Accuracy 0.8875 / F1 0.8875**; model `output/tygr/model_stable.model`.
- **Quality is below the official model** (the official one is trained on real TYDA and produces
  char*/f32*/struct; the self-trained one only reaches int/char*/array), so it is only a fallback.

### 3.3 Why not just download TYDA and retrain to high quality
TYDA (TYGR's official dataset, a Dropbox link in the README) is real Gentoo C/C++ binaries,
**100+ GB (`tar.lz4`), impractical**. So modern-environment self-training is limited to a small self-built
corpus. The official model already solves quality, so no large-scale retraining is needed.

---

## 4. Reproduction command cheatsheet (modern angr-env, Path A)
```bash
cd tygr_original
gcc -gdwarf-4 -O0 -w X.c -o X                                  # needs DWARF
python -m src.index datagen X X.pkl                            # serial path works
python -m src.index datasplit D.pkl --train tr --validation va --test te
python -m src.index train tr va -o m.model --epoch 60 --batch_size 1   # batch_size 1 to avoid OOM
python -m src.index test m.model.best.model te                # batch_size 1
```
> ⚠️ The WSL `/tmp` is cleared when the VM idle-shuts down (tmpfs). Write intermediate files to a persistent
> path (`output/tygr/`).

---

## 5. Choosing in SymbAI-Taint
`src/type_recovery/inference.py` defaults to the **official model + tygr-orig** (`_recover_with_gnn`,
subprocess). Override via env vars:
- `TYGR_MODEL`: switch model (e.g. `.../x64.O2.base.model` or the self-trained `output/tygr/model_stable.model`).
- `TYGR_PYTHON`: the tygr-orig python (default `/root/miniconda3/envs/tygr-orig/bin/python`).

Integration details and data flow: [GNN_INTEGRATION.md](GNN_INTEGRATION.md).
