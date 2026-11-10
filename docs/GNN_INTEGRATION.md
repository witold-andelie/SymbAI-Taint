# GNN Type-Recovery Integration

> This document records the changes, rationale, reproduction steps, and known limitations of genuinely
> integrating **GNN type recovery** into the taint-analysis pipeline.
> In one line: the GNN (TYGR's GlowGNN) was previously an **empty shell** (Stage 6 type recovery always
> output 0). It now works using TYGR's **official pretrained model**, and the full pipeline reaches
> P/R/F1 = 1.0.

---

## 1. Background: why the GNN did not work before

- Stage 6 "GNN type recovery" previously relied on a local `gat_model.pt`, but it was a **zero-feature
  shell** whose inference always returned 0 types. The past 100/100/100 was achieved with the **GNN not
  participating**.
- We reference [TYGR](https://github.com/sefcom/TYGR) (2024 paper, GNN type inference on stripped
  binaries), which **open-sources its pretrained models** (under the repo's `model/` directory) by
  architecture/optimization level: `x64.O0.base.model`, etc.
- TYGR's training set **TYDA** is also open (an official Dropbox link in the README), but it is **100+ GB,
  impractical to download**, so we use the official pretrained model directly.

## 2. Core difficulty: the official model is pinned to the original environment

The official model was trained and pickled in TYGR's original environment (see
`tygr_original/environment.yml`), and is **version-locked**:

| Component | Official model requires | The modern angr-env |
|---|---|---|
| python | 3.8.10 | 3.11 |
| pytorch | 1.8.1 | 2.x |
| torch-geometric | 1.7.0 | 2.7 |
| **angr / pyvex** | **9.0.7491** | latest |

Two incompatibilities:
1. **Pickle load fails**: PyG 1.7 → 2.7 changed internal classes (`Inspector._cls`), so `torch.load` fails.
2. **Feature vocabulary mismatch**: the model's graph features come from **angr/pyvex 9.0.7491** (its edge
   operation vocabulary is exactly 44); modern angr datagen produces features whose dimension does not match
   (`index out of bounds for size 44`).

**Conclusion**: to use the official model, the **entire TYGR original environment must be faithfully
reproduced**, rather than forcing adaptation in the modern environment.

## 3. Solution: an independent `tygr-orig` conda environment

We build a version-faithful conda environment **`tygr-orig`** dedicated to running the official model's
predict. The OPM main pipeline stays in `angr-env` and calls `tygr-orig`'s python via **subprocess** — the
two environments coexist without cross-contamination.

### Reproduction
Script: `output/tygr/build_orig_env.sh` (+ `output/tygr/req_rest.txt`). Equivalent commands:
```bash
conda create -y -n tygr-orig python=3.8.10
conda run -n tygr-orig pip install torch==1.8.1+cpu torchvision==0.9.1+cpu torchaudio==0.8.1 \
    -f https://download.pytorch.org/whl/torch_stable.html
conda run -n tygr-orig pip install torch-scatter==2.0.6 torch-sparse==0.6.9 \
    -f https://data.pyg.org/whl/torch-1.8.1+cpu.html
conda run -n tygr-orig pip install torch-geometric==1.7.0
conda run -n tygr-orig pip install angr==9.0.7491 archinfo==9.0.7491 claripy==9.0.7491 \
    cle==9.0.7491 pyvex==9.0.7491
conda run -n tygr-orig pip install -r output/tygr/req_rest.txt
```
For the full dependency pitfalls (capstone 4.0.2, protobuf 3.20.3, etc.) see
[VERSION_COMPAT.md](VERSION_COMPAT.md).

### Verify
```bash
cd tygr_original
conda run -n tygr-orig python -c "import torch; print(type(torch.load('model/MODEL_base/x64.O0.base.model', map_location='cpu')).__name__)"
# → GlowGNN
conda run -n tygr-orig python -m src.index predict -v model/MODEL_base/x64.O0.base.model <binary-with-DWARF> /tmp/out.pkl
# → per-variable types: char* / f32* / array<void> / struct ...
```

## 4. Integration into OPM

| File | Change |
|---|---|
| `src/type_recovery/inference.py` | New `_recover_with_gnn()`: **subprocess** calls `tygr-orig` python to run the official model's predict → loads the var_dict → `_btype_to_str()` converts TYGR btypes to OPM types (pointer→char*/pointer, array→array) → assembles `TypeRecoveryOutput`. `recover_types()` now **prefers** the GNN, falling back to heuristics. Model/interpreter overridable via env vars `TYGR_MODEL` / `TYGR_PYTHON`. |
| `src/pipeline.py` | `OPMState` gains `binary_debug`; Stage 1 keeps the unstripped **-g binary** before stripping; Stage 6 feeds it to the GNN (**TYGR locates variables via DWARF; the GNN predicts their types**, so a debug-carrying binary is needed). |
| `src/typed_ir/type_injector.py` | The original `_extract_variables_from_block` was a stub (always 0 typed). Now GNN predictions are **folded directly** into `variable_types` (and buffer/pointer maps). |
| `tygr_original/src/predict.py`, `test.py` | `torch.load(..., weights_only=False)` wrapped in try/except (old torch 1.8 lacks that argument). |

### PIE base alignment
GNN types attach at DWARF `low_pc` (e.g. `0x1149`), while angr uses PIE-rebased addresses (`0x401149+`).
`_recover_with_gnn` reads the base from `cfg.angr_cfg.project.loader.main_object.mapped_base` and maps via
**both the absolute address and the (address − base) offset**, so types attach to the correct named CFG
functions (`vuln_use_after_free → pointer/struct/char*`). Verification: `output/tygr/verify_base_align.py`.

### Data flow
```
source.c
 └─Stage1─ gcc -g → keep -g binary (binary_debug) + stripped copy (for CFG/taint)
 └─Stage6─ recover_types(binary_debug)
            └─ subprocess: tygr-orig python  src.index predict  official x64.O0 model  binary_debug
                 └─ TYGR datagen (locate vars via DWARF + features via angr 9.0.7491) → GlowGNN → per-var types
            └─ var_dict → TypeRecoveryOutput {char*/array/int...}
 └─Stage7─ folded into TypedIR.variable_types (86 typed variables)
 └─Stage10+ taint analysis / symbolic evidence / evaluation
```

## 5. Current effect (memory_vuln.c, full pipeline)
```
Stage 6  GNN type recovery → 30 functions (char*/array)
Stage 7  type injection    → 86 typed variables   (was 0)
Stage 10 taint             → 4 sources / 11 sinks / 29 paths + UAF/double-free
Stage 12 evaluation        → P=1.0  R=1.0  F1=1.0
```

## 5b. Evidence of the GNN's irreplaceable value (fully-stripped)

Fully stripping `memory_vuln` with `strip --strip-all` (erasing `.symtab`, so all local function names are
gone), then running GNN type recovery (script `output/tygr/demo_fullstrip.py`):

| Fully-stripped CFG name | (cross-ref) real name | GNN-recovered type semantics |
|---|---|---|
| `sub_4011e9` | vuln_use_after_free | pointer, **struct**, **char\*** |
| `sub_401260` | vuln_double_free | pointer, struct, char* |
| `sub_401354` | safe_memory | **char\*, char\*, char\*** |
| `main` | main | **int32, char\*, char\*** (argc/argv) |

**Conclusion**: after full stripping, function names are entirely lost — pure "name matching + structure
heuristics" sees only meaningless `sub_xxxx`; the GNN still accurately labels each nameless function as
handling char* buffers / pointers / structs. **On a fully-stripped binary, the GNN is the only source of
type/buffer semantics** — this is its core value beyond source/symbol-level heuristics.

## 6. Known Limitations / Next Steps
1. **PIE base alignment (✅ solved)** — `_recover_with_gnn` now bridges DWARF `low_pc` and angr's rebased
   addresses (verification `verify_base_align.py`); 6-program regression-free (all 1.0).
2. **Type-driven sink detection (✅ implemented + closed loop)** — `_find_sinks_by_types` (`OPM_TYPE_SINKS=1`,
   off by default, so the standard 6 programs are unchanged / regression-free). Logic: promote a custom
   function that is **nameless + GNN-typed char*/buffer (≥2) + present in the call graph** to a sink
   candidate, and inject an argv source for its main-reachable caller → form a taint path.
   - **Demo** (`output/tygr/demo_custom_sink.c` + `demo_type_sink.sh`): a `store_record(char* dst, char*
     src)` that does a hand-rolled `while` buffer copy and calls **no libc**:

     | | Off (name/structure) | On (`OPM_TYPE_SINKS=1`) |
     |---|---|---|
     | sink detection | **0** (missed) | candidate (incl. store_record) |
     | taint path | **0** | **`argv -> store_record` (1)** |
     | **P/R/F1** | **0 / 0 / 0** | **1.0 / 1.0 / 1.0** |

     → shows the GNN types recover detections that "name + structure heuristics" both miss, **with a complete
     evaluation loop**.
   - **Closed loop**: ① type-sinks classified as `buffer_overflow` (`type_buffer_sinks` →
     `_get_vulnerability_type`); ② the GT extractor supports an explicit annotation `// @vuln: <type>
     <source> -> <sink>` (`extract_annotations`, parsed before comments are stripped); ③ evaluation matches
     on `(source, sink)` → custom_sink reaches **P/R/F1 = 1.0** under `OPM_TYPE_SINKS=1`, consistent with the
     standard 6 programs (zero regression with the flag off).
   - On a real benchmark, type-driven sinks need refinement to reduce FPs (see [JULIET_PILOT.md](JULIET_PILOT.md) §4.x/§7).
3. **LLM × GNN**: the Juliet ablation shows the LLM (types-only evidence) is a no-op; feeding in the angr
   symbolic constraints is the next step (JULIET_PILOT.md §7).
4. **Type recovery currently needs DWARF to locate variables**: on a fully DWARF-less binary, a preceding
   variable-recovery pass is needed (a known next step). The analysis (CFG/DFG/taint) binary may be fully
   stripped.
5. Fallback (also works): a modern-environment self-trained GlowGNN (`output/tygr/model_stable.model`, test
   Acc 0.887); the official model is higher quality, so the self-trained one is only a fallback.

## 7. Quick Start
```bash
# Run a single program (GNN auto-enabled; build the tygr-orig env first)
python scripts/run_pipeline.py tests/test_programs/memory_vuln.c -o output/gnn_demo
# Look for "GNN type recovery: N functions" and "N typed variables" in the Stage 6/7 logs.
```
Optional env vars:
- `TYGR_MODEL` — switch to another architecture/optimization model (e.g. `.../x64.O2.base.model`)
- `TYGR_PYTHON` — the tygr-orig python (default `/root/miniconda3/envs/tygr-orig/bin/python`)

---
*Related: version details in [VERSION_COMPAT.md](VERSION_COMPAT.md); progress/recovery in `output/tygr/RESUME.md`.*
