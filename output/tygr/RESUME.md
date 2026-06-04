# GNN Integration — Reproduction & Recovery Notes

> Reproduction notes for the GNN type-recovery integration. All tasks are local processes (a network drop
> does not affect them). Full details: [../../docs/GNN_INTEGRATION.md](../../docs/GNN_INTEGRATION.md) and
> [../../docs/VERSION_COMPAT.md](../../docs/VERSION_COMPAT.md).

## Final approach: official model via the `tygr-orig` environment (primary path)
- Use the **official pretrained model** `tygr_original/model/MODEL_base/x64.O0.base.model` (trained on the
  real TYDA dataset; produces char*/f32*/array/struct). The TYDA dataset itself (an official Dropbox link in
  TYGR's README) is 100+ GB and impractical to download.
- The official model is **version-locked** (`tygr_original/environment.yml`): python3.8 + torch1.8.1 +
  PyG1.7.0 + **angr/pyvex 9.0.7491**. Loading it in the modern angr-env fails (pickle `Inspector._cls` +
  feature-vocabulary mismatch, `edge_dim = 44`).
- **Solution**: reproduce an isolated conda env **`tygr-orig`** (python `/root/miniconda3/envs/tygr-orig/bin/python`).
  Build script `build_orig_env.sh` + `req_rest.txt`. Pitfalls: downgrade capstone→4.0.2, protobuf→3.20.3;
  pin numpy/networkx/numba/pandas to old versions.
- **Verified**: the official model loads (GlowGNN); predict produces char*/f32*/array/struct types.

## Integration (in `src/type_recovery/inference.py`)
- `recover_types` prefers `_recover_with_gnn`: **subprocess** calls the tygr-orig python to run the official
  model's predict → loads the var_dict → `_btype_to_str` (pointer→char*/pointer, array→array) → assembles
  `TypeRecoveryOutput` (buffer_labels: char*/array/pointer = True).
- Default model = official x64.O0 (env vars `TYGR_MODEL`/`TYGR_PYTHON` override); the self-trained synthetic
  model `model_stable.model` is a fallback.
- `pipeline.py`: Stage 1 keeps the unstripped `-g` binary `state.binary_debug`; Stage 6 feeds it to the GNN.
- **PIE base alignment**: map DWARF `low_pc` to angr's rebased addresses via `mapped_base`.
- End-to-end verified: `recover_types(c000)` → real char*/array types, src=gnn.

## Self-training route (fallback, also works)
A synthetic C corpus (80 files / ~720 functions) → `ctr/cva/cte.pkl` → training (**key: `--batch_size 1`**
to avoid OOM on a 4 GB WSL; `model.py edge_dim` made dynamic) → test Acc 0.8875. Model
`output/tygr/model_stable.model`.

To restart training (under `tygr_original/`):
```bash
python -m src.index train output/tygr/ctr.pkl output/tygr/cva.pkl -o output/tygr/corpus.model --epoch 60 --batch_size 1
python -m src.index test output/tygr/corpus.model.best.model output/tygr/cte.pkl
```

## Environment / command quick reference
- env: `/root/miniconda3/envs/angr-env/bin/python`; TYGR CLI: `cd tygr_original && python -m src.index <cmd>`
- compile with DWARF: `gcc -gdwarf-4 -O0 -w X.c -o X`
- datagen: `python -m src.index datagen BIN OUT.pkl` (serial path works)
- ⚠️ WSL `/tmp` is cleared on idle shutdown (tmpfs) → write intermediate files to `output/tygr/` (persistent).
- WSL memory: `.wslconfig` set to 6 GB + 8 GB swap.

## Reproduction scripts in this directory
- `build_orig_env.sh` + `req_rest.txt` — build the tygr-orig env
- `verify_base_align.py` — verify PIE base alignment (GNN types map to real function names)
- `demo_fullstrip.py` — GNN recovers type semantics after `strip --strip-all`
- `demo_type_sink.sh` + `demo_custom_sink.c` — type-driven sink detection (0/0/0 → 1.0)
- `run_all_gnn.sh` — run all 6 test programs with the GNN
