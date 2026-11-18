# Route B information pilot

This experiment measures whether genuine neural type information helps the existing
selector within an analysis budget. It runs before any development of Variant E.
The test panel is new relative to the v1–v23 development records. Six separately
compiled authored programs cover saturation, lane layout, table lookup, mirroring,
grid indexing and periodic control. They share a fixture harness. They are useful
for a first decision and do not represent six real projects.

## Fixed protocol

Each binary contributes two queries on the same byte store into a 64-byte output
array. The entry value ranges from 0 to 31 or from 0 to 255. A separate executable
checks the source index for every input from 0 to 255 before the model is run.
The checker still needs fresh evidence to exclude a violation within each binary
query's scope. The source check serves as a reference for the authored fixtures.
It does not verify arbitrary compiled programs.

| Arm | Information supplied to the existing selector |
|---|---|
| B | None. |
| C | The model's Top-1 label for the predeclared parameter. |
| K | The same genuine Top-3 candidate set as D, with uniform weights and no model scores. |
| D | The genuine Top-3 set and retained raw logits. |

All four arms use the same operation catalog, policy weights, checkers, empty initial
checkpoint and structural features. The K arm uses the same scoring function as
D; only its type weights are uniform. Precomputed information only affects operation
order. The per-function mapping selects the single DWARF-located parameter named
`setting` before reading its candidates. A missing or ambiguous match stays
unavailable. This association has function-parameter scope.

The two analysis budgets are 0.15 and 0.50 seconds. The preregistered decision uses
0.15 seconds. Repeat each comparison twice with rotating arm order. Each arm therefore
has 12 queries per repetition. Report results within program groups because the two
queries in a program share a compiled function and neural record. Timing repetitions
measure variability. They do not increase the number of independent programs.

The clock charges selection, execution and validation. Fresh checker preparation and
native type acquisition are measured separately. All planned outcomes, including
unknowns, unavailable type records and wrong decisions, remain in the denominator.
Native model inputs and raw output pass the v22.1 trace and logit checks before
admission. Reference labels are read by the evaluator after trial collection.

## Decision

Advance to a paired end-to-end cost measurement if one neural arm covers at least
four groups, resolves more queries than B in both repetitions in at least two
groups with a recorded operation-order change, never resolves fewer in any
available group, and the experiment produces
zero wrong decisions. This is a pilot decision criterion. A favorable result
motivates measurement of model acquisition and a strong fixed control before
implementing a gated scheduler.

If genuine coverage is insufficient, inspect acquisition and mapping before making
a scientific judgment. If the effect is absent at sufficient coverage, retain the
result and defer Variant E. Keep any future tuning separate from this panel's
observations.

## Run

From the repository root, run the source reference on Windows with GCC installed.

```powershell
py -3 -B scripts/run_route_b_pilot.py --reference-only
```

For the full CPU pilot, use the existing WSL analysis environment and the separate
original TYGR interpreter on the D: workspace.

```bash
cd /mnt/d/AI_Models/symbolic/SymbAI-Taint
conda activate angr-env
python -B scripts/run_route_b_pilot.py
```

Artifacts go under the workspace parent's `.scratch/selective_analysis/` directory.
Retain `plan.json`, `summary.json`, the run records, and the evidence files needed
to audit them. Temporary reference executables and per-acquisition caches are
removed after use.
The repository contains the small authored inputs and the protocol. The external
model checkpoint and generated outputs follow the
[reproducibility guide](../../../docs/REPRODUCIBILITY.md).

## Local validation

The initial Windows run confirmed all 1,536 source inputs. The repository suite
passed 1,289 tests, and the architecture validator accepted 22 OPM views. A separate
smoke check exercised B on the known v21 scalar fixture. This fixture remains
outside the new panel. The new panel's WSL binary and neural results are pending.
