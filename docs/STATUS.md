# Project status

Updated 13 November 2026. The active protocol is **frozen pilot v1**, established on
10 November; the latest completed diagnostic is **development v23**. Development
revision numbers are separate from the legacy 13-stage pipeline's version numbers.

## Current checkpoint

The external DWARF location adapter now works with the observed pyelftools 0.27 entry
API in the original TYGR runtime. The corrected v22.1 WSL run, reusing the same v21 ELF,
produced genuine outputs for all three authored functions: seven variable records,
eleven readout rows, three completed guarded forwards and no location errors. Admission
requires matching location traces, model identity and guarded raw outputs. Original TYGR
source and model weights were unchanged.

The v23 offline audit finds an exact representation collision: the safe and outside-table
queries have identical prepared/collated model inputs and all 75-class value-row logits,
although their historical operation capabilities differ. This limits that representation
on that pair. It neither proves that all neural guidance is useless nor shows a scheduling
improvement. The scalar/table cases remain developer controls.

Cold acquisition cost was **8.305 s**. The previous v21 fixed cascade's three-query
parent cost totaled **2.162 s**. These different-run/stage observations are descriptive,
not a paired end-to-end speed comparison or a runtime bound.

Evidence: [successful v22.1 repair](pilot_evidence.md#v221-successful-wsl-repair-audit),
[v23 audit](pilot_evidence.md#v23-retained-type-information-collision-audit),
[v23 specification](architecture/pilot_revision_v23.md).
The raw receipt bundles remain local and are not distributed with the repository.

## Implementation boundary

| Component | Status |
|---|---|
| Query, type-view, evidence and cost contracts | Executable; binary/query identities recorded and offline gold separated. |
| Shared A-D runner | A is fixed order; B/C/D share selector, parameters and non-type information. |
| Local checks and independent validation | Restricted modeled write queries; unsupported behavior, incomplete scope and timeouts retain `unknown`. |
| Non-neural controls | Bounds, frame, interval, finite-readonly and expanded checks in explicitly separate diagnostics. |
| Genuine TYGR acquisition | Frozen 75-class GlowGNN in an isolated old runtime; DWARF-assisted locations, raw scores and guarded forwards. |
| Correspondence audits | Restricted location/group associations exist; precise event typing and general completeness are unproven. |
| OPM architecture | 22 DOT/SVG views; limited notation and interface checks are explicit. |

The pilot lives in `src/selective_analysis/`, `benchmarks/selective_analysis/` and the
associated scripts/tests. It runs independently of `src/pipeline.py`. No new GNN
training, LLM or GPU is required for the model-free developer mechanisms.

## Evidence limits

- Twelve authored mechanisms check the original analysis boundary. Compiled integration,
  indirection and typed-complementarity panels are separate development panels, not an
  accumulated independent test set. Variables, rows and repetitions are not samples.
- Non-neural cascades cover complementary mechanisms. Some paired timings improved on
  expanded-only within known panels; they do not establish a neural gain.
- The existing v13 routing diagnostic produced no B/C/D order change on three known
  integration queries. It is a result about that heuristic and panel.
- RQ1/RQ2, calibrated uncertainty, type accuracy, cross-project generalization and an
  independent algorithm contribution remain open.
- Scoped results rely on explicit program-model assumptions. Native replay and
  whole-program correctness are not established.
- The active acquisition is DWARF-assisted, so it does not demonstrate fully stripped
  end-to-end type-information recovery.

## Validation and availability

The complete local suite passed **1,285 tests** with 19 dependency warnings. An export
of public files without upstream source/weights/raw receipts passed **1,273 tests with
12 optional skips**. All **22 OPM views** validated and rendered (440 view-local nodes,
593 links). The seven upstream-parser checks now explicitly skip when excluded source
is absent. See the [verification record](VERIFICATION.md) for environment, timing,
the Windows path-length limitation and the scope of these checks.

The public tree contains implementation, authored fixtures, tests, specifications and
rendered views. Upstream source, model weights, Conda environments, generated binaries
and historical raw bundles are excluded. See [reproducibility](REPRODUCIBILITY.md).

## Next research decision

Keep the three typed cases as regression and cost controls. Do not tune scores on them
to force a positive result. Define a small independent program-grouped panel and a
specific hypothesis about information beyond structural or traditional type analysis.
Compare the same scheduler with hidden types, Top-1, Top-K without scores, genuine
scores and traditional types, charging all actual costs. Only then consider grouping,
learning or incremental updates.

The corrected repair and v23 audit need no further WSL run to close their current gate.
New data collection would be a new experiment.

See the [architecture](architecture.md), [OPM views](architecture/README.md),
[pilot guide](../benchmarks/selective_analysis/README.md),
[chronological evidence](pilot_evidence.md) and [documentation map](README.md).
