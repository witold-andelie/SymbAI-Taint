# SymbAI-Taint: Property-Directed Analysis Scheduling

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
![Python 3.13](https://img.shields.io/badge/Python-3.13-blue.svg)
![Status](https://img.shields.io/badge/status-research%20pilot-lightgrey.svg)

## Overview

SymbAI-Taint studies whether neural type predictions, or learned structural
features, improve the choice and order of analysis backends for scoped binary
property queries under a limited computation budget.

The findings at the tested scale:
- Type pilots v1-v3 found no incremental neural type information beyond a
  deterministic structural baseline.
- The pre-registered Route B v4 and v5 experiments found that a learned
  structural backend order did not beat a fixed symbolic-then-concrete cascade.
- Neural scheduling benefit was not shown.
- The cascade's remaining headroom against a per-query oracle is small and
  concentrated in a few kernels.

The selector sets priorities; semantic checkers and fresh evidence validation
support decisions. Unsupported behavior, incomplete evidence and expired
requests remain `unknown`. Reference labels belong to offline evaluation.

## Pre-registered series

| Study | Question | Panel or data | Decision | Key numbers | Results |
| --- | --- | --- | --- | --- | --- |
| v2 | Does deeper message passing add type information beyond structure? | 129 training variables; 200 new development variables in two projects. | **No R1**; R2 also failed. | Structural A5: 121/200; deeper A3: 88, 59, 83 correct across seeds. | [Type pilot v2](benchmarks/selective_analysis/route_b/README.md#type-pilot-v2-results) |
| v3 | Does expanded training help, and do neural scores add to structure? | 1,460 training variables in 15 projects; 571 fresh development variables in three projects. | **Neither**. | Structural D5: 269; expanded DG: 247, 251, 239 correct. | [Type pilot v3](benchmarks/selective_analysis/route_b/README.md#type-pilot-v3-results) |
| v4 | Does a learned structural backend order beat the fixed orders? | 62 held-out queries in 17 binary groups. | **not supported**. | F: 120 of 124 verified, 35.1 s; L: 110, 60.9 s. | [Structural selection](benchmarks/selective_analysis/route_b/README.md#route-b-v4-structural-selection-results) |
| v5 | Is the cascade equivalent to the oracle, and is learned order non-superior? | 169 new, sanitizer-screened queries in 41 binary groups. | **Q1 not supported**; **Q2 supported**. | F: 332 of 338 verified, 97.0 s; L: 326, 113.7 s; no wrong decisions. | [Cascade headroom](benchmarks/selective_analysis/route_b/README.md#route-b-v5-cascade-headroom-results) |

Type pilot v1 was a development pilot, not a pre-registered decision: training
was feasible, but a reliable graph-message effect was not established
([training results](benchmarks/selective_analysis/route_b/README.md#training-pilot-results)).

In v5, oracle time headroom was 0.030 s per trial, with a 90% cluster-bootstrap
interval of [0.000, 0.067] s against a 0.05 s margin. The oracle added no verified
decisions. All time headroom came from jsonsl and zopfli, so equivalence was not
established even though the point estimate was inside the margin.

The original v4 panel included an ill-defined out-of-buffer read in
`sds-sdsAllocSize-L300`, causing wrong decisions in both symbolic-first arms.
The report-only sanitizer-screened re-score retained F 118, C 100 and L 108
verified of 120, with no wrong decisions; **not supported** was unchanged.

## Method and safeguards

- Decision protocols are frozen by SHA-256 before held-out runs; changes require
  separately versioned pre-registration or dated amendments. v1 is exploratory.
- Project-disjoint panels keep related queries within binary groups; development
  observations and seed repetitions do not become independent held-out samples.
- For v4/v5, runtime reference labels remain sealed until all trials are collected;
  runtime reads query contracts and fixture bytes.
- Uncertainty is estimated by paired cluster bootstrap over binary groups.
- Consolidated backends must pass the archived outcome regression gate; v5 re-runs
  it and requires backend identity against the v4 freeze.
- The v5 native screen uses ASan/UBSan with ASLR disabled via `setarch`; it excludes
  undefined behavior and disagreement with MinGW references before freezing.
- The sealed evaluation projects, utf8.h and b64, were never opened for these runs.

See the [protocol index](benchmarks/selective_analysis/route_b/README.md#pre-registered-series)
and [reproducibility guide](docs/REPRODUCIBILITY.md#route-b-v4-and-v5-pipelines).

## Earlier development observations

These are scoped development conclusions. Detailed results remain in the linked
records and the chronological [Route B README](benchmarks/selective_analysis/route_b/README.md).

| Line of work | Conclusion and existing evidence |
| --- | --- |
| Native acquisition and query discrimination | Genuine outputs were admitted, but a query pair had identical model inputs and logits; acquisition costs did not establish an end-to-end gain. [Acquisition audit](docs/pilot_evidence.md#v221-successful-wsl-repair-audit), [comparison](docs/pilot_evidence.md#v23-retained-type-information-collision-audit), [cost interpretation](docs/STATUS.md#current-checkpoint). |
| Deadline engineering and transfer | Cache-preserving checks improved known cases, but the frozen cutoff did not transfer with a coverage or cost gain. [Cache checks](benchmarks/selective_analysis/route_b/README.md#cache-preserving-deadline-checks), [disjoint-project test](benchmarks/selective_analysis/route_b/README.md#frozen-cutoff-test-on-six-new-projects). |
| Live progress and action choice | Counters were observable and continuation/switching had different regimes; phase-only replay savings did not become a live advantage over the cascade. [Progress](benchmarks/selective_analysis/route_b/README.md#prospective-progress-observation), [shared checkpoints](benchmarks/selective_analysis/route_b/README.md#actions-from-a-shared-resident-checkpoint), [replay](benchmarks/selective_analysis/route_b/README.md#phase-only-baseline-replay), [live comparison](benchmarks/selective_analysis/route_b/README.md#live-phase-rule-with-charged-cleanup). |
| Native input eligibility | Timing fixtures needed matched neural inputs; native debug/stripped pairs subsequently passed identity and binding checks. [Feasibility](benchmarks/selective_analysis/route_b/README.md#strong-baseline-headroom-and-neural-input-eligibility), [preparation](benchmarks/selective_analysis/route_b/README.md#native-debugstripped-input-preparation). |
| Native baseline and direct execution | Direct concrete execution added no batch completions; local speed differences did not establish a scheduling gain. [Baseline](benchmarks/selective_analysis/route_b/README.md#official-native-baseline-results), [control](benchmarks/selective_analysis/route_b/README.md#official-native-control-results), [local actions](benchmarks/selective_analysis/route_b/README.md#official-local-action-results). |
| Neural representation and compatibility | Equivalent encoded inputs hid opposite local choices; graph/read-hook corrections exposed relation incompatibility, and alternative base weights did not resolve it. [Information assessment](benchmarks/selective_analysis/route_b/README.md#local-information-assessment), [graph audit](benchmarks/selective_analysis/route_b/README.md#confirmed-graph-stage-observations), [read-hook comparison](benchmarks/selective_analysis/route_b/README.md#confirmed-read-hook-intervention-results), [operator audit](benchmarks/selective_analysis/route_b/README.md#confirmed-installed-operator-behavior), [weight audit](benchmarks/selective_analysis/route_b/README.md#alternative-x64-base-checkpoint-audit). |
| Corpus, mapping and export | Pinned project splits, corrected build recipes and passive audits established an admitted training/development dataset; exclusions remained explicit. [Readiness](benchmarks/selective_analysis/route_b/README.md#independent-type-corpus-readiness), [recipe correction](benchmarks/selective_analysis/route_b/README.md#type-corpus-v2-link-recipe-correction), [inventory](benchmarks/selective_analysis/route_b/README.md#completed-v2-type-inventory), [mapping](benchmarks/selective_analysis/route_b/README.md#confirmed-four-function-mapping-results), [export protocol](benchmarks/selective_analysis/route_b/README.md#bulk-traindevelopment-graph-export), [completed export](benchmarks/selective_analysis/route_b/README.md#completed-bulk-graph-export). |
| Fresh type training | Training and score replay worked, but predictions mostly separated value widths rather than pointer classes. [Training protocol](benchmarks/selective_analysis/route_b/README.md#minimal-full-relation-training-pilot), [coverage diagnosis](benchmarks/selective_analysis/route_b/README.md#coverage-and-representation-diagnosis). |

## Reproducing the experiments

Use the repository root as the working directory in each runtime. Generated files
go under `../.scratch/selective_analysis/`. Replace angle-bracket placeholders
with relative paths under that directory; use fresh output directories.

Use the [minimal requirements](benchmarks/selective_analysis/requirements.txt)
for the model-free pilot. Native TYGR acquisition uses its isolated original
runtime; see [runtime compatibility](docs/VERSION_COMPAT.md).

```bash
python -m pip install -r benchmarks/selective_analysis/requirements.txt
```

| Existing check | Command | Runtime |
| --- | --- | --- |
| Route B source reference | `python -B scripts/run_route_b_pilot.py --reference-only` | Windows or WSL, GCC |
| Route B grouped information comparison | `python -B scripts/run_route_b_pilot.py` | WSL `angr-env` plus original CPU `tygr-orig` |
| Original model-free pilot | `python -B scripts/run_selective_pilot.py --make-mechanisms --variants A B --budgets 1` | Python with angr |
| OPM contracts and rendering | `python -B scripts/validate_architecture.py --render` | Python and Graphviz |

### Route B v4 pipeline

Run the rows in order. The gate, freeze and development labels require retained
historical scratch inputs; the freeze script pins a named regression receipt.
These are artifact replay procedures, not a clean-checkout one-command run.

| Step | Exact command | Runtime |
| --- | --- | --- |
| 1. Regression gate | `python -B scripts/regress_route_b_v4_backends.py` | WSL `angr-env` |
| 2. Freeze | `python -B scripts/freeze_route_b_v4.py` | Windows/MinGW |
| 3. Development labels and fit | `python -B scripts/label_route_b_v4_development.py --freeze <v4-freeze-dir>` | WSL `angr-env` |
| 4. Plan panel | `python -B scripts/build_route_b_v4_panel.py --plan-only --output <v4-panel-dir>` | Windows/MinGW |
| 5. Build saved plan | `python -B scripts/build_route_b_v4_panel.py --build --output <v4-panel-dir>` | Windows/MinGW |
| 6. Collect and audit | `python -B scripts/run_route_b_v4_panel.py --freeze <v4-freeze-dir> --selector <v4-selector-dir> --panel <v4-panel-dir>` | WSL `angr-env` |

### Route B v5 pipeline

The source fetch commands are network-bound; this documentation update does not
run them. Compile each source manifest before merging. Plan and build share an
output directory; finalization writes a separate panel directory.

| Step | Exact command | Runtime |
| --- | --- | --- |
| 1. Fetch base sources and Juliet | `python -B scripts/prepare_route_b_v5_sources.py` | Windows/MinGW |
| 2. Base DWARF inventory | `python -B scripts/build_route_b_v5_dwarf.py --sources <base-sources-dir>` | WSL `angr-env` |
| 3. Fetch added sources | `python -B scripts/prepare_route_b_v5_sources.py --amendment 2` | Windows/MinGW |
| 4. Added DWARF inventory | `python -B scripts/build_route_b_v5_dwarf.py --sources <added-sources-dir>` | WSL `angr-env` |
| 5. Merge compiled manifests | `python -B scripts/merge_route_b_v5_sources.py --base <base-sources-dir>/sources-manifest.json --amendment <added-sources-dir>/sources-manifest.json --output <merged-sources-dir>` | Windows/MinGW |
| 6. Plan panel | `python -B scripts/build_route_b_v5_panel.py --plan-only --sources-manifest <merged-sources-dir>/sources-manifest.json --output <v5-build-dir>` | Windows/MinGW |
| 7. Build saved plan | `python -B scripts/build_route_b_v5_panel.py --build --output <v5-build-dir>` | Windows/MinGW |
| 8. Native sanitizer screen | `python -B scripts/screen_route_b_v5_sanitizers.py --build-dir <v5-build-dir> --output <v5-screen-json> --gcc gcc` | WSL `angr-env` |
| 9. Finalize screened panel | `python -B scripts/build_route_b_v5_panel.py --finalize --build-dir <v5-build-dir> --screen <v5-screen-json> --output <v5-panel-dir>` | Windows/MinGW |
| 10. Screen earlier panel | `python -B scripts/screen_route_b_v5_sanitizers.py --build-dir <v4-panel-dir> --output <v4-screen-json> --gcc gcc` | WSL `angr-env` |
| 11. Report-only re-score | `python -B scripts/rescore_route_b_v4_screened.py --run <v4-run-dir> --screen <v4-screen-json> --output <v4-rescore-json>` | Windows or WSL (Python only) |
| 12. Re-run regression gate | `python -B scripts/regress_route_b_v4_backends.py` | WSL `angr-env` |
| 13. Freeze | `python -B scripts/freeze_route_b_v5.py --sources <merged-sources-dir> --build <v5-build-dir> --screen <v5-screen-json> --panel <v5-panel-dir> --regression <rerun-regression-dir>` | Windows/MinGW |
| 14. Development labels and refit | `python -B scripts/label_route_b_v5_development.py --freeze <v5-freeze-dir>` | WSL `angr-env` |
| 15. Collect and audit | `python -B scripts/run_route_b_v5_panel.py --freeze <v5-freeze-dir> --selector <v5-selector-dir> --panel <v5-panel-dir>` | WSL `angr-env` |
| 16. Report | `python -B scripts/report_route_b_v5.py --run <v5-run-dir> --selection <v5-panel-dir>/selection.json --screen <v5-screen-json> --v4-screen <v4-screen-json> --v4-rescore <v4-rescore-json> --v4-run <v4-run-dir> --output <v5-report-dir>` | Windows or WSL (Python only) |

WSL uses Ubuntu with gcc 9, libasan and `setarch` for the sanitizer screen.
The screen itself disables ASLR. MinGW gcc builds the native query fixtures on
Windows. See the [pipeline and artifact guide](docs/REPRODUCIBILITY.md#route-b-v4-and-v5-pipelines)
for pinned prerequisites and retained outputs, and the
[pilot guide](benchmarks/selective_analysis/README.md) for earlier commands.

## Limitations

| Boundary | Scope of the finding |
| --- | --- |
| Scale | Type v2 used 200 development variables in two projects; v3 used 571 in three. Backend panels were 62 queries / 17 groups (v4) and 169 / 41 (v5). |
| Backend catalog | Only `symbolic_certificate` and `concrete_enumeration`, with fixed-order and learned-order comparisons. |
| Query and budget | v4/v5 use scoped finite-domain write-bound queries, a 3 s per-query budget and a finite 256-input domain. |
| Compilation | v4/v5 analyze x86-64 freestanding kernels built with MinGW; WSL native sanitizer builds screen their reference adapters. |
| Selector | One selector model family was tested: structural logistic and ridge regressions with a fixed expected-time order rule. |
| Neural evidence | Type accuracy is not scheduling benefit; the type pilots did not establish incremental information beyond structure. Neural scheduling benefit was not shown. |
| Headroom | v5 did not establish equivalence to the oracle within the time margin; the remaining measured opportunity is concentrated in jsonsl and zopfli. |

The type interface relies on DWARF-assisted locations and uncalibrated scores.
These results do not establish whole-program correctness or a general limit on
other backend catalogs, model families or query domains.

## Repository structure

```text
src/selective_analysis/            Query contracts, checkers, selectors and evidence
benchmarks/selective_analysis/     Development fixtures and run guides
  route_b/                         Pre-registrations, amendments and result records
scripts/                           Experiment and validation entry points
docs/architecture/                 OPM DOT sources, SVGs and frozen specifications
docs/pilot_evidence.md             Chronological evidence and receipt identities
tests/                             Contract, analysis and reproduction checks
```

The [documentation map](docs/README.md) links current guides and legacy records.
The [evidence log](docs/pilot_evidence.md) records local receipt identities;
upstream sources, model weights and historical raw bundles are obtained separately.

## Citation

Cite the [SymbAI-Taint repository](https://github.com/witold-andelie/SymbAI-Taint)
and the specific commit or experiment protocol used.

## License

Project source is distributed under the [Apache license](LICENSE).
