# Reproducibility and artifact availability

Updated 13 November 2026. This guide separates clean-checkout experiments from
diagnostics that replay locally retained development receipts.

## Distributed files

The repository includes the selective-analysis implementation, authored mechanism
generators and C sources, synthetic test fixtures, frozen specifications, OPM DOT
sources and SVG renders. The pilot is independent of `src/pipeline.py`.

Upstream TYGR source, weights, Conda environments, generated ELF files, library caches
and historical raw `.scratch` bundles are not distributed. The [evidence log](pilot_evidence.md)
records observations and artifact identities, not a downloadable raw dataset. Hashes
alone do not make a run replayable.

## Tier 1: clean-checkout mechanisms and tests

Use a Python environment with [pilot dependencies](../benchmarks/selective_analysis/requirements.txt).
The measured Windows environment was Python 3.13.10, angr/claripy 9.2.217 and pytest 9.0.3.
The WSL analysis environment used Python 3.10.20 and angr 9.2.212; these are distinct
runtimes. See [compatibility](VERSION_COMPAT.md). From the repository root in PowerShell:

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
$env:TEMP='D:\AI_Models\symbolic\.scratch\selective_analysis'
$env:TMP=$env:TEMP
py -3 -B -m pytest tests -q -p no:cacheprovider --basetemp=D:/AI_Models/symbolic/.scratch/selective_analysis/pytest-public
py -3 -B scripts/validate_architecture.py --render
py -3 -B scripts/run_selective_pilot.py --make-mechanisms --variants A B --budgets 1 --output D:/AI_Models/symbolic/.scratch/selective_analysis/public-pilot
py -3 -B scripts/evaluate_selective_pilot.py --runs D:/AI_Models/symbolic/.scratch/selective_analysis/public-pilot/runs.json --gold D:/AI_Models/symbolic/.scratch/selective_analysis/mechanisms/gold.json --output D:/AI_Models/symbolic/.scratch/selective_analysis/public-pilot/evaluation.json
```

Create the scratch directory before assigning it as TEMP if absent. Use fresh output
and basetemp names. `src/selective_analysis/workspace.py` sets the default scratch root
relative to the checkout's parent; moving the checkout changes that root. Keep generated
files on the intended data drive. Graphviz is needed for `--render`; SVGs are included.
On Windows, use a short checkout-parent path: nested provenance fixtures can exceed
legacy directory-length limits in a deeply nested checkout (`WinError 206`). A shorter
snapshot parent resolves that environment limitation without changing the test cases.

Run `pytest tests`, not the repository root: optional upstream trees contain CLI modules
named `test.py` that are not this suite. Seven parser checks, four native-encoder checks
and one checkpoint check need optional upstream source/weights and skip when those files
are absent. Available but invalid artifacts must still fail. Other synthetic tests run
with the declared dependencies.

The twelve generated mechanisms are developer examples, not a held-out benchmark.
C/D without genuine accepted type artifacts remain unavailable. This A/B run does not
simulate neural predictions or answer RQ1/RQ2.

## Tier 2: optional native acquisition

Genuine exports use separately obtained [TYGR](https://github.com/sefcom/TYGR) source and
the pinned GlowGNN checkpoint in a compatible isolated runtime. The observed runtime is
Python 3.8.10, torch 1.8.1+cpu, torch-geometric 1.7.0, angr/pyvex 9.0.7491 and pyelftools
0.27. CPU acquisition is supported; training and a GPU are unnecessary. Audits do not
implicitly install environments or modify upstream source.

The measured checkpoint SHA-256 is
`f592caaa6c685f291f576b16fbf8b752a95e7cb757ea620751830563b77f67c8`.
The saved model has 31 input features and 75 classes. Its declared relation domain has
60 IDs while eight saved RGCN layers have capacity 44; actual prepared inputs must pass
domain checks. Neither runtime version alone guarantees valid inputs. Raw scores are
not calibrated correctness probabilities.

Follow the [pilot guide](../benchmarks/selective_analysis/README.md) for preparation,
compilation and acquisition commands. WSL paths refer to the observed `/mnt/d` workspace.
The interface uses DWARF-assisted locations without supplying ground-truth type labels to
the network. A compiler/runtime change can alter ELF hashes, locations and eligibility;
a new compilation is a new artifact, not the old experiment.

The current repair is external to original TYGR. Legacy self-trained models and constant
confidences cannot replace genuine C/D inputs. Model loading, graph creation, mapping,
selection, checking and validation contribute to end-to-end cost. Report cached/shared
costs with the actual number of queries served.

## Tier 3: historical receipt replay

Many versioned diagnostics select or pin previous `.scratch` bundles. Examples include
`run_native_readout_correspondence.py` (v19 inputs), `run_location_repair.py` (the v21
ELF) and `audit_type_information.py` (successful v22.1 repair). Other drivers locate
earlier bundles by glob. These are replay procedures for specific retained artifacts,
not fresh-checkout one-command experiments.

If the expected bundle is absent, do not fabricate it, replace its hash or reinterpret
a fresh run as the recorded experiment. Use Tier 1, collect an explicitly identified
Tier 2 run, or obtain the original bundle separately. Source copies/input identities
are part of admission checks. Failed receipts remain failures.

## Route B v4 and v5 pipelines

These pipelines replay retained artifacts and require the historical scratch
inputs named by the scripts. They are not complete clean-checkout runs. Run from
the repository root in each runtime, using relative paths. Generated files go
under `../.scratch/selective_analysis/`. The main README gives the exact
[v4 commands](../README.md#route-b-v4-pipeline) and
[v5 commands](../README.md#route-b-v5-pipeline), including all required arguments.

| Runtime | Required tools and role |
| --- | --- |
| Windows | Python and MinGW gcc for the freestanding native query builds; git and curl for source preparation. |
| WSL Ubuntu | gcc 9 plus libasan and `setarch` for native ASan/UBSan screening; gcc and ld for DWARF inventories. |
| WSL `angr-env` interpreter | Run regression gates, development labeling/fitting, held-out backends and reporting with this environment's `python -B`. |

The sanitizer runner applies `setarch <arch> -R` itself. ASLR must be disabled;
the instrument livelock signature aborts the screen instead of becoming a kernel
exclusion ([amendment 3](../benchmarks/selective_analysis/route_b/cascade_headroom_v5_amendment_3.md#2-sanitizer-runtime-under-address-randomization)).

| v4 order | Step and runtime |
| --- | --- |
| 1 | `regress_route_b_v4_backends.py` in WSL `angr-env`: reproduce archived outcomes. |
| 2 | `freeze_route_b_v4.py` on Windows: pin the design, implementation and regression evidence. |
| 3 | `label_route_b_v4_development.py --freeze <v4-freeze-dir>` in WSL `angr-env`: label development data and fit L. |
| 4 | `build_route_b_v4_panel.py --plan-only --output <v4-panel-dir>` on Windows/MinGW. |
| 5 | `build_route_b_v4_panel.py --build --output <v4-panel-dir>` on Windows/MinGW, reusing the saved plan. |
| 6 | `run_route_b_v4_panel.py --freeze <v4-freeze-dir> --selector <v4-selector-dir> --panel <v4-panel-dir>` in WSL `angr-env`, followed by its offline audit. |

The regression script requires `route-b-project-disjoint-20261119T141817Z`, its
`intake.json`, fixture binaries and per-case native references. The v4 freeze
script reads the named receipt `route-b-v4-backend-regression-20261121T073429858926Z`;
it has no argument for replacing that receipt. Development labeling also reads
earlier `route-b-*/intake.json` bundles, and panel planning reads retained source
manifests and DWARF inventories. Missing receipts cannot be replaced by invented
hashes or labels.

| v5 order | Step and runtime |
| --- | --- |
| 1 | `prepare_route_b_v5_sources.py` on Windows: fetch base projects and Juliet. |
| 2 | `build_route_b_v5_dwarf.py --sources <base-sources-dir>` in WSL: compile the base inventory. |
| 3 | `prepare_route_b_v5_sources.py --amendment 2` on Windows: fetch the added projects. |
| 4 | `build_route_b_v5_dwarf.py --sources <added-sources-dir>` in WSL: compile the added inventory. |
| 5 | `merge_route_b_v5_sources.py` on Windows: merge the compiled manifests, retaining the base Juliet section. |
| 6 | `build_route_b_v5_panel.py --plan-only`, then `--build` on Windows/MinGW, with the same output directory. |
| 7 | `screen_route_b_v5_sanitizers.py` in WSL: screen the unscreened native build. |
| 8 | `build_route_b_v5_panel.py --finalize` on Windows: apply the screen and caps into a separate panel directory. |
| 9 | `screen_route_b_v5_sanitizers.py` on the v4 panel, then `rescore_route_b_v4_screened.py`, in WSL; report-only sensitivity analysis. |
| 10 | Re-run `regress_route_b_v4_backends.py` in WSL `angr-env`. |
| 11 | `freeze_route_b_v5.py` on Windows: pin the design, amendments, implementation, compiled sources, build, screen, panel and re-run gate. |
| 12 | `label_route_b_v5_development.py --freeze <v5-freeze-dir>` in WSL `angr-env`: refit L using earlier queries only. |
| 13 | `run_route_b_v5_panel.py` in WSL `angr-env`: collect every trial before opening offline references. |
| 14 | `report_route_b_v5.py` in WSL `angr-env`: combine decisions, exclusions, v4 re-scoring and report-only pooled results. |

Only source preparation is network-bound: both project-fetch modes invoke
`git clone`, and the base preparation downloads the official Juliet archive via
`curl`. The remaining steps use retained local inputs. Fetching again pins the
then-current default-branch heads; matching the recorded run requires its pinned
sources and hashes. No fetch is performed by this documentation update.

The v5 freeze and development labeler require the named v4 freeze, selector and
panel bundles below. The re-run regression directory is supplied separately to
`freeze_route_b_v5.py --regression`; the archived v4 gate is not accepted as that
re-run. The full design and dated amendments are linked in the
[Route B index](../benchmarks/selective_analysis/route_b/README.md#pre-registered-series).

| Retained artifact | Names to preserve |
| --- | --- |
| v4 freeze | `route-b-v4-freeze-20261121T073634943739Z/freeze.json` and `source_snapshot/`. |
| v4 selector | `route-b-v4-selector-20261121T074211473909Z`: `development-queries.json`, `runs.json`, `model.json`, `summary.json`. |
| v4 panel and run | `route-b-v4-panel-20261121T073950924Z`: `plan.json`, `panel.json`, `offline-references.json` and fixtures; `route-b-v4-run-20261121T074927114386Z`: `plan.json`, `records.json`, `summary.json`. |
| v5 sources and build | `sources-manifest.fetch.json`, compiled and merged `sources-manifest.json`, DWARF inventories, pinned source files; `plan.json`, `unscreened-panel.json`, `unscreened-references.json` and build fixtures. |
| v5 finalized panel | `route-b-v5-panel-20261122T221742Z`: `panel.json`, `offline-references.json`, `selection.json` and retained fixtures. |
| v5 freeze | `route-b-v5-freeze-20261122T221749467036Z/freeze.json` and `source_snapshot/`; the freeze pins the design, every dated amendment and artifact hashes. |
| v5 selector and run | `route-b-v5-selector-20261122T221820142755Z`: `development-queries.json`, `runs.json`, `model.json`, `summary.json`; `route-b-v5-run-20261122T222921001778Z`: `plan.json`, `records.json`, `summary.json`. |
| Screens and reports | Preserve the screen JSON files and v4 re-score JSON at the supplied output paths, plus `route-b-v5-report-20261122T211650Z/report.json` and `report.md`. |

## Interpretation rules

- Count fixed queries/programs, not variables, readout rows, repetitions or repeated
  diagnostics. The v21/v22.1 panel has three functions in one ELF, not three projects.
- Gold labels are offline. Split future data by program/project before tuning.
- B/C/D keep the same selector and non-type inputs; changing both algorithm and type
  input cannot isolate the information's contribution.
- Exclusions cover only the declared query. Unsupported behavior and incomplete evidence
  retain `unknown`; native replay is absent.
- The v23 collision and cold costs do not establish neural benefit, paired speedup,
  general impossibility or an independent publication contribution.
