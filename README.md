# SymbAI-Taint: Property-Directed Analysis Scheduling

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
![Python 3.13](https://img.shields.io/badge/Python-3.13-blue.svg)
![Status](https://img.shields.io/badge/status-research%20pilot-lightgrey.svg)

Code, experimental protocols and evidence notes for an academic study of which
local program-analysis operations to run under a limited computation budget.

## Overview

Binary program analysis can use several checks to answer the same scoped
property query. Some checks are cheap but incomplete. Others cost more and
may resolve queries that the cheaper checks leave open. SymbAI-Taint asks
whether learned information helps choose and order these checks. It tested
two kinds: neural type predictions and structural features.

The selector ranks operations. Semantic checkers and fresh validation decide
each query. Unsupported behavior, incomplete evidence and expired requests
remain `unknown`, and only the offline evaluator reads the reference labels.

Current state, from a series of pre-registered experiments (type pilots v1-v3,
Route B v4 and v5):
- Neural type predictions added no information beyond a deterministic structural
  baseline.
- A learned structural backend order did not beat a fixed symbolic-then-concrete
  cascade.
- That cascade's remaining headroom against a per-query oracle is small. In v5 it
  came entirely from two projects.
- Neural scheduling benefit was not shown.

![OPM system view of the frozen scheduling pilot](docs/architecture/system.svg)

## Main contributions

1. **Pre-registered evaluation series.** The decision rule of every
   pre-registered experiment is frozen by SHA-256 before its held-out data are
   evaluated, and later runners refuse to start if it changes. v4 and v5 also
   freeze their implementation and artifacts. v5 records each change made
   before the freeze as a dated amendment.
2. **Controlled scheduling protocol.** The same operation catalog and checkers
   support fixed-order, learned-order and oracle comparisons on
   project-disjoint panels. Uncertainty comes from a bootstrap over binary
   groups.
3. **Scoped evidence and cost accounting.** The runner records the query,
   decisions, timeouts and charged time. Reference labels stay sealed until
   every trial is collected.
4. **Sanitizer-screened benchmark construction.** Each extracted kernel's
   native reference also runs under AddressSanitizer and UBSan, with address
   randomization disabled. Kernels whose reference depends on undefined behavior
   are excluded before the freeze.
5. **Audited model integration.** An external adapter repairs DWARF4 location
   ranges in the isolated TYGR runtime. Guards validate native graph inputs and
   export the actual logits of the frozen 75-class checkpoint.

## Key results

| Question | Verified observation | Evidence |
|---|---|---|
| Can a fresh full-relation type model learn from the pinned corpus? (v1, development pilot) | Development Top-1 was 28/25/28 of 52 with messages and 25/25/25 without, against 11/52 for the frequency prior. The models mainly separated 32-bit from 64-bit values, so every `char*` was predicted as `struct*`. | [Training pilot](benchmarks/selective_analysis/route_b/README.md#training-pilot-results), [coverage diagnosis](benchmarks/selective_analysis/route_b/README.md#coverage-and-representation-diagnosis) |
| Does a deeper RGCN add type information on new projects? (v2, pre-registered) | **No R1.** On 200 new development variables, the four-layer RGCN reached 88, 59 and 83 correct across seeds. The deterministic structural baseline reached 121/200 and beat every GNN arm. | [Type pilot v2](benchmarks/selective_analysis/route_b/README.md#type-pilot-v2-results) |
| Does more training coverage help, and do neural scores add to structure? (v3, pre-registered) | **Neither.** With 1,460 training variables in 15 projects, the expanded RGCN reached 247, 251 and 239 of 571 fresh development variables. The structural baseline reached 269. | [Type pilot v3](benchmarks/selective_analysis/route_b/README.md#type-pilot-v3-results) |
| Does a learned structural backend order beat the fixed orders? (v4, pre-registered) | **Not supported.** On 62 held-out queries in 17 binary groups, the symbolic-first cascade verified 120 of 124 trials in 35.1 s, and the learned order 110 in 60.9 s. The cascade matched the oracle on verified decisions. One ill-defined kernel (an out-of-buffer read) caused wrong decisions in both symbolic-first arms. | [Structural selection](benchmarks/selective_analysis/route_b/README.md#route-b-v4-structural-selection-results) |
| Is the cascade equivalent to the oracle, and is the learned order non-superior? (v5, pre-registered) | 169 sanitizer-screened queries in 41 binary groups, with no wrong decisions. **Q2 supported:** the learned order verified 326 of 338 trials in 113.7 s, against 332 in 97.0 s for the cascade, and was measurably slower. **Q1 not supported:** the oracle added no verified decisions. Its time headroom was 0.030 s per trial, with a 90% interval of [0.000, 0.067] s, so the upper bound exceeds the 0.05 s margin. All of it came from jsonsl and zopfli. | [Cascade headroom](benchmarks/selective_analysis/route_b/README.md#route-b-v5-cascade-headroom-results) |
| Were earlier panels affected by undefined behavior? | The v5 sanitizer screen excluded 20 of 187 built kernels. On the v4 panel it excluded only `sds-sdsAllocSize-L300`, the query behind every v4 wrong decision. Without that kernel, v4 has no wrong decisions and its decision is unchanged. | [Cascade headroom](benchmarks/selective_analysis/route_b/README.md#route-b-v5-cascade-headroom-results) |
| Did neural type information improve the first Route B scheduling pilot? | All six programs had usable predictions. At the primary budget, B resolved 16/24 trials, Top-1 resolved 14/24, unscored Top-K resolved 12/24, and scored Top-K resolved 13/24. The pilot's advancement criterion was unmet. | [Route B results](benchmarks/selective_analysis/route_b/README.md#wsl-results) |
| Does the frozen checkpoint support native inputs? | Seven of twelve functions have verified genuine entry predictions. Five were refused before inference for unsupported relation IDs. utf8proc and LZ4 have identical full entry logits, and their encoded input graphs are identical up to a node renumbering that preserves features, relations and readout. | [Native information assessment](benchmarks/selective_analysis/route_b/README.md#local-information-assessment) |
| Did a model-free deadline policy transfer to new projects? | On six newly selected source kernels from six disjoint projects, both methods verified 20/24 trials. The 100 ms policy added a paired median of 3.429 s per batch, so its coverage and cost transfer criteria failed. | [Disjoint-project test](benchmarks/selective_analysis/route_b/README.md#frozen-cutoff-test-on-six-new-projects) |

The research questions are answered negatively at the tested scale:
- **RQ1** asked whether neural information improves the same scheduler under an
  equal budget. The type pilots found no incremental type information, and the
  v4 and v5 backend-order tests found no learned-order gain.
- **RQ2** asked whether the candidate set and its scores add value beyond Top-1.
  It was not supported in the first Route B pilot and was not pursued further.

The earlier development observations remain in the chronological
[Route B README](benchmarks/selective_analysis/route_b/README.md) and the
[status record](docs/STATUS.md). They cover acquisition audits, deadline and
progress engineering, native input preparation, read-hook and relation-capacity
audits, and the type corpus, mapping and graph export.

## Installation

For the model-free pilot, use a Python environment with the
[minimal requirements](benchmarks/selective_analysis/requirements.txt).
The documented Windows stack uses Python 3.13.10 and angr 9.2.217. The Route B
v4 and v5 runs use an `angr-env` interpreter in WSL Ubuntu. They also need MinGW
gcc on Windows for the native fixtures, and gcc 9 with libasan and `setarch` in
WSL for the sanitizer screen. Native GlowGNN acquisition uses the original TYGR
stack in an isolated WSL environment. See
[runtime compatibility](docs/VERSION_COMPAT.md).

```bash
python -m pip install -r benchmarks/selective_analysis/requirements.txt
```

## Data

| Panel | Where to find it | Purpose |
|---|---|---|
| Twelve generated ELF mechanisms | `benchmarks/selective_analysis/mechanisms.py` | Development fixtures for the original A–D runner. |
| Compiled integration and typed readiness | `benchmarks/selective_analysis/compiled_queries/`, `typed_complementarity/` | Workload-specific mapping, acquisition and operation checks. |
| Route B pilot | `benchmarks/selective_analysis/route_b/` | Six new authored programs and twelve fixed queries, grouped by program. |
| Type corpora v1-v3 | Built by `scripts/prepare_type_corpus_v3.py` and its predecessors | Pinned open-source projects with project-level train and development splits for the type pilots. |
| Route B v4 panel | Built by `scripts/build_route_b_v4_panel.py` | 62 held-out queries in 17 binary groups: Juliet CWE129 cases and kernels from the pinned corpora. |
| Route B v5 panel | Built by `scripts/prepare_route_b_v5_sources.py` through `scripts/build_route_b_v5_panel.py` | 169 sanitizer-screened queries in 41 binary groups. They are kernels from 38 new open-source projects pinned at fetched commits, plus Juliet 1.3 CWE124 cases. |

The repository contains source fixtures, pre-registrations, scripts and offline
reference labels for the authored panels. Generated corpora, panels, freezes and
run records stay under the parent directory's `.scratch/selective_analysis/`,
and the Route B README names each one. Obtain the pinned TYGR checkpoint,
upstream sources and the Juliet archive separately. Historical raw receipts stay
in local storage, with their identities recorded in the
[evidence log](docs/pilot_evidence.md). The utf8.h and b64 evaluation projects
are sealed and were never opened. The [reproducibility guide](docs/REPRODUCIBILITY.md)
describes what can run from a clean checkout.

## Reproducing the experiments

Use the repository root as the working directory. The development workspace
keeps generated files under the parent directory's `.scratch/selective_analysis/`.

| Check | Command | Runtime |
|---|---|---|
| Route B source reference | `python -B scripts/run_route_b_pilot.py --reference-only` | Windows or WSL, GCC |
| Route B grouped information comparison | `python -B scripts/run_route_b_pilot.py` | WSL `angr-env` plus original CPU `tygr-orig` |
| Original model-free pilot | `python -B scripts/run_selective_pilot.py --make-mechanisms --variants A B --budgets 1` | Python with angr |
| OPM contracts and rendering | `python -B scripts/validate_architecture.py --render` | Python and Graphviz |
| Route B v4 test | Six ordered steps, from `scripts/regress_route_b_v4_backends.py` to `scripts/run_route_b_v4_panel.py` | Windows MinGW and WSL `angr-env` |
| Route B v5 test | Sixteen ordered steps, from `scripts/prepare_route_b_v5_sources.py` to `scripts/report_route_b_v5.py` | Windows MinGW and WSL `angr-env`; source fetching needs network access |
| Offline v4/v5 tests | `python -B -m pytest -q tests/test_route_b_v5_*.py tests/test_route_b_v4_*.py tests/test_structural_features.py` | Python, no angr |

The [reproducibility guide](docs/REPRODUCIBILITY.md#route-b-v4-and-v5-pipelines)
lists the v4 and v5 steps with their exact arguments and frozen artifacts. See the
[Route B protocol](benchmarks/selective_analysis/route_b/README.md#pre-registered-series)
for the pre-registrations and amendments, and the
[pilot guide](benchmarks/selective_analysis/README.md) for the original runner and
its offline evaluation command.

## Verification

- **Source reference.** The Route B runners check the full declared input range
  with independently compiled reference executables, before any analysis result
  is read.
- **Decision checks.** Decisive analysis results require fresh validation within
  the query scope. Type input and learned features affect priorities only.
- **Frozen protocols.** Each pre-registered run checks the SHA-256 pin of its
  design. v4 and v5 also check their implementation and artifacts, and v5 also
  checks its amendments. v5 requires the v4 backends to be byte-identical to the
  v4 freeze, and requires the v4 regression gate to pass again.
- **Native sanitizer screen.** v5 kernels whose reference shows undefined
  behavior, or disagrees between compilers, are excluded before the freeze.
- **Artifact checks.** The guarded model path preserves source and model hashes,
  location traces and logits. The local v23 synchronization passed 1,285 tests
  and validated 22 OPM views. The offline v4 and v5 suites pass 176 tests. See
  the [verification record](docs/VERIFICATION.md).

## Limitations

The findings hold at the tested scale:
- The type pilots used 200 (v2) and 571 (v3) development variables from two and
  three projects.
- The backend panels have 62 queries in 17 groups (v4) and 169 queries in 41
  groups (v5).
- v4 and v5 cover two backends, a 3 s budget per query and a finite domain of 256
  inputs per write-bound query.
- Their kernels are x86-64 freestanding fixtures built with MinGW.
- One selector model family was tested: structural logistic and ridge regression
  with an expected-time order rule.

v5 did not establish that the cascade is equivalent to the oracle within the
time margin. The type interface relies on DWARF locations, and scores are
uncalibrated. These results do not establish a general limit for other backend
catalogs, model families or query domains.

## Repository structure

```text
src/selective_analysis/            Query contracts, checkers, backends, selectors and evidence
benchmarks/selective_analysis/     Developer fixtures and run guides
  route_b/                         Pre-registrations, amendments, program groups and results
scripts/                           Experiment, panel-building and validation entry points
docs/architecture/                 OPM DOT sources, SVGs and frozen specifications
docs/pilot_evidence.md             Chronological evidence and receipt identities
tests/                             Contract, analysis and reproduction checks
```

The [documentation map](docs/README.md) links the current guides and earlier
experiments on the separate legacy pipeline.

## Citation

Cite the [SymbAI-Taint repository](https://github.com/witold-andelie/SymbAI-Taint)
and the specific commit or experiment protocol used.

## License

Project source is distributed under the [Apache License 2.0](LICENSE).
