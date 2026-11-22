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
whether pretrained neural type predictions help choose the next check.

The selector ranks operations using structural information and, when assigned
to a neural arm, types from a frozen TYGR/GlowGNN checkpoint. The checker uses
program semantics and explicit query assumptions, and fresh validation checks
decisive evidence. The offline evaluator reads the reference labels.

![OPM system view of the frozen scheduling pilot](docs/architecture/system.svg)

## Main contributions

1. **Controlled scheduling protocol.** The same selector, policy parameters,
   operation catalog and checkers support type-blind, Top-1 and scored Top-K
   comparisons. The fixed-order arm provides a separate baseline.
2. **Scoped evidence and cost accounting.** The runner records the query,
   decisions, timeouts and separate acquisition and analysis costs.
3. **Audited model integration.** An external adapter repairs DWARF4 location
   ranges in the isolated TYGR runtime. Guards validate native graph inputs and
   export the actual logits of the frozen 75-class checkpoint.
4. **Route B evaluation.** A new panel of six authored programs compares
   precomputed Top-1, an unscored Top-K set and scored Top-K with the same
   type-blind selector. Its decision rule comes before any gated acquisition work.

## Key results

| Question | Verified observation | Evidence |
|---|---|---|
| Can the model run on the compiled development panel? | v22.1 obtained output for 3/3 functions in one ELF, with seven variable records and three guarded forwards. | [Acquisition audit](docs/pilot_evidence.md#v221-successful-wsl-repair-audit) |
| Can those predictions distinguish the table-query pair? | Both queries yielded identical actual model inputs and all 75-class output rows despite different analysis-operation outcomes. | [v23 comparison](docs/pilot_evidence.md#v23-retained-type-information-collision-audit) |
| How costly is acquisition? | Cold acquisition took 8.305 s. A historical fixed cascade recorded 2.162 s for its three-query total in a separate run. | [Cost interpretation](docs/STATUS.md#current-checkpoint) |
| Did neural type information improve Route B scheduling? | All six programs had usable predictions. At the primary budget, B resolved 16/24 trials, Top-1 resolved 14/24, unscored Top-K resolved 12/24, and scored Top-K resolved 13/24. The pilot's advancement criterion was unmet. | [Route B results](benchmarks/selective_analysis/route_b/README.md#wsl-results) |
| Can a stronger model-free baseline improve completion? | Cache-preserving deadline checks verified 24/24 trials on six known queries repeated four times, compared with 20/24 for the original cascade. The paired median batch saving was 1.468 s. Independent generalization and neural benefit remain open. | [Cache-preserving checks](benchmarks/selective_analysis/route_b/README.md#cache-preserving-deadline-checks) |
| Did the frozen 100 ms policy transfer to new projects? | On six newly selected source kernels from six disjoint projects, both methods verified 20/24 trials. The 100 ms policy added a paired median 3.429 s per batch, so its coverage and cost transfer criteria failed. | [Disjoint-project test](benchmarks/selective_analysis/route_b/README.md#frozen-cutoff-test-on-six-new-projects) |
| Can live progress be observed cheaply? | All 15 counter-mode runs still active at 100 ms had received counters. Median paired added query time was 0.764 ms, with an 82.874 ms maximum. Identical phase/counter views had different 500 ms continuation outcomes. | [Progress observation](benchmarks/selective_analysis/route_b/README.md#prospective-progress-observation) |
| Do continuation and switching have different useful regimes? | From 24 resident shared prefixes, continuation was cheaper in 16 pairs, switching was the only validated action in six, and two remained unresolved. Thirteen continuation preferences already had candidate evidence awaiting validation. | [Shared-checkpoint actions](benchmarks/selective_analysis/route_b/README.md#actions-from-a-shared-resident-checkpoint) |
| How strong is a phase-only rule? | Retrospective replay of continuing candidate validation and otherwise switching preserved 22/24 results while reducing aggregate charged work from 39.409 to 26.337 s. The remaining observed oracle opportunity was 5.938 s across three prefixes. | [Phase-rule replay](benchmarks/selective_analysis/route_b/README.md#phase-only-baseline-replay) |
| Did the phase rule beat the original cascade in live execution? | With all startup and cleanup charged, the phase rule verified 19/24 queries, versus 12/24 for always-switch and 20/24 for the original cascade. It lost one cascade success and added 1.148 s at the paired batch median. | [Live phase-rule comparison](benchmarks/selective_analysis/route_b/README.md#live-phase-rule-with-charged-cleanup) |
| What must be checked before another neural trial? | The four live arms' successful-query union equals the cascade's 20/24. Its four successful fallbacks spent 2.443 s in unsuccessful symbolic stages. All twelve timing ELFs lack section tables required by the current DWARF-assisted adapter. Matched neural inputs and acquisition costs remain to be established. | [Feasibility audit](benchmarks/selective_analysis/route_b/README.md#strong-baseline-headroom-and-neural-input-eligibility) |
| Are native inputs now available? | Twelve native debug/stripped pairs passed code/data identity, 3,072 native output checks, and twelve entry-argument bindings. | [Native input preparation](benchmarks/selective_analysis/route_b/README.md#native-debugstripped-input-preparation) |
| Does the frozen checkpoint support the new inputs? | Seven of twelve functions have verified genuine entry predictions; five were refused before inference for unsupported relation IDs. utf8proc and LZ4 have identical full entry logits; their encoded input graphs are identical up to a feature-, relation- and readout-preserving node renumbering. | [Native information assessment](benchmarks/selective_analysis/route_b/README.md#local-information-assessment) |
| What does the matched native baseline show? | The cascade resolved 30/36 trials on twelve known functions, with no wrong decisions. stb ilog and bzip2 remained unknown. Most of miniz and XZ's 2.1 s request time was worker restart after preceding timeouts. | [Native baseline costs](benchmarks/selective_analysis/route_b/README.md#official-native-baseline-results) |
| Did direct concrete execution improve the native batches? | No: the paired cascade resolved 30/36, direct concrete execution 11/36, with zero direct gains and nineteen losses. The cascade was faster in all six batch pairs by a paired median 6.833 s. Most direct losses followed worker replacement or remaining-budget exhaustion, so local action value remains a separate question. | [Native control results](benchmarks/selective_analysis/route_b/README.md#official-native-control-results) |

The project's main research questions remain open. **RQ1** asks whether neural
information improves the same scheduler under an equal end-to-end budget.
**RQ2** asks whether the candidate set and its scores add value beyond Top-1.

The [local action-value matrix](benchmarks/selective_analysis/route_b/README.md#official-local-action-results)
resolved 30/36 cascade actions and 27/36 direct concrete actions. Direct
execution was consistently faster on utf8proc and Brotli, without adding
completions. The [information assessment](benchmarks/selective_analysis/route_b/README.md#local-information-assessment)
found opposite local choices for utf8proc and LZ4 despite equivalent encoded
neural inputs. The [no-forward stage audit](benchmarks/selective_analysis/route_b/README.md#confirmed-graph-stage-observations)
found distinct 25-node and 297-node graphs reduced to three-node variable views,
and confirmed read-hook field names unregistered by the original runtime.
The [three-arm no-forward comparison](benchmarks/selective_analysis/route_b/README.md#confirmed-read-hook-intervention-results)
found that field routing alone preserved both three-node views. Adding AFTER
read-event timing restored diagnostic parameter dependencies, retaining 17 and
221 nodes. The restored LZ4 input was refused for relation IDs 50 and 55, outside
the checkpoint's 44 slots. The [installed-operator audit](benchmarks/selective_analysis/route_b/README.md#confirmed-installed-operator-behavior)
found that out-of-capacity relation IDs silently contribute no messages in the
examined RGCN path. This explains why a successful forward would not establish
input compatibility. The [alternative x64 base weight audit](benchmarks/selective_analysis/route_b/README.md#alternative-x64-base-checkpoint-audit)
found the same 44-slot limitation in O1, O2 and O3; none passed the complete
relation-domain requirement. A [six-project data-readiness panel](benchmarks/selective_analysis/route_b/README.md#independent-type-corpus-readiness)
is pinned with project-level train/development/evaluation splits. Its initial
inventory completed 10/12 profiles; a missing b64 translation unit is corrected
in the [v2 recipe](benchmarks/selective_analysis/route_b/README.md#type-corpus-v2-link-recipe-correction).
The [completed inventory](benchmarks/selective_analysis/route_b/README.md#completed-v2-type-inventory)
verified all 12 profiles, with 90 O0 functions and 391 source-variable records.
Training covers 11 observed classes; graph/readout admission remains pending.
The [four-function mapping audit](benchmarks/selective_analysis/route_b/README.md#confirmed-four-function-mapping-results)
confirmed recorded location/readout correspondence for all eight selected
CFA-slot variables, with no model loaded. The [bulk graph exporter](benchmarks/selective_analysis/route_b/README.md#bulk-traindevelopment-graph-export)
is prepared for all 43 train/development functions and 190 candidate variables.
The completed export admits 41/43 functions and 181/190 source variables,
with 129 training variables and 52 development variables. A separate passive
review rechecked 317 artifact hashes. The [minimal training pilot](benchmarks/selective_analysis/route_b/README.md#minimal-full-relation-training-pilot)
trains a fresh 60-relation RGCN and an identical architecture with messages
disabled, with three fixed seeds and source-variable evaluation. It completed in
WSL: development Top-1 was 28/25/28 of 52 with messages and 25/25/25 without,
against 11/52 for the frequency prior. A [coverage diagnosis](benchmarks/selective_analysis/route_b/README.md#coverage-and-representation-diagnosis)
shows that the models mainly separate 32-bit from 64-bit values, so every
`char*` is predicted as `struct*`. A [pre-registered v2 run](benchmarks/selective_analysis/route_b/README.md#type-pilot-v2-results)
on two new development projects (200 variables) found no reliable gain from a
deeper RGCN, and a deterministic structural baseline (121/200) beat every GNN arm. A
[pre-registered v3 expansion](benchmarks/selective_analysis/route_b/README.md#type-pilot-v3-results)
to 1,460 training variables did not change that: on 571 fresh development variables the
decision was negative for neural type information at this scale. A pre-registered
[v4 test](benchmarks/selective_analysis/route_b/README.md#route-b-v4-structural-selection-results)
found that a learned structural backend order did not beat the fixed symbolic-first cascade, which
matched the oracle on verified decisions over 62 held-out queries.
A pre-registered, sanitizer-screened
[v5 test](benchmarks/selective_analysis/route_b/README.md#route-b-v5-cascade-headroom-results) on
169 new queries (41 groups) confirmed that the learned order is not better than the cascade. The
cascade's remaining time headroom (0.030 s per trial) could not be bounded below the 0.05 s margin.
Neural scheduling benefit remains unmeasured and Variant E is deferred.

## Installation

For the model-free pilot, use a Python environment with the
[minimal requirements](benchmarks/selective_analysis/requirements.txt).
The documented Windows stack uses Python 3.13.10 and angr 9.2.217. Native
GlowGNN acquisition uses the original TYGR stack in an isolated WSL environment.
The Route B pilot runs on CPU. See [runtime compatibility](docs/VERSION_COMPAT.md).

```bash
python -m pip install -r benchmarks/selective_analysis/requirements.txt
```

## Data

| Panel | Where to find it | Purpose |
|---|---|---|
| Twelve generated ELF mechanisms | `benchmarks/selective_analysis/mechanisms.py` | Development fixtures for the original A–D runner. |
| Compiled integration and typed readiness | `benchmarks/selective_analysis/compiled_queries/`, `typed_complementarity/` | Workload-specific mapping, acquisition and operation checks. |
| Route B pilot | `benchmarks/selective_analysis/route_b/` | Six new authored programs and twelve fixed queries, grouped by program. |

The repository contains source fixtures and offline reference labels. Obtain
the pinned TYGR checkpoint and upstream source separately. Historical raw
receipts stay in local storage, with their identities recorded in the
[evidence log](docs/pilot_evidence.md). The [reproducibility guide](docs/REPRODUCIBILITY.md)
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

See the [Route B protocol](benchmarks/selective_analysis/route_b/README.md) for the
decision rule and the [pilot guide](benchmarks/selective_analysis/README.md) for
the original runner and its offline evaluation command.

## Verification

- **Source reference.** The Route B runner checks the full declared input range
  with independently compiled reference executables before collecting type data.
- **Decision checks.** Decisive analysis results require fresh validation within
  the query scope. Type input affects priorities only.
- **Artifact checks.** The guarded model path preserves source/model hashes,
  location traces and logits. The local v23 synchronization passed 1,285 tests
  and validated 22 OPM views. See the [verification record](docs/VERIFICATION.md).

## Limitations

The verified neural results so far are development observations. Route B uses six
separately compiled authored programs with a shared harness, and its two queries
per program share a neural record. The type interface relies on DWARF locations.
Scores are uncalibrated. Each decision covers a declared first-visit write query
under modeled assumptions. The project has yet to demonstrate neural scheduling
benefit or generalization to independent real projects.

## Repository structure

```text
src/selective_analysis/            Query contracts, checkers, selectors and evidence
benchmarks/selective_analysis/     Developer fixtures and run guides
  route_b/                         New program groups and offline reference labels
scripts/                           Experiment and validation entry points
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
