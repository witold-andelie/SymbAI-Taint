# Pilot v1: local development evidence

> **Artifact availability:** this is an index of locally retained development receipts.
> Paths and hashes identify observations; they do not imply that raw `.scratch` bundles,
> upstream source or model weights are included in Git. See [reproducibility](REPRODUCIBILITY.md)
> for clean-checkout commands and the separate requirements of historical replay.
> [Current status](STATUS.md) distinguishes completed gates from older pending work.

Entries retain their original chronology. The latest native collection is
[the successful v22.1 repair](#v221-successful-wsl-repair-audit), audited on
13 November 2026. The completed [v23 representation audit](#v23-retained-type-information-collision-audit)
uses those retained artifacts only, with no new inference or property execution. The earlier
[real GNN end-to-end run](#first-real-end-to-end-run) remains unchanged.

Recorded on 10 November 2026. This is a mechanism and execution-boundary check for the
[partial pilot](../benchmarks/selective_analysis/README.md), not an independent benchmark
or evidence of neural scheduling benefit. All 12 cases are developer fixtures with explicit
object bounds and a first-dynamic-visit scope. No real GNN predictions were supplied.

## Checks

- All 25 new checks in `tests/test_selective_analysis.py` passed, including checks over the
  actual ELF instructions, fresh modeled witness validation, reaching definitions, missing
  type handling, type-view isolation, hard timeouts and offline denominator preservation.
- The full `tests` directory passed 28 checks (19 dependency deprecation warnings). Its
  three historical structure tests are smoke checks and do not establish legacy correctness.
- After adding artifact/model identity fields to the ledger, all 25 new checks passed again.
- The architecture validator accepted the frozen A-D contract, 3 DOT views, 48 view-local
  nodes, 74 OPM links, matching interfaces and separated label/type routing. SVGs were
  regenerated from DOT. This is not a certification of program-analysis soundness.

## Information-only run

The complete run contains 144 records: 12 fixed queries, four variants and three budgets.
The table reports resolved queries whose outcomes match the developer labels. All observed
decisive outcomes matched those labels; unresolved and unavailable queries remain included.

| Charged budget per query | A resolved / 12 | B resolved / 12 | C / D |
|---|---|---|---|
| 0.1 seconds | 0 | 0 | Each 12 unavailable, `unknown` |
| 0.3 seconds | 11 | 12 | Each 12 unavailable, `unknown` |
| 1.0 seconds | 12 | 12 | Each 12 unavailable, `unknown` |

For A at 0.3 seconds, `m07` produced a candidate result but process finalization took the
charged time to 0.31364 seconds. The final result correctly remained `unknown`. This single
timing difference is not statistical evidence for B's superiority. Fixed ordering and
environment noise must be controlled before interpreting scheduling gains.

Preparation is outside the charged information-only interval, while actual cold wall time
is still recorded. These sub-second budgets therefore cannot be interpreted as total
deployment latency. The prototype does not treat precomputed GNN information as free in an
end-to-end experiment.

## End-to-end run

The complete run contains 48 records: the same 12 queries, four variants and a 5-second
per-query cold-process budget.

| Variant | Resolved | Unknown | Wrong decisive outcomes | Total cold wall time, 12 queries |
|---|---|---|---|---|
| A | 12 | 0 | 0 | 22.596 s |
| B | 12 | 0 | 0 | 22.030 s |
| C | 0 | 12 | 0 | 1.209 s, unavailable |
| D | 0 | 12 | 0 | 1.180 s, unavailable |

Each available A/B arm reported eight modeled violations and four complete exclusions
within the declared scope. Witnesses were checked by fresh modeled reexecution; no native
replay was performed. C/D fail before analysis because online inference is not configured.
Their shorter failure time is **not an efficiency result** and their zero error count is
**not accuracy evidence**.

## Local artifacts

Raw records and binaries remain outside Git under `D:/AI_Models/symbolic/.scratch/`.
The following hashes identify these particular measured runs; later reruns should use a
fresh directory and will have different timings and record hashes.

| Artifact relative to `.scratch/selective_analysis/` | SHA-256 |
|---|---|
| `pilot-v1-information/runs.json` | `f2d410f7d911414b7e4865e717375a8ddccafb1b2d5d4cc83a06a3d527c906b6` |
| `pilot-v1-end-to-end/runs.json` | `5f317a2fd603d9349758fcfb840f03f0d604ff58ea3375eabb3f4ab2b3b1035a` |
| `mechanisms/gold.json` | `6d6c619f36abefb8d14d24a2bb431b71aa7de8aa697a0691aef1942c974dfd21` |

Each run directory also contains `evaluation.json`, per-query requests, result files,
flushed `events.jsonl` and worker logs. The two measured runs preceded the addition of
runtime-version and consumed-type-artifact hash fields; current runs include those fields.
The selector, operations, solver and budget rules used for the reported outcomes are unchanged.

## Next evidence required

User-run WSL inspection located the existing `angr-env` and `tygr-orig` environments.
The subsequent `tygr-location-20261110-235725-961.json` report found no TYGR modules,
entry points, source roots or matching models in its declared search roots, with no errors
and `search_incomplete=false`. This is a scoped location result, not a claim about every
directory on the machine. No download or model loading occurred during those inspections.

Validate the exporter against an actual compatible TYGR model, review location-to-use-site
correspondences and obtain genuine C/D information-only records. Then implement charged
online inference for C/D end-to-end trials. Any empirical claim about RQ1/RQ2 additionally
requires independent cases, repeated balanced runs and the planned strong controls.

## WSL acquisition failure and correction, 11 November

The user-run preparation failed before repository access. The captured
`.scratch/wsl/pilot-20261111-000040-986/tygr-fetch.log` reports
`Host key verification failed.` Git's exit code 128 alone did not identify the cause.
The noninteractive SSH command supplied no task-specific trusted host file.

The driver now validates a pinned public key against GitHub's independently published
Ed25519 fingerprint and writes a per-run `ssh/known_hosts` and provenance record on D:.
It retains strict host checking and does not modify global SSH configuration. The key and
fingerprint were checked against [GitHub's official documentation](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints)
on 11 November. Account authentication is still a separate stage.

A regression at the `fetch_tygr` subprocess boundary failed on the original host-trust
configuration, then passed after the fix. Another regression rejects a changed fingerprint
before writing the trust file. All 27 selective-analysis checks passed. The tests replay
the local failure boundary and validate the actual generated public-key file; they do not
connect to GitHub. The original WSL connection could not be rerun by the agent because
its WSL execution channel still returns access denied. Successful acquisition and real
model loading remain unconfirmed until a user-run retry supplies those records.

## SSH acquisition completed via the existing Windows identity

The next user-run WSL attempt, `pilot-20261111-000633-991/tygr-fetch.log`, passed host
verification but failed account authentication with `Permission denied (publickey)`.
This is a separate failure stage. No Conda package or model code had run at that point.

A direct Windows OpenSSH check using the existing Windows identity and the same pinned
host trust successfully authenticated as `witold-andelie`. Git's read-only SSH check then
returned the expected upstream commit. A native Windows SSH wrapper under `.scratch/wsl/`
was used to complete the sparse clone. No private key was copied into the workspace.

Acquisition is now complete at the pinned commit
`280320129a7f8bbfb9ee61b9a2155d2ddeac44c6`. The official model's 6,053,463 bytes match Git blob
`d3a44c657e672ffc6d08a6b45bb343c91355eb37` and SHA-256
`f592caaa6c685f291f576b16fbf8b752a95e7cb757ea620751830563b77f67c8`.
All 149 checked-out files were verified against upstream blobs; 66 text files were
normalized from Windows checkout line endings to LF. The model bytes were not changed.
The checkout remains Git-ignored. Acquisition metadata is in
`.scratch/wsl/windows-tygr-acquisition.json`.

A non-executing inspection of the model's pickle opcode stream found the saved
`decoder_type=independent` and `flatten_vars=true`, consistent with the planned exporter.
This was archive parsing only, not a PyTorch model load or inference. WSL model loading
and genuine C/D prediction/mapping results remain pending. The existing preparation
command now reuses the acquired local checkout and does not need a new SSH clone.

## Real model loading confirmed

The user-run preparation at `.scratch/wsl/pilot-20261111-001329-996/` successfully loaded
GlowGNN in Python 3.8.10, torch 1.8.1 CPU, PyG 1.7.0 and angr 9.0.7491. Its inspection
reported 75 unique display labels, `decoder_type=independent`, `flatten_vars=true`,
the expected SHA-256 and a `(x)` forward signature. `inference_performed=false` explicitly
separates this load check from prediction evidence.

Before the first inference run, source inspection found that upstream `predict_phase=True`
constructs an incomplete variable/type pair and its serial generator drops all variables
when zipping those lists. The exporter now uses the upstream DWARF locator mode, discards
its companion type output and supplies `None` for decoder labels. It retains the original
value-node ordering beside raw logit rows. The vendor checkout was not patched.

All 29 focused checks passed after adding unlabeled-forward contract checks. A one-case
compiled integration driver is prepared to produce genuine logits, symbol addresses and
disassembly on D:. This step reuses the direct-index mechanism and does not extend the
formal evaluation denominator. Actual predictions and reviewed mappings remain pending.

## First real neural information-only integration

This section records development revision v1. Revision v2 is reported separately below;
the original raw records are preserved.

The first real-data A-D integration is complete. On this single compiled function query,
C/D changed operation selection but resolved no additional query over the identical
selector with types hidden (B). This is an integration result, not an RQ1/RQ2 answer.

| Information budget | A | B | C | D |
|---|---|---|---|---|
| 0.1 s | unknown | unknown | unknown | unknown |
| 0.3 s | unknown | modeled violation | modeled violation | modeled violation |
| 1.0 s | modeled violation | modeled violation | modeled violation | modeled violation |

All 12 query/variant/budget records were retained. All variants were available; C/D
consumed genuine model output. No decisive outcome disagreed with the explicitly scoped
source-derived label. A at 0.3 s exceeded the finalization-inclusive budget (0.32253 s)
and was retained as unknown. These are fixed-order, single-run measurements, not a
statistical comparison. Windows Python 3.13/angr 9.2.217 performed the symbolic runs;
precomputed GNN output came from WSL's version-faithful TYGR environment.

### Inference and location evidence

The user-run `.scratch/wsl/inference-20261111-002014-1018/` probe produced two records
with genuine 75-class logits. Its reported export interval was **5.727797 seconds**,
including model loading, graph extraction and forwarding but excluding compilation and
subsequent mapping/reanalysis. That interval is outside the information-only budget;
it is not a complete end-to-end measurement and cannot be treated as free deployment work.

The ELF content hash is
`0fb55db6be585f4c71134f6a9483828292f5a73f529420bc21a753a62a7c81a5`.
The query enters `probe_write` at RVA `0x1129` with unsigned RDI in `[0,15]`, checks the
first visit to byte store `0x114b`, and uses the 8-byte `probe_buffer` at RVA `0x4018`.
The program's `main` calls the function with zero; the query deliberately concerns the
stated function-entry range, not reachability of bad input from that fixed `main`.

The mapping review checked the assembly and three relations at the target instruction:

1. DWARF pointer location `CFA-24` is `[rbp-8]` and holds the declared object base.
2. DWARF index location `CFA-40` is `[rbp-24]` and holds the entry RDI value.
3. The write's RAX is the sum of those two values.

Each relation was checked by UNSAT of its negation in a fresh symbolic entry state,
without neural constraints. Local reaching definitions also produced 81 definitions and
79 dependency edges. A separate fresh modeled reexecution checked the violating input
RDI=8, whose one-byte destination is one past the object. Native replay was not attempted.

`mapping-review/reviewed_mapping.json` projects prediction `1129:1` only as the **base-pointer
contributor** at the address site. This is a post-inference integration review, not a
pre-registered general mapping algorithm. The index prediction `1129:0` remains in the
original export and is explicitly listed as unprojected because the current interface
accepts one type view per query. The mapping does not cover the entire address operand set.

The index's exported Top-3 (`char*`, `struct*`, `void*`) disagree with its source declaration
and contain no integer candidate. This is an observed mismatch in the pipeline, not a
measured general type error rate. Whether it originates in model prediction, upstream
graph features or node association requires further auditing. No candidate was used as
a symbolic fact or to prune a path.

### What the selector actually did

At the 1-second budget, the logged actions and charged times were:

| Variant | Action order | Charged time |
|---|---|---|
| A | definitions, bounded paths, expanded paths | 0.30518 s |
| B | expanded paths | 0.21702 s |
| C | definitions, expanded paths | 0.27988 s |
| D | definitions, expanded paths | 0.28494 s |

The projected base-pointer candidates are `char*`, `struct*`, `void**`. All three collapse
to the same pointer-role feature in the current selector, so C and D receive effectively
identical task features despite different raw candidate scores. This case cannot isolate
the potential value of candidate distributions. The neural term changes B's first choice
to a dependency observation, which provides no decisive evidence in this prototype.
That observation is an operation-design limitation: dependency facts are recorded but
not yet consumed to improve a later check. The scheduler and operation weights were not
retuned after seeing this result.

Further work should make operation evidence usable and audit the feature projection
before claiming neural benefit or expanding examples. Online, charged C/D inference is
still missing. Neither the information-only result nor the separate 5.728-second export
can substitute for the frozen end-to-end comparison.

### Reproduction artifacts

All raw files remain on D: under the inference directory above:

- `summary.json`, `raw-types.json`, `symbols.log`, `disassembly.log`, `inference.log`.
- `mapping-review/audit.json`, `queries.json`, `reviewed_mapping.json`, `mapped-types.json`.
- `mapped-integration-v1/runs.json`, `evaluation.json`, `action-summary.json`, per-run ledgers.

The captured review script is `.scratch/wsl/review_inference_probe.py`. It is a one-case
audit harness, not part of the general runtime. The 12 original developer mechanisms'
formal denominator was not expanded by this integration check.

## Development v2: measured reuse and retained candidates

Dependency preparation now supplies exact execution snapshots to later operations rather
than only logging a graph. The same compiled query demonstrates actual reuse, preserved
precision and fresh validation. Candidate labels and scores also survive the selector's
projection. The [v2 implementation and measurement plan](architecture/pilot_revision_v2.md)
was written before running the new A-D comparison.

### Reuse without changing the checked scope

The 42-definition backward slice produced a plan for all nine instructions before the
target. Every instruction was executed while building snapshots. Both later checks then
reused paid states; neither omitted an instruction using a slice-based irrelevance claim.

| Sequence on the same query | Build prefix | 8-step check | 128-step check | Fresh validation | Total executed prefix steps |
|---|---|---|---|---|---|
| Fresh checks | 0 | 8 | 9 | 9 | 26 |
| Prepared exact prefix | 9 | 0 (8 reused) | 0 (9 reused) | 9 | 18 |

The 8-step query remained unknown, and the 128-step query still produced RDI=8. Validation
reused zero steps. These are instruction-prefix counters, not complete analysis work:
they omit RDA traversal, solving, state-copy work and the target-write observation itself.
All those operations still pay actual wall time in the runner. In the paired diagnostic,
RDA plus prefix preparation took 89.3 ms, while the two fresh path checks together took
66.0 ms. Thus fewer replayed steps alone do not establish a net time saving, especially
when a strategy would otherwise skip dependency preparation.

### Candidate information reaches the shared score

C exposes only `char*`; its entropy, score margin and disagreement are explicitly missing.
D retains the genuine labels and conditional weights:

| Label | Retained-set weight | Raw logit |
|---|---|---|
| `char*` | 0.912364 | 3.072667 |
| `struct*` | 0.067062 | 0.462240 |
| `void**` | 0.020575 | -0.719316 |

Its conditional entropy is 0.344794 nats, score margin 2.610427 and candidate disagreement
0.162672. These are properties of the retained Top-3 set, not correctness probabilities.
The common definitions score is now 5.833333 in C and 6.511132 in D. Their action order
still happens to be identical: definitions followed by expanded paths. No policy weight
was changed after observing this revision's outcomes.

### Same-budget run and limits

All 12 records are retained, with genuine input available in C/D:

| Information budget | A | B | C | D |
|---|---|---|---|---|
| 0.1 s | unknown | unknown | unknown | unknown |
| 0.3 s | modeled violation | modeled violation | modeled violation | modeled violation |
| 1.0 s | modeled violation | modeled violation | modeled violation | modeled violation |

At 1 s, charged times were A 0.28272 s, B 0.22563 s, C 0.29056 s and D 0.28091 s. This
single fixed-order run still provides no extra resolved query for neural information
relative to B. Historical v1/v2 differences do not isolate caching or diversity effects:
two implementation aspects changed and timings vary. The separate 5.728-second GNN export
is not charged here, and online C/D end-to-end acquisition remains pending.

### Verification and artifacts

All **47 focused tests** passed, including prepared/fresh equality on the same 12 existing
mechanisms, depth-cap preservation, stale-query rejection, fresh validation despite a
poisoned cache, expired preparation, candidate identity retention and raw-score exclusion
from C. The full suite passed **50 checks** with 19 dependency deprecation warnings; its
three historical structure checks remain smoke checks. OPM validation and SVG regeneration
passed with the same 3 views, 48 view-local nodes and 74 typed links.

The diagnostic is `.scratch/wsl/inference-20261111-002014-1018/prefix-reuse-v2.json`.
The new run's `mapped-integration-v2/` contains `runs.json`, `evaluation.json`,
`action-summary.json`, per-action ledgers and an archived source manifest. The v1 directory,
binary, original logits and reviewed correspondence were kept unchanged. No additional
mechanism programs, training data, rented compute or API calls were introduced.

## Development v3: pre-run implementation checkpoint

The [v3 specification](architecture/pilot_revision_v3.md) fixes the next real measurement
at 3, 10 and 20 seconds on the same reviewed query. No selector or symbolic-operation
parameters changed from v2. Each C/D worker now starts fresh TYGR export inside its own
deadline, verifies a per-run nonce and content identities, matches the new record to a
reviewed physical locator anchor, and only then exposes the requested type view.

The existing mapping review now includes its already-checked function address and
`CfaLocation(-24)` range as an identity anchor. This adds no model scores or expected
outcomes to runtime inputs. The prior expert review and fixed query/bounds remain setup
inputs outside the measurement; fresh matching and acquisition are inside it.

All **58 focused tests** passed after the change. The full suite passed **61 checks**
with the same 19 third-party deprecation warnings. Tests use clearly controlled subprocess
fixtures for online success/failure, never present their scores as real experimental
predictions, and retain the earlier real ELF checks. They cover fresh nonces, C's score
isolation, changed-model rejection, stale output, mismatched locations, charged timeouts,
unavailable cost breakdowns and absence of model work in B.

At this checkpoint, the WSL entry included a live process-group cleanup test and preserved all twelve
method/budget outcomes. That actual Linux lifecycle check and genuine online-model
measurement had not yet run; their subsequent results follow below. No end-to-end neural advantage is claimed at implementation
time. All setup, cache, export, ledger and result files default to D:.

## First real end-to-end run

The 11 November 2026 WSL run completed the predeclared A-D comparison at 3/10/20 seconds
on the same reviewed compiled query. Fresh online acquisition and timeout cleanup worked.
**No neural net benefit was observed:** C/D obtained no additional conclusion, paid much
more time at the larger budgets, and exhausted the smaller budget before selection.

The twelve rows below represent **one query**, not twelve independent programs. A resolved
result here is the same modeled violation, with a fresh concrete-input modeled reexecution
using RDI=8. It is not native input replay or a whole-program conclusion.

| Budget | A: result / wall | B: result / wall | C: result / wall | D: result / wall |
|---|---|---|---|---|
| 3 s | violation / 2.232 s | violation / 1.027 s | unknown / 3.011 s | unknown / 3.009 s |
| 10 s | violation / 1.177 s | violation / 1.181 s | violation / 6.542 s | violation / 5.788 s |
| 20 s | violation / 1.177 s | violation / 1.228 s | violation / 6.343 s | violation / 5.938 s |

The original evaluator reports zero wrong decisions. With one positive query, that is an
integration check, not an accuracy estimate. The two unknown results are hard timeouts;
their last event is `type_export_started`, with no selected action. Their model-stage
breakdowns are unavailable, and the elapsed time remains charged rather than recorded as
free acquisition.

### Acquisition and selection audit

| Arm / budget | Acquisition total | Export subprocess | Physical-location matching | Acquisition share of total wall |
|---|---|---|---|---|
| C / 10 s | 5.350 s | 5.278 s | 24.8 ms | 81.8% |
| D / 10 s | 4.599 s | 4.526 s | 25.9 ms | 79.5% |
| C / 20 s | 5.113 s | 5.031 s | 33.0 ms | 80.6% |
| D / 20 s | 4.548 s | 4.476 s | 24.7 ms | 76.6% |

Export includes interpreter/import startup, model loading, graph extraction, forward
inference and serialization; this table does not isolate neural forward time. Matching
against the fixed reviewed locator is a small part of the measured cost.

The audit verified six distinct acquisition IDs, four completed fresh exports, binary/model
and raw/mapped artifact hashes, and C's exclusion of model scores. All four completed exports
had identical candidate logits and raw value-node logits. C/D both selected definitions
followed by expanded paths; B selected expanded paths directly. Fresh validation reused
zero prepared steps. A/B incurred no model acquisition and emitted no export-start events.

D's shorter wall time cannot be attributed to candidate distributions: most of its timing
difference occurred in export, before selection. Runs were once per arm in fixed order,
on a cold process but without flushing OS caches. There is no timing significance estimate.

The POSIX descendant-cleanup check passed: its fixture started, and its descendant did not
survive termination. All 14 runtime source files matched the pre-run hash map; their exact
contents were archived before the subsequent accounting correction.

### Artifacts and subsequent accounting correction

The root is `D:/AI_Models/symbolic/.scratch/wsl/end-to-end-20261111-102804-821/`:

- `plan.json`: budgets, execution order, provider settings and runtime source SHA-256 map.
- `source_snapshot/`: the 14 matching source files, preserving the measured implementation.
- `process-cleanup.json`: actual Linux process-group lifecycle result.
- `results/runs.json`, `evaluation.json`, per-run ledgers, raw logits and mapping receipts.
- `validated-audit.json`: identity, freshness, validation and timing cross-checks.

The original `results/runs.json` SHA-256 is
`4e9e6ce15aaf5e84f79502c90be64ccfef5f40dd43dc6f3ca8fbb3d67052b6e9`.
The binary and frozen model retain the identities recorded in the earlier integration.
Human locator review, fixed query/bounds and harness setup remain excluded setup inputs.
The run therefore validates one reviewed, DWARF-assisted integration, not general mapping.

Audit also found that failed workers' displayed elapsed/charged time was stamped before
parent result recovery, while `process_wall_seconds` was stamped afterwards. The two
timeout differences were 6.47 and 7.90 ms. A regression first reproduced this discrepancy;
the runner now uses the same parent elapsed boundary for all three end-to-end fields,
including failed workers. All **58 focused tests** passed after the fix. Original measurements,
their source snapshot and hashes remain unchanged; the table above reports the originals.

### Operation-menu finding and next gate

A separate audit reused the twelve existing mechanism queries without GNN inputs. Fresh
8-step checks resolved eleven; fresh 128-step checks resolved twelve. Wherever the shorter
check resolved a query, the longer check produced the same status with exactly the same
executed-prefix step count. Both use one early-stopping executor. The longer check is not
forced to do its full cap on an easy query.

This counter audit does not establish universal runtime dominance. It does show that a
meaningful cost/precision choice has not yet been demonstrated. The next gate is an
expanded-check-only control and at most one genuinely complementary operation, documented
in [the development decision](architecture/operation_selection_gate.md). No policy weights,
operation definitions or benchmark denominator were changed after observing the v3 result.

## Development v4: operation-choice controls

The [v4 plan](architecture/pilot_revision_v4.md) was declared before implementation and
measurement. A-D's selector and original operation catalog remain unchanged. Three separate
controls were added: expanded-only, bounds-only and fixed bounds-then-expanded. None receives
neural information. The cheap operation reads executable ELF bytes, propagates conservative
unsigned register intervals, and returns a checkable exclusion certificate or unknown.
Unsupported behavior and possible out-of-bounds values do not become violations or exclusions.

### Frozen inputs and actual cold-process costs

The Windows run used exactly the **same twelve developer mechanisms**, three repetitions,
rotating the four-method order, and a 3-second end-to-end budget per trial. All 144 records
are retained. The repeated denominator is 36 per method; there are still only twelve unique
queries, not thirty-six independent samples. Gold was loaded after all workers terminated.

| Method | Correctly resolved / repeated queries | Unknown | Wrong | Timeouts | Total wall | Median trial wall |
|---|---|---|---|---|---|---|
| Frozen no-type B | 36/36 | 0 | 0 | 0 | 72.009 s | 1.978 s |
| Expanded-only | 36/36 | 0 | 0 | 0 | 72.988 s | 1.988 s |
| Bounds-only | 12/36 | 24 | 0 | 0 | 8.715 s | 0.227 s |
| Bounds-then-expanded | 36/36 | 0 | 0 | 0 | 50.549 s | 1.914 s |

The combined control's total wall time is **30.7% lower** than expanded-only. Its total is
17.022, 17.235 and 16.291 seconds across the three repetitions; expanded-only totals are
24.764, 24.778 and 23.446 seconds. This is a descriptive developer result, not a statistical
generalization, an accuracy estimate or evidence for GNN guidance. B and expanded-only are
close in total cost; the measurements do not establish a meaningful difference between them.

The cheap operation settles `m02` (unsigned bound), `m06` (mask), `m09` (overwritten index)
and `m10` (unreachable target), using fresh abstract rechecks. It returns unknown for the
remaining eight mechanisms. The combined control pays for all **24 fallback attempts**
across the three repetitions, then runs a fresh expanded check and fresh modeled validation.
It never imports a symbolic prefix or result from another trial.

### What produces the saving

This is an actual cost distinction from two depth caps on the same executor. Bounds-only
needs Capstone and pyelftools, and can complete its four decisive query cases without
loading angr. The combined control loads angr only after the cheap operation returns
unknown. It retains full coverage at a lower aggregate cost on these fixtures.

Most of the observed saving comes from preparation: expanded-only pays 62.549 seconds in
preparation over its 36 trials, whereas the combined control pays 43.547 seconds. Those
19.002 seconds account for about 85% of the 22.439-second total difference. Process/library
startup is consequential on these tiny queries. The result is not a claim of a new
abstract domain or an asymptotic improvement. The cheap operation's total check time over
all 36 bounds-only trials is 6.15 ms, with 15.81 ms for its decisive fresh abstract rechecks;
the larger wall cost includes preparation, startup, input verification and finalization.

In particular, a fixed cheap-first strategy already obtains the saving. There is no evidence
here that a neural selector improves on it, or that coarse pointer-type predictions carry
information beyond the available instruction structure. That remains the research question.
WSL replication is the next measurement, not new training or additional mechanism cases.

### Verification, scope and artifacts

The full suite passed **81 checks**, including **78 focused checks** and the three historical
smoke checks, with 19 existing third-party warnings. New regressions cover the same twelve
mechanisms, unsigned underflow and exact wrap, 32-bit zero extension versus partial-register
writes, flag clobbering, stack modification, certificate tampering, query identity, deadlines,
fresh abstract rechecking and full-check fallback. The flag-clobber unit was subsequently
tightened so its branch actually skips the target write; all four shortcut regressions passed
again. Unit-only edge cases do not add to the experimental mechanism denominator.

The abstract validator freshly decodes the bytes and reruns the same restricted interpreter;
it is not an independent implementation or native replay. The supported subset deliberately
excludes arbitrary loads/stores, signed guards, stack manipulation, unmodeled calls, nonstandard
ELF layouts and executable relocations. A work limit or repeated state retains unknown.
The existing full checker supplies modeled witnesses after fallback. No general x86-analysis
soundness or stripped-binary type-mapping result is claimed by these checks.

The new OPM diagnostic view validates alongside the original three: **4 views, 68 view-local
nodes and 104 typed links**. A-D's interfaces and type/label boundaries still pass validation.

Artifacts are under
`D:/AI_Models/symbolic/.scratch/selective_analysis/operation-gate-v4-20261111-111130-33032/`:

- `plan.json`: complete pre-run schedule, budget, environment and 16 runtime source hashes.
- `source_snapshot/`: the exact runtime sources; the unchanged pre-run v4 specification was
  additionally archived during the post-run audit before this result was documented.
- `runs.json`, `repetition-*/`: all records, per-action ledgers, worker logs and certificates.
- `evaluation-0.json`, `evaluation-1.json`, `evaluation-2.json`: offline per-repetition joins.
- `summary.json`, `validated-audit.json`: cost summary and identity/accounting cross-checks.

All sixteen measured runtime sources still match their recorded hashes and archived copies.
The audit verified 144 unique method/query/repetition identities, twelve unique query hashes,
the planned execution order, complete cold-process charging, zero neural acquisition cost,
fresh validation and all 24 fallbacks. The `runs.json` SHA-256 is
`17fb6acbdcee45b6fac09291cd3f73c1e439e2e2c1d5f5de15a63e1495bdb5da`.
No GNN calls, API requests, training, rented compute or new conda packages were used.

## WSL replication of v4 and routing headroom

The user-run WSL diagnostic completed on 11 November 2026 with all 144 planned records.
The audit verified **identical hashes for all sixteen runtime sources and all twelve
queries** relative to the Windows run. This repeats the experiment in another environment,
not on independent data. It uses Python 3.10.20, angr/claripy/pyvex 9.2.212, Capstone 5.0.6
and pyelftools 0.32 on WSL2. No operations, policy weights, budgets or examples were changed.

| Method | Correctly resolved / repeated queries | Unknown | Wrong | Timeouts | Total wall | Median trial wall |
|---|---|---|---|---|---|---|
| Frozen no-type B | 36/36 | 0 | 0 | 0 | 38.154 s | 1.029 s |
| Expanded-only | 36/36 | 0 | 0 | 0 | 36.706 s | 1.029 s |
| Bounds-only | 12/36 | 24 | 0 | 0 | 9.994 s | 0.277 s |
| Bounds-then-expanded | 36/36 | 0 | 0 | 0 | 28.131 s | 1.029 s |

The combined control reduces total wall time by **23.4%** relative to expanded-only,
retaining all observed conclusions. Per-repetition combined totals are 9.446, 9.392 and
9.294 seconds; expanded-only totals are 12.147, 12.455 and 12.104 seconds. The median trial
time is effectively unchanged: the four cheap-decisive cases benefit while eight still
require fallback. Three repeats estimate execution variability, not dataset generalization.

Exactly the same four mechanisms are discharged by local bounds. All **24 fallbacks**
are retained and paid, including their failed cheap checks. Abstract exclusions have fresh
byte-decoded rechecks; modeled violations have fresh concrete-input validation with zero
prefix reuse. Elapsed, charged and process-wall fields agree. All runs stay within their
3-second budgets, and no neural acquisition occurs.

Of the 8.574-second aggregate saving, 6.300 seconds, about **73.5%**, are preparation savings.
The observation is consistent with avoiding the full loader on four cases per repetition;
it does not establish a novel scheduling algorithm or uniform per-query acceleration.

### Post-run analysis: little saving remains for this routing choice

For each combined-control fallback, the ledger records the time from selecting the local
check to finishing its unknown result. These **24 failed local attempts total 1.255 seconds**,
about 52.3 ms each, or 4.46% of the combined control's total wall time.

A perfect free predictor could try to skip those attempts while preserving all twelve
cheap successes. Charging the full recorded attempt durations as avoidable is optimistic:
shared imports and later preparation may change when an earlier operation is omitted.
This is a recorded-cost opportunity estimate, **not a measured oracle strategy, a formal
runtime bound, or a new same-budget result**. It is a post-run diagnostic, not a criterion
used to tune the measured selector.

Under that optimistic accounting, only 1.255 seconds across all 36 combined trials are
available to repay features, decisions and routing mistakes; averaged across every query,
that is about 34.9 ms. The earlier compiled-probe neural acquisition alone took 4.5-5.4
seconds per cold query. These are different query workloads and do not give an exact
break-even prediction. They nevertheless provide no evidence that paying for the current
neural provider merely to skip these cheap attempts would improve this control.

Keep bounds-first fallback as a strong no-type baseline. Do not integrate the GNN into it
or train a selector on these twelve cases as a response to this result. A further neural
scheduling experiment first needs evidence of substantially more expensive avoidable work,
or measured information generation under a separately declared accounting unit that can
repay its costs. Changing to a persistent model or binary batch would require a new plan
and paid startup, graph generation, matching and selection; cached scores do not become
free end-to-end inputs. Independent queries and mapping validation remain outstanding.

### Audited artifacts

The WSL root, visible on D:, is
`D:/AI_Models/symbolic/.scratch/selective_analysis/operation-gate-v4-20261111-112033-998/`.
It retains `plan.json`, `source_snapshot/`, `runs.json`, all per-worker ledgers and logs,
three offline evaluations and `summary.json`. `validated-audit.json` additionally records
source/query equality with Windows, all 144 scheduled identities, complete accounting,
the 24 fallback checks, per-query medians and the failed-attempt opportunity estimate.
The audit script is the parent workspace's `.scratch/selective_analysis/audit_wsl_operation_gate_v4.py`.
The original `runs.json` SHA-256 is
`cc1366e7e52d7182cac496999c5f8a209474ef20ad58349f8d28c73d654853da`.

No measured runtime source or original result was changed during the audit. No new model
calls, conda changes, training, rented hardware or API work was needed. The WSL-replication
capability is now marked completed; neural value and independent validation remain pending.

## Development v5: pre-run implementation checkpoint

The [v5 plan](architecture/pilot_revision_v5.md) was written before implementation. The WSL
operation logs show about 94.8 ms per expanded execution plus validation, with little
recorded saving available from skipping cheap failures. Before adding operations, the next
diagnostic separates the existing provider's costs on the single reviewed compiled probe.
It introduces no additional mechanism program or learned selector.

`scripts/profile_neural_acquisition.py` requests three fresh CPU acquisitions, each capped
at 30 seconds. The exporter can now produce a separate, opt-in stage receipt: imports,
model loading, graph/location generation, graph preprocessing, batch preparation, actual
model forward, logit export, identity hashing and raw serialization. Generator `next()`
and exhaustion are timed without including consumer work. Collation is separated from
the forward call. The ordinary acquisition does not request this receipt.

Provider validation checks stage names, finite nonnegative durations, call counts, flat
accounting and the acquisition/binary/model/raw-output identities. Actual subprocess wall
time stays authoritative. Script clocks exclude interpreter startup and receipt writing;
mapping and provider checks are additionally paid. This does not measure warm inference
or justify subtracting startup from a future end-to-end comparison.

All **91 tests** passed: 88 focused checks plus three historical smoke checks, with the same
19 dependency warnings. Ten new tests verify generator accounting, overlap rejection,
unlabeled model calls, malformed/stale profile rejection, failure retention and the actual
exporter/provider command path using an explicitly dummy backend. Profiled and ordinary
exports have identical predictions in that controlled fixture. These dummy weights,
predictions and timings provide wiring evidence only, not real-model performance results.
Exporter syntax is checked against Python 3.8; provider/harness syntax against Python 3.10.

At this implementation checkpoint, genuine WSL measurement was still pending. The entry archives the v5 plan and runtime
sources before measuring, then retains all three trial outcomes, event logs, new raw logits,
mapped views, profile receipts and prediction identities under
`.scratch/wsl/acquisition-profile-v5-*/` on D:. No compilation, environment modification,
model download, training or API call is needed. Earlier v3/v4 measured files and archived
sources remain unchanged; the new profiling implementation has its own source identity.

## Real v5 acquisition costs

The user-run WSL diagnostic completed all three predeclared cold CPU acquisitions on the
existing reviewed compiled probe. The audit checked all **sixteen source/specification
hashes** against both the pre-run snapshot and current files, three fresh acquisition IDs,
model/binary/raw/mapped/profile identities and internally consistent flat timing receipts.
All three prediction identities match each other **and the historical v3 predictions**.
Consistency is not a type-accuracy result; no ground-truth type label reached the model.

| Trial | Acquisition wall | Imports | Model loading | Graph generation | Model forward | Mapping |
|---|---|---|---|---|---|---|
| 1 | 7.492 s | 5.403 s | 0.046 s | 1.162 s | 0.1023 s | 0.0282 s |
| 2 | 5.154 s | 3.265 s | 0.0407 s | 1.055 s | 0.0819 s | 0.0127 s |
| 3 | 5.006 s | 3.182 s | 0.0416 s | 1.029 s | 0.0907 s | 0.0156 s |

The median acquisition wall time is 5.154 seconds. Independently calculated stage medians
are imports 3.265 seconds, loading 0.0416 seconds, graph generation 1.055 seconds and model
forward 0.0907 seconds. These medians need not belong to the same trial and must not be
added as a decomposition of a particular median run. The remaining receipts retain batch
preparation, graph preprocessing, hashing, raw serialization and unallocated script time.
Outer exporter wall time additionally contains 0.521-0.609 seconds beyond the script clock;
this includes startup/finalization boundaries and is not an isolated interpreter-startup
measurement. Provider validation and physical-location matching remain additionally paid.

### Interpretation for the next research step

Import time is the largest measured cold cost, occupying 63.4%-72.1% of each acquisition's
wall time. Graph generation is the next substantial stage, at 1.029-1.162 seconds. Weight
loading is small for this frozen model. Forward takes 0.0819-0.1023 seconds, only
**1.37%-1.81%** of the corresponding complete acquisition. Holding all other work unchanged,
even hypothetical zero-cost forward would remove only that fraction of the measured wall
time. This arithmetic is not a measured GPU speedup or a whole-analysis benchmark.

Therefore forward optimization alone is not a supported way to repair the current cold
acquisition cost. A persistent worker could avoid repeated imports/loading, but this run
does not measure one; subtracting those durations would not establish its latency. Graph
generation, feature preparation, inference, matching and validation would still need actual
measurement and charging. Sharing a representation with the checker would require a
verified interface, particularly across the two existing angr environments.

The twelve v4 mechanisms and this compiled probe are different workloads. Their cost
scales motivate further investigation but are not a paired neural/non-neural comparison.
The current fixtures have not exposed enough expensive, avoidable analysis work to justify
the neural provider, and no neural information advantage has been demonstrated. Preserve
the fixed bounds-first fallback as a strong baseline. Any further scheduling work first
needs evidence that type information improves a meaningful operation choice beyond
structure, under the declared accounting unit. Startup engineering by itself would not
establish that research contribution or publication readiness.

### Audited artifacts and completed capability

Artifacts remain under
`D:/AI_Models/symbolic/.scratch/wsl/acquisition-profile-v5-20261111-114641-1245/`:

- `plan.json`, `source_snapshot/`: the predeclared plan and sixteen matching source/spec files.
- `trial-*/`: fresh raw and mapped predictions, exporter logs, caches and stage receipts.
- `events-*.jsonl`, `trials.json`, `summary.json`: actual acquisition events and all three results.
- `validated-audit.json`: freshness, source/content identities, prediction equality, stage
  validation and per-trial cost shares checked after the run.

The original `trials.json` SHA-256 is
`86127a61bf6f08b45a54d35244060dd5de2e106e40df6901d20533761a948623`.
The captured audit is the parent workspace's `.scratch/wsl/audit_acquisition_profile_v5.py`.
The actual-model profiling capability is now completed. Original measurements, source
snapshots, the frozen A-D selector and operation catalog remain unchanged. No new model,
training, environment installation or formal mechanism case was introduced.

## Development v6: information value on Windows

The [v6 plan](architecture/pilot_revision_v6.md) was written before implementation and
measurement. It retains the frozen A-D selector, parameters and original operation catalog,
and adds two separately identified fixed controls. The six methods use one common symbolic
and byte-bound checker initialization. The analysis clock starts afterwards, excluding
model acquisition, prior mapping, artifact loading/projection and common preparation.
Selection, selected dependency preparation, checking, fresh validation, recording and parent
finalization remain paid. This is **information-only**, not a deployment-cost comparison.

The inputs are the existing compiled query and the completed v5 acquisition
`93b14d3ba6524416b395612c8822eb21`. Raw/mapped file hashes, the receipt and physical locator
anchor were checked, and the copied mapping was independently reconstructed from the raw
record. It retains the real `char*` Top-1 and `char*`, `struct*`, `void**` Top-3 logits.
C sees no scores; D retains them. B and the fixed controls read no candidate values.
The twelve generated mechanisms still lack reviewed neural mappings; no predictions were
filled in for them. There is **one unique reviewed query** in this experiment.

### Predeclared budgets and observed outcomes

The native Windows run retained all **54 records**: six methods, three budgets and three
rotating-order repetitions. The entries below count repetitions of the same positive query,
not independent examples. All completed decisive results have fresh concrete-input modeled
validation with RDI=8 and zero validation-prefix reuse. No wrong decision was observed.

| Information budget | A | B | C | D | Expanded-only | Bounds-then-expanded |
|---|---|---|---|---|---|---|
| 0.05 s | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 |
| 0.15 s | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 |
| 0.50 s | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 |

| Method | Median charged time at 0.50 s | Observed complete action sequence |
|---|---|---|
| A | 0.3499 s | definitions, bounded paths, expanded paths |
| B | 0.2286 s | expanded paths |
| C | 0.3037 s | definitions, expanded paths |
| D | 0.3648 s | definitions, expanded paths |
| Expanded-only | 0.2849 s | expanded paths |
| Bounds-then-expanded | 0.2614 s | local bounds, expanded paths |

These are descriptive timings from three repetitions on one query. B and expanded-only
use the same substantive check but have different observed medians; that difference is
not evidence for scheduling quality. C and D also have identical action order. Their time
difference cannot establish a candidate-distribution effect or statistical significance.
The abstract cheap check meets an unsupported stack instruction in this compiled fixture
and returns unknown before fallback; its four successes on the generated mechanisms do
not transfer automatically to this binary.

### Accounting effects and scope of the negative result

At 0.05 seconds, all eighteen trials exhausted the information budget during worker
analysis. At 0.15 seconds, six exhausted it during analysis and twelve had validated
candidates converted to unknown because finalization exceeded the declared budget.
Windows exit/cleanup/recovery costs are substantial at these scales. For the 0.50-second
records, post-run ledger differences estimate median outer tails of roughly 0.158-0.202
seconds across methods. These differences are not a new worker-only budget comparison.
The original accounting and unknown results are retained unchanged.

Under the declared budgets, type information supplied no additional resolved query over B,
even with acquisition excluded. Its current projection and fixed ranking rule prioritized
paid definition recovery, while B selected the expanded check directly. D's extra genuine
scores changed score values but produced the same action sequence as C. This establishes
**no observed information benefit for this query and this implementation**. It does not
prove that neural types are generally uninformative or that a new selector would fail.
Independent reviewed mappings remain necessary before a broader research conclusion.

Keep these negative observations rather than tuning the frozen weights on this case.
At this Windows checkpoint, WSL replication was pending because finalization costs vary
by environment; the completed replication is recorded below.
Further work should first improve independent mapping coverage and identify decisions
where type information changes useful evidence, before paying for acquisition optimization.

### Verification and artifacts

All **100 tests** passed: 97 focused checks and three historical smoke checks, with 19
existing dependency warnings. New checks cover common initial facts and policy identity,
absent scores in C, no candidate reads in B/controls, rejection of synthetic type sources,
tampered remapping despite updated file hashes, wrong acquisition IDs, late selections,
fixed-control isolation and subprocess information accounting. Deliberately fabricated
test types are not empirical model outputs.

The new OPM information view passes alongside the original views: **5 views, 96 view-local
nodes and 146 typed links**, with the same label/type routing and original interfaces.
Its separate Preparation Costs and Information Budget make the excluded/paid boundary
explicit. The fixed controls have their own declared stage lists; only B/C/D form the
same-policy, same-catalog type ablation.

Artifacts remain under
`D:/AI_Models/symbolic/.scratch/selective_analysis/information-value-v6-20261111-120355-39700/`:

- `plan.json`, `source_snapshot/`: the pre-run schedule and eighteen matching source/spec hashes.
- `inputs/`: frozen raw/mapped predictions, locator review, acquisition receipt and validation.
- `runs.json`, `repetition-*/`: all 54 retained records, ledgers, checked evidence and worker logs.
- `evaluation-*.json`, `summary.json`: offline per-repetition labels and descriptive comparisons.
- `validated-audit.json`: policy/input identity, shared initial facts/cache, score masking,
  validation and budget checks, action sequences and post-run tail estimates.

The audit verified one query hash, all 54 scheduled method/budget/repetition identities,
identical B/C/D policy hashes, identical structural features and initial checkpoints, empty
initial prefix caches and no online export events. The original `runs.json` SHA-256 is
`f81a15a365a04ab8b620837eb1f8bc58b6002bc4f10ec001d8a9f64cae27ff30`.
The captured audit is the parent workspace's `.scratch/selective_analysis/audit_information_value_v6.py`.
No new model call, training, external API, conda installation or formal mechanism program
was needed. Original v3-v5 results and the v6 measured runtime sources remain unchanged.

## V6 WSL replication and input scope

The WSL information diagnostic completed all 54 predeclared trials on 11 November 2026.
The audit verified **identical eighteen source/specification hashes, query identity and
raw/mapped type inputs** relative to the Windows experiment. B/C/D share the same policy
hash, initial structural facts and checkpoint. Every run begins with empty prefix caches;
only selected dependency preparation is paid and reused within that run. No online model
call occurred. These are repeated observations on the same one positive query.

| Method | Resolved at 0.05 s | Resolved at 0.15 s | Resolved at 0.50 s | Median charged time at 0.50 s |
|---|---|---|---|---|
| A | 0/3 | 0/3 | 3/3 | 0.4279 s |
| B | 0/3 | 0/3 | 3/3 | 0.2681 s |
| C | 0/3 | 0/3 | 3/3 | 0.4131 s |
| D | 0/3 | 0/3 | 3/3 | 0.4140 s |
| Expanded-only | 0/3 | 0/3 | 3/3 | 0.3031 s |
| Bounds-then-expanded | 0/3 | 0/3 | 3/3 | 0.3112 s |

All decisive results have the same modeled violation, fresh concrete-input validation,
RDI=8 and zero validation-prefix reuse. There are no observed wrong decisions. At 0.05 s,
all eighteen records exhaust the information budget during analysis. At 0.15 s, nine
exhaust it during analysis and nine have candidates excluded from the resolved count
because finalization exceeds the budget. Original accounting is unchanged. Post-run
0.50-second ledger differences estimate median outer tails of 0.179-0.238 seconds by
method; they do not create a new worker-only performance result or isolate a single
cause of teardown cost.

B always selects expanded paths directly. C and D select definitions first; all their
0.50-second trials then select expanded paths. At 0.15 s, one C trial ends before that
second selection. This truncated trace is a budget effect, not evidence that candidate
scores improve decisions. D gives no extra resolved result over C. Timing differences
between methods with identical substantive checks, or three repeated runs of one query,
do not establish statistical significance.

### A concrete limitation of the current information input

The existing one-case symbolic review already checked by UNSAT of negations that:

- `CFA-24` contains the object base pointer.
- `CFA-40` contains entry RDI, the index.
- The target write address is pointer plus index; its write length is the constant one byte.

The frozen runtime type view contains only prediction **`1129:1`**, the base pointer.
The raw artifact also contains **`1129:0`**, the index at `CFA-40`, but no independent
index use-site view is passed to the selector. Its raw Top-3 labels remain `char*`,
`struct*` and `void*`; they were not relabeled to fit the source or the desired outcome.
The existing exporter preserves variable order through upstream flattening, gather and
scatter order; the audit found no row-reordering evidence that would justify changing
these observed outputs.

This is a post-run review of two documented address contributors in one query, not a
general mapping-completeness result or a newly accepted runtime mapping. It identifies
an input boundary of the present experiment. It does not prove that projecting the index
would improve scheduling. Different variables' type candidates must remain separate; a
pointer/index score mixture would not be a meaningful distribution for either variable.
The current checker still receives neither prediction as a semantic fact.

### Research decision and retained artifacts

Windows and WSL now agree: **no extra information benefit was observed for this one
query, projection and frozen policy**, even with acquisition excluded. Preserve this
negative result. Next prioritize operand-qualified mapping and a small number of
independent reviewed property queries within the existing case budget, rather than
changing weights on this query. More general information value and end-to-end value
remain separate pending research questions. Broader mapping, native replay and resource
accounting are not completed by this replication.

The WSL root is
`D:/AI_Models/symbolic/.scratch/selective_analysis/information-value-v6-20261111-121333-1279/`.
It retains the predeclared schedule, eighteen-source snapshot, frozen genuine inputs,
all 54 per-worker records/logs, three offline evaluations and summary. The post-run
`validated-audit.json` also records source/input equality with Windows, policy and
projection isolation, fresh validation, all unknown reasons, timing-tail estimates and
the limited input-scope review. Its referenced original mapping audit SHA-256 is
`f3b5e41bc2b2bcd3686b77292c57ea71a069d9bb0223dd40788e297b375ba8d7`.

The unchanged `runs.json` SHA-256 is
`9b2c2cdcb1e2ffb7ab312647b582b8de828a10ab00969c44f22dfbabdf8524cb`.
The captured audit is the parent workspace's
`.scratch/selective_analysis/audit_information_value_v6.py`, invoked with this WSL output
directory. The WSL information-replication capability is now completed. No measured
runtime source, original result, model, operation or policy parameter was changed.

## Development v7: independent operand bindings

The [v7 plan](architecture/pilot_revision_v7.md) was declared before implementation and
validation. The existing query now has distinct base-pointer and index IDs in a new
role-qualified bundle, with their original prediction identities and raw candidate values.
This is **two operands of the same query**, not two independent examples. The old v6
input and selector have not been replaced or remeasured.

### Fresh program evidence, independent of type predictions

On the existing compiled probe, the diagnostic verifies a nonempty target state and
four UNSAT-of-negation checks: base slot equals the declared object base; index slot
equals entry RDI; the observed target address equals the two slot values' sum; and the
observed write length equals one byte. It captures the write before address concretization.
The verifier accepts only the query and a strict plan of physical locations/roles/anchors,
with no candidate labels or scores. The proposal uses the existing CFA slot review and
location metadata, not variable names or a predicted type.

The Windows run completed two independent fresh entry-state passes, each executing nine
prefix instructions. Their structured evidence matched. First-state satisfiability avoids
a vacuous relation proof; binary content is checked before and after each pass. Forks,
unmodeled calls, precision loss, work/time limits and solver errors cannot be promoted to
verified evidence. This is repeated symbolic checking under the declared model, not a
separately implemented theorem checker or a native runtime replay.

The verification phase took 1.957 seconds and the diagnostic pipeline 1.969 seconds.
Those clocks include first imports and project construction inside verification, and
exclude earlier input copying/source archiving and the last report write. They are not
isolated SMT times, an end-to-end acquisition measurement or a speedup claim. Online use
of this extra verification would need to charge its real costs.

### Separate views and shared facts

| Role | Prediction | Physical slot | Retained candidates | Conditional Top-3 weights |
|---|---|---|---|---|
| Base pointer | `1129:1` | CFA-24 | `char*`, `struct*`, `void**` | 0.912364, 0.067062, 0.020575 |
| Index | `1129:0` | CFA-40 | `char*`, `struct*`, `void*` | 0.525704, 0.430182, 0.044114 |

These weights are independently normalized within each retained candidate set, not
calibrated correctness probabilities. No scores from different variables are merged.
The index predictions are not repaired from the source declaration or the desired result.
Mapping correctness establishes where a prediction applies, not whether the prediction
itself is right. The constant length is a program fact and has no manufactured neural view.

C exposes one label per role without scores or uncertainty values; D retains the real
Top-K labels/logits and separate conditional weights. A/B expose zero type views. The
separate `operand-program-facts.json` contains roles, storage, anchors and proven relations
for all future arms, with no candidate types, scores or prediction IDs. This prevents
attributing additional symbolic program facts to the GNN. None of these new role views is
yet consumed by the frozen scalar selector, and no information-value gain is measured here.

### Verification and retained artifacts

All **120 tests** passed, including 117 focused checks and three historical smoke checks,
with the existing 19 third-party warnings. Twenty new checks use an explicit machine-code
fixture and fabricated candidates only as unit data. They cover independently normalized
views, score hiding in C, hidden A/B resources, old-schema rejection, swapped/wrong slots,
duplicate/missing roles, changed PC ranges/functions/binaries, partial or altered evidence,
work limits and deadlines, cross-variable mixing despite an updated outer hash, metadata-only
proposals and candidate-free shared facts. The old candidate projector was extracted into
a shared pure helper; the original type-view regression checks still pass.

The new OPM mapping view passes with the prior models: **6 views, 116 view-local nodes
and 174 typed links**. Validation additionally rejects a raw-candidate route into symbolic
verification, fresh rechecking or common program facts. The graph uses explicit location-
metadata and candidate-data views; it is a modeling profile, not general code-flow certification.

Actual artifacts remain under
`D:/AI_Models/symbolic/.scratch/selective_analysis/operand-mapping-v7-20261111-124714-46812/`:

- `run-plan.json`, `source_snapshot/`: input identities and eighteen archived source/spec hashes.
- `inputs/`: copied genuine raw export, original base-pointer mapping/review, prior slot audit
  and acquisition receipt. No new inference was performed.
- `operand-plan.json`, `first-proof.json`, `validated-proof.json`: the proposed bindings and
  two-pass program evidence.
- `operand-types.json`, `operand-program-facts.json`: the separate role bundle and common facts.
- `views-C.json`, `views-D.json`, `summary.json`, `validated-audit.json`: projected views and
  source/content/proof/score-preservation audit results.

All eighteen source/spec files match their pre-run hashes. The raw input SHA-256 remains
`93dac202d588ff3efa4fdca355cb96f788f25cf590adfb1a31e4e6d2fb4d7057`.
The role-bundle SHA-256 is
`d2cab3154a50694420f11da728613f3a185f00215f45d6323232b258b9823b5f`;
the original summary SHA-256 is
`bf197298813c1219d9b491862a5b17519f1d86b626f6c2ddfd5973d4a7cfc5dd`.
The post-run audit is `.scratch/selective_analysis/audit_operand_mapping_v7.py` in the parent
workspace. WSL replication, independent mapped queries and a declared role-aware selector
interface were pending at this Windows checkpoint. No new training, model call, API work
or independent case was added. The WSL replication follows below.

## V7 WSL mapping replication

The user-run mapping diagnostic completed on 11 November 2026. The audit checked all
**eighteen source/specification hashes**, the query, genuine raw export, acquisition
receipt and old reviewed input against the Windows run. Both fresh symbolic passes
verified all five checks, each with nine prefix instructions. Query-domain target
satisfiability, base/index slot bindings, the address sum and one-byte length all agree.

The resulting program-evidence fingerprint and canonical role-bundle fingerprint are
identical across Windows and WSL. The bundle files have different byte-level SHA-256 values;
the audit confirmed their normalized bytes differ **only in line endings**. Canonical
semantic equality, file integrity and measured timing are recorded separately.

The base-pointer binding remains `1129:1` at CFA-24 and the index binding remains `1129:0`
at CFA-40. Every retained candidate and raw logit is preserved. C has two independent
label-only views with no scores; D has two independent candidate/score views. A/B have
zero neural views, and all future arms can use the separate candidate-free program-facts
artifact. No cross-variable candidate mixture or model-based program assumption is added.

WSL verification took **2.1828 seconds**, and the diagnostic pipeline took **2.2067 seconds**.
These are one-run diagnostic clocks including first imports/project construction within
verification. They are not isolated SMT costs, a controlled environment speed comparison
or an end-to-end neural scheduling result. No new inference or model loading was performed.

### Completed scope and next boundary

The input-layer gap is closed for **two declared operands of this one reviewed query**.
The proposal factory still relies on its existing binary identity, physical slot review,
single-successor prefix and one affine address form. It is not general automatic mapping,
and successful mapping does not establish that the predicted types are correct. In
particular, the index's pointer-class candidates remain unchanged.

The frozen selector still does not consume the new role bundle. Independent mapped-query
coverage, a declared role-aware selection interface, native replay and resource accounting
remain pending. Next prioritize a few independent queries within the existing case budget
and verify supported operand bindings before evaluating a new selection policy. Existing
negative v6 observations and their input scope remain as recorded.

### Retained WSL artifacts

The root is
`D:/AI_Models/symbolic/.scratch/selective_analysis/operand-mapping-v7-20261111-125534-1388/`.
It retains `run-plan.json`, `source_snapshot/`, original inputs, `operand-plan.json`, the
first and freshly validated proofs, `operand-types.json`, common facts, C/D projections
and the original summary. `validated-audit.json` records all identities, per-role values,
fresh-check counts, common-fact isolation and cross-environment canonical equality.

The WSL bundle SHA-256 is
`640471a88cd325a5cad9afd0f3aff4fcdd023c60db1b44aea64f61d56596ffd4`;
the original summary SHA-256 is
`d4962d751ecd7893b1e6135e0759b370c9323b2a33251f46a843b61f810fe917`.
The unchanged raw input SHA-256 remains
`93dac202d588ff3efa4fdca355cb96f788f25cf590adfb1a31e4e6d2fb4d7057`.
The audit script is the parent workspace's `.scratch/selective_analysis/audit_operand_mapping_v7.py`,
invoked with this WSL output directory. The one-query WSL mapping-replication capability
is now completed. No measured runtime source, original result, model, operation or policy
parameter was changed during the audit.

## V8 implementation checkpoint: two compiled developer queries

On 11 November 2026, development v8 added an executable WSL entry for two predeclared
authored C programs: affine-offset and masked-index writes. The specification is
`docs/architecture/pilot_revision_v8.md`; sources and label-free query specifications are
in `benchmarks/selective_analysis/compiled_queries/`. Expected outcomes are kept in a
separate offline file, loaded only after both runtime cases finish. This is a separate
mapping/validation track. It does not add held-out projects, alter the twelve-mechanism
denominator or rerun/tune the frozen A-D selector.

Operand-plan v2 checks entry-input addition and bitwise-AND expressions using machine-width
semantics. They are proof obligations, never extra constraints. Physical locator metadata
enumerates exactly two base/index assignments without reading names, candidate types,
scores or expected outcomes. Acceptance requires exactly one verified assignment, explicit
rejection of its alternative and fresh symbolic rechecking. Incomplete alternatives stay
unknown. V7 identity-input plans and their evidence remain supported.

The runner archives source/specification hashes, compiles from archived sources, obtains
one fresh CPU export per binary using the pinned existing model and preserves raw values.
Compilation/extraction/export/mapping/property stages have hard process caps of
30/30/120/20/10 seconds. Each completed assignment attempt is saved before the next runs.
Independent property checking and validation run even if neural acquisition later fails.
All planned cases, missing artifacts and unknowns remain in the offline denominator.
Common facts and per-role C/D views are exported only for verified mappings; selection is
not integrated. All task-created files and caches remain on D.

Local validation passed **143 tests**, comprising **140 focused checks** and the three
historical smoke checks. The 23 new tests use explicitly handcrafted machine-code and
candidate fixtures, including false-transform rejection, unsigned wraparound, unresolved
alternatives, label-free protocols, failure denominators and actual subprocess CLI paths.
They are not genuine new neural observations. Both C sources pass strict syntax checking
with the existing Windows GCC. Actual symbol/instruction extraction also recovered the
known entry, write and object of the existing GCC-produced integration ELF, without
requiring a nonportable symbol `linked_addr` attribute. Seven OPM views validate and render
with 136 view-local entities and 204 links. These checks cover the declared rendering
profile and data routes, not full OPM semantics.

The agent cannot launch WSL from its sandbox. **Genuine compilation, acquisition and
mapping for the two new sources remain pending** the user-run command
`python -B scripts/run_compiled_queries.py` in WSL angr-env. No v8 empirical timings,
type accuracy, new mapping success, generalization or neural scheduling gain are claimed
at this implementation checkpoint.

## V8 genuine WSL acquisition and mapping validation

The user-run entry completed on 11 November 2026 at
`D:/AI_Models/symbolic/.scratch/wsl/compiled-queries-v8-20261111-132527-1399/`.
Both planned developer queries were extracted, both fresh CPU exports completed and
both base/index assignments were uniquely verified. There are two correct scoped
property results, zero wrong results and zero unknowns in this two-case run.

| Query | Validated property result | Physical mapping | Fresh export wall time | Mapping process wall time | Property process wall time |
|---|---|---|---:|---:|---:|
| offset_index | violation | verified | 6.4339 s | 1.1185 s | 0.9680 s |
| masked_index | excluded_within_scope | verified | 4.2249 s | 1.1183 s | 0.9682 s |

These are single-run stage clocks including their respective process startup/cleanup,
not an A-D comparison or isolated SMT cost. Extraction took 1.6194 s and 0.8682 s;
compilation took 0.3698 s and 0.3168 s. No warm service, amortization or runtime speedup
was measured. Acquiring and mapping types already costs several seconds while the
independent property worker finishes in about one second on these small queries.

For `offset_index`, the modeled witness has entry RDI=12, so the transformed index is
16 for an eight-byte object. It passed fresh concrete-input modeled reexecution; no
native replay was attempted. For `masked_index`, the checker completely discharged
the declared first-write scope and performed a fresh-state complete-scope recheck.
Neither result is a claim about main reachability, all writes or whole-program safety.

### Independent audit

The post-run audit verified all **21 source/specification hashes** against the archived
copies and current measured sources. It checked the pinned model, different acquisition
IDs, binary/query identities, zero-timeout receipts and the complete two-case offline
denominator. It reconstructed all Top-K candidates and scores from the retained
value-node logits and their 75-class vocabulary, with no changes to raw predictions.

Each query retains two proposed physical assignments. One is rejected by a satisfiable
negation of the base-slot claim; the other proves all five checks. The accepted assignment
was freshly rechecked in WSL. The Windows audit independently reproduced both original
assignment proofs and the property conclusions. Every accepted pass has ten prefix
instructions. Base and index remain separate, with prediction IDs `1129:1` and `1129:0`
respectively, qualified by each binary/query identity. Both queries have A/B zero neural
views and C/D two separate role views. Candidate-free common facts match their proofs.

The original index prediction was not corrected using source knowledge: `offset_index`
has Top-1 `char*`, with `u64` second; `masked_index` has Top-1 `u64`, then `i64` and
`char*`. The first query's base is also Top-1 `char*`. These retained observations show
why location validity and type correctness must be treated separately. Conditional
Top-K weights remain uncalibrated and are not type-correctness probabilities.

Along with the original direct-index probe, three compiled developer queries now have
verified mappings for two operands each. They are authored mechanism variants, not three
independent projects or a held-out test set. Neither v8 query entered the frozen selector.
RQ1/RQ2 gains, native replay and generalization remain unproven.

### Post-hoc operation applicability check

After auditing the run, a separate Windows diagnostic checked the unchanged operations
on these exact binaries. The eight-step checker returned unknown on both without reaching
the target; the target is after ten prefix instructions. The restricted byte-decoded
local checker returned `unsupported_instruction:push` on both. Definition recovery is
preparation only, while the expanded checker supplies both validated property conclusions.
This is an applicability check, not a controlled timing or neural scheduling experiment.
It does not change the original run, operations, selector or its parameters.

The next engineering gate is conservative handling of supported compiler stack frames
in a local check, followed by checking whether useful operation tradeoffs actually arise.
It is premature to interpret the richer role bundles as evidence of better scheduling.

### Artifacts and identities

The original run retains source snapshots, run plan, per-query compilation/extraction
records, binary contracts, raw exports, assignment proposals/attempts, accepted proofs,
role bundles, common facts, projections, property receipts, offline labels and summary.
Added sidecars are `validated-audit.json` and `operation-readiness.json`; original measured
files remain unchanged. The audit entry is the parent workspace's
`.scratch/selective_analysis/audit_compiled_queries_v8.py`; the applicability entry is
`.scratch/selective_analysis/check_v8_operation_readiness.py`.

- Original summary SHA-256: `4c1c219c0b6406be46b6135ad156283d0287ecd9af2c93dd401e1ca02930ca23`.
- Original case-results SHA-256: `333a43c6b09e002502c19d19405bf7286b6994c0607d578a9e1990ff6a50e8e5`.
- Offset binary SHA-256: `87ddc7b2c076cbf8eac8752d722b2bd94a1bd007d68c49d4dc13d3b13caaf79e`.
- Masked binary SHA-256: `3819825049678a3cf15229507fea4a16c39f17c4deff2248d79005a6e95b04d7`.
- Offset raw export SHA-256: `cca1114f344cae96aa6b89668756bba9accdbe8bd46ba9748b2029b6f3dca5b9`.
- Masked raw export SHA-256: `2342b33b5949ce18adea10d1c6cafd43927f7f894b1f9a4298ae900759a4de6c`.

## V9 restricted compiler-frame checking and Windows control results

Development v9 was declared before implementation and measurement. The new checker is
separate from v4 LocalBoundsChecker, the old frozen A-D catalog and selector. It derives
a unique entry RSP from the actual reference call state, and checks the bounded stack
window against mapped image segments and the declared object. Only a straight-line
canonical frame and initialized aligned eight-byte negative RBP slots are supported.
The proof is an interval exclusion; unsafe ranges remain unknown rather than becoming
existential witnesses. Other memory, partial overlaps, uninitialized slots, pointer
escape, calls and branches remain unknown. Decisive results require fresh entry-context
and byte-decoded rechecking. Both entry preparation and validation are charged.

The full Windows suite passed **172 tests**, including **169 focused checks** and the
three historical smoke checks. Twenty-nine new tests cover actual instruction semantics,
partial/overlapping slots, unknown memory, frame escape, stack/image/object aliasing,
non-unique entry RSP, exact overwrites, unsigned wrap, bounded allocation, false or
mismatched certificates, fresh validation, deadlines, paid fallback and isolated CLI
execution. Neural inputs are rejected by the frame-control worker. These unit fixtures
are not new empirical research cases. Eight OPM DOT views validate and render, with
158 view-local entities and 236 links; these are profile checks, not full OPM verification.

### Fixed comparison and measured results

The comparison reused the original direct-index probe and both v8 compiled binaries.
No new inference, training, compiler execution, API work or research case was added.
Each method/query/repetition ran in a fresh process with a 5-second end-to-end budget.
The method order rotated across three repetitions; all 27 planned records were retained.
Sources and binaries were archived first, and labels were read only after workers exited.

| Control | Resolved / repeated queries | Wrong | Unknown | Timeouts | Total wall time | Median wall time |
|---|---:|---:|---:|---:|---:|---:|
| expanded_only | 9/9 | 0 | 0 | 0 | 17.2172 s | 1.9029 s |
| frame_bounds_only | 3/9 | 0 | 6 | 0 | 16.6927 s | 1.8463 s |
| frame_bounds_then_expanded | 9/9 | 0 | 0 | 0 | 17.1212 s | 1.9144 s |

Frame checking excludes only the masked input, in all three repetitions. The original
direct index and offset-index inputs remain unknown locally and yield validated modeled
violations after the full fallback. The fallback reuses the paid project but executes
fresh symbolic states with zero prepared-prefix reuse, including final result validation.

The fallback total is 0.0960 s (about 0.56%) lower, while its median is slightly higher.
This small mixed timing difference does **not** establish a stable speed advantage.
One machine's three repeated developer queries cannot establish generalization or neural
information value. The operation now has a useful supported result on a compiler-produced
frame, but paid entry-context construction, cold startup and fresh validation matter.
WSL replication remains pending before interpreting the tradeoff further.

### Audit and artifacts

The run root is
`D:/AI_Models/symbolic/.scratch/selective_analysis/frame-bounds-gate-v9-20261111-135510-55168/`.
It retains the plan, all 21 source/specification snapshots and hashes, copied input
binaries, 27 isolated requests/logs/event ledgers/results, combined runs, offline gold,
per-repetition evaluations and original summary. Added `validated-audit.json` verifies
source/input identities, exact planned coverage, correct offline joins, action orders,
fresh fallback states, absent neural inputs and full parent cleanup/recovery accounting.
It independently rechecks the unique successful frame certificate fingerprint. Original
measured records and sources were not changed during the audit.

The audit entry is the parent workspace's
`.scratch/selective_analysis/audit_frame_bounds_v9.py`. Original summary SHA-256 is
`4e624a50cc4726d165cac0e628198401abdc6cf67500ebcf2e4807334fcd4dbb`;
original runs SHA-256 is
`f939240509f052133bd7cb00f5f5e8663f3e8cf0c67ddf5ce329a91a7b2a9271`.
The existing WSL environment can run `python -B scripts/run_frame_bounds_gate.py` to
replicate the declared source/query protocol without model acquisition or new binaries.

## V9 WSL replication and timing sensitivity

The user-run WSL entry completed at
`D:/AI_Models/symbolic/.scratch/selective_analysis/frame-bounds-gate-v9-20261111-143422-1488/`.
All 27 records remain present, covering the same three binaries/query contracts, three
methods and three repetitions with the same rotated schedule and offline labels. All
21 source/specification hashes match the Windows source snapshot and current sources.
Property conclusions, local unknowns, action orders and zero-prefix-reuse fallback agree.
No wrong decisions or timeouts occurred. Parent cleanup/recovery remains fully charged.

| Control | Resolved / repeated queries | Unknown | Total wall time | Median wall time |
|---|---:|---:|---:|---:|
| expanded_only | 9/9 | 0 | 10.6096 s | 0.9785 s |
| frame_bounds_only | 3/9 | 6 | 8.7101 s | 0.9300 s |
| frame_bounds_then_expanded | 9/9 | 0 | 9.2143 s | 1.0298 s |

### Interpretation of the timing difference

The full primary aggregate is 13.15% lower for fallback, but it does not establish a
stable improvement. The first full run (repetition 0, direct-index query) costs 2.7318 s,
while its paired fallback costs 1.0788 s. That is the **only one of nine matched pairs**
where fallback is faster. The overall fallback median is higher, and each query's fallback
median is also higher than its full-check median. The exact cause of the unusually slow
first run was not separately profiled; it must not be attributed to a particular import,
cache or solver phase from the aggregate alone.

An explicitly post-hoc sensitivity calculation removes that same query/repetition from
both methods. The remaining eight pairs sum to 7.8778 s for full and 8.1355 s for fallback,
which is 3.27% higher for fallback. This is a sensitivity diagnostic, **not a replacement
result**: no record was removed from the primary run, evaluator or summary. It shows why
the original total alone is insufficient evidence for speed. Frame-only also resolves
fewer queries and cannot be ranked as an equivalent faster solver from its total time.

The operation is functionally usable on the compiled masking case. Stable net savings,
neural guidance and held-out generalization remain unestablished. A declared shared-process
batch can next distinguish process overhead from repeated analysis costs, retaining real
startup and finalization charges. No import time should be subtracted after measurement
to invent a warm-run result. The existing three inputs and frozen methods suffice for
that cost diagnostic.

### Certificate reproduction and retained artifacts

The audit reconstructs the successful frame certificate on Windows and freshly validates
the reconstructed proof. Its semantic content, instruction trace, entry RSP, stack/image
separation and address intervals match the WSL certificate. The single differing metadata
field is the recorded `entry_context.angr_version`: WSL 9.2.212, Windows 9.2.217. The audit
compares all other fields exactly and preserves both version strings and the original
certificate/hash; it does not rewrite or re-sign the WSL proof as a Windows result.

Added sidecars are `validated-audit.json` and `timing-sensitivity.json`. Original plans,
source snapshots, inputs, requests, event ledgers, results, labels and evaluations are
unchanged. The audit entry is the parent workspace's
`.scratch/selective_analysis/audit_frame_bounds_v9.py`; the descriptive timing entry is
`.scratch/selective_analysis/frame_timing_sensitivity_v9.py`.

Original summary SHA-256 is
`2156c6a43609ec1930d8e97630b71704ba7666a649088f8ccffb9be646976dc0`;
original runs SHA-256 is
`1e11a75585761075c022c1f59b4d6df1df29aad0e29d8f368c2448e0702d231d`.
WSL v9 replication is now complete. No measured runtime source, checker, selector or
parameter was changed during this audit.

## V10 correctness review, explicit batches and Windows results

The v10 plan was declared before implementation and measurement. Two Codex child tasks
were used for a bounded independent review and implementation/testing of the new batch
core. The main agent inspected their code/results, requested stricter evidence and
sequential-timing validation, independently reproduced the review finding, and ran the
complete suite. Child output was not treated as an approval or empirical result by itself.

### Correctness finding and conservative fix

The review identified an accepted ELF layout where PT_DYNAMIC described a relocation
table that was not covered by the section table inspected by the old file-byte checker.
The reference loader changed instruction bytes, while the abstract checker and its fresh
same-implementation recheck both interpreted the unchanged file bytes. The main agent
reproduced a false exclusion relative to BinaryChecker on a unit-only layout. This is a
concrete correctness finding, distinct from the three ordinary GCC developer inputs.

V10 now requires active dynamic relocation tables to match section metadata and mapped
file bytes, rejects unsupported formats/write widths and the whole span of executable
relocations, and compares every frame-decoded instruction with actual reference memory.
The local/frame operation revisions are `unsigned_local_bounds_v10_relocation_guard` and
`compiler_frame_bounds_v10_loader_consistency`. Unverifiable dynamic layouts can return
unknown, including sectionless inputs. The guard is deliberately restricted and does not
claim general ELF verification. Symbolic query semantics and A-D selection are unchanged.

Regression tests retain the dynamic-table mismatch, section-byte disagreement, relocation
overlap across an executable boundary, unsupported write width, accepted data relocation
and direct loaded-byte disagreement. The old v9 measurements and source snapshots remain
unchanged. Their known GCC program facts were independently verified before this fix;
new measurements use the corrected implementation and must be identified accordingly.

### Batch protocol and validation

One cold process executes all three existing queries once. Three fixed controls and
three rotated repetitions produce nine batch receipts and 27 query outcomes. Both method
order and within-batch query order rotate. Each batch receives 15 s end to end. Projects,
states, prefixes and explicit evidence are not shared across different queries; imports
and ordinary library caches can warm. The same-query fallback may reuse its already paid
project but no executed prefix. No new inputs, compilation, neural inference, training,
API or GPU work is part of this diagnostic.

The primary cost includes the complete parent interval through process exit, recovery,
initial finalization and provisional receipt serialization. Final timing stamping/receipt
writing and experiment orchestration/offline evaluation are explicitly outside that
boundary. Query-local intervals are components, not free-start primary costs. Every
requested identity survives failure. Flushed, complete rows may recover under-budget
partial failures; missing/truncated/mismatched evidence and overlapping/inverted intervals
are rejected. Any over-budget parent batch demotes decisive outcomes to unknown and
retains their original evidence. Gold is loaded only after all workers exit.

The full suite passed **253 tests**: 250 focused tests plus three historical smoke checks.
The new batch runtime has 66 tests, its CLI/evaluator eight, and the ELF guard seven.
They cover actual unit ELF semantics, fresh per-query projects, global remaining budget,
partial-flush recovery, stale/crashed worker files, malformed identities/evidence, timing
overlap and late completion. Nine OPM DOT views validate and render, with 177 view-local
entities and 260 links. These model checks cover the declared profile and data routes,
not full OPM semantics or an independently verified proof system.

### Primary Windows run

The primary run is
`D:/AI_Models/symbolic/.scratch/selective_analysis/frame-batch-v10-20261111-161225-61120/`.

| Control | Batches | Resolved / repeated queries | Wrong | Unknown | Total batch wall time | Median batch wall time |
|---|---:|---:|---:|---:|---:|---:|
| expanded_only | 3 | 9/9 | 0 | 0 | 6.214 s | 2.058 s |
| frame_bounds_only | 3 | 3/9 | 0 | 6 | 5.639 s | 1.882 s |
| frame_bounds_then_expanded | 3 | 9/9 | 0 | 0 | 6.096 s | 2.030 s |

No batch timed out or exceeded its budget. The same masked query is the only locally
excluded input; the two modeled violations use full fallback. Full and combined costs
remain close in this small developer diagnostic; no stable net gain, neural value or
generalization follows. These are three unique queries and three batch repetitions per
method. V9 and v10 change both accounting unit and the correctness guard, so their totals
are not a matched algorithm-speed comparison. WSL batch replication remains pending.

An earlier run at `frame-batch-v10-20261111-161127-28368/` was launched before the parent
confirmed that the full-test process had exited. It is retained with all original records
and marked in `run-context.json` as potentially load-confounded and ineligible for primary
timing interpretation. The repeat rule was declared before the second execution: repeat
all nine unchanged batches after test exit, independently of timing direction. Runs are
not pooled and no result was selected by speed. The primary run's own context records
the confirmed test exit and this provenance.

### Audit and artifacts

The primary audit verified all **22 source/specification hashes**, copied binary/query
identities, fixed orders, all nine batch receipts and all 27 outcomes. Reconstructing
parent finalization from the retained worker files, flushed events and charged clocks
reproduces each receipt exactly. Query durations never replace complete batch charges;
provisional serialization occurs before the authoritative clock. Action evidence confirms
zero prefix reuse in full checks and no neural inputs. The unique successful frame
certificate fingerprint was independently reconstructed/validated after the run.

Artifacts include `run-plan.json`, `source_snapshot/`, copied inputs, per-batch requests,
worker logs/results, flushed event ledgers, provisional and final receipts, `batches.json`,
offline gold, the original summary, `run-context.json` and added `validated-audit.json`.
Original measured files were not modified during audit. The audit entry is the parent
workspace's `.scratch/selective_analysis/audit_frame_batch_v10.py`.

Original summary SHA-256 is
`331d20d38e1ad44830207baeb004f9732876b6ff77f09fcbaec1c290bf260f4e`;
original batches SHA-256 is
`3b1931bf6c04aa5b57d43dedf6ef5c6534ab45600aa61c07abe78c6721232e05`.
WSL can replicate with `python -B scripts/run_frame_batch.py` in the existing angr-env.

## V10 WSL batch replication and decision checkpoint

The user-run WSL diagnostic completed at
`D:/AI_Models/symbolic/.scratch/selective_analysis/frame-batch-v10-20261111-162901-1557/`.
All nine batches and all 27 query outcomes are retained. All 22 source/specification
hashes match archived copies and the Windows measurement. Binary/query identities,
within-batch query orders, method schedule and offline labels agree across environments.
Every batch completed under 15 seconds without validation errors, timeouts or budget
overrun. Reconstructing finalization from worker results, flushed events and recorded
parent clocks reproduces every final receipt exactly.

| Control | Batches | Resolved / repeated queries | Wrong | Unknown | Total batch wall time | Median batch wall time |
|---|---:|---:|---:|---:|---:|---:|
| expanded_only | 3 | 9/9 | 0 | 0 | 4.7704 s | 1.2392 s |
| frame_bounds_only | 3 | 3/9 | 0 | 6 | 3.3775 s | 1.1418 s |
| frame_bounds_then_expanded | 3 | 9/9 | 0 | 0 | 3.8346 s | 1.2922 s |

The unknown frame results occur after recognized instructions reach an address interval
not proved inside the object, not because the new byte/loader guard rejects the normal
GCC inputs. The masked query is excluded locally in every repetition. Full results and
fallback witnesses use fresh modeled validation with zero prepared-prefix reuse. No
neural information is used, and query-local durations do not replace complete charges.

### Paired timing interpretation

| Matched repetition | Full batch | Fallback batch | Fallback relative difference |
|---|---:|---:|---:|
| 0 | 2.2920 s | 1.3001 s | -43.28% |
| 1 | 1.2392 s | 1.2423 s | +0.25% |
| 2 | 1.2392 s | 1.2922 s | +4.28% |

The original primary total is 19.62% lower for fallback, while the median is 4.28% higher.
Only the first matched batch favors fallback. A separate post-hoc sensitivity calculation
removes repetition 0 from both methods: the remaining full/fallback totals are 2.4784 s
and 2.5345 s, giving fallback 2.27% higher cost. This calculation is **not a replacement
result**. No original batch, query outcome or primary evaluation was discarded or
rewritten. It demonstrates sensitivity to one initial batch; these records alone do
not identify the cause as a particular import, cache effect or solver phase.

An independent Codex child review recomputed these matched values and reached the same
interpretation. Primary artifact/proof validation was performed separately by the main
agent. Frame-only has fewer resolved outcomes, so its lower time is not an equivalent
faster-solver comparison. Three authored inputs and three batch repetitions cannot
establish a stable speed advantage, generalization or a neural-selector contribution.

### Cross-environment proof reproduction

The successful WSL certificate is reconstructed on Windows and its new reconstruction
is freshly validated. All certificate semantics, instruction trace, entry stack facts,
declared bounds and result agree exactly except the recorded
`entry_context.angr_version`: WSL 9.2.212 and Windows 9.2.217. Only that metadata field
is omitted from the semantic comparison; both version values, the original certificate
and its fingerprint remain preserved. No WSL proof is rewritten as a Windows proof.

### Artifacts and next gate

Added sidecars are `validated-audit.json` and `timing-sensitivity.json`. Original source
snapshots, copied inputs, requests, event ledgers, worker/provisional/final receipts,
batch collection, labels and summary remain unchanged. The audit entry is the parent
workspace's `.scratch/selective_analysis/audit_frame_batch_v10.py`; the post-hoc timing
entry is `.scratch/selective_analysis/frame_batch_sensitivity_v10.py`.

Original summary SHA-256 is
`0910b715b93fe091f4fb8528e07b747d2ac9aa1e415b660e2458202068fccedf`;
original batches SHA-256 is
`67d88b25665f8388503ebda8cc30ed0a7afb94d4871048a55ed86735b3f490f4`.

The accounting and functional batch replication capability is completed. Keep the
current infrastructure stable and return to operation-value feasibility: establish
meaningful local/full-check tradeoffs at comparable checkpoints, then test the
incremental value of genuine neural type information over the same structural and
conventional-type inputs. The current three queries remain integration/developer inputs;
they are not a basis for training a benefit predictor or claiming held-out performance.

## V11 operation evidence, work attribution and paid-proof consequences

The v11 plan was declared before implementation and measurement. Independent Codex child
tasks reviewed the scientific design, implemented the offline evaluator and implemented
the conditional compiled-proof panel. The main agent reviewed the implementations,
clarified incomplete-cost/work handling, added probe/CLI integration tests, ran the full
suite and audited the measured data. The existing A-D selector and catalog were unchanged.

### Protocol and checks

All twelve existing generated mechanisms remain the primary denominator. Each worker
captures pre-action structural features and probes five fixed alternatives from separate
fresh function-entry checkpoints/projects. Three rotated repetitions produce 180 records
in 36 workers, each capped at 20 s including startup, shared features, all alternatives,
validation and recovery. Missing/late records remain in the denominator. Gold is read
only after all runtime workers stop. No new cases, compilation, inference, training,
package installation, API or GPU work is part of this experiment.

Probe-local costs include required setup, preparation, execution, validation and provisional
record serialization. Shared worker/feature costs are separately retained and are not
free deployment inputs. This is an operation-effect dataset, **not an end-to-end policy
throughput experiment**. RDA graph counts and snapshots are planning artifacts, not
validated query conclusions. Observed symbolic execution counts include paid preparation,
main execution and fresh validation; abstract interpreter counts are kept separate.

The new direct-prefix-without-RDA control executes every eligible straight-line prefix
instruction and copies reached states, without a dependency analysis. It never skips an
instruction and publishes the cache only after reaching the target. Both composites
reuse only their own paid prefix; final validation reuses zero prefix steps.

The full suite passed **375 tests** (372 focused and three historical smoke checks).
The 122 new checks comprise 22 runtime/integration, 78 offline evaluator and 22 conditional
proof-audit tests. They enforce fixed coverage, canonical empty checkpoints, missing and
late evidence, full cost/work observability, actual opcode semantics, causal prefix
controls, preserved raw inputs and rejection of free semantic/neural feature inputs.
Ten OPM DOT views validate and render with 202 view-local entities and 289 links. The
profile validator now rejects retained-mapping-proof routes into runtime probes/features.
These checks do not establish full OPM semantics or a general proof system.

### Measured Windows operation effects

The root is
`D:/AI_Models/symbolic/.scratch/selective_analysis/operation-effects-v11-20261111-182644-6312/`.
The experiment began only after the full test process exited. All 180 rows and all 36
workers completed with no wrong validated decisions, timeouts or source changes.

| Probe | Resolved / repeated queries | Wrong | Unknown | Median probe-local time |
|---|---:|---:|---:|---:|
| bounded_paths | 33/36 | 0 | 3 | 0.090097 s |
| expanded_paths | 36/36 | 0 | 0 | 0.097572 s |
| definitions_then_expanded | 36/36 | 0 | 0 | 0.119756 s |
| direct_prefix_then_expanded | 36/36 | 0 | 0 | 0.093777 s |
| local_bounds | 12/36 | 0 | 24 | 0.005348 s |

The three bounded unknowns are the same long-prefix query across repetitions. All **33
shared bounded/full correct answers use identical counted execution/validation steps**.
A smaller depth cap is therefore not a cheaper semantic operation on those shared
successes. Both prefix composites have zero total counted-step difference from full
checking on each of their 36 matched pairs: preparation executes the prefix instead of
making its work disappear. RDA also performs its planning work, and its median full
probe cost is higher than both expanded and direct-prefix cost on every one of the
twelve queries. These are descriptive observations for this fixed, one-query workload;
they do not rule out reuse across multiple later analyses under another declared unit.

Local bounds supplies four stable exclusions: m02, m06, m09 and m10. Each has an observed
three-repeat cost range strictly below its full-check range. This is descriptive range
separation, not statistical significance, a selector result or deployed-policy speedup.
The direct-prefix control also has such ranges on m06 and m10, but identical total
execution work and m10's ineligible prefix show why timing separation alone cannot be
called a new analysis contribution. The predeclared structural first-choice hint settles
ten inputs on its first recorded operation; this is a trace-level diagnostic, not a
measured fallback policy or a learned-accuracy result. The two unknown first choices
remain recorded and would need further checking.

### Separate compiled-input proof panel

The three compiled integration inputs are not pooled with the twelve primary mechanisms
and are not remeasured as probe examples. Their existing bundle/raw hashes, query identity,
recorded proof and straight-line retained trace are checked. Conditional arithmetic on
the verified object/index/address/one-byte facts yields direct witness RDI=8, offset
witness RDI=4 and complete mask exclusion, without consulting neural labels/scores or
executing a symbolic prefix. No new program-validation claim is made by this panel.

All three queries are therefore already decidable **after their prior paid semantic
mapping proof**. Those facts cannot be free inputs when claiming a downstream neural
scheduling contribution. This is a prospective information/cost boundary: the frozen
earlier runner did not consume the complete common-facts artifact, so the panel does not
demonstrate leakage in its previous results. Future work must limit correspondence to
location identity, or pay for semantic verification and include its facts-to-decision
baseline. Raw neural predictions and original proofs remain unchanged.

### Audit, provenance and next boundary

The audit verified all **26 source/specification hashes**, copied query/binary contracts,
all request orders, empty checkpoints, 180 recovered records, 36 parent receipts and the
offline evaluator output. Probe times never replace or duplicate parent worker charges.
It also verifies the separate three-input deduction panel, original bundle hashes and
the absence of a new program verification claim. Original measured files remain unchanged;
the added sidecar is `validated-audit.json`. Its entry is the parent workspace's
`.scratch/selective_analysis/audit_operation_effects_v11.py`.

Retained files include the plan/source snapshot, all twelve generated binaries/contracts,
requests, flushed events, worker results, provisional/final records, parent receipts,
`records.json`, `evaluation.json`, offline gold and `compiled-proof-panel.json`.
Original records SHA-256 is
`6961bd4f4f756e7f7f94a6d6104235efd8fca15babb73ea8911baadfdb75ae43`;
evaluation SHA-256 is
`94e74e1d58675cd9983967ced83a08e093836c0146711264a3f84d7b084917dd`;
summary SHA-256 is
`6916865f2a4458131f87c857b14695576c8dc1a7228ed020b8c5cbcba30e6983`.

Operation applicability is partially established, but new neural scheduling or RDA value
is not. Revise the semantic-mapping boundary and useful operation choices before adding a
selector or training a benefit model. Keep the small case budget and accounting framework.

## V11 WSL operation evidence replication

The retained WSL root is
`D:/AI_Models/symbolic/.scratch/selective_analysis/operation-effects-v11-20261111-184101-2283/`.
All 180 probes and 36 workers completed. The audit verifies the same 26 archived source
and specification hashes as the Windows run, identical query/order/checkpoint contracts,
and identical decision statuses and counted execution work. No failed attempt was removed.

| Probe | Resolved / repeated queries | Wrong | Unknown | Median probe-local time |
|---|---:|---:|---:|---:|
| bounded_paths | 33/36 | 0 | 3 | 0.099494 s |
| expanded_paths | 36/36 | 0 | 0 | 0.104358 s |
| definitions_then_expanded | 36/36 | 0 | 0 | 0.134515 s |
| direct_prefix_then_expanded | 36/36 | 0 | 0 | 0.102993 s |
| local_bounds | 12/36 | 0 | 24 | 0.021430 s |

All 33 shared bounded/full successes again perform the same counted steps. Both prefix
composites have zero total counted-work difference from full checking in all 36 pairs.
RDA's median probe cost exceeds both full and direct-prefix cost on every unique query.
Local checking has the same four stable exclusions, m02/m06/m09/m10, with three-repeat
observed cost ranges below full checking in both environments. Its 24 unknown records
split equally between unsupported behavior and insufficient interval precision. The
Windows direct-prefix timing separations do not replicate as separated ranges in WSL.
These are descriptive operation observations, not deployed policy speedups.

The separate compiled panel again derives direct witness 8, offset witness 4 and mask
exclusion from the already-paid mapping facts alone. This reproduces the need to remove
semantic target proofs from a supposedly location-only acquisition stage. It establishes
no GNN information value. Twelve unique mechanisms, rather than 180 independent samples,
remain the primary denominator; the three compiled inputs remain a separate panel.

The audit sidecar is `validated-audit.json`; original measured files are unchanged.
`records.json` SHA-256 is
`67b20155eac369981bff2063bcd4a47917eaf37d906f21f9f5af861097a6cf70`;
`evaluation.json` is
`bb59a9af1837c5632b0ac962ff0a6111046381612c0a1eda25ad361341a1e9b2`;
`summary.json` is
`d0429e695e9d5dbb83b5ebd221380dbb923cacdcf2e7be4e1757bb56a610293e`.
The next declared gate is v12 static location correspondence, followed by useful,
nonredundant operation choices. The frozen A-D selector remains unchanged.

## V12 static location correspondence

The [v12 specification](architecture/pilot_revision_v12.md) was declared before implementation
and this diagnostic. It separates correspondence from the target-semantic proof exposed
by v11. No old proof, operand plan, object/index anchor or prior property result enters the
new runtime. The fixed query contract remains an identity input; its capacity, object
address and input ranges do not choose associations.

`location_correspondence.py` uses Capstone and pyelftools, guarded ELF relocation coverage,
and a maximum 64-instruction static walk of a canonical AMD64 frame. It tracks syntactic
load origins through registers, replacing overwritten origins and refusing partial slots,
unknown address contributors, frame changes, unsupported flow and ambiguous locations.
Exact function/CFA/half-open PC ranges must cover each load and the declared write site.
This does not establish path feasibility, object identity, index value or write bounds.
The current locator metadata remains **DWARF-assisted**, not fully stripped recovery.

The distinct `symbai.location_type_bundle.v1` preserves the raw payload and uses neutral
load-occurrence identities rather than semantic base/index roles. C and D freshly rebuild
the static correspondence before projection. A/B expose no views, C exposes Top-1 labels
without scores, and D retains each prediction's own Top-K raw logits and conditional
softmax weights. No predictions are merged, corrected or made solver facts. The old mapped
type reader rejects this schema. Neither this bundle nor its views enter the frozen selector.

### Validation and review

The main agent implemented the mapper and entry and reviewed the delegated 31 CLI tests.
A subsequent read-only sub-agent review found no concrete implementation issue; the main
agent independently audited the measured artifacts. Other delegated implementation/review
tasks reached their usage limit before delivering code, and were taken over by the main
agent. No agy calls, packages, model execution, GPU use or new cases were needed.

The 67 new tests cover names/labels/scores being irrelevant to association, overwritten
registers, half-open ranges, ambiguous/missing CFA identities, changed binaries/raw inputs,
old proof fields/schemas, forbidden imports, independent C/D projection and the three-case
failure denominator. The **full suite passes 442 tests** (439 focused and three legacy
smoke checks), with 19 third-party deprecation warnings. The initial full attempt had one
existing v6 accounting-test failure: charged finalization reached 0.594525 s against its
0.5 s budget and correctly demoted the outcome to unknown. A targeted rerun reproduced the
failure. That functional test now has a 5 s budget plus an explicit preparation-not-charged
assertion; no runner, timeout or experimental budget changed. Failed logs remain under
`.scratch/selective_analysis/tests/information-50379751fca2/` and
`information-55faeaabd940/`. The complete suite then passed; the last CLI metadata addition
also passed all 31 CLI tests. All test processes exited before the real diagnostic.

Eleven OPM DOT views validate and render with 221 view-local entities and 311 links. The
new view explicitly isolates candidate values from static association and old semantic
proofs from all runtime processes. These are architecture-profile checks, not full OPM
standard compliance or analysis soundness certification.

### Three frozen-export integration results

The retained Windows root is
`D:/AI_Models/symbolic/.scratch/selective_analysis/location-correspondence-v12-20261111-195730-82888/`.
Python 3.13.10, Capstone 5.0.6 and pyelftools 0.33 were used. All eight source/specification
hashes and all original/copied binary/raw/query bytes remain unchanged. The clean runtime
import check finds no angr, Claripy, Z3, property checker or semantic mapping module.

| Retained input | Available load bindings | A/B views | C/D views per arm | Initial static mapping | C/D projection with static rechecks |
|---|---:|---:|---:|---:|---:|
| direct_index | 2 | 0 | 2 | 0.098681 s | 0.011459 s |
| offset_index | 2 | 0 | 2 | 0.004534 s | 0.009546 s |
| masked_index | 2 | 0 | 2 | 0.004345 s | 0.009258 s |

All three planned inputs remain; none is unavailable. The same process performs all
three projections, so the first timing includes lazy library imports and later timings
share that process. They are one diagnostic observation, not repeated cost estimates,
policy throughput or a speedup comparison with semantic proving. The 0.214782 s recorded
runtime includes projection/recording after input/source snapshots; it excludes historical
GNN acquisition and overall command startup. No end-to-end neural gain follows.

A separate post-hoc audit opens the old semantic bundles **after** the new records exist.
All six unordered prediction-ID/CFA-offset pairs agree. It also checks copied bytes,
fingerprints, every static trace instruction against ELF bytes, each load's RBP displacement,
and each C/D label/logit/conditional weight against its own original prediction. No old
anchor or result is used to construct a binding. The sidecar is `validated-audit.json`;
the audit entry is `.scratch/selective_analysis/audit_location_correspondence_v12.py`.
Original records SHA-256 is
`8c98ff1f767b214a6742fed6fa2d0365c38a55848a489ecb5324813443293d15`;
summary SHA-256 is
`e8815bac110a1afbfd3ab7734063778ccf6e7f54ab3a47ae4842a718c77e1bed`.

This establishes the restricted correspondence boundary on the same three integration
inputs. It proves neither neural value, general mapping completeness nor held-out behavior.
The WSL replication below independently validates the Linux artifact boundary. Before a
new B/C/D experiment, the next scientific requirement remains a small, nonredundant operation
menu with useful and predictable tradeoffs. RQs, the primary case budget and frozen selector
remain unchanged.

## V12 WSL correspondence replication

The retained WSL root is
`D:/AI_Models/symbolic/.scratch/selective_analysis/location-correspondence-v12-20261111-200207-2431/`.
Python 3.10.20, Capstone 5.0.6 and pyelftools 0.32 were recorded, compared with Windows
Python 3.13.10 and pyelftools 0.33. All **eight source/specification hashes** and every
original binary, raw-export and query-manifest hash match the Windows diagnostic. All
three inputs remain available with two neutral load-occurrence bindings each.

| Input | Bindings | Initial static mapping | A-D projection with C/D static rechecks |
|---|---:|---:|---:|
| direct_index | 2 | 0.182481 s | 0.051081 s |
| offset_index | 2 | 0.014776 s | 0.048902 s |
| masked_index | 2 | 0.015105 s | 0.048844 s |

The recorded projection/recording segment is **0.503939 s**, excluding source/input
snapshots, command startup and historical neural acquisition. The first mapping includes
lazy library import work and subsequent mappings share the process. These single-process
observations do not establish an environment speed comparison, repeated cost estimate,
end-to-end neural gain or policy throughput.

The main agent's offline audit checks every copied input and source snapshot, request/query
identity, bundle fingerprint, instruction byte, RBP load displacement, raw candidate label,
logit and conditional weight. It finds no forbidden runtime imports or changed sources/inputs.
All six unordered prediction-ID/CFA pairs agree with the prior semantic bindings, consulted
only after the new projection records exist. No old proof supplies a runtime matching fact.

Cross-environment comparison finds identical static bindings, occurrences, traces, raw
payloads and parsed A-D views. Only the local binary filepath and its dependent bundle
fingerprint are excluded from bundle-content comparison. Original path-dependent
fingerprints and serialized file hashes are preserved and checked independently. Serialized
JSON bytes may differ across platforms; canonical content is compared without rewriting
the measured files. Different runtime metadata and timings are retained rather than forced
to agree. This audit constructs no new property proof and performs no GNN inference.

The added sidecar is `validated-audit.json`, produced by the existing parent-workspace
`audit_location_correspondence_v12.py` with explicit WSL-path translation for file access.
The original `records.json` SHA-256 is
`f73fa7eaab08ed200c7e4e851ddc45df915cf092c2efe5c13ff1b1d3aefff990`;
`summary.json` SHA-256 is
`d119734c4dca46c6c44fef4731f4da74e94a6fce512f7d4e4685fe3f630a5346`.
All measured originals remain unchanged.

V12's restricted location-correspondence gate is complete on both environments. It still
covers only the three existing DWARF-assisted integration inputs, with no selector
integration, property decision, mapping-completeness or held-out claim. The next research
gate is useful nonredundant operations and type information that adds value beyond the
same structural features. Preserve the 12-mechanism primary denominator and separate
three-input integration panel; another correspondence rerun is not needed without a
new failure, change or declared question.

## V13 routing sensitivity gate

The [v13 specification](architecture/pilot_revision_v13.md) preceded implementation and
this diagnostic. The three retained inputs/predictions were already known development
data, not an unseen preregistered or held-out set. The gate asks whether genuine types
change a simple shared operation order beyond strong structural information before
another execution study. It does not implement a learned policy or claim algorithm novelty.

### Implemented boundary and validation

The separate `routing_sensitivity.py` policy orders the existing frame interval checker
and full first-visit checker. No checker is imported or executed. One B/C/D function uses
the same static syntax features, catalog, tie-break and constants. B is scored before raw
candidate JSON is parsed. C/D use fresh v12 location-only binding and independent occurrence
projections of the frozen exports. The old frozen selector, runner, property operations and
their measured sources remain unchanged. No semantic proof, gold label, prior property
outcome, new model run, training, compilation, package or GPU is used.

Full checking has score 1; frame syntax has structural score 1.25 with an immediate mask,
0.75 otherwise when supported, and 0 when unsupported. C/D add a bounded heuristic mix
of pointer and scalar-integer support from distinct occurrences. Pointer-to-integer
labels count only as pointers. D's supplied conditional weights must match its finite,
ranked raw logits; arbitrary weights and duplicated candidate labels are rejected. This
is not a calibrated utility, semantic type rule or independence assumption. Each occurrence's
prediction ID and original candidate identity remain available in the records.

The complete fixed grid is [0, 0.25, **0.5 primary**, 1, 2]. Masked cases are frame-first
for all nonnegative weights by construction; unmasked cases switch only if weight times
the signal exceeds 0.25. Zero/0.25 cannot switch. These known score constraints are part
of the specification, not a post-hoc explanation of results. No weight is selected for
test performance, and no case is removed for disagreeing with a preferred result.

The main agent reviewed 75 delegated module tests, added 17 CLI tests and corrected the
reported validation issues before the real diagnostic. The 92 new cases use fabricated
TypeViews and authored ELF bytes, never empirical model evidence. They cover disjoint
labels, exact conditional weights, strict thresholds/ties, score-only and label-only
changes altering a choice, query/name/bounds independence, B-before-raw ordering, strict
requests, unsupported features, lost mappings, D-only failure and full failure denominators.
**All 534 tests pass** (531 focused plus three legacy smoke checks), with 19 third-party
deprecation warnings. The final CLI integrity addition passed all 17 CLI tests. All test
processes exited before the genuine frozen-export diagnostic.

Twelve OPM views validate/render, with 241 view-local entities and 338 links. The new
view isolates raw-free feature/B processing from C/D preparation and routes type views
only into the shared ordering process. It models orders and diagnostics, not executed
properties or full OPM standard compliance.

### Observed Windows orders and type signals

The retained root is
`D:/AI_Models/symbolic/.scratch/selective_analysis/routing-sensitivity-v13-20261111-201922-83476/`.
All three planned inputs and all 45 routing rows completed: 30/30 C/D-versus-B grid
comparisons are available, **zero orders changed**, including the primary six comparisons.
These are three distinct query hashes, not 30 independent test examples.

| Input | Mask cue | C signal | D signal | B/C/D order throughout the fixed grid |
|---|---|---:|---:|---|
| direct_index | absent | 0 | 0 | expanded_paths, then frame_bounds |
| offset_index | absent | 0 | 0.105496326 | expanded_paths, then frame_bounds |
| masked_index | present | 1 | 0.994956921 | frame_bounds, then expanded_paths |

For direct indexing, both views have zero contributor-mixture signal. For offset indexing,
Top-K includes a scalar `u64` alternative even though both Top-1 labels are pointers. D
therefore changes the score but not the order on this grid. Its algebraic strict switch
threshold is **2.369750775**, above the fixed maximum 2. The grid was not enlarged to
manufacture a difference. Only the direct input and masked structural dominance imply
invariance at every finite nonnegative weight under this policy; the offset D case does
not. More candidate information in an intermediate score is not evidence of useful routing
or a positive RQ2 answer. The mask result is already determined by B's structural preference.

An initial offline audit assertion incorrectly assumed zero unmasked D support in both
inputs. The retained rows exposed the offset scalar alternatives; that assumption was
corrected in the audit, without changing policy, weights, inputs or any measured row.
The informal earlier statement that all unmasked Top-K candidates were pointers was also
corrected. The final independent audit recomputes the distinct signal/threshold above.

The single-process diagnostic-through-records clock is 0.180568 s, including static feature
capture, shared C/D binding, separate projections/rechecks, grid scoring and record
persistence/summary preparation. It excludes input/source snapshots, command startup,
historical neural acquisition and final summary serialization. Lazy imports are shared
after the first case; no repeated cost estimate or per-arm end-to-end comparison follows.
The recording/summary-preparation component is 0.013239 s. No source/input/copy changed,
and no forbidden property-engine import occurred.

### Independent audit and scope decision

The main agent's separate offline audit verifies ten source/specification hashes, all
original/copied binary/query/raw identities, three distinct queries, static instruction
counts/mask syntax, CFA/load matches, untouched candidate labels/logits/conditional
weights, shared hashes and all 45 score/order calculations. It recomputes signals directly
from raw predictions without calling the production selector. The sidecar is
`validated-audit.json`; the parent-workspace entry is
`.scratch/selective_analysis/audit_routing_sensitivity_v13.py`.
Original `records.json` SHA-256 is
`9f9615d8174d73d251b7fdfae3de16a6f48d1ead9f219b2c6c0915779a9d6793`;
`summary.json` SHA-256 is
`f43e8a6941f62845c587bf5e284fa9b43f59d65530558540b8770ea61fbda6ac`.

This gate finds no ordering effect from neural views under this heuristic on these known
inputs at the declared weights. Identical complete orders imply the same two-operation
fallback sequence given equal checker outcomes/stops; they do not establish actual timing,
property quality, acquisition-inclusive performance or the impossibility of useful neural
guidance. The frozen primary runner/RQs remain unchanged. No redundant checker experiment,
weight tuning or trained selector is justified by this panel alone. A later declared study
needs an operation-specific information hypothesis and a small panel chosen for analysis
needs rather than favorable neural outputs. The twelve generated mechanisms and three
compiled integration cases remain separate. WSL can replicate this cheap gate with
`python -B scripts/run_routing_sensitivity.py`; the completed Linux replication is below.

## V13 WSL routing sensitivity replication

The retained WSL root is
`D:/AI_Models/symbolic/.scratch/selective_analysis/routing-sensitivity-v13-20261111-203008-2439/`.
All ten runtime source/specification hashes match the Windows run. All three query hashes,
original/copied binaries, query manifests and frozen raw-export hashes also match. Python
3.10.20, Capstone 5.0.6 and pyelftools 0.32 were recorded; their Windows counterparts remain
preserved separately. No source, input or copied input changed and no forbidden runtime
module was imported.

The main agent audited the WSL artifacts directly on D. It independently recomputes all
45 scores/orders from binary syntax and raw candidate labels/logits, validates every CFA
load correspondence and conditional weight, and verifies policy/features/catalog controls.
All 30 C/D-versus-B comparisons are available with zero changed orders, including the six
primary comparisons. The same three unique integration inputs remain the denominator.

| Input | C signal | D signal | B/C/D complete order over the fixed grid |
|---|---:|---:|---|
| direct_index | 0 | 0 | expanded_paths, frame_bounds |
| offset_index | 0 | 0.1054963258630303 | expanded_paths, frame_bounds |
| masked_index | 1 | 0.994956921004449 | frame_bounds, expanded_paths |

The offset D strict weight threshold again equals 2.369750775250543. It is outside the
predeclared [0,2] grid; it does not imply weight invariance beyond that grid. Masked order
agreement is already forced by the structural baseline, while direct indexing has zero
type signal. The distinct causes are preserved rather than pooled into a general claim
that candidate scores are useless.

Parsed case records match Windows exactly after removing only measured stage costs:
features, binding IDs, independent projections, signals, scores, geometry, ordering and
hash controls all agree. All non-timing fields of the comparison summary also agree.
Original serialized artifacts are not rewritten to obtain that match; platform-specific
paths in requests/plans, file hashes, runtime metadata and clocks remain retained.

The WSL diagnostic-through-records clock is 0.442573 s, including a 0.100349 s
recording/summary-preparation component. As in Windows, this clock excludes source/input
snapshots, historical model acquisition, command startup and final summary serialization.
This single run establishes no repeated timing estimate, cross-environment speed comparison,
property improvement or end-to-end gain. No property operation or new neural inference
was executed on either platform.

The added audit sidecar is `validated-audit.json`; the existing parent-workspace audit
entry accepts the Windows run as its second argument for explicit cross-environment checks.
Original `records.json` SHA-256 is
`b90a88107c582a0b29cfb1150945a20e034c8bcccb37389be8ef53e54b98e4f7`;
`summary.json` SHA-256 is
`7e4f3c48bfd70f8e23367633ee6dedda6f54e4f13ae7790603cdbe821efda192`.
All measured originals remain unchanged. This turn changes audit/documentation metadata
only; the previously passing 534-test runtime suite is not represented as newly rerun.
Architecture validation still passes all twelve views.

V13's routing-only gate is complete on both environments. It supports the bounded negative
result for this heuristic on three known developer inputs, while RQ1/RQ2 and independent
algorithm novelty remain unresolved. Further work needs a concrete hypothesis linking
type information to the value of a specific analysis operation, assessed against strong
structural features and fixed controls. More weight scanning or repeated property runs
on this same panel would not by itself supply that missing evidence. Preserve the small
case budget and use the existing three inputs as integration tests.

## V14 readonly-indirection mechanism gate

The [v14 specification](architecture/pilot_revision_v14.md) preceded implementation and
this measurement. It selects three new tiny authored mechanisms for a concrete capability
hypothesis, independently of neural outputs: a large scalar span, a readonly pointer chain
and an unsafe same-shape chain. These are a separate mechanism panel, neither added to the
original twelve-input denominator nor pooled with the three compiled integration inputs.
There are no model predictions, source-level type labels or held-out results for them.

### Implementation and checks

The main agent reviewed the delegated `FiniteReadonlyChecker` and all 36 unit tests,
implemented the fixture generator, literal-reference helper and isolated worker entry,
and added 17 orchestration/reference tests. The finite domain supports restricted 64-bit
straight-line moves/address calculations/arithmetic and qword loads of immutable file
bytes. Every Cartesian value set is capped at 32, with excess becoming Top. A small mask
still refines Top to its full image; no deliberately disabled transfer creates the contrast.
Correlation loss is retained conservatively, with no sampled subset or abstract witness.

The checker composes the existing ELF/decoder guard and additionally checks complete read
spans against file backing, segment permissions, address wrap and relocation writes. It
refuses mutable/unmapped/ambiguous/uninitialized reads, partial registers, non-target
stores, calls and branches. An exclusion requires every abstract target span inside the
declared object, with a full certificate and fresh checker/data/decoder recheck. It is not
a general points-to implementation, new VSA theory, relational domain or native proof.

The **full 587-test suite passes** (584 focused and three legacy smoke checks), with 19
third-party deprecation warnings. New tests cover readonly permissions/full spans and
relocations, cap saturation, Top-mask images, machine-width wrap, correlation loss,
unsupported effects, tampered data/certificates, literal AST inputs, exhaustive reference
coverage, request-label rejection and offline denominators. All tests exited before the
real mechanism run. Thirteen OPM DOT views validate/render with 261 view-local entities
and 366 links; labels cannot flow to operations or reference construction.

### Measured Windows mechanism outcomes

The retained root is
`D:/AI_Models/symbolic/.scratch/selective_analysis/indirection-gate-v14-20261111-204648-86836/`.
All twelve isolated method records and three separate reference workers completed within
their 30 s limits, with unchanged source identities and no wrong decisive results,
reference disagreements or unresolved references. Each method/case is measured once;
the twelve records are not twelve independent programs.

| Authored mechanism | Interval only | Finite readonly only | Expanded only | Fixed interval then finite | Separate modeled reference |
|---|---|---|---|---|---|
| scalar_span | excluded | unknown | excluded | excluded | excluded |
| readonly_chain | unknown | excluded | unknown | excluded | excluded |
| readonly_chain_outside | unknown | unknown | violation | unknown | violation |

Here “excluded” means only `excluded_within_scope` for the declared object/entry/domain
and first target visit. The scalar query has 1024 possible indices into a 1024-byte
object; intervals represent them compactly while the capped finite input becomes Top.
The safe chain reads two readonly pointers and then offsets 2/6, producing target addresses
0x402002/0x402006. Finite resolution excludes both, while the current interval checker
reports `memory_read_outside_subset`. Existing expanded checking returns unknown on that
safe chain because its conservative guard records `address_concretization`. This is a
limitation of this configured checker, not a general claim about angr or symbolic execution.

The unsafe chain changes the second offset to 12. The finite operation returns unknown
instead of turning an abstract out-of-bounds possibility into a witness or exclusion.
Expanded checking finds a freshly modeled-reexecuted violation. The separate literal
reference also finds input RDI=1, write address 0x40200c and length one. The fixed fallback
actually runs interval first: it stops there on the scalar case, and pays both interval
and finite operations on the two chains. Its two exclusions combine the observed abstract
capabilities; it is a strong non-neural control, not a learned result.

### Separate correctness references and audit

All method workers finish before any reference worker starts. The scalar reference uses
a fresh full symbolic check and validation over its 1024-input domain. The safe-chain
reference enumerates all 16 inputs with literal BVV registers and rechecks each from a
fresh state; all 16 discharge. The unsafe reference tries inputs 0 then 1 and freshly
reexecutes the witness. Literal references reject symbolic target addresses and address
concretization rather than weakening the old checker guard. They read no abstract
certificate, expected label or neural prediction. Reusing the target-property observer
provides a common scope; the reference engine is distinct from finite/interval transfer.
It remains modeled evidence and shares the declared loader/query assumptions.

Reference workers' costs are separate from runtime method rows and cannot be free
features in a later scheduling comparison. Recorded parent times include process/recovery
through the stated clock boundary, excluding final parent-record and aggregate serialization.
Preparation/execution/fresh-validation costs are retained; their sums omit process overhead.
Single-pass cold-process observations support no speedup, statistical or deployment claim.
Runtime versions were not separately emitted by each worker. The audit records its inspected
Python 3.13.10 / angr 9.2.217 / Capstone 5.0.6 / pyelftools 0.33 environment and the source's
explicit same-executable worker launch, rather than inventing per-worker version receipts.

The audit verifies all twelve source/specification snapshots, three binary/query identities,
empty checkpoints, strict requests, worker events/parent recovery, method-before-reference
ordering and all reference receipts. It independently verifies finite certificate hashes,
each readonly byte/value/segment hash and permissions, and all discharged address spans.
The two finite exclusion certificates are the same safe query in finite-only and fallback
methods, not two independent examples. The sidecar is `validated-audit.json`, produced by
`.scratch/selective_analysis/audit_indirection_gate_v14.py` in the parent workspace.
Original `records.json` SHA-256 is
`0ed8e0fdd7bfe6dba08c1ac334ddf89d09fa4ab3e4586a94c1ae6a97689e9a0a`;
`references.json` is
`fbce282f6e39d962ef491d968ec60e49b9eac39d2ec179d056c758459c47f5e4`;
`summary.json` is
`3631d9e21a81ec47eea2275917a763e874ff6cd500d69253324feff7da1f7d3b`.
All measured originals remain unchanged.

This establishes a restricted complementary-operation mechanism on authored examples.
It does not establish novelty, incremental neural information, general memory analysis,
native replay or held-out behavior. A combined domain or fixed fallback can already
handle the two safe mechanisms. A future neural comparison must therefore include strong
structure/cardinality controls and justify why types predict operation value beyond them;
the current mixed-type score is not validated by this result. The old frozen selector/RQs
remain unchanged. WSL can replicate with `python -B scripts/run_indirection_gate.py` in its
existing environment; the completed Linux validation is below.

## V14 WSL readonly-indirection replication

The retained WSL root is
`D:/AI_Models/symbolic/.scratch/selective_analysis/indirection-gate-v14-20261111-205443-2442/`.
The main agent's audit verifies all twelve runtime source/specification hashes against
Windows, all generated query/binary identities and empty checkpoints, all twelve method
records and three separate reference records. There are no timeouts, wrong decisive
conclusions, reference disagreements or unresolved references. Original measured files
remain unchanged; the added `validated-audit.json` is a separate offline audit sidecar.

Every method status and fixed fallback sequence matches Windows. Abstract operation
outcomes, traces and exclusion certificate fingerprints also match exactly, including
the readonly bytes, finite sets and cap-32 saturation. The two finite certificates still
represent the same safe query in standalone and fallback methods, not two new examples.

| Authored mechanism | Interval only | Finite readonly only | Expanded only | Interval then finite | Separate reference |
|---|---|---|---|---|---|
| scalar_span | excluded | unknown | excluded | excluded | excluded |
| readonly_chain | unknown | excluded | unknown | excluded | excluded |
| readonly_chain_outside | unknown | unknown | violation | unknown | violation |

All exclusions retain the declared first-visit/object/input scope. The safe-chain full
checker again reports `address_concretization` as its precision-loss reason; no guard is
relaxed to force an exclusion. The literal reference independently checks/rechecks every
one of its 16 input assignments. The large scalar reference remains a fresh symbolic
complete-scope check over 1024 input values. The unsafe reference again finds RDI=1 and
the one-byte write at 0x40200c. Any full-check witness is separately verified to be in
the 0..15 domain, select the outside cell and have a fresh modeled replay; equal SAT
witness choices across platforms are not required. Reference construction still follows
completion of every method worker and consumes neither gold nor abstract certificates.

| Method | Resolved / three inputs | Unknown | Total observed parent/recovery time |
|---|---:|---:|---:|
| interval_only | 1/3 | 2 | 0.737209 s |
| finite_readonly_only | 1/3 | 2 | 0.734568 s |
| expanded_only | 2/3 | 1 | 3.841506 s |
| interval_then_finite | 2/3 | 1 | 0.736069 s |

The two 2/3 rows resolve **different query subsets**. Expanded-only resolves scalar and
unsafe-chain queries; interval-then-finite resolves scalar and safe-chain queries. Their
totals therefore do not show a matched-quality speedup. A single pass with isolated cold
processes also does not establish timing stability or deployment throughput. Parent
clocks exclude final parent-record and aggregate serialization, as previously declared;
reference-panel costs remain separate. Runtime versions were not emitted per worker;
the sidecar's `inspection_environment` describes the Windows auditor, not WSL runtime
version receipts. Preserve that provenance limitation rather than filling it from memory.

The offline audit compares all static program contracts, abstract outcomes/certificates
and reference modes/domain sizes/per-input statuses while retaining each platform's
paths, receipts, timings and serialized hashes independently. Its parent-workspace entry
is `.scratch/selective_analysis/audit_indirection_gate_v14.py`, with the Windows run as
the optional second argument. Original `records.json` SHA-256 is
`aaac0469bdc1754d91f4a9a01127a3c85a9c05a890a729e87de981e527f92ffb`;
`references.json` is
`f6ea01a908257e87d7cc6f8eb7b11b2736a8ffdbcfdeaeb0890d2cce2ced12b9`;
`summary.json` is
`81db32c3d6cad82413295b8cc7c8e7e9efc4f623decc4cefd4739b6270f9452b`.

V14's restricted authored capability mechanism is now replicated on both environments.
This turn updates audit/documentation metadata only, without rerunning or modifying the
previously passing 587-test runtime suite. Thirteen OPM views still validate. The result
establishes complementary capabilities in these implementations, not neural value,
novelty, native execution proof or independent generalization. Before neural scheduling,
the next strong control should actually combine interval, finite readonly and expanded
checking after unknowns, retaining all costs and query identities. Static load structure
and cardinality may suffice for routing, and remain necessary competing information.

## V15 complete fixed cascade baseline

The [v15 specification](architecture/pilot_revision_v15.md) preceded implementation and
measurement. It freezes two methods on only the three retained v14 binary/query inputs:
expanded-only, and a fixed interval → finite-readonly → expanded sequence. Every attempt
starts at the same fresh function entry, without shared abstract facts, path snapshots,
solver states or previous results. Unknown and failed attempts advance within the same
30 s query budget; only a freshly validated decisive result stops. The existing checkers,
cap32, max128 instructions, literal reference, frozen selector and archived v14 sources
remain unchanged. The copied gold file is opaque until all method and reference workers
finish. No new program, model inference, training, package, API or GPU is involved.

### Implementation and verification

`fixed_cascade.py` implements the fixed operations, fresh evidence requirements, paid
failure paths and observed runtime metadata. `run_fixed_cascade.py` owns isolated worker
deadlines, immutable inputs, exact payload persistence and final availability. The pure
`cascade_evaluation.py` checks the complete eighteen-trial/three-reference matrix, empty
checkpoint identities, fixed sequences, payload SHA-256/fingerprints, parent-authoritative
status, fresh validation tags and independent reference agreement. Wrong decisive results,
unresolved references or malformed provenance block interpretation rather than disappearing.

A Codex subagent implemented the pure evaluator and its initial tests. The main agent
reviewed that code and the tests, added a nonzero-process-exit consistency guard and its
regression test, and independently audited the real measured artifacts. The main agent
also corrected recovery of non-object event lines before measurement and added regression
coverage. Neither correction changes an archived checker or historical measurement.

The full **665-test suite passes** (662 focused and three legacy smoke checks), with 19
third-party deprecation warnings. The 78 added checks cover real cascade operation
sequences, late/failed attempts, strict requests, accounting bytes and identities,
malformed event recovery, matrix/reference validation and matched-pair accounting.
The full suite completed before the measured run started; no test process ran concurrently
with it. Fourteen OPM views validate/render, containing 284 view-local entities and 397
links. The new [fixed-cascade view](architecture/fixed_cascade.svg) separates runtime,
payload persistence, parent finalization, fresh references and offline gold use.

### Retained Windows run

The primary root is
`D:/AI_Models/symbolic/.scratch/selective_analysis/fixed-cascade-v15-20261111-211633-90976/`.
All eighteen planned method trials and three fresh separate references completed on time
with no failed workers, wrong decisions or reference disagreements. Thirteen snapshotted
source/specification files and all original/copied input identities remain unchanged.
All twenty-one workers emit the same observed environment: Python 3.13.10, Windows,
angr 9.2.217, Capstone 5.0.6 and pyelftools 0.33. The actual interpreter path is retained
per worker; it is installed on C, while task outputs and caches remain on D. These are
worker receipts, closing v14's missing per-worker-version limitation.

| Known authored query | Expanded-only, all three repetitions | Fixed cascade, all three repetitions | Cascade attempted operations |
|---|---|---|---|
| scalar_span | excluded_within_scope | excluded_within_scope | interval |
| readonly_chain | unknown | excluded_within_scope | interval → finite_readonly |
| readonly_chain_outside | violation | violation | interval → finite_readonly → expanded |

Expanded-only therefore has 6/9 correct repeated outcomes and three unknowns, with two
of three unique queries correct in every repetition. The cascade has 9/9 and all three
unique queries correct in every repetition. Repetitions are not independent programs.
The safe-chain full checker retains its conservative address-concretization unknown;
no guard was relaxed. Abstract operations never promote a possible outside address to
a witness. Expanded checking and a fresh modeled replay supply the unsafe-chain witness.

The three separate reference workers start only after every method worker has finished.
Scalar checking uses fresh symbolic complete-scope checking over 1024 input values.
The safe chain exhaustively checks all sixteen literal BVV inputs and freshly rechecks
each exclusion. The unsafe reference again finds literal RDI=1 and a one-byte write at
0x40200c. References consume no gold, abstract certificates or prior results. They share
the declared loader/property assumptions and remain modeled evidence, without native
input replay or an unrestricted whole-program safety claim.

### Costs and interpretation limits

The primary parent clock starts before request writing/process launch and closes only
after recovery, complete detailed trial-payload persistence and its hash. It includes
startup/imports, actual worker-version lookup, preparation, all attempts, fresh validation,
event/worker-result recording and cleanup. The exact payload bytes and canonical fingerprint
are bound into a separate final receipt. Late candidate evidence is retained but becomes
unknown under parent finalization. Final accounting-receipt work, aggregate copying and
offline evaluation are explicit exclusions; their costs are not claimed to be free in
deployment. Stage sums do not replace this parent charge, and separate reference costs
are not runtime features.

There are six matched correct query/repetition pairs (scalar and unsafe chain), and three
cascade-only pairs (safe chain). Only the former enter the cost comparison. All six,
including the first, remain retained:

| Matched query | Repetition | Expanded-only parent charge | Cascade parent charge |
|---|---:|---:|---:|
| scalar_span | 0 | 2.175183 s | 0.247849 s |
| scalar_span | 1 | 1.856237 s | 0.227098 s |
| scalar_span | 2 | 2.066670 s | 0.231530 s |
| readonly_chain_outside | 0 | 2.066971 s | 2.045628 s |
| readonly_chain_outside | 1 | 2.041540 s | 2.067057 s |
| readonly_chain_outside | 2 | 2.046667 s | 2.076719 s |

The corresponding matched totals are 12.253268/6.895882 s, with medians
2.056668/1.146739 s. These are descriptive values, not a stable speed claim. The scalar
cascade can avoid importing angr, whereas the unsafe cascade pays failed abstract checks
before full checking; two unsafe pairs are slightly slower. The predeclared method order
alternates globally but is **not fully counterbalanced per query**: scalar and safe chain
are cascade-first twice, while unsafe chain is expanded-first in all three repetitions.
Ordinary filesystem caches were not reset. Preserve this post-run limitation and all
original results rather than silently changing the schedule and selecting favorable runs.
A future timing study needs per-query counterbalancing declared before measurement.

The independent offline sidecar is `validated-audit.json`, produced by the parent-workspace
`.scratch/selective_analysis/audit_fixed_cascade_v15.py`. It verifies exact persisted bytes,
receipts, source/input contracts, schedules, worker events, fixed sequences, witnesses,
reference coverage and the six matched cost pairs. Original `records.json` SHA-256 is
`6a5d56ba12fbcab17c9028cf02ba74a90fa0032e58caccf3897816dd3ac850de`;
`references.json` is
`ddb9ca68bc30f2ef365269275adc021b206363d2767dd6c2245cf1c1b25b3cbc`;
`summary.json` is
`59fc9c2156a74f8e2ec5f679e97ec22b243cd3beba9da9b11a878bad3ebac195`.
All measured originals are retained unchanged.

This establishes a concrete strong non-neural baseline on the three authored mechanisms,
not neural benefit, new analysis theory, held-out performance or journal readiness.
V13's negative routing observation remains unchanged. A later neural selector must show
incremental information over this fixed baseline and structural/cardinality controls
after paying acquisition costs. WSL replication is pending; run
`python -B scripts/run_fixed_cascade.py` in the existing `angr-env`. It uses retained v14
inputs, records fresh references and writes all artifacts under the same D workspace.

## V15 WSL fixed-cascade replication

The retained WSL root is
`D:/AI_Models/symbolic/.scratch/selective_analysis/fixed-cascade-v15-20261111-212550-2471/`.
All eighteen planned method trials and three fresh separate references completed within
their parent budgets. There are no failed workers, late conclusions, wrong decisions,
unresolved references or reference disagreements. The main agent audits the retained
request/payload/event/receipt bytes and recomputes the pure evaluation on both platforms;
every recomputed field matches the corresponding saved summary. Measured originals remain
unchanged. Only separate offline audit sidecars are added.

All thirteen measured source/specification hashes and five copied input hashes match
Windows, as do query/binary/checkpoint identities, all eighteen outcomes and attempted
operation sequences. The fifteen abstract attempt results match exactly, including
certificate hashes and traces. The three finite exclusion certificates on each platform
are independently checked against ELF segment permissions, file-backed bytes, qword values,
read/segment hashes and discharged write spans. They repeat the same safe-chain query,
not three independent programs.

| Method | Correct repeated outcomes | Unknown | Wrong / failures | Correct in every repetition, unique queries |
|---|---:|---:|---:|---:|
| expanded_only | 6/9 | 3 | 0 / 0 | 2/3 |
| fixed_cascade | 9/9 | 0 | 0 / 0 | 3/3 |

The scalar case stops at interval checking; the safe readonly chain stops after interval
and finite checking; the unsafe chain pays both abstract unknowns before expanded checking.
Expanded-only retains the safe chain as unknown. Three fresh references start after all
method workers, with the same symbolic 1024-value scalar domain, exhaustive/rechecked
sixteen-input literal safe-chain domain and RDI=1 unsafe witness at 0x40200c. Modes,
domain sizes, per-input reference outcomes and query results agree with Windows. Shared
modeling assumptions, first-target-visit scope and lack of native replay remain limitations.

Actual receipts from all twenty-one WSL workers report Python 3.10.20 at
`/root/miniconda3/envs/angr-env/bin/python`, Linux, angr 9.2.212, Capstone 5.0.6 and
pyelftools 0.32. Preserve these separately from Windows Python 3.13.10 / angr 9.2.217 /
pyelftools 0.33. No environment or package was changed for this replication. The offline
auditor runs on Windows; its environment is not substituted for these WSL worker receipts.

### Matched WSL costs and limits

There are six common correct query/repetition pairs and three cascade-only safe-chain
pairs. The latter do not enter the matched latency comparison. Parent charges include
request writing, startup/imports, provenance lookup, all attempted preparation/checking/
fresh validation, recording, cleanup, recovery and detailed payload persistence. Final
accounting-receipt work, aggregate copying and offline evaluation remain explicitly
excluded; reference-panel costs remain separate. No parent charge is replaced by a stage sum.

| Matched query | Repetition | Expanded-only | Fixed cascade |
|---|---:|---:|---:|
| scalar_span | 0 | 1.640413 s | 0.290218 s |
| scalar_span | 1 | 0.887826 s | 0.289524 s |
| scalar_span | 2 | 0.939130 s | 0.290204 s |
| readonly_chain_outside | 0 | 1.088473 s | 1.142236 s |
| readonly_chain_outside | 1 | 1.088578 s | 1.194781 s |
| readonly_chain_outside | 2 | 1.088225 s | 1.141961 s |

Matched totals are 6.732645/4.348923 s; medians are 1.088349/0.716089 s. These describe
the six retained pairs, not overall equal-work deployment costs or a stable speed result.
Scalar checking benefits from avoiding the full engine import. Conversely, every unsafe
cascade is slower here, by 0.053735–0.106203 s. No first trial is removed. The same declared
schedule leaves expanded-only first for the unsafe case in all three repetitions, and
ordinary filesystem caches were not reset. Keep that limitation; do not pool platform
times, treat repetitions as independent programs, or infer neural value from these totals.

The sidecars are `validated-audit.json` from parent-workspace
`.scratch/selective_analysis/audit_fixed_cascade_v15.py` and `cross-platform-audit.json`
from `.scratch/selective_analysis/compare_fixed_cascade_v15.py`. The second script executes
no property checker or model; it recomputes the pure evaluation, independently checks ELF
data certificates and compares non-timing identities/evidence. Original `records.json`
SHA-256 is `2b19d45908a9a2e728f70ebbbff2b8837d88b6f7b2a5a8923e20227c7d800f1f`;
`references.json` is
`5d89f5f6988809483fac91857127a42bfa513a68d6167cfacccf1b16b5ef8b4a`;
`summary.json` is
`2260eb2e22a335a36dac88cb8423433232fafcb783320adb02c2e440b10f7b40`.

This completes the fixed baseline's cross-platform gate on three known authored mechanisms.
This turn changes only offline audit/documentation metadata; the previously passing
665-test runtime suite and frozen v15 source/specification files remain unchanged.
Fourteen OPM views still validate. A subsequent neural study must identify and test
incremental information over this actual baseline and structural/cardinality controls
with charged acquisition; it cannot claim a neural contribution from this replication.

## V16 information readiness and trace-cost gate

The [v16 specification](architecture/pilot_revision_v16.md) was written after inspecting
v15 outcomes/costs and the current adapter, before implementing/aggregating this diagnostic.
This is explicitly retrospective feasibility work, not preregistered validation. It adds
no programs, variants, metadata, models or learned policy and changes no v15 runtime source.
No property operation, graph generator, model, mapper, compiler, package, API or GPU runs.
The main agent runs the completed CLI locally against the existing shared D artifacts;
there is no additional WSL experiment to request.

### Implementation, delegation and checks

`information_readiness.py` inspects ordinary ELF64 section metadata, recomputes stored
candidate ordering/mean scores from every original value-node logit, validates recorded
location-only bundle identities/bindings and inventories exact binary/query/use-site
matches. It does not run or generalize the old mapper. Debug-section presence alone is
never called a usable DWARF locator. Original ground-truth labels remain absent from model
inputs; placeholder scores cannot substitute for the stored logits.

A Codex subagent implements the pure `trace_headroom.py` and 42 tests. It first calls the
unchanged strict v15 evaluator, rejects blocked/wrong/failed/late evidence, and accounts
for unknown prefixes from the actual fixed-cascade ledger. The main agent reviews that
code/tests and independently re-accounts the real output. The subagent also reviews the
main agent's readiness/CLI implementation. Its repeated-source-anchor finding is fixed
before the actual CLI run by restricting evidence extraction to the exact `sym_exec_one`
function; source-excerpt preflight then passes. Twenty-four additional main-agent tests
exercise score/provenance corruption, binary/query identity confusion, metadata presence
versus readiness, incomplete bindings and path rebinding. They use fabricated metadata,
not new benchmark programs.

The full **731-test suite passes** (728 focused and three legacy smoke checks), with 19
third-party deprecation warnings, in 56.21 s. The test process exits before the actual
offline aggregation. Fifteen OPM views validate/render with 303 view-local entities and
419 links. The new [offline readiness view](architecture/information_readiness.svg) keeps
retrospective correctness labels, inventory, trace-cost accounting and historical context
inside the evaluation boundary. Frozen A-D semantics are unchanged.

### Retained output and exact information availability

The retained root is
`D:/AI_Models/symbolic/.scratch/selective_analysis/information-readiness-v16-20261112-014723-26724/`.
Its immutable snapshots contain fourteen source/specification/evidence files and 26 input
files. The original v15 WSL 18+3 evaluation is recomputed, including gold only for offline
correctness. Neither labels nor property certificates enter type availability. All source,
original input and copied input hashes remain unchanged, with no forbidden runtime imports.

| Existing panel | Unique fixed queries | Genuine stored predictions | Existing syntactic bindings | Role here |
|---|---:|---:|---:|---|
| v12 compiled integration | 3 | 3 query exports | 6 | Frozen type/location inventory |
| v15 complementary mechanisms | 3 | 0 matching exports | 0 matching bindings | Complete cascade cost traces |

The two panels have **zero matching binary hashes**, hence zero exact mapped-query
intersection. Matching case names would not repair that. All three complementary binaries
have no ELF section table and no debug-info section. The current exporter explicitly uses
the DWARF-assisted generator, and the location mapper requires the canonical CFA/RBP frame
subset; these sectionless register/readonly-load mechanisms do not satisfy those interfaces.
The gate records C/D inputs as unavailable, without zero-filled type features or a claimed
negative neural-value result. It does not claim that no other TYGR adapter could work.

The reviewed source excerpts also show why repairing the incomplete prediction branch
is more than appending a missing register variable. That branch constructs register
locations from values in VEX-offset space while `RegLocation` interprets DWARF register
numbers. Action summaries use block addresses, overwrite register/address dictionary entries
and read final-state values. A reliable new bridge needs instruction/read-write/width/
overwrite identities and nonempty node correspondence. No new bridge or mapping validation
is performed in this gate. The source hashes, exact lines and bounded excerpts are retained
in `source-findings.json` as review evidence, not an executed provenance proof.

### Revealed-outcome deletion model

For each fixed-cascade trace, retrospectively select its final correctly decisive operation
and remove all preceding unknown attempts at their recorded `elapsed_seconds`. Keep the
final operation and every other parent cost fixed. This is an optimistic oracle with
revealed outcomes, never a scheduling feature. All nine traces, including first repetitions,
remain in the denominator; all three query identities remain separate.

| Known query | Deleted prefix | Deleted time across repetitions 0 / 1 / 2 |
|---|---|---|
| scalar_span | none | 0 / 0 / 0 s |
| readonly_chain | interval | 0.062361 / 0.061617 / 0.062418 s |
| readonly_chain_outside | interval + finite_readonly | 0.077805 / 0.078000 / 0.077840 s |

Across the nine cascade traces the original parent charge is 5.219725 s. Optimistic
prefix deletion is **0.420041 s**, leaving a hypothetical fixed-trace charge of 4.799684 s.
The per-trace deleted-time median is 0.062361 s and maximum 0.078000 s. These totals are
over nine repetitions of three authored queries, not independent workloads. They concern
all cascade traces, unlike v15's six matched-correct latency pairs.

Only within this declared model must added information/selection cost be below the deleted
cost to produce a net saving. The deletion sum is **not an unconditional real-runtime upper
bound**: importing a dependency in a removed first check can shift that import to the next
check, and changed order/cache/recording behavior can alter other costs. No skipping policy
is actually executed, and preparation already supplies no free semantic mapping proof.
Static load/cardinality controls remain strong competitors, not measured new baselines
in this arithmetic. The safe/unsafe chains share instruction/type structure and differ
in readonly numerical contents; type labels do not automatically resolve that bounds
difference. No learning or complexity is added to manufacture a signal.

The historical v5 three cold acquisitions remain separate context: median 5.154144 s on
the different reviewed compiled binary/query. Its inputs and receipts are copied, but no
cross-panel cost subtraction, ratio, new-panel acquisition estimate or warm-service claim
is computed. This gate cannot establish that neural acquisition on these new interfaces
would cost the same, nor that neural information is intrinsically useless.

### Independent audit and decision

The sidecar `validated-audit.json` is produced by the independent parent-workspace
`.scratch/selective_analysis/audit_information_readiness_v16.py`. Using only standard
library JSON/ELF-byte parsing, it verifies the fourteen source and 26 input identities,
sectionless binaries, empty panel intersection, all nine deletion calculations, retained
charges/statistics and separate historical context. It invokes no project model/checker.
Primary `availability.json` SHA-256 is
`1a25076b33eb248998c097a6ca79bfd1460bfc4cb0549f768d156eea4d8a955c`;
`trace-headroom.json` is
`6e1ee9d250c0bdbea2a24d9bb9a2717cefd8015d927d576996a116b5d2d437ad`;
`summary.json` is
`41ed082df55ae42a6144a7927a84d50430dc6616e847b8e583c34eb8820e5887`.
All measured and original diagnostic files remain unchanged. Diagnostic elapsed time is
offline aggregation overhead, explicitly not an end-to-end deployment budget; final
summary serialization is outside that diagnostic clock.

The current panels cannot yet support the planned C/D comparison. This is an unmet input
precondition, not evidence against RQ1/RQ2. Preserve those questions and the replicated
non-neural baseline. Before building a new bridge or trained selector, require a precise
value-node provenance contract and a concrete potential operation-value signal beyond
structural load/cardinality cues, with plausible acquisition cost. Current known-case
coverage and a small conditional saving do not establish that research mechanism, novelty,
held-out behavior or journal readiness. No additional WSL run is needed for this gate.

## V17 instruction-level syntax provenance

The [v17 specification](architecture/pilot_revision_v17.md) preceded implementation and
retained collection, following v16 and a local PyVEX API inspection. This implements a
restricted identity prerequisite, not the missing type-information hypothesis or a TYGR
readout adapter. It uses exactly the same three original binary/query identities. No
benchmark program, compiler, DWARF annotation, model, network, package, API or GPU is added.
Every prior exporter, checker, graph generator, source/specification and result is unchanged.

### Syntax-only implementation

`instruction_provenance.py` builds a separate graph from executable instructions, without
an angr state, claripy, Z3 or model. Runtime requests contain exactly schema, binary path/
hash, entry RVA and target-store RVA. Object/capacity/input-range/type/label parameters and
old evidence stay out of the worker. The parent pins all three original binary and full
query hashes before stripping parameters. Whole-file hashing supplies identity; readonly
data values are not interpreted or loaded into the graph.

Each instruction is decoded with Capstone and lifted separately with PyVEX optimization
level zero. Exactly one matching IMark, PC/delta/length, block size and ordinary fallthrough
are required. Every temporary read resolves an earlier same-instruction definition.
Register locations use VEX byte offsets and explicit widths. Puts update exactly their
real spans; Gets freeze current byte sources, including entry bytes. AL/AH/AX preserve
untouched bytes, while an EAX zero extension is accepted only as represented by its lifted
full-width Put. No final-state register value is consulted. Load values remain opaque;
there is no memory-value evaluation, alias proof or store-to-load forwarding.

For each ordinary memory effect, restricted affine IR address syntax is normalized modulo
2^64 and compared with Capstone base/index/scale/displacement and width. This traversal
stops at current register reads, keeping prior definition dependencies separate and Store
data out of the address. Repeated base/index registers, unsupported address sizes/prefixes,
control flow, special effects and unsupported IR remain unavailable. Target Store syntax
is never executed; the whole instruction's IR and next-PC checks finish before acceptance.

The separate pure `provenance_validation.py` replays node event order, byte versions and
temporary scopes, verifies target completion, exact dependencies/fingerprints and memory
access/binding consistency, and independently recomputes recorded affine fields. It checks
structural/source consistency, not machine-code equivalence, property correctness or
TYGR feature/readout compatibility. Those limits are explicit in its interface.

### Delegation, corrections and verification

One Codex subagent designs/writes 53 kernel tests; a second independently reviews the
kernel/runner, implements the pure parent validator and writes 69 tamper tests. The main
agent reviews both contributions and writes eighteen parent accounting/recovery/identity
tests. Before retained collection, review findings lead to explicit fixes: allow the
operand-size prefix needed for AX while rejecting unsupported prefixes, distinguish entry
byte identities, normalize missing/invalid inputs, preserve partial graphs on later lift
errors, reject pseudo-complete worker graphs, pin original input identities and deduct
already-spent request-writing time from the child budget. No archived implementation or
measurement is patched to force a result.

The full **871-test suite passes** (868 focused and three legacy smoke checks), with 19
third-party deprecation warnings, in 68.63 s. All tests finish before retained collection.
The 140 new checks include partial writes/zero extension, overwritten RAX/RDI identities,
same-instruction Get/Put ordering, repeated temporary IDs across instructions, Store data
isolation, self-address loads, RIP/scale correspondence, resealed graph tampering, unknown
IR after the target Store, malformed IMarks, failed/late workers and paid serialization.
Unit byte fragments are fabricated checks, not extra benchmark programs. Sixteen OPM
views validate/render with 327 view-local entities and 447 links; the new
[instruction-provenance view](architecture/instruction_provenance.svg) preserves the boundary.

### Retained Windows result

The primary root is
`D:/AI_Models/symbolic/.scratch/selective_analysis/instruction-provenance-v17-20261112-081731-109612/`.
All three planned inputs produce on-time available syntax graphs. All nine source/
specification hashes, four original/copied input hashes and pinned original query/binary
identities remain unchanged. Each isolated worker reports Python 3.13.10, Windows,
PyVEX 9.2.217, archinfo 9.2.217, Capstone 5.0.6 and pyelftools 0.33. Forbidden import
lists are empty. No property engine, solver, neural prediction or TYGR graph is run.

| Original mechanism | Instructions through target | Nodes | Memory syntax bindings | Direct address-register bindings |
|---|---:|---:|---:|---:|
| scalar_span | 2 | 41 | 1 | 2 |
| readonly_chain | 6 | 109 | 3 | 5 |
| readonly_chain_outside | 6 | 109 | 3 | 5 |

The two chain graphs preserve the RAX definition from the first load for the second
load's address. The later LEA creates a distinct RAX definition used by the target Store;
it never rewrites the earlier read's sources. The target RDI read separately refers to
the second load's write. VEX offsets, widths, instruction/statement identities and the
dependency graph retain these intermediate values without source-variable names or DWARF.

Safe and outside chains have **identical normalized syntax fingerprints**, while their
full binary hashes differ. Their executable syntax is the same and only readonly numerical
contents differ. These graphs intentionally do not observe that difference. Do not attach
different type labels to manufacture a signal, or generalize this result to TYGR inference
that uses other context/memory features. The new representation has no proven compatibility
with the frozen trained model's preprocessing or readout semantics.

Observed parent diagnostic charges are 0.401858/0.344123/0.340587 s. They cover request
serialization, startup/imports/version lookup, lifting/recording/address checks, parent
validation/recovery, process cleanup and complete detailed payload persistence/hashing.
Final accounting-receipt work and aggregate serialization remain explicit exclusions;
global input/source snapshot setup is outside the per-process clock. These isolated syntax
diagnostic times are not a policy speed comparison, model-acquisition estimate or proof
of net neural benefit. The child receives only the remaining shared 30 s parent budget.

### Independent audit and next boundary

The separate parent-workspace `.scratch/selective_analysis/audit_instruction_provenance_v17.py`
produces `validated-audit.json`. It imports neither the project recorder nor its validator.
It verifies source/input identities, strict requests, original query hashes, payload bytes/
hashes/fingerprints, parent receipts and all worker version/import records. It independently
decodes actual executable bytes, lifts fresh one-instruction IR, compares complete ordered
Get/Put/temp/constant/expression/load/store event sequences and replays byte/temporary
sources. Capstone operand forms and direct address-read bindings also match. Both old/new
RAX identity pairs and the unchanged safe/outside syntax are checked. The fresh IR uses
the same installed backend and therefore shares its modeling assumptions; this is not a
different semantic engine or native execution proof.

Original `records.json` SHA-256 is
`ce6a5667a43736b085a58d01b52376690d354c1361ed093a22e846c1b81feb5e`;
`summary.json` is
`03a2b6be530c683dd7e0bc4aed90a60c7ff14d757f76c685840d27920c8090f9`.
Original diagnostic files and every earlier retained run remain unchanged.

This closes the restricted Windows syntax-provenance prerequisite on the three known
mechanisms. It does not close general variable recovery, TYGR readout compatibility,
conditional information value, neural scheduling, native replay or held-out evaluation.
RQ1/RQ2 and v16's zero mapped-panel intersection remain unchanged. WSL replication can
run `python -B scripts/run_instruction_provenance.py` in the existing `angr-env`, without
installation, compiler, GPU or model loading. Only after identity replication should a
future bridge validate its feature/context correspondence; an operation-value hypothesis
beyond strong static structure/cardinality controls is still required.

## V17 WSL instruction-provenance replication

The retained WSL root is
`D:/AI_Models/symbolic/.scratch/selective_analysis/instruction-provenance-v17-20261112-082512-2903/`.
All three original binary/query identities complete on time with available syntax graphs,
no forbidden imports and unchanged source/original/copied input hashes. The main agent
audits requests, payload bytes/hashes/fingerprints, process/clock receipts and actual
worker version metadata, independently replays register-byte/temporary definitions and
compares decoded machine bytes with fresh one-instruction IR event sequences. This
offline audit uses the Windows inspector's fresh PyVEX backend and shares that backend's
modeling assumptions; it is not native execution or an independent semantic engine.

All nine source/specification files and four copied input files match Windows. More
strongly, all three **complete graph objects match exactly**, not merely counts or
fingerprints. This includes identity, nodes, edges, instructions, byte sources, instruction/
statement positions, scoped temporary dependencies, opaque loads, normalized address
formulas and register bindings. Both intermediate/overwritten RAX pairs remain distinct.
The serialized summaries are byte-identical, while per-process paths, versions and costs
remain platform-specific in the retained records.

| Original mechanism | Instructions | Nodes / dependency edges | Memory bindings | Address-register bindings |
|---|---:|---:|---:|---:|
| scalar_span | 2 | 41 / 38 | 1 | 2 |
| readonly_chain | 6 | 109 / 100 | 3 | 5 |
| readonly_chain_outside | 6 | 109 / 100 | 3 | 5 |

Scalar syntax fingerprint is
`a85e80f698c8b5e90562236a70989c455ed2b7fb9d1aa05f0943458bdb44fbb2`.
Both readonly chains retain fingerprint
`086af49a1b41cd82c9041b130db9206b1a797c0553083afa893c0fc635565196`.
Their different complete-binary hashes coexist with identical syntax graphs because
readonly numerical contents are not interpreted. Preserve this equality; it supplies
no signal for distinguishing the two properties through this representation alone and
does not characterize other TYGR/context features.

All three WSL workers report Python 3.10.20 at
`/root/miniconda3/envs/angr-env/bin/python`, Linux, PyVEX/archinfo 9.2.212, Capstone 5.0.6
and pyelftools 0.32. Windows separately reports Python 3.13.10, PyVEX/archinfo 9.2.217
and pyelftools 0.33. These are actual worker receipts, not inferred from the inspector.
The WSL run uses `angr-env`; it does not validate the separate older `tygr-orig` model
environment or pretrained readout compatibility.

WSL parent diagnostic charges are 0.544161/0.396095/0.344519 s in case order. Their
request-to-complete-payload clock includes startup/imports/version lookup, all recording/
address checks, parent validation/recovery and cleanup; final accounting receipt and
aggregate serialization remain explicitly excluded, as does global snapshot setup.
These single-pass diagnostic observations are not a platform speed comparison, a policy
experiment or a model-acquisition estimate. No property checker, symbolic state, solver,
TYGR graph generator, model, training, compiler, package, API or GPU is run in this gate.

The separate `validated-audit.json` comes from parent-workspace
`.scratch/selective_analysis/audit_instruction_provenance_v17.py`.
`cross-platform-audit.json` comes from
`.scratch/selective_analysis/compare_instruction_provenance_v17.py`; this second script
executes no decoder, IR lifter or analysis and verifies exact complete-graph equality,
source/input identity and unmodified original output hashes. Original `records.json`
SHA-256 is `865c947579857525fea6dc102061445956dbc8a3c080e090b1375e7db857420e`;
`summary.json` is
`03a2b6be530c683dd7e0bc4aed90a60c7ff14d757f76c685840d27920c8090f9`.
Original retained files remain unchanged; only offline audit sidecars are added.

The restricted syntax-provenance gate is complete on both environments. This turn changes
only offline audit/documentation metadata; the previously passing 871-test runtime suite
and frozen v17 sources/specification are unchanged. Sixteen OPM views still validate.
Before genuine type readout, validate correspondence to the trained model's graph/context
and feature/readout semantics. RQ1/RQ2, the zero frozen mapped-panel intersection and
the need for a type-specific operation-value hypothesis beyond strong structural controls
remain unchanged. No further syntax repetition is needed for this checkpoint.

## V18 frozen model-interface audit

The [v18 specification](architecture/pilot_revision_v18.md) follows v17 replication and
preliminary local source/checkpoint inspection. It precedes implementation and retained
aggregation; this is a retrospective compatibility diagnostic, not blind validation.
Every prior runner, graph, model, raw export and measurement stays unchanged. The new
entry executes no TYGR class, framework, graph generator, solver, model forward, training,
compiler, package, network/API or GPU operation. It creates no adapted model input.

### Passive checkpoint reader and verification

A Codex subagent implements `checkpoint_metadata.py` and 44 tests. The main agent reviews
the opcode interpreter, object/state/memo handling and storage/tensor descriptor checks.
GLOBAL, REDUCE, NEWOBJ, BUILD and persistent references become passive data objects;
no referenced callable/class/state method is resolved or invoked. The explicit protocol-2
opcode subset, byte/stack/memo/item/depth limits and exact pinned SHA-256 bound the input.
Only `archive/data.pkl` is decompressed from the ZIP. Complete-file bytes participate in
identity hashing, but tensor storage arrays are not decompressed, interpreted or allocated
as tensors. Saved config fields that are objects (`type_set` and `archs`) are explicitly
listed as unexpanded rather than filled from current source defaults.

The main agent implements the pure model-interface analysis and six CLI identity tests
plus 27 interface tests. Peer review identifies and fixes missing direct ELF-byte anchoring
and source-snapshot rechecks before retained collection. Regression checks cover replacing
an ELF while updating its local plan, manifest path changes, resealing only a payload's
canonical fingerprint, and source excerpt selection without execution. The future observed-
ID guard also rejects coefficient shapes inconsistent with saved relation counts.

All **948 tests pass** (945 focused and three legacy smoke checks), with 19 third-party
deprecation warnings, in 46.76 s. The 77 added checks include passive GLOBAL/constructor/
BUILD behavior, memo aliasing/cycles, malformed/unsupported opcodes, resource caps, tensor
layout/storage consistency, real frozen metadata, saved-versus-active dimension distinctions,
relation-ID bounds, unchanged input objects and unavailable semantic projections. Unit
fixtures reuse existing mechanism bytes and fabricated metadata; no new benchmark program
is added. Tests finish before retained aggregation. Seventeen OPM views validate/render
with 346 view-local entities and 469 links; see the
[model-interface view](architecture/model_interface.svg).

### Actual saved structure

The retained root is
`D:/AI_Models/symbolic/.scratch/selective_analysis/model-interface-v18-20261112-085618-109984/`.
Seventeen source/evidence/specification files and eleven input files are copied and checked,
including original and copied source hashes. All v17 original binary/query identities,
recorded payload fingerprints/serialized hashes and complete three-query coverage match.
There are no changed sources/copies/inputs or forbidden runtime imports. The frozen model
SHA-256 remains `f592caaa6c685f291f576b16fbf8b752a95e7cb757ea620751830563b77f67c8`.

| Saved item | Actual metadata / parameter evidence |
|---|---|
| Architecture / width / engineered feature groups | 5 + 8 + 18 = 31 |
| Encoder first weight | [128, 31] |
| Decoder final weight / output count | [75, 128] / 75 |
| Decoder / variable handling | independent / flatten_vars true / node aggregation mean |
| Explicit bit-vector value encoding | disabled; the 18 other features still depend on values/annotations |
| Ordered relation labels | 29 plus reserved unknown |
| Direction offset / declared relation count | 30 / 60 |
| Saved model edge_dim | 44 |
| Each of eight saved RGCN layers | num_relations 44, num_bases 10 |
| Per-layer basis weight / coefficient shape | [10, 128, 128] / [44, 10] |
| Parameter/storage descriptor count | 40 / 40, all ZIP byte sizes consistent |

Thus the encoder/output dimensions agree, but the saved preprocessor can encode IDs 0..59
while each saved layer's relation domain is 0..43. **Potential IDs 44..59 are outside that
domain.** They are the inverse forms of ULE, SignExt, ZeroExt, LShR, left/right shifts,
If, Or, Not, And, Xor, Eq, fp_conv, fp_op, fp_cmp and reserved unknown. Current encoding
would assign inverse And ID 53 and inverse unknown ID 59. The new guard checks observed
IDs against every saved layer capacity; passing it would still not prove edge semantics.

This is not evidence that these IDs occurred in earlier exports or that past forward
calls failed. The old raw-logit adapter did not retain prepared edge tensors. Source
defaults alone cannot settle saved state, and successful forward calls alone cannot
settle which edges were consumed. No runtime behavior for unsupported IDs is inferred
without observing the original environment's actual prepared input and implementation.
Original scores remain genuine historical outputs with this observability limitation.

### Value, context, edge and readout gaps

The three original v17 graphs retain **259 nodes**: 38 syntactic literal candidates and
221 nonliteral nodes without the upstream `ast_val` contract. All 259 still lack a
projection to upstream annotation-address semantics. Thirty-eight literal values do not
establish matching signed casts, deduplication, annotations or context. No missing value
is replaced by zero. Source excerpts show the 18 engineered features include zero/one/
size/sign/register/address indicators, and upstream values come from solver evaluation
with signed conversions. Their values cannot be inferred from syntax dimensions alone.

All **238 dependency edges** remain without a trained typed/directional relation mapping.
VEX `Iop_*` names are not the saved Claripy/annotation vocabulary; operand-index edges are
not automatically reg_loc/reg_data/mem_loc/mem_data relations. The audit supplies no unknown
fallback or renamed edge ID. It keeps the AST deduplication and ancestor/descendant context
slicing distinction visible rather than silently treating the new prefix graph as the
trained representation. The serial upstream generator also supplies literal architecture
token `arch`, outside the saved named architecture list. Current `encode_arch` maps that
token to zeros; changing it to `x64` is a changed input convention, not automatic validation.
This source fact does not reconstruct an unseen training distribution.

The **twelve address-readout candidates** retain precise register/event identities, but
none has a declared projection to trained `GlowVar.nodes`, groups or output rows.
Flattening changes the upstream row unit; the exporter separately averages original
value-node raw logits per variable. An output with 75 columns is therefore insufficient
to establish which event/variable it describes. No readout group or tensor is synthesized.
`direct_bridge_ready` is **false**, with five retained structural/semantic blockers.
This does not exclude every possible future bridge or establish zero neural information.

### Independent audit and next decision

The parent-workspace `.scratch/selective_analysis/audit_model_interface_v18.py` writes
`validated-audit.json`. Using only standard-library JSON/ZIP/pickle-opcode inspection,
it checks all seventeen source and eleven input identities, storage/shape bounds and
graph inventories. Raw scalar witnesses independently recover one 31-wide encoder,
one 31-wide feature input, declared counts 30/60, edge_dim 44, all eight num_relations 44,
all eight num_bases 10 and out_dim 75, including memo-referenced field keys. A second
subagent separately checks those raw witnesses without importing its own reader. Deep
serialized module ownership relies on the reviewed passive parser rather than claiming
a second complete independent unpickler or neural execution.

The audit independently re-accounts all 259 nodes, 38 literal candidates, 221 missing
nonliteral value contracts, 238 unmapped edges and twelve readout candidates. Potential
out-of-capacity IDs are recomputed from the saved ordered vocabulary and actual layer
capacities. No historical edge usage or failure is inferred. Original
`checkpoint-metadata.json` SHA-256 is
`36135a1326099d1dae1991366c2e6dc21435d9b3619e2fbf0c793f8b29300c13`;
`interface-report.json` is
`e7b764b7ce4372b14ca25d1a8f3584eb78eaf6fc8f6af63cdd3e9821c753b747`;
`summary.json` is
`772f7dbd721cdcbdc6c07b9abd41873ed06fed786fbeee4936c3c8bca04c8eeb`.
Original diagnostic/measurement files remain unchanged. The offline clock is not model
acquisition/deployment cost and excludes final summary serialization.

The direct v17-to-checkpoint connection must not proceed merely because input dimensions
match. Next establish the original preprocessing's actual relation usage and complete
value/context/readout provenance; changing relation numbers, expanding layers, inserting
zeros or selecting arbitrary groups would change trained semantics rather than validate
them. A compatible bridge would still need to demonstrate incremental operation-selection
value beyond fixed and structural/cardinality controls. RQ1/RQ2 and the frozen panels
remain unchanged. No new WSL prediction or syntax repetition is needed for this offline gate.

## V19 native preprocessing capture preflight

Declared [v19](architecture/pilot_revision_v19.md) before new native collection, following
the v18 interface findings. This is a preparation result only: original-environment WSL
capture remains pending. The existing v12 compiled `direct_index`, `offset_index` and
`masked_index` panel is reused without recompilation or new programs. It is separate
from v17's sectionless authored mechanisms, and no counts or neural gains are pooled.

### Implemented capture and reviewed boundaries

`scripts/run_native_preprocessing.py` prepares a fixed three-case matrix, copying and
hashing nine project/specification dependencies, all seventy original TYGR Python sources
and eight inputs: the pinned model, retained location plan, three ELF files and three
original query manifests. Query hashes and binary hashes are checked against fixed
identities, rather than accepting a locally updated plan. Native requests contain only
input/function/model/source identity and workspace paths. They do not supply property
bounds, expected labels, historical predictions or paid proof records.

The standalone Python 3.8 worker isolates original TYGR's `src` namespace from this
project. In the existing old CPU stack, it loads the pinned checkpoint for actual saved
configuration and layer capacities, then blocks `forward` on every loaded model module.
It uses the unchanged serial DWARF-assisted generator, discards its accompanying gold
output, and records original preprocessing/collation inputs. Native generation uses
symbolic execution for graph features; no property query is decided. No model/encoder/
GNN/decoder forward is allowed, including when capacity findings occur.

Every nonempty generated function is first persisted with identity, then with complete
native NodeLabels, graph/edge iteration order and original variables before preparation.
Successful preparation adds all CPU tensor values and shapes, directional relation IDs,
original and flattened groups and collated gather/scatter membership. A preparation or
collation failure retains the original function record. The installed RGCN method's
source and package versions are recorded without executing or inferring its bad-ID
behavior. Raw architecture token is preserved. The initial last-sorted-label
interpretation is superseded by [the post-capture first-label erratum](architecture/pilot_revision_v19_erratum.md).

A delegated pure validator checks full tensor shapes/values, positional edge agreement,
model contract, original/flattened row partitions, batch membership and receipt identity.
Unknown labels, architecture-token zeros, graph-ID/feature-row issues and domain violations
remain findings on faithfully captured data. It neither inserts missing features nor
relabels relations to make an input compatible. Newly observed IDs cannot establish
historical usage or validate a v17 feature/context/readout projection.

Independent code review identified and main review fixed three material issues before
collection: loss of a generated graph when preparation fails; counting parent recovery
as observed zero forward attempts; and returning success despite failed or forward-using
captures. Final native forward coverage now requires a native-worker final receipt and
a complete successful process. Parent recovery, intermediate snapshots, timeout and
nonzero exit cannot establish that coverage. Forward clues still block interpretation,
even in invalid envelopes. All three planned cases remain in the denominator. A failed
matrix is persisted before a nonzero final command exit.

Each request has a 60 s parent-owned request-through-complete-payload-persistence budget,
including startup, loading, generation, preparation, validation/recovery and cleanup.
Source/input setup, final accounting receipt and aggregate/offline evaluation are explicit
exclusions. Selected stage timers also retain failed preparation and raw conversion/
stage-persistence costs; these are not an additive full cost decomposition. No diagnostic
time is interpreted as scheduler throughput or end-to-end neural benefit.

### Windows preparation and independent audit

After all test processes completed, the preparation-only command retained
`.scratch/selective_analysis/native-preprocessing-v19-20261112-132530-111772/` under the
parent workspace. It verifies **79 source files, eight inputs and three fixed compiled
identities**, records the expected saved contract and launches **zero native workers**.
Both original and copied source/input identities remain unchanged; the upstream inventory
is unchanged. There are no `workers/` or `records.json` runtime observations in this root.

The separate standard-library auditor
`.scratch/selective_analysis/audit_native_preflight_v19.py` independently rehashes every
original/copy, recomputes each binary/query identity, checks the pinned checkpoint and
saved 31-feature/75-class/60-ID/eight-44-capacity contract, and parses the reduction map as
data. It verifies that preparation claims no native capture or prediction and writes
`validated-preflight.json`. The audited `run-plan.json` SHA-256 is
`e992c8807fa30f679ca78622e6a089db8531a3ddafe8f6bb2ea37d8d9000ca4a`;
`preflight-summary.json` is
`56f360b86e09e32f4245e4cd7fb715a4d714385969a87f4c193b06d28c10cd50`;
`expected-model-contract.json` is
`ef673a606d712667fa5b20916c02c7e683bcac4e41fcd11e6d23ae25e7416449`.

Final validation: **1061 project tests pass** with nineteen existing third-party
deprecation warnings; **eighteen OPM views, 363 view-local nodes and 491 links** validate
and render. Eighty pure-validator counterexample tests and thirty-three worker/parent
tests cover origins, failed matrices, exact payload hashes, budget endpoints, forward
guards, native order/groups, strict requests, integrity and failed-stage cost recording.
An initial unscoped pytest collection entered an upstream command-line test and aborted;
the successful complete runs explicitly target this project's `tests/` directory.

The main agent reviewed both delegated implementations/findings and retained all previous
measurement sources/specifications/inputs. No WSL launcher was retried. The next command
is `python -B scripts/run_native_preprocessing.py` from WSL `angr-env`; it automatically
uses the existing `tygr-orig` interpreter. Actual tensor IDs and target-row observations
remain unknown until those runtime receipts are returned. RQ1/RQ2, native prediction,
v17 bridging, held-out evaluation and novelty remain unresolved.

## V19 WSL native preprocessing audit

The user completed the original-environment capture at
`.scratch/selective_analysis/native-preprocessing-v19-20261112-132805-3628/` under the
parent workspace. The main agent audited the retained files rather than relying only
on terminal output. No native process, new graph generation or model was started during
this review. All three fixed compiled integration cases remain separate from v17's
sectionless mechanisms and from the primary twelve-case development set.

| Case | Native nodes | Native edges | Directional entries | Original group sizes | Flattened rows | Parent charge |
| --- | ---: | ---: | ---: | --- | ---: | ---: |
| direct_index | 27 | 32 | 64 | 3, 3 | 6 | 7.465483 s |
| offset_index | 29 | 35 | 70 | 4, 3 | 7 | 5.160208 s |
| masked_index | 30 | 36 | 72 | 4, 3 | 7 | 4.957149 s |

Totals are **86 native nodes, 103 original edges, 206 directional entries, six original
variables and twenty flattened readout rows**. Twenty rows are not twenty independent
queries or variables. All three captures contain one target function and verify native
group/row/gather/scatter correspondence. No property result or type correctness is
evaluated here. Each receipt records 23 guarded model modules, zero forward attempts and
no model forward. Every process completes within its parent-owned 60 s budget.

Observed relation IDs are `{0,1,2,3,4,5,7,30,31,32,33,34,35,37}`. Each is in every saved
layer's `0..43` domain. This resolves the observed-input domain question for these three
captures. It does not remove the declared 60-ID versus saved 44-capacity constraint, prove
arbitrary input compatibility or reconstruct IDs used in historical forward calls.
All native architecture tokens are the literal `arch`; their five architecture-prefix
features are zero on all 86 nodes. That convention is preserved, not silently changed
to `x64` or assumed to match an unseen training distribution.

### Source interpretation correction

Both main and independent AST inspection found an error in the original specification
and validator: the upstream encoder's `return` is directly **inside** its sorted-label
loop, so it selects the **first** sorted label. The previous last-label interpretation
and its fabricated multi-label fixture were wrong. The collector itself invokes the
unmodified native encoder and retained its actual return values.

All **103 observed edges have a single label**, so first/last are identical on this
matrix. No observed ID, tensor, successful status or readout group changes. The live
validator and fabricated fixtures are corrected; four regression cases isolate and run
only the actual upstream pure encoder function from its AST, without importing TYGR,
classes or a framework. See [the erratum](architecture/pilot_revision_v19_erratum.md).
The measured v19 specification and all captured snapshots/payloads remain unchanged.
The original validator SHA-256 is
`20f9ad6c2eec36f112683a0bb32596059bbf0337aa83a768699fd03968d55436`;
the corrected live validator is
`0d72b82181aa7aca719e1a5b7baef32bb5c4d421aed7ab18eababd9512de182d`.

### Independent feature and correspondence review

The delegated standard-library script
`.scratch/selective_analysis/independent_native_feature_audit_20261112.py` imports no
project validator, framework, external class or checkpoint object. It checks frozen
source AST, raw saved scalar/list opcode witnesses, native labels and complete prepared/
batch arrays. Main review inspected the script and its explicit limits.

It independently recomputes **26 of 31 columns**, matching **2236 feature values per
tensor** for both prepared and batch inputs. These are the five architecture-prefix
columns, eight bit-width columns and thirteen value/address-derived columns. The other
five columns depend on effective runtime architecture attributes/methods: proximity to
initial stack pointer, argument-register membership, register-name translation, artificial
register offsets and return-register offsets. Those dependencies were not retained in
the primitive metadata, so their semantics are **not independently reconstructed**.
Their 430 values per tensor are only checked for exact storage and prepared/batch equality.
The audit does not substitute Windows archinfo or source defaults for the old runtime.

All 2666 observed values per tensor are binary 0/1 with exact float32 representation;
no rounding tolerance is used. Every native edge/endpoint, all 206 relation entries,
original group order, row partition, gather/scatter and num_vars array independently
match. The review establishes consistency of these captured native readouts, not a
mapping from v17 instruction events or proof that averaged output rows represent a
particular target operand. The feature-audit result SHA-256 is
`d57b12c6d0599a9065b9218972767606340562d6a22862befed9557dd43aaf27`;
its script SHA-256 is
`a6933d4d49028261867e098452cf52a6f1938349fe522c073b042dba6d126a9d`.

### Identity, receipt and validation closure

`scripts/audit_native_preprocessing.py` independently checks the fixed query/binary/model
anchors, all **79 captured source files and eight original/copied inputs**, strict request
fields and path identities, request fingerprints, actual persisted payload bytes,
worker/parent/aggregate equality, process outcomes and parent budgets. WSL source and
input manifests match the original Windows preflight exactly. Historical input/source
snapshots remain intact; the only current-source difference is the documented live
validator correction. Full validation/summary replay with that corrected rule reproduces
the complete recorded summary exactly because all observed edges are single-label.
The audit writes `validated-audit.json` and records its own and the corrected validator's
source hashes. No original measurement file is rewritten.

The immutable `records.json` SHA-256 is
`e9404ef9ca4846b28538b8a7be95093ec20156c0b180d6c91fe5251381bb0dd2`;
`summary.json` is
`39f23c5c7b2de9e2f8703e8cdb6c83a3a1f4ad01aa155a53cec3e96529d9c29e`.
After correction, **1070 project tests pass** with nineteen existing third-party
deprecation warnings. **Eighteen OPM views, 363 view-local nodes and 491 links** validate.
The RQ1/RQ2 shared-selector contract remains unchanged. No installation, GPU/API, new
sample, inference, WSL launcher or benchmark repetition was used for this audit.

This closes the native-input observation gate for the three existing compiled cases;
no WSL rerun is needed. Next establish which native value/readout groups correspond to
the target write's base/index operands, and whether that correspondence can cover the
complementary-operation mechanisms. Capacity agreement alone cannot justify an arbitrary
v17-to-model adapter. Neural information value, prediction quality, scheduling gains,
held-out evaluation and novelty remain open.

## V20 native readout group and frontier correspondence

Declared [v20](architecture/pilot_revision_v20.md) before implementation or its retained
diagnostic. The graph-frontier supplement was explicitly declared after read-only
inspection of the same known developer captures; it is exploratory mechanism evidence,
not a held-out hypothesis test. No binary, native capture, score, group order, model or
query was changed. The existing three compiled integration cases remain separate from
the primary twelve-query set and the sectionless complementary-operation panel.

### Minimal correspondence and its granularity

`scripts/run_native_readout_correspondence.py` first replays the v19 identity/receipt
audit. Each correspondence request contains exactly binary/hash, entry/write RVAs and
the full native-capture fingerprint. Original query manifests remain retained for their
fixed identity anchors, but object bounds, input ranges, expected answers, historical
type scores and role proofs are not forwarded to correspondence. No inference, solver,
native graph generation, compiler, GPU, installation or API runs in this revision.

The new module reuses the v12 canonical-frame static decoder without changing it and
freshly decodes the actual ELF bytes. Each address-contributing eight-byte stack load
has one native CFA location whose lifetime covers both the load and target use. This
associates its complete original variable group using physical metadata, not names,
prediction IDs, sampled values or selected candidate labels. The association is
conditional on the captured location metadata; it does not prove storage extent, alias
uniqueness, a universal live-value equality or semantic base/index roles.

**All six load occurrences associate uniquely.** Each group retains all members and
flattened rows, bound to the exact native capture fingerprint. There are still only
three queries and six original variables; twenty readout rows are not extra samples.

| Case | Load RVA / CFA offset | Native group | Complete rows | Rows with equal annotation PC |
| --- | --- | ---: | --- | --- |
| direct_index | 0x1140 / -24 | 1 | 3, 4, 5 | 4 |
| direct_index | 0x1144 / -40 | 0 | 0, 1, 2 | none |
| offset_index | 0x1145 / -24 | 1 | 4, 5, 6 | none |
| offset_index | 0x1149 / -40 | 0 | 0, 1, 2, 3 | 2 |
| masked_index | 0x1145 / -24 | 1 | 4, 5, 6 | none |
| masked_index | 0x1149 / -40 | 0 | 0, 1, 2, 3 | 3 |

Only three groups have a PC-coincident member. Even those are **not exact-event proofs**:
the frozen upstream history reconstruction uses `act.bbl_addr` and per-location summary
dictionaries, while direct annotation hooks use `state.addr`. Read and write annotation
classes are collapsed to common location/data edge labels. V19 did not export annotation
class, action order, statement ID, path instance or register-byte versions. Source AST
findings retain these distinctions; a scalar address in a NodeLabel is not sufficient
instruction-event provenance. Exact-event status stays unverified for all six occurrences;
this is not a measured event-recovery accuracy of zero.

### Exploratory native address-graph frontier

The separate pure frontier module keeps every byte-sized mem_loc target attributed to
the declared target annotation address. Each case has **two target candidates sharing
one native address root**, so a common root cannot identify one read/write event. Reverse
traversal follows only data and declared operator edges and stops at the first original
readout member. Location, unknown and mixed disallowed edges are retained as blocked
facts. Cycles and DAG reconvergence have separate records; one native-order path witness
per root/member is retained rather than enumerating all semantic paths.

| Case | Per-capture root | Frontier members: (group, output row, native node) |
| --- | ---: | --- |
| direct_index | 4 | (0, 0, 7), (1, 5, 12) |
| offset_index | 4 | (0, 0, 6), (1, 4, 14) |
| masked_index | 4 | (0, 0, 6), (1, 5, 15) |

Node ID 4 is local to each capture, not a cross-binary identity. These paths provide
native-graph candidate contribution evidence reaching both associated groups. They do
not prove equivalence to a VEX operand, a semantic base/index assignment, complete
dependencies or a v17 projection. All original group members and their aggregation are
unchanged. No selected-row mean/logit/probability is computed or substituted for the
historical whole-variable prediction.

The same-PC pitfall is concrete: masked_index native nodes 6, 22 and 29 have the same
annotation PC, width and sampled zero value while belonging to different groups. Name,
PC, width or sampled-value matching alone would be an unsafe association rule. The
coarse CFA/lifetime match remains available even without any PC-coincident row.

### Retained artifacts and independent replay

The final output is
`.scratch/selective_analysis/native-readout-v20-20261112-185905-96624/` under the parent
workspace. It retains **nineteen source/evidence files and thirteen inputs**. Source
snapshots include `scripts/__init__.py`, `src/__init__.py`, every loaded local Python
module and the four frozen upstream files used for annotation/context evidence. Runtime
inventory finds thirteen loaded local Python files, with no untracked dependency. Both
original and copied source/input hashes remain unchanged. No forbidden framework or
property-engine module is imported. Windows Python/Capstone/pyelftools versions are
recorded separately from the historical Linux native-generation environment.

An earlier local diagnostic at
`.scratch/selective_analysis/native-readout-v20-20261112-185317-55480/` is retained with
seventeen source files. Main review strengthened source accounting to explicitly include
the two executed parent package initializers and detect future omitted local imports.
After focused regression additions and a full test pass, the final offline run retained
that complete inventory. All three static traces, occurrences, group/row records and
complete frontier reports match the earlier diagnostic exactly. These repeats do not
add samples or constitute independent performance trials.

The separate standard-library script
`.scratch/selective_analysis/audit_native_readout_v20.py` rehashes every source/input
original and copy; checks minimal requests, full capture/group fingerprints, row/location
facts and lack of event/role claims; and independently redoes physical group joins.
It parses ELF executable segments and checks every retained instruction's actual bytes
and contiguous addresses. Instruction decoding itself still relies on the reviewed v12
decoder, not an asserted second independent disassembler. A breadth-first replay checks
frontier membership independently of the implementation's depth-first traversal and
verifies each reverse-edge witness and first-readout stopping condition. It writes
`validated-audit.json` without importing any project module, model or solver.

Final `records.json` SHA-256 is
`3c5f0516524d76a24e2409ada09929dfb0cc1cdc9b53ce5a3226bf9674ad8e9f`;
`summary.json` is
`3a1eec7147651f64687d5c9f4995aefd0d88f220e16270ee9e9ed2eeb5e7c6c3`;
the independent audit script is
`48339778a3faa08feebd0813abd5ae567843d795db64fc73ec06c872e39f503c`.

Main review covered both delegated modules, all focused counterexamples and independent
replay. **1183 project tests pass**, with nineteen existing third-party deprecation
warnings; **nineteen OPM views, 379 view-local nodes and 511 links** validate and render.
New tests cover ambiguity, lifetimes, identity changes, misleading names/IDs/values,
same-PC false positives, readout order, unknown/mixed-edge blocking, cycles/reconvergence,
shared membership, unsupported decoding, retained partial origins and source inventory.

Per-case timing is a shared-process offline diagnostic and excludes historical native
acquisition and global preparation. It is not a scheduler comparison or deployment
cost. No new WSL run is needed for this gate. Exact-event typing is not an added
prerequisite for testing coarse whole-variable features: the available association can
support ranking-only experiments with its granularity explicit. The next useful gate
is overlap between genuinely typed inputs and complementary operations, together with
end-to-end cost headroom. Neural information value, semantic roles, v17 coverage,
held-out generalization and novelty remain unproven.

## V21 compiled typed-complementarity preparation

Declared [v21](architecture/pilot_revision_v21.md) on 13 November 2026 before its
implementation/collection. V20's coarse association is available only on the old typed
integration inputs, while v14/v15's complementary operation inputs are different
sectionless binaries. Those results cannot be joined into a neural-benefit claim.
This revision prepares a small prospective overlap panel rather than extending the
unsupported exact-event gate or synthesizing predictions for the old inputs.

### Fixed new input panel and execution boundaries

The panel contains exactly **three authored functions in one shared PIE binary**:
typed_scalar_span, typed_readonly_table and typed_readonly_table_outside. Their declared
objects have capacities 1024, 8 and 8, with RDI domains [0,1023], [0,15] and [0,15].
The readonly offset tables contain {2,6} and {2,12}; table functions mask the index to
one bit. These are related capability shapes with a single readonly value-table load,
not identical reproductions of v14's two-level pointer chains. They form a separate
development panel and are not new primary/held-out samples or independent projects.

Two C translation units and disabled LTO prevent cross-unit constant replacement of
the external readonly table loads. A predeclared 64-bit AND inline assembly statement
avoids an unintended 32-bit opcode limitation in the frozen finite checker. An empty
register barrier keeps the pointer access materialized. Normal trivial main provides
standard PIE linkage. These authored choices are fixed before observing outcomes and
apply to every control; no checker or original TYGR source is changed. Sources, compiler
flags/version, ELF/DWARF symbols and complete function disassembly will be retained.

Extraction requires an AMD64 PIE with actual nonempty .debug_info/.debug_abbrev,
unambiguous defined function/object symbols, exact object capacities, uniquely mapped
writable objects, executable complete function bytes and one constant byte-store target.
The three contracts are fixed independently of type output or gold. Gold labels are a
separate file parsed only after runtime. Native acquisition receives binary/model/source
identities, not query bounds, expected answers or previous predictions.

One cold CPU child in the existing tygr-orig environment performs original serial
DWARF-assisted native preparation and genuine frozen-model forward calls, preserving
whole-variable aggregation. Every actual batch is recorded and checked before forward:
31-wide finite CPU features, 75 output classes, the declared relation domain and all
eight saved 44-relation layer capacities, endpoints and gather/scatter row membership.
Unsupported inputs are refused without relabeling/filling features or expanding layers.
Each generated nonempty function is retained before preprocessing. Complete earlier
predictions survive a later failure, with overall eligibility still requiring a complete
on-time identity-checked acquisition. Raw rows, vocabulary, candidate means and variable
identities are rechecked by the parent; duplicate/incomplete outputs are not coverage.
Function-level coverage does not establish semantic base/index roles or exact use sites.

Each query independently runs the four existing controls and a separate modeled reference:
interval-only, finite-readonly-only, expanded-only, fixed interval/finite/expanded cascade,
and reference. Runtime does not consume type labels or gold. Control order rotates by
query and all attempts remain visible, irrespective of acquisition success. The operation
execution/validation implementations are reused unchanged. No A-D/new selector, training,
GPU, package installation, network/API or native program execution is introduced.

### Budgets and readiness interpretation

The shared acquisition has a **120 s parent-owned cap**; each of the twelve controls
and three separate references has **30 s**. Parent clocks include request writing,
startup/imports, operation/native computation, recovery/cleanup and persisted detailed
payloads. Compiler/source setup, final accounting receipts and aggregate/offline evaluation
are explicit exclusions. One binary's acquisition is charged once and amortized over the
three planned queries; cached results are not free information.

The eventual summary reports complete query extraction, eligible genuine function
coverage, operation statuses/reasons, their intersection and reference disagreements.
Capability difference requires all three single-operation trials to have complete valid
receipts, so timeout/missing/wrong-identity output cannot manufacture an overlap. Every
planned query stays visible even when extraction or acquisition fails. Parent persistence
past a cap invalidates eligibility. The separate native function count/variable rows do
not inflate the three-query denominator.

Cold acquisition and total fixed-control costs are a single-pass descriptive sanity
check, not a counterfactual runtime bound or stable same-budget net benefit. Optimized
DWARF, model input compatibility, actual coverage and operation complementarity remain
hypotheses until Linux runs. No positive result is assumed from the authored labels.

### Windows checks and retained preflight

Windows MinGW GNU C syntax-only checking of both source files passes with -Wall/-Wextra.
It is not Linux code generation or actual ELF/DWARF/model validation. The final preparation
root is `.scratch/selective_analysis/typed-complementarity-v21-20261113-123506-36760/`
under the parent workspace. It snapshots **119 source/specification files**, including
all seventy original TYGR Python sources and project package initializers, plus the
single pinned model input. It records the prospective command and versions, verifies
original/copy/model/inventory integrity and finds no omitted loaded local Python module.
It creates **zero ELF binaries and launches zero native/compiler/control workers**.

An earlier preparation at
`.scratch/selective_analysis/typed-complementarity-v21-20261113-122813-15192/` stopped
before plan serialization because a compiler-version local variable shadowed the package
version-query function. Its partial snapshots and failure note are retained. Main review
renamed the local and added a complete preparation-path regression, including package
version queries and an assertion that preparation cannot launch workers. After the
full validation pass, the final preparation above succeeded. No failed native or
operation outcome is omitted; neither preparation performed such an operation.

The independent standard-library script
`.scratch/selective_analysis/audit_typed_preflight_v21.py` rehashes every source original
and copy plus the pinned model, checks three fixed label-free runtime specs and separate
gold, flags/two translation units/fixed methods/budgets, validates the worker's Python 3.8
syntax and pre-forward guard placement, and verifies absence of binaries/acquisition/
control outputs. It imports no framework or project parser and writes
`validated-preflight.json`. Final `run-plan.json` SHA-256 is
`209d03e68bd78c545a1693408610400feb2705b5dea70a26aa4df7f770ac2ef3`;
`preflight-summary.json` is
`4f7fa88ea104659cc67200d42565473f856100ea99fc3ebf31ee2a74a61c2d72`.

**1233 project tests pass**, with nineteen existing third-party deprecation warnings;
**twenty OPM views, 403 view-local nodes and 544 links** validate and render. Fifty new
tests cover fixed scopes/gold rejection, actual instruction decoding with controlled ELF
metadata, capacity/object/DWARF boundaries, pre-forward invalid-domain refusal, whole-group
logit identity/aggregation, duplicates/partial/late outputs, cost endpoints, false overlap
from incomplete controls, reference disagreements, Python 3.8 and the full prepare path.
Main agent completed/reviewed the implementation directly after delegation was unavailable.

Linux compilation, genuine new predictions, fifteen runtime trials and any readiness/
cost conclusion are **pending**. Run `python -B scripts/run_typed_complementarity.py`
from the D-drive project in WSL angr-env. It automatically uses the existing tygr-orig
interpreter and records all logs/failures. The agent did not retry the denied WSL launcher.
RQ1/RQ2, prior panels and all earlier measured sources/specifications remain unchanged.

## V21 WSL collection and location-base diagnosis

Audited on 13 November 2026. The user ran the predeclared v21 protocol in WSL angr-env;
the retained root is `.scratch/selective_analysis/typed-complementarity-v21-20261113-124728-819/`
under the parent workspace. GCC 9.4 produced one normal PIE ELF, SHA-256
`b3b8eb8a03d09112ef513aea572a840c547161bb41c7041386b2f7616267d9ed`.
All three fixed queries extracted. All fifteen controls/references completed with zero
wrong decisions against the authored labels. These are development cases, not held-out
evidence. A complete exclusion concerns only the explicit first-write query scope.

| Query | Interval | Finite readonly | Expanded | Fixed cascade | Separate reference | Genuine records |
|---|---|---|---|---|---|---|
| typed_scalar_span | excluded | unknown | excluded | excluded | excluded | 1 |
| typed_readonly_table | unknown | excluded | unknown | excluded | excluded | 0 |
| typed_readonly_table_outside | unknown | unknown | violation | violation | violation | 0 |

Here `excluded` abbreviates `excluded_within_scope`. Each query has differentiated
single-operation capability, but genuine function coverage and typed/capability overlap
are **1/3**. The old native worker completed one guarded forward with one genuine
whole-variable output. Its scalar Top-3 is struct*, char*, i32; this is not a type
accuracy result. No variable/use-site mapping or new selector was evaluated.

Cold shared acquisition cost is **8.051903 s**, descriptively **2.683968 s per planned
query**. The three fixed-cascade controls total **2.162008 s**. These are one-pass
parent-owned request-through-payload-persistence measurements, not a runtime bound,
statistical speed comparison or neural net benefit. Receipt/aggregate/evaluation work
remains excluded as declared. Missing type outputs cannot be silently dropped from
either the denominator or acquisition cost.

The independent script `.scratch/selective_analysis/audit_typed_collection_v21.py`
rechecks all 119 source originals/copies, the model, preflight/collection source identity,
binary bytes, extraction metadata/query fingerprints, all sixteen acquisition/control
request/candidate/payload/receipt chains, raw logit means and the complete summary.
It uses no native model, symbolic solver or WSL launcher. It writes `validated-audit.json`
and `dwarf-location-audit.json` beside the historical results. Anchors:

- `run-plan.json`: `5f8874459680a49105afd17b817f04fca63980f1bdf9154fe7059f860538e32f`.
- `summary.json`: `fe29568f7af273cde1b00a64cfec2ebdfc105c1d766f9ae84793f6e7ffdc7bb1`.
- `records.json`: `79ea7f425584095d1b13d1958818c3c0a19a192d5210bebc179fd9c92c75b1db`.
- `acquisition.json`: `ce7ed20934def5c2ec8ec8f12f4bfa1e0e05866174ea07fbf45e209e3af77430`.
- Location audit: `e97ec5d88b41a4ca035c9742291d8d9d35ac178ca5686f86a743fe9846bf5b6f`.

### Missing outputs have an independently reproducible location bug

Both table functions contain DWARF variables. The `No variable in function` messages
occur after filtering empty native node groups, unlike the separate main/no-DWARF-var
message. Native source `src/analysis/dwarf/location.py` adds the current function low PC
to small relative location-list offsets and ignores base-selection records. The ELF's
CU base is 4393; table function starts are 4405 and 4435. Their eight relative entries
are therefore shifted by 12 or 42 bytes. Five resulting intervals are wholly outside
their functions. For example, the safe-table offset variable should cover [4423,4435),
while the old parser produces [4435,4447).

DWARF4 defines relative list offsets against the preceding selected base, or the CU base
when no selection precedes the entry; see section 2.6.2, printed pages 30–31 of the
[official specification](https://dwarfstd.org/doc/DWARF4.pdf). This establishes a concrete
translation error. It does **not** establish that repairing it restores native groups:
other limits, including block-address annotations, can still affect correspondence.
The v21 specification, measured source copies and original TYGR files are preserved.

## V22 external location-repair preparation

The [v22 specification](architecture/pilot_revision_v22.md) freezes a narrow repair on
the exact same ELF/query identities. No additional case, compilation, control trial or
selector is introduced. The external adapter wraps the original simple/struct list
entry points and their lookup aliases. It resolves CU/selected bases, retains absolute
entries, preserves list order/overlap and original expression acceptance, and delegates
lists with already-absolute ranges and a zero legacy heuristic base. Single expressions
retain original function bounds. Unknown/missing/overflowing bases or unsupported
DWARF versions fail closed. This is explicitly an **adapted pipeline**, not a claim
that unmodified TYGR produced new outputs. It does not repair other expression/struct
semantics or establish exact event/type-role mapping.

The standalone Python 3.8 wrapper reuses the archived v21 acquisition implementation
and pre-forward guard. It verifies wrapper/adapter/helper identities and the origin of
loaded native location modules, while the archived worker rechecks all seventy original
sources, ELF and model before/after acquisition. Native graph/tensors and raw predictions
remain retained; every actual forward must pass saved input-domain checks. The parent
matches runtime adapter traces to the offline ELF projection before admitting coverage.
Failure, partial output or mismatched trace cannot create a missing function's coverage.
One 120 s cold parent acquisition includes wrapper setup, imports, loading, native
generation, guards, forwarding, export and persisted normalized payload. The prior
property-control results remain historical; they are not new timed comparisons.

**1259 project tests pass**, with nineteen existing dependency warnings; twenty-six
new checks cover the concrete old heuristic, CU/base-selection/absolute/zero/overlapping
ranges, invalid inputs, both aliases, unchanged single/multi-expression acceptance,
Python 3.8 parsing, implementation fingerprints, conservative coverage and complete
worker-free preparation. **21 OPM views, 421 view-local nodes and 569 links** validate
and render. Original pipeline sources/checkers and all v21 artifacts remain unchanged.

Final Windows preparation is retained at
`.scratch/selective_analysis/location-repair-v22-20261113-130652-40084/`.
It verifies **123 sources and six inputs**, reuses one ELF and launches zero native
workers. Its seven-variable offline projection is independently replayed through the
actual unchanged location parser plus the archived adapter: six variable lists change,
all nine ranges are retained, and the scalar expression stays unchanged. The script
`.scratch/selective_analysis/audit_location_repair_preflight_v22.py` imports no model or
solver and writes `validated-preflight.json`. Final plan SHA-256 is
`b3d0ded2cf300b90f7e5dcdb8e82f134788cf9e3b0a3f09177796c178d4926b7`;
preflight summary is `722cb6e29ffbb5cffd8298a7d51bcd9332f74581573d75144c6b4d690dc992e0`.

An initial focused-test run encountered the existing Windows pytest temporary-directory
ACL restriction. The new test now uses the suite's established D-drive workspace fixture;
the partial temporary directory is retained. A preparation regression fixture initially
omitted archived helper files and was corrected before the complete successful suite.
An earlier successful preflight at 130209 is retained but predates the wrapper's added
loaded-module-origin check; the final root above supersedes it for reproduction.

**Linux adapted acquisition is pending.** Run `python -B scripts/run_location_repair.py`
from the existing WSL angr-env in the project directory. The agent has not launched WSL
or a native model. Full coverage, prediction correctness, information value and equal-
budget scheduling gains remain hypotheses. RQ1/RQ2 and frozen A-D remain unchanged.

## V22 WSL adapter rejection audit

Audited on 13 November 2026. The user-run root is
`.scratch/selective_analysis/location-repair-v22-20261113-161334-1554/` under the
parent workspace. The parent acquisition completes in **7.345111 s**, but admits
**zero adapted function outputs over three planned queries**: only one of seven
expected adapter location records appears. Six `var_loc exception` messages originate
from the original lookup's bare exception handler. The runtime log contains no actual
exception detail, and the v22 receipt did not record pyelftools' version or tuple shape.
Do not retroactively claim an observed exception type/version from these logs.

The independent audit `.scratch/selective_analysis/audit_location_repair_collection_v22.py`
rehashes all **123 measured source copies and six original/copied inputs**, verifies
the acquisition request/candidate/payload/receipt chain, matches the raw native output
and adapter trace, and rechecks saved input domains plus raw whole-variable logits.
There is one complete, guard-passed scalar forward/output, **identical to v21**. Thus
the summary's accepted coverage 0/3 is an adaptation-admission result, not evidence
that the model lost its scalar output. The raw prefix remains available for independent
inspection. The six missing location lists correspond to the two table functions.
No new property controls, selector comparison or native replay were performed.

The audit adds `validated-audit.json` without rewriting the measured artifacts:

- Plan SHA-256: `dd70719dfac292049e4abf7e6f1146c1d42e640820d43efacf45b8011bf46d77`.
- Summary: `2d82b6ef19864957d6834e637eb168e97b4f225d93bb106d56efcc6af94505ab`.
- Acquisition: `3f60df470b173b1d46059d46183e83bf9b5f730859ec9819455b42c2dc00701b`.
- Offline trace: `25297dd11d98c2f308dd04ca8a2eb3651ef5293918738354c1aedbed5e6c1d2b`.

## V22.1 old pyelftools compatibility correction

The old TYGR environment file declares pyelftools 0.27. Its
[official location-list source](https://github.com/eliben/pyelftools/blob/v0.27/elftools/dwarf/locationlists.py)
defines four-field LocationEntry and two-field BaseAddressEntry tuples, with no
`is_absolute` field. V22 unconditionally reads/replaces that modern field. The main
agent's previous replay tested current pyelftools only and missed this runtime seam.
The [v22.1 specification](architecture/pilot_revision_v22_1.md) records the correction
before changing code. No historical specification, measured source or input is edited.

Two new regressions first fail on the old adapter with AttributeError for `is_absolute`,
including delegation to the actual original expression handler. The correction accepts
only the explicitly known four-/six-field layouts, treats old DWARF4 entries as relative,
and replaces only fields their concrete tuple declares. Modern absolute entries and
the existing semantic trace stay intact. Entry layout validation occurs at install,
before generation and model forwarding. The wrapper records actual pyelftools version
and tuple layouts in `adapter-api.json`, captures location errors before lookup can
swallow them in `adapter-errors.json`, and invalidates adaptation if any were recorded.
The parent includes these errors in its summary instead of hiding them behind a
generic trace mismatch. The saved-input guard and raw-logit admission remain unchanged.

The independent script `.scratch/selective_analysis/audit_location_compatibility_v22_1.py`
uses the **actual retained ELF and unchanged original expression handler**. Its ELF
reader is current pyelftools; legacy entries reproduce the exact public 0.27 tuple
contract. This is explicit interface replay, not execution in the old native environment.

| Adapter / entry interface | Successful variable locations | Ranges | Errors | Trace records |
|---|---:|---:|---:|---:|
| Frozen v22 / modern | 7 | 9 | 0 | 7 |
| Frozen v22 / legacy 0.27 | 1 | 1 | 6 | 1 |
| Corrected v22.1 / modern | 7 | 9 | 0 | 7 |
| Corrected v22.1 / legacy 0.27 | 7 | 9 | 0 | 7 |

The frozen legacy replay's six AttributeErrors and one surviving scalar trace reproduce
the observed omission pattern. Corrected old/new layouts produce identical expression
locations and match the offline projection. This establishes the compatibility defect
and local repair; it cannot identify unrecorded historical exception details or promise
native readout coverage.

**1265 project tests pass**, with nineteen existing dependency warnings. The location
suite has 32 tests, including six new checks for the legacy interface, original-handler
delegation, error persistence before suppression, early rejection of unknown APIs and
explicit parent error reporting. **21 OPM views, 423 view-local nodes and 575 links**
validate/render. The location view now makes actual entry-API checking explicit.

Windows preparation is retained at
`.scratch/selective_analysis/location-repair-v22-1-20261113-162031-34552/`.
It verifies **124 sources and six inputs**, reuses the same one ELF and launches zero
native workers. Its plan SHA-256 is
`f4d01552e902ed6a69057854a6b871c1668cd01d7ae74152116b3cd41c869591`;
preflight summary is `722cb6e29ffbb5cffd8298a7d51bcd9332f74581573d75144c6b4d690dc992e0`.
The four-way replay and integrity audit are saved as `validated-preflight.json`.

The command remains `python -B scripts/run_location_repair.py` in WSL angr-env.
New output uses `location-repair-v22-1-...` and variant
`external_dwarf4_location_base_adapter_v22_1`. Linux collection is pending. Preserve
the failed v22 data; do not combine its incomplete trace with a new acquisition or
claim neural information value, type accuracy or speed from this implementation fix.

## V22.1 successful WSL repair audit

Audited on 13 November 2026. The user-run root is
`.scratch/selective_analysis/location-repair-v22-1-20261113-162629-1577/` under the
parent workspace. The exact retained v21 ELF is reused. All three functions now have
genuine outputs: one scalar variable and three variables per table function. The three
guarded forwards complete; seven original variable records span eleven readout rows
and 41 native graph nodes. These are **three queries**, not seven/eleven/41 samples.
All seven location records match the offline projection, and no adapter error occurs.
The actual recorded pyelftools version is **0.27**, with the expected four-field
LocationEntry, two-field BaseAddressEntry and one-field LocationExpr. Original TYGR
source inventory, model and historical property results remain intact.

The independent script `.scratch/selective_analysis/audit_location_repair_collection_v22_1.py`
verifies all **124 source originals/copies and six input originals/copies**, exact
Windows-preflight/WSL-collection source identities, request/candidate/payload/receipt
chains, raw native output, API/adapter trace, query hashes, saved-domain guards and
full raw-logit aggregation. It reconstructs the complete summary and writes
`validated-audit.json`. The scalar prediction is unchanged from v21. No new native
model/solver runs in this audit; actual binary inputs are not replayed natively.

- Plan SHA-256: `8ddadbc64c09501a6fc876e057eb0af4529bc3386adc9d0c84aa72c9a9087421`.
- Summary: `c06b2e1fc598093beccac4cd615918fdff824ab0bc3bed2569ad1153ccdff979`.
- Acquisition: `81d62369f324ec10a171c0c4df6f37c669998ea23e53073a5ed8b34f9ad7aea2`.
- Offline trace: `25297dd11d98c2f308dd04ca8a2eb3651ef5293918738354c1aedbed5e6c1d2b`.

The cold parent acquisition is **8.304885 s**, descriptively **2.768295 s per planned
query**. No new property controls, selector, event/role mapping, accuracy evaluation or
held-out experiment is measured. Repair and acquisition admission are now complete.
The two table functions' complete prepared/collated inputs are identical, prompting the
following retained-data audit before any additional selector or weight tuning.

## V23 retained type-information collision audit

The [v23 specification](architecture/pilot_revision_v23.md) is declared after observing
these known development predictions and before implementing the reusable audit. It is
not unseen-data preregistration. `scripts/audit_type_information.py` revalidates the
anchored successful acquisition and historical inputs, then constructs all feature views
**before parsing the historical operation outcomes**. The pure module
`src/selective_analysis/type_information.py` retains original native group order and
all variables, without putting names, function/prediction addresses or outcomes into
the neural representation. It records separate Top-1-only labels, Top-K labels/raw
scores/conditional weights, full retained 75-class value-row logits, and exact prepared
and collated model-input signatures. Conditional Top-K weights are not calibrated type
correctness probabilities. No exact event or base/index role is claimed.

All three unordered pairs are compared, then historical interval/finite/expanded status
vectors are joined offline. The safe/outside table pair has **identical prepared inputs,
identical actual model batch inputs, identical Top-1 features, identical Top-K scores
and identical complete 75-class value-row logits**. The scalar/table pairs differ in
these representations. The observed table Top-1 sequence is i32, struct*, struct* in
native group order; variable naming/role/type correctness is not established by this.

| Observed table-query evidence | typed_readonly_table | typed_readonly_table_outside |
|---|---|---|
| Prepared/actual model input | Identical pair | Identical pair |
| Top-1 / Top-K / all retained logits | Identical pair | Identical pair |
| Historical interval-only outcome | unknown | unknown |
| Historical finite-readonly-only outcome | excluded_within_scope | unknown |
| Historical expanded-only outcome | unknown | violation |

This is an exact information collision in the recorded neural views, not just a small
Top-3 difference. Those views alone cannot distinguish this pair. A selector with
additional structural/readonly-content evidence, operation observations or adaptive
fallback may still distinguish or resolve them. The result does not prove all neural
schedulers useless. Conversely, different scalar/table type vectors do not prove extra
value over their obvious instruction/load structure. No new policy, type weight or
candidate operation is introduced to force an order difference.

The paid cold acquisition is **8.304885 s**. V21's historical fixed-cascade parent
costs are 0.385914 s, 0.386224 s and 1.389870 s, totaling **2.162008 s**. These are
different runs/stages, not a matched end-to-end speed comparison, a counterfactual
cost-saving bound or a persistent-service measurement. Current observations provide
no positive net-benefit evidence. Eleven readout rows and repeated representations
do not inflate the three-query denominator or make cached neural data free.

The completed Windows offline run is retained at
`.scratch/selective_analysis/type-information-v23-20261113-163845-52748/`.
It snapshots **16 source/specification files and five input artifacts** and launches
no model, property or subprocess workers. It preserves every original acquisition and
control record. The independent standard-library script
`.scratch/selective_analysis/audit_type_information_v23.py` reconstructs every Top-1,
Top-K weight, full-logit and model-input representation directly from raw records,
checks pair equality by actual data rather than just hash comparison, verifies historical
capabilities/costs and source/input original/copy identities, then writes
`validated-audit.json`. No model or symbolic framework is imported.

- V23 plan SHA-256: `6da5785fe0e9499065fd6cd9a5c6c6ce9427d07e7809ee2c6a8cf320c0f3045c`.
- Summary: `40f5b2d6fb24caba19b54120230a3e084cee855a43167de094b5caef6543eff3`.
- Representations: `fe689b9847cbce70cae65d2fe248d9cf9e6281c866b7cce1c4995294790a059a`.
- Pair comparisons: `9c5c9d96b8ceda03a2db44de339c0fc17f2346d14514a5a3ddcacba8051733bc`.

**1285 project tests pass**, with nineteen existing dependency warnings. Twenty new
checks cover identity-free representations, original group ordering, Top-K versus full
logit differences, missing/duplicate/nonfinite/malformed records, independent input/output
collision flags, strict three-query denominators, offline status scope and anchor refusal.
**22 OPM views, 440 view-local nodes and 593 links** validate/render. The native repair
and current offline audit need no additional user-run WSL command.

### Research decision after this panel

Keep these three cases as integration/regression and cost controls. Do not train or tune
a selector on them, add modules to manufacture neural gain, or repeat expensive C/D
timings as evidence of information value. A later small independent development panel
needs a strong structural baseline and meaningful operation-cost differences; it must
first test whether neural features add information beyond that baseline. Additional
readonly-content/structural cues belong equally to B/C/D when used. Whole-function
features can be tested without inventing an exact-event prerequisite, but their scope
must remain explicit. RQ1/RQ2, frozen B/C/D, hardware limits and the twelve-query primary
panel remain unchanged. Neural scheduling value and publication novelty are unproven.
