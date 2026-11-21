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

Route B starts with the [paired information pilot](../benchmarks/selective_analysis/route_b/README.md).
It fixes six new authored program groups, twelve queries and four information arms.
The Windows source reference confirmed the bounded index across all 1,536 declared
inputs. The WSL comparison admitted predictions for all six groups and completed
192 trials with zero wrong decisions. At 0.15 s the type-blind arm resolved 16/24
trials, compared with 14/24 for Top-1, 12/24 for unscored Top-K and 13/24 for scored
Top-K. At 0.50 s all arms resolved 18/24. The results leave Variant E deferred.
See the [paired results and scope](../benchmarks/selective_analysis/route_b/README.md#wsl-results).

The six groups provide a fixed pilot for this selector and operation catalog.
Keep this panel and the three earlier typed cases as documented controls if a
later experiment tests a different source of information or changes the catalog.

The independent proof-validation follow-up tested nine source-selected bounded
loop functions from four upstream projects. At 3 s both methods resolved 6/27
trials with zero wrong decisions. All six correct decisions in the certificate
arm used replay fallback. The audit identifies separate limits in symbolic
exploration and instruction flag semantics.
[Bounded-loop validation results](../benchmarks/selective_analysis/route_b/README.md#independent-bounded-loop-validation-cohort).

A parent-enforced cold-worker rerun accepted no late results. Both arms
resolved 3/27 trials at 3 s and 0/27 at 1 s. A separate producer profile found
that native Z3 checks accounted for 0.9% of producer time on zlib `multmodp`
and 41.0% on FFmpeg `av_gcd`.
[Deadline and producer results](../benchmarks/selective_analysis/route_b/README.md#parent-enforced-deadlines-and-producer-costs).

A guarded four-instruction batching pilot reproduced the full path and
first-write results for `multmodp` and `av_gcd`. It lowered successor
calls from 847 to 582 and from 217 to 129. Complete paired trials at
relaxed budgets showed median wall-time savings of 0.229 s and 1.416 s.
At 3 s both modes remained unresolved on both cases.
[Instruction batching results](../benchmarks/selective_analysis/route_b/README.md#guarded-instruction-batching-pilot).

With the same batch producer, the `multmodp` development case resolved
3/3 trials at 3 s after prewarming when using certificate validation.
Fresh replay and both cold arms resolved 0/3 at that budget. At 8 s all
four arms resolved 3/3, with paired certificate savings of 1.94 s cold
and 1.91 s prewarmed. The `av_gcd` fallback control completed after the
checker rejected an unsupported instruction.
[Cold and prewarmed validation results](../benchmarks/selective_analysis/route_b/README.md#certificate-validation-with-cold-and-prewarmed-workers).

A frozen comparison on six additional scalar functions found 10/12
verified results per arm at each of the 3 s and 8 s prewarmed budgets.
OpenJPEG supplied all four direct certificates. The predeclared
cross-project criterion was unmet with one qualifying project. The most
frequent certificate rejection was the unsupported `bsr` instruction.
[Frozen scalar-function comparison](../benchmarks/selective_analysis/route_b/README.md#frozen-certificate-comparison-on-new-scalar-functions).

Guarded `bsr` support and subtraction flags raised direct certificate
acceptance from 2/12 to 8/12 at both budgets on the same six cases.
The total remained 10/12 correct per arm, and all accepted results
passed the post-run audit. The saved Lua and zlib certificates also
passed the revised checker.
[Instruction semantics regression](../benchmarks/selective_analysis/route_b/README.md#guarded-bit-scan-and-subtraction-flags-regression).

A frozen follow-up on six functions from four additional projects
resolved 6/12 trials per arm at both budgets. fmt's hexadecimal
digit count supplied all direct certificates, with a paired median
8 s saving of 42 ms. No project met the predeclared criterion.
[Independent follow-up results](../benchmarks/selective_analysis/route_b/README.md#independent-comparison-after-the-bit-scan-revision).

On three previously unresolved 64-input contracts, concrete execution of
the same ELF fixtures verified 4/6 trials at both budgets. The frozen
symbolic pipeline verified 0/6. Boost and LibTomMath completed in every
concrete repetition. Two GMP inputs reached the target exactly at the
boundary of the primary depth window.
[Finite-input execution baseline](../benchmarks/selective_analysis/route_b/README.md#exact-finite-input-execution-baseline).

An input-domain sweep held each ELF fixed at 16, 64, and 512 inputs.
At 512 inputs, fmt completed with three symbolic paths and a paired
certificate comparison against exhaustive execution. Both zlib arms
were unresolved at that size, with the symbolic producer exceeding its
state limit.
[Input-domain size sweep](../benchmarks/selective_analysis/route_b/README.md#input-domain-size-sweep).

A bounded symbolic prefix changed the backend selected for some small
input domains. With probe cost included, prewarmed 3 s coverage rose
from 12/18 to 14/18 in development. Both selectors reached 12/12 on
the routing holdout. The prefix selected a faster backend for queries
from FreeType, Opus, and SDL in both repetitions. On the same holdout,
a direct 3 s deadline from process launch yielded 8/12 verified
results with the prefix and 2/12 with input count alone. All six
paired gains came from those three projects, with zero paired losses,
wrong decisions, or late admissions.
[Prefix selection results](../benchmarks/selective_analysis/route_b/README.md#symbolic-prefix-for-selecting-an-execution-strategy).

A cold-start test on six new scalar queries from five projects used
the frozen selector and included both fixed backends. At 3 s the prefix
and fixed concrete execution each verified 12/12 trials. The fixed
symbolic backend verified 8/12. The coverage criterion remained unmet
against concrete enumeration. The audit found zero wrong decisions or
late admissions in all 36 trials.
[Independent cold-start results](../benchmarks/selective_analysis/route_b/README.md#cold-start-test-on-five-new-projects).

The same six binaries were retested at 128 and 256 inputs under a 3 s
cold deadline. Fixed concrete execution verified 9/12 and 7/12 trials,
respectively, and fixed symbolic execution verified 8/12 at both sizes.
At 256 inputs, both utf8proc byte classification trials required the
concrete backend and both stb bit reversal trials required the
symbolic backend within the measured deadline.
[Cold-start domain scaling](../benchmarks/selective_analysis/route_b/README.md#cold-start-domain-scaling-on-the-same-six-kernels).

Extending the frozen prefix rule to 256 inputs yielded 7/12 verified
trials, equal to the simultaneously rerun fixed symbolic backend, and
missed the coverage criterion. Both utf8proc probes selected concrete
execution and took over 0.9 s. Both then reached the parent deadline
before completing enumeration. Fixed concrete execution verified
3/12 trials in the same run.
[Extended prefix test](../benchmarks/selective_analysis/route_b/README.md#prefix-applicability-extended-to-256-inputs).

A paired timing audit estimated 168 ms of routing headroom in the
utf8proc repetition with a completed concrete control. A separate
120 ms parent deadline test admitted all 20 short synthetic tasks and
stopped and reaped all 40 longer tasks. The longest interval through
recovery was 138 ms. These measurements cover the timer with synthetic
work and a retrospective budget calculation for the recorded trial.
[Routing headroom diagnostic](../benchmarks/selective_analysis/route_b/README.md#routing-headroom-and-synthetic-deadline-test).

A real isolated-prefix comparison admitted eight of 12 probe replies
within the 120 ms response window and recovered all helpers. All
loading and cleanup costs were included in the 3 s cold deadline.
The isolated arm and fixed symbolic execution each verified 8/12
trials, while fixed concrete execution verified 2/12. The isolated
arm took 188 ms longer at the paired median on eight shared successes
and missed the coverage criterion. The initial reply-versus-exit
transport issue was corrected, and both versions' records were
retained.
[Isolated-prefix comparison](../benchmarks/selective_analysis/route_b/README.md#isolated-prefix-with-parent-enforced-response-admission).

A persistent-worker comparison processed the same six queries in
forward and reverse batches, charging all loading and recovery to
an 18 s batch budget with at most 3 s per request. The prefix
verified 10/12 queries, fixed concrete execution 9/12, and fixed
symbolic execution 8/12. It preserved every fixed-method success.
Both prefix batches took about 9.95 s. The same-panel engineering
criterion passed. A Windows staging-file cleanup error was corrected,
and all six reported batches were rerun.
[Persistent-worker batch results](../benchmarks/selective_analysis/route_b/README.md#persistent-workers-under-a-charged-batch-budget).

A stronger fixed baseline first ran the symbolic backend and used
concrete execution for unresolved queries under the same deadline.
In a fresh paired comparison, it and the persistent prefix each
verified 12/12 queries. The fixed fallback batches took 7.170 s
and 7.187 s, compared with 8.161 s and 8.163 s for the prefix.
The prefix added zero decisions and missed the coverage criterion.
All 24 query records passed the audit. The current panel therefore
leaves the prefix's advantage over fixed fallback unestablished.
[Fixed fallback comparison](../benchmarks/selective_analysis/route_b/README.md#fixed-symbolic-to-concrete-fallback-baseline).

A retrospective route replay used the backend that had completed
each query in both earlier cascade repetitions. The replay verified
12/12 queries in 6.018 s and 6.029 s per batch; the newly paired
cascade verified 10/12 in 10.177 s and 8.848 s. Both added decisions
came from the stb integer-log query, whose direct concrete runs
left 117--124 ms under their local deadlines. Avoiding its timeout
also avoided a backend replacement. The first batch pair included
1.037 s of initial-loading variation. These are same-panel
headroom measurements using historical outcomes.
[Retrospective route replay](../benchmarks/selective_analysis/route_b/README.md#retrospective-zero-acquisition-route-replay).

A four-repetition latency test produced 21/24 verified queries for
the fixed cascade and 23/24, 24/24, 24/24, and 22/24 for historical
route replay with 0, 50, 100, and 150 ms of added request latency.
Every unresolved result came from the integer-log query. Zero-delay
replay missed once, and the 100 ms arm's minimum post-reply slack
was 11.7 ms. A stable latency guarantee remains unestablished.
All 120 query records passed the result and deadline audit.
[Repeated latency sensitivity](../benchmarks/selective_analysis/route_b/README.md#repeated-sensitivity-to-added-routing-latency).

A cooperative 100 ms first-stage cascade was tested in four batch
repetitions alongside the original cascade and historical replay.
It verified 18/24 queries, compared with 21/24 and 23/24. The cap
interrupted bit-reversal symbolic attempts that otherwise completed
in 102--114 ms. utf8proc's capped first attempts still took
925--937 ms. The capped method lost three paired successes and
added 2.903 s at the paired batch median. All 72 query records
passed the result and deadline audit.
[Cooperative first-stage budget results](../benchmarks/selective_analysis/route_b/README.md#cooperative-first-stage-budget-baseline).

A local profile traced utf8proc's first-stage overrun to repeated
cached-model constraint evaluation during symbolic-address enumeration.
A query-local exact cacheless frontend with per-model deadline checks
preserved entry constraints and passed cancellation and reuse tests.
In a fresh four-repetition comparison on the same six developer
queries, the original, ordinary capped, and guarded cascades verified
20/24, 18/24, and 22/24 trials. utf8proc's capped stage fell from
922--938 ms to 100--111 ms. The guarded method gained three paired
decisions and lost one, with 0.261 s median batch savings and one
batch 3.156 s slower. Stable advantage remains unestablished. All
72 records passed independent result and deadline checks. The
configuration remains experimental and no neural information was
evaluated.
[Model-cache diagnosis and guarded enumeration](../benchmarks/selective_analysis/route_b/README.md#model-cache-diagnosis-and-guarded-enumeration).

The next diagnostic found that disabling the model cache increased
simple proof costs. A query-local variant retained the default
composite cache and added deadline checks within cached-model and
native-model enumeration. Constraint, copying, cancellation, and
cached-read reuse checks passed. A fresh comparison on the same six
known queries repeated four times verified 20/24 trials with the
original cascade, 24/24 with a cache-preserving 100 ms first stage,
and 23/24 with 150 ms. The 100 ms arm gained four integer-log
results, lost zero baseline successes, and saved a paired median
1.468 s per batch. Its smallest integer-log reply slack was 8.2 ms.
All 72 records passed independent result and deadline checks. The
same-panel engineering criterion passed, and the 100 ms configuration
is frozen as a non-neural development reference for the next disjoint
comparison. Neural benefit and independent generalization remain
unestablished.
[Cache-preserving deadline checks](../benchmarks/selective_analysis/route_b/README.md#cache-preserving-deadline-checks).

A frozen-configuration test then selected one source kernel from each
of six previously unused projects: Jansson, cJSON, LZ4, bzip2, XZ,
and Brotli. The fixture definitions and criteria preceded compilation
and timing; all 1,536 native inputs passed independent mathematical
checks. Both the original cascade and the frozen 100 ms method
verified 20/24 trials across four repetitions, with all bzip2 trials
unresolved. There were zero paired gains or losses. The 100 ms method
added a paired median 3.429 s per batch because it interrupted
Jansson and cJSON symbolic checks that completed within roughly
0.2 and 0.43 s under the original method. All 48 records passed
independent result and deadline checks. Preservation passed, while
coverage and cost transfer failed. The original cascade remains the
primary general baseline and the 100 ms version remains a sensitivity
control. This test covers extracted scalar functions with wrappers;
neural information and complete applications were not evaluated.
[Frozen cutoff test on six new projects](../benchmarks/selective_analysis/route_b/README.md#frozen-cutoff-test-on-six-new-projects).

A prospective progress diagnostic reused all twelve observed functions
in 48 phase-only and counter-mode runs. Both modes verified 16/24
symbolic-only runs. All fifteen counter-mode runs still active at
100 ms had counters actually received before the checkpoint. Median
paired added query time was 0.764 ms, with an 82.874 ms maximum.
Identical phase/counter views occurred with different subsequent
500 ms validated-continuation outcomes. All 48 records passed source,
symbolic-reference, and receipt-time checks. The counters are usable
observations, but this view alone does not fully distinguish the
recorded outcomes. Actual switching utility, neural benefit, and
held-out prediction were not evaluated.
[Prospective progress observation](../benchmarks/selective_analysis/route_b/README.md#prospective-progress-observation).

A shared-resident-checkpoint study then collected 24 action pairs
from the twelve known functions. Both actions paid the same actual
prefix and used the same residual 3 s budget. Continuation validated
16/24 actions and switching validated 22/24. Continuation was cheaper
in sixteen pairs, switching alone validated six, and two pairs were
unresolved. Thirteen continuation preferences already had candidate
evidence awaiting validation. Among eleven active-producer prefixes,
three preferred continuation, six switching, and two remained
unresolved. All 48 records passed independent checks. Prefixes took
31--945 ms, and resident-state measurements excluded startup and
state destruction. No routing or neural benefit was measured.
[Actions from a shared resident checkpoint](../benchmarks/selective_analysis/route_b/README.md#actions-from-a-shared-resident-checkpoint).

A retrospective phase-rule replay continued validation when candidate
evidence was available and otherwise selected switching. It preserved
the switching control's exact resolved set of 22/24 prefixes, while
aggregate charged work fell from 39.409 to 26.337 s. The remaining
observed oracle opportunity was 5.938 s across two cJSON prefixes
and one Jansson prefix. The 96 replay selections passed independent
checks against pre-action features and measured receipts. These are
development replay costs, with inherited startup and cleanup
exclusions; no live policy or neural benefit was measured. The phase
rule is a stronger structural candidate baseline for prospective
evaluation.
[Phase-only baseline replay](../benchmarks/selective_analysis/route_b/README.md#phase-only-baseline-replay).

A live comparison then charged startup, state discard, final cleanup,
transport, validation, and recovery under unchanged 18 s batch and
3 s request deadlines. Across 96 planned records, always-continue,
always-switch, the frozen phase rule, and the original cascade
verified 16/24, 12/24, 19/24, and 20/24 queries. The phase rule
dominated always-switch on this run, but lost one cJSON success
against the cascade and added a paired median 1.148 s per batch.
Its stronger-control advantage criterion failed. The independent
audit passed all 96 records and charged-cleanup receipts. The
original cascade remains the primary general baseline; the phase
rule remains a structural comparison arm. No neural or held-out
benefit was evaluated.
[Live phase rule with charged cleanup](../benchmarks/selective_analysis/route_b/README.md#live-phase-rule-with-charged-cleanup).

A strong-baseline feasibility audit found that the four live methods'
successful-query union equals the cascade's 20/24. Four successfully
resolved concrete fallbacks spent a total 2.443 s in preceding
unsuccessful symbolic stages; this is trace-local work rather than
measured scheduling savings. All twelve timing ELFs lack section
tables needed by the current DWARF-assisted locator. No neural
inference was attempted. The historical acquisition profile is not
a matched cost for this panel. The next gate is code-identical
native debug/stripped input pairs with verified variable mapping,
followed by new baseline and acquisition measurements. Variant E
remains deferred.
[Strong-baseline feasibility audit](../benchmarks/selective_analysis/route_b/README.md#strong-baseline-headroom-and-neural-input-eligibility).

The user completed all twelve native debug/stripped builds in WSL.
Independent reinspection passed code/data identity, all 3,072 native
outputs, and twelve entry-argument bindings. Sources and the frozen
builder were unchanged. Full use-site mapping and new baseline
timings remain pending. The two-function native probe completed:
cJSON produced genuine output and a verified entry binding; Brotli
was refused before any forward. Its inverse-left-shift edge has
relation ID 48, outside every saved layer's 44-slot domain. The
checkpoint's preprocessing declares 60 relations, and upstream
model code hardcodes 44. No lossless remapping has been established.
An independent audit revalidated cJSON's raw logits and binding,
reproduced the Brotli guard refusal, and found no changed prior
inputs or upstream sources. This is a checkpoint-compatibility
limitation, not a location-adapter failure or a neural-value result.
The remaining ten-function run then completed with six usable
entry predictions. The combined independent audit confirms 7/12
usable functions. xxHash, stb bit reversal, Jansson, XZ, and Brotli
remain unavailable because of saved relation-domain limits, with
zero forward attempts on each failed function. No source or input
changes were reported. utf8proc and LZ4 have exactly equal full
75-class entry logits but different actual input tensors. This
limits that readout's discriminatory value for the pair; it does
not show that the complete scheduling feature vectors are equal.

The native baseline gate measured the unchanged cascade on all
twelve new native ELF queries, three repetitions in six six-query batches.
Startup, transport, validation, cleanup, and worker recovery are
charged. Parent-only reporting stratifies results by the seven
available and five unavailable neural entries; workers receive no
neural features. The official WSL run resolved 30/36 trials; stb
ilog and bzip2 accounted for all six unknowns. No wrong decisions,
late admissions, process leaks, or batch overruns were recorded.
Independent reinspection checked all 36 records, 379 workspace
artifact hashes, and 2,152 complete or partial concrete observations.
The WSL runtime source hashes were retained at collection and
were not reread from Windows. Variant E remains deferred.

The first WSL launch stopped before any timed batch because an
archived hash dictionary used Windows keys while its caller used
WSL paths. An external adapter now resolves unique equivalent
D-drive dictionary keys during parent and worker bootstrap.
Archived keys, values, digests, source files, and analysis logic
are preserved. The actual full import chain was reproduced with
foreign-style keys before the fix and passed afterwards; a fresh
worker also completed that bootstrap. A wrong recorded digest
still fails. Twenty-three targeted tests and the revised one-case
host smoke passed before the successful WSL retry.

Stage inspection separates execution from worker replacement:
miniz and XZ each waited about 1.94 s before their operation opened,
after the preceding query's timeout. Their remaining request tails
were about 0.17 s. stb ilog began concrete enumeration and observed
204--207 inputs before each timeout; bzip2 timed out in the symbolic
producer. The older `fallback_trials` field counts finalized policy
choices, so zero on an unfinished request does not imply no fallback
started. The supplementary independent audit retains actual starts.

The next gate compared the cascade with direct concrete
execution on the same complete twelve-case panel: two fixed arms,
three repetitions, twelve paired batches, 72 query records, unchanged
deadlines and charged cleanup. It distinguishes started and finalized
attempts and reports pre-operation waiting separately. Both arms
passed the one-case host execution smoke, and 25 targeted tests
passed before the formal WSL comparison. That comparison completed
with 30/36 cascade results versus 11/36 direct results, no direct
gains, and nineteen direct losses. All six paired batches favored
the cascade, with a paired median 6.833 s lower batch time. The
independent audit checked 72 records, 384 workspace artifact hashes,
8,536 concrete observations, admission and cleanup clocks, and worker
reaping. No correctness or admission errors were found.

Direct execution's 25 unknowns contain six ready-worker timeouts,
seventeen requests with more than one second of pre-operation
waiting, and two requests whose producers never started. Sixteen
of the nineteen direct losses had that long wait, two never started,
and one timed out with a ready worker. The one-second threshold is
post hoc descriptive grouping, not a routing rule or causal estimate.
The global comparison supports the cascade under the frozen batch
protocol; it does not establish that symbolic-first is best for every
query in isolation. No neural scheduler or benefit was evaluated.

The local operation-value matrix is now prepared in
`scripts/measure_native_local_actions.py`. Every action uses its own
fresh worker. The parent confirms readiness before opening an equal
3 s allowance, retains all twelve queries and independent checkers,
and separately records startup, action, parent termination/reaping,
and total diagnostic wall time. The frozen cascade and direct concrete
strategy each run three times per query, with balanced first-arm
order, giving 72 actions. Query initialization, transport, checking,
validation and worker-side cleanup remain inside the action allowance.

Twenty-eight targeted tests, both one-case host executions, and an
actual 3 s host timeout/reaping probe passed. The host smoke's action
and startup clocks and the 72-action pairing were independently checked.
The official WSL collection then completed 72 actions with 30/36
cascade resolutions and 27/36 direct resolutions. cJSON accounted
for the three direct losses; neither method resolved stb ilog or
bzip2. Direct execution was faster in all three repetitions of
utf8proc and Brotli. No new completions or neural benefits were
measured. Independent review checked 72 fresh worker identities,
389 workspace artifact hashes, 10,582 concrete observations and
all readiness, allowance, admission and recovery ledgers. Recorded
WSL runtime hashes were not independently reread from Windows.

The post hoc local action opportunity was 4.248 s across all three
twelve-case repetitions, with 3.303 s on neural-available cases.
These are replay sums from observed actions, not expected utility,
a deployable policy or an end-to-end saving. Brotli lacks usable
model output. The available direct winner, utf8proc, has exactly
the same retained 75-class entry logits as LZ4, which favors the
cascade by about 1.61 s per action. Their three-node input graphs
match under permutation [1, 2, 0], preserving all 31 node features,
directed relation IDs, and variable readout membership. Different
raw tensor order therefore did not preserve a distinguishing graph.

An optimistic post hoc type-output-only grouping, prioritizing
completion count and then observed action cost, retained the cascade
in every available feature group. This does not rule out a joint
structural/neural policy or refute the broader hypothesis; it does
not establish incremental neural value on this panel either.
The next recommended work is input-graph coverage on the utf8proc/
LZ4 pair: inspect execution capture, graph splicing and feature
encoding before collecting more timing data or training a scheduler.
Variant E remains deferred. The local diagnostic does not replace
the charged global batch result.

The two-function stage observer is now prepared in
`scripts/audit_native_graph_stages.py` and
`scripts/capture_tygr_graph_stages.py`. It retains original execution
returns and records step exceptions, action histories, read-hook
fields, pre/post-splicing graphs, normalization mappings and feature
encoding. The original checkpoint is loaded for its preprocessing
configuration; every model forward is blocked. The parent requires
the final encoded input to match the frozen original up to node
renumbering and validates location traces independently.

Static review identifies hypotheses rather than a confirmed cause:
the executor catches step exceptions and returns partial states;
read hooks assign long-form expression attributes whose registration
must be checked in the old runtime; splicing removes nodes outside
the selected variables' reachability; encoding coarsens node values.
Host angr 9.2.217 field names are not evidence about the actual
9.0.7491 runtime. Thirty targeted tests, Python 3.8 worker syntax,
strict request identity checks and frozen snapshot replays passed.
The original-runtime capture subsequently completed for both
functions with zero forward attempts and no observer/location errors.
Both executed the target write, and neither recorded a step exception.
The pre-splice graphs had 25 and 297 nodes; both variable-seeded
views retained only three nodes and only register location/data edges.
Retained node features were unchanged by splicing, and both final
batches exactly matched their historical inputs. Thus the observed
graph distinction was lost before final encoding, in the selected
variable view. This does not by itself establish a defect in the
reachability algorithm: the selected parameter nodes lacked a
directed connection to the target-related memory nodes beforehand.

The old angr 9.0.7491 runtime confirms that `reg_read_expr` and
`mem_read_expr` are registered, while the long names written by
the original read hooks are not. The hook-created parameter-read
annotation appears on the long field but not on the actual first
argument-read action. This confirms an interface mismatch; a repair
intervention is still needed to establish which field/timing changes
restore propagation. Earlier neural-negative findings remain scoped
to the historical acquisition pipeline.

Independent review checked both observations and 90 unique workspace
artifact hashes, reconstructed the exact retained node/edge set,
verified target writes and original-input parity, and retained old
runtime metadata. Simply disabling splicing is insufficient for the
current checkpoint: the full LZ4 graph uses relation IDs 50 and 55,
outside its 44 saved slots. The next recommended step is a no-forward
controlled comparison of original hooks, field-name correction, and
field-name plus event-timing correction, with graph restoration and
checkpoint compatibility reported separately. No upstream source,
checkpoint or frozen result has been changed.

The controlled comparison is now implemented in
`scripts/compare_tygr_read_hooks.py`, with the standalone Python 3.8
worker `scripts/capture_tygr_hook_variants.py` and external adapter
`scripts/tygr_read_hook_variants.py`. It prepares six fresh subprocess
captures: the same two functions under original hooks, fresh-expression
field routing with BEFORE timing, and the same routing with read-only
AFTER timing. Both intervention arms call the original read hooks once;
stale aliases from ignored reads are not routed. Write-hook timing is
preserved, and all in-memory patches are restored on exit.

Twenty-one targeted tests passed, including actual host inspection
reads, callback delegation/restoration and independent replay of passed
and rejected input-guard receipts. The host emitted four inspection-API
deprecation warnings; the adapter intentionally retains the original
runtime's API. Python 3.8 worker/adapter syntax checks and six strict
prepared-request identity checks passed. The preparation-only bundle is
`route-b-read-hook-controls-20261119T190856661660Z`; its
`host-validation.json` records preparation checks without model loading.
These checks are not old-runtime intervention outcomes.

The original arm must reproduce its retained native input. Intervened
graphs retain the unchanged saved-model guard's pass or rejection,
replayed by the parent, as a separate observation. No model forward is
allowed in any arm. A passing tensor guard alone does not establish
that a changed graph matches the checkpoint's training distribution or
produces useful predictions. Target-PC graph reachability remains a
diagnostic indicator rather than a full use-site or property proof.
The subsequent WSL collection completed all six captures in
`route-b-read-hook-controls-20261119T191220997252Z`. Independent offline
review checked 99 unique workspace artifact hashes, original source
inventories, location traces, exact splice mappings, retained features,
the first RDI-read annotations, target-write actions and unchanged guard
receipts. All captures had zero forward attempts and no step exceptions.

Field routing with BEFORE timing produced exactly the original collated
inputs: three retained nodes in each function and no diagnostic
parameter-to-target-PC memory path. With field routing and AFTER timing,
the first argument read carried `RegisterReadAnnotation`, both diagnostic
paths appeared, and the views retained 17 nodes for utf8proc and 221 for
LZ4. This isolates the timing effect conditional on corrected routing in
these two functions. A timing-only arm was not run, and full use-site
mapping, property validity and neural usefulness remain untested.

The restored utf8proc input passed the unchanged tensor guard. LZ4 was
refused for inverse `If` and `Eq` relation IDs 50 and 55. Passive inspection
of the checkpoint's pickle opcodes, without unpickling or model execution,
confirmed that its saved operation list equals the current reduced list:
30 relation kinds per direction, 60 declared IDs, but `edge_dim=44`.
This confirms the stored schema/capacity discrepancy. It does not prove
the historical training mapping or how every runtime path treats an
unsupported ID. No remapping, edge deletion or capacity expansion is
admitted as an inference fix.

Both restored views have one original DWARF variable, `x`, with two
flattened value-node readouts rather than one. Those are not two distinct
source variables. Any subsequent inference must retain that correspondence
and evaluate changed preprocessing separately from the historical inputs.
The next task is to establish relation-schema provenance and a justified
compatible checkpoint path before a paired neural comparison. The guarded
LZ4 failure is not an experimental crash. Variant E remains deferred.
[Controlled intervention results](../benchmarks/selective_analysis/route_b/README.md#confirmed-read-hook-intervention-results).

`scripts/audit_relation_schema.py` now implements the provenance and
operator-behavior audit. Its host preparation in
`route-b-relation-schema-20261119T192634266587Z` reuses the bounded passive
checkpoint parser, checks all eight `[44, 10]` basis coefficient matrices,
compares the saved/source operation vocabulary, and enumerates all 60
declared IDs. IDs 44 through 59 are outside every saved layer's capacity;
they are all inverse relations under the saved offset of 30. The restored
LZ4 input has 574 directed relation entries, including 130 with ID 50 and
66 with ID 55. These are static counts, not observed operator omissions.

The upstream Git tree lists 24 model paths. Only the frozen x64 O0 base
checkpoint is checked out; the x64 O1/O2/O3 base blobs are unavailable
locally. The checkout is shallow, so it provides no local history proving
the original training mapping. Git checks disable all network protocols
and lazy fetching. No alternative weight or dataset was downloaded.

Twelve targeted tests passed, including passive real-checkpoint capacity
verification and interpretation checks that reject uninformative synthetic
controls. The prepared standalone Python 3.8 worker will retain the actual
installed RGCN source and test eleven tiny, deterministic CPU layer calls.
Its basis count and relation capacity match the saved layer branch, but
its two-channel parameters are artificial and never loaded from TYGR.
Positive and empty controls distinguish raised errors, zero single-edge
messages and nonzero messages; mixed-edge controls test output equality
against valid-only input. The subsequent original-runtime collection is
retained in `route-b-relation-schema-20261119T192837627552Z`.
None of these outcomes by itself establishes training semantics or
admits a rejected checkpoint input. The production guard is unchanged.

The runtime collection completed eleven synthetic layer calls with the
expected positive controls. IDs -1, 44, 50, 55 and 59 each yielded zero
single-edge messages. Adding IDs 50 or 55 to a valid edge produced exactly
the valid-only output. The retained PyG 1.7.0 source explains this behavior:
the examined dense-feature basis path loops over
`range(self.num_relations)` and selects `edge_type == i` for each relation.
With 44 slots, the other IDs are not selected. This describes the installed
operator path, not a replay of historical training or trained-model output.

Independent offline review verified 112 unique workspace artifact hashes,
all eleven numerical controls, saved forward/message source excerpts, the
range/mask source structure, and all eight frozen coefficient capacities.
No framework was imported by the offline audit, and neither collection nor
review loaded or forwarded the pretrained checkpoint. The original Linux
source file was not reread from Windows; its retained copy and receipt
hashes were verified.

For the restored LZ4 tensor, that source behavior implies that the 196
entries with IDs 50/55 would contribute no relation messages in the
examined 44-slot path if passed through without the guard. This is a
source-supported inference, not an observed frozen-model forward. The
remaining valid relations, node features and root/readout computations
are not thereby absent. A successful forward would not establish complete
relation processing or validate the training distribution.

The next bounded task is passive inspection of the alternative upstream
x64 base checkpoint metadata, with identities and provenance retained.
Candidate admission requires matching operation/readout semantics and
adequate capacity in every active relation layer; tensor dimensions alone
are insufficient. If no compatible pretrained option is found, a complete
60-relation model trained on independently split data becomes a separate
research decision. No layer expansion, relation aliasing, silent truncation
or training on these diagnostic cases has been adopted. Variant E remains
deferred until neural information value is evaluated.

The alternative x64 base checkpoint audit is complete in
`route-b-candidate-checkpoints-20261119T193458001Z`. O1, O2 and O3 were
retrieved over SSH in an isolated D-drive cache at upstream commit
`280320129a7f8bbfb9ee61b9a2155d2ddeac44c6`. Each blob was checked against
its Git tree identity and recorded with a SHA-256 digest. The original O0
checkpoint, upstream source files, frozen reader and input guard remain
unchanged. No pickle objects were executed, tensor storage arrays loaded,
neural frameworks imported or checkpoint forwards performed.

All three candidates have the same ordered 75-type vocabulary and saved
preprocessing configuration as O0. Each declares 60 relation IDs but
contains eight 44-slot relation layers. None satisfies the complete-domain
metadata requirement. Independent review checked the commit/tree/blob
identity chain, all 24 candidate coefficient matrices, and each ordered
type vocabulary. Twenty-two targeted tests passed, including exact passive
agreement with the original frozen reader, storage-read prevention,
identity rejection and candidate-admission controls.

The raw candidate files, metadata, source snapshots and minimal Git
commit/tree proofs remain on D. After verification, the duplicate isolated
Git cache was removed, reclaiming 16,773,588 bytes; `cleanup.json` records
the exact target. The verifier was rerun using the archived proofs. These
findings cover the three x64 base optimization variants at the pinned
commit, not every upstream model or historical release.

The next task is independent data/type-label readiness before deciding on
a small, complete-60-relation training experiment. A source-only observation
of the pinned twelve-kernel panel confirms that every wrapper declares
`benchmark_step(uint64_t x)`. This panel remains useful for integration and
cost regression, but provides no diversity in that declared entry type.
It is not the training set for a replacement predictor. Candidate model
training must use independently separated projects and must preserve the
same-scheduler information-value comparison before Variant E is considered.

A separate source-readiness panel is now pinned in
`route-b-type-corpus-20261119T195435581328Z`: inih, rxi/map and jsmn are
assigned to training; optparse to development; utf8.h and b64.c to
evaluation. The project-family assignments were written before any label
inventory or training. Sources were retrieved over SSH, commits and exact
compiler-input hashes retained, and original license notices preserved.
O0 and O1 variants stay in the same project partition. These six small
projects form an exploratory readiness panel, not publication-scale
generalization evidence.

The new `scripts/prepare_type_corpus.py`, `scripts/build_type_corpus.py`
and `src/selective_analysis/type_corpus.py` preserve original interfaces,
compile native ELF profiles, and inventory actual DWARF variable types.
Header translation units contain only upstream configuration macros and
includes; the link-only `main` is excluded from the data. The legacy
`src/type_recovery/dataset.py` still contains all-zero placeholder node
labels and is not used by this new path.

Label conversion uses the pinned original pure-Python type classes,
conversion function and reduced-75 normalizer without importing torch or
angr. Unsupported conversions remain explicit `unmapped` records; no
class-zero label is fabricated. This is a whole-variable type inventory,
not the upstream struct-member location expansion or a validated graph
readout mapping. Having a 75-label vocabulary does not establish coverage
of all 75 labels.

Thirteen targeted tests passed, including the real retained ELF's entry
label, base/character distinctions, pointer/array normalization, type
cycles, split-family isolation and comment/string-aware clone screening.
The independent source audit verified six commits, selected code and
license hashes, and the split manifest. All six MinGW syntax checks and
portable preparation passed. Native Linux compilation, label coverage and
O1 retention are pending; host syntax is not ELF validation.

The prepared WSL command builds twelve small O0/O1 profiles and records
unmapped types, location-attribute presence, per-project counts and
cross-split exact/identifier-normalized function-body matches. O0 is the
primary counting profile; O1 is a retention comparison rather than
additional independent data. All counts, failures and clone-review
candidates remain in the report. Actual graph extraction, architecture
features, complete relation processing and variable/value-row mapping
still require validation. Training remains disabled, and no model,
property checker or scheduler is run by this inventory.
[Independent type-corpus readiness](../benchmarks/selective_analysis/route_b/README.md#independent-type-corpus-readiness).

The first WSL inventory completed 10/12 profiles in
`route-b-type-corpus-20261119T195435581328Z/labels-20261119T220108266544Z`.
Five projects yielded 85 O0 functions and 368 mapped variable records.
Both b64 profiles failed at link time because the preparer's selected
translation units omitted upstream `buffer.c`. The retained logs identify
unresolved `b64_buf_malloc` and `b64_buf_realloc`; the upstream Makefile
includes `buffer.o`. Syntax-only preflight did not detect this source-closure
error. It is a preparation defect, not a neural experiment outcome.

The future preparer recipe now includes `encode.c`, `decode.c` and
`buffer.c`. A real native-host link regression reproduced the missing-symbol
failure before the fix and passed afterward; all 14 type-corpus tests pass.
This validates source closure on the host, not Linux label coverage.

The versioned correction is retained as
`route-b-type-corpus-v2-20261119T220534466210Z`. Its manifest records its
parent manifest hash and the new buffer file's source/Git identity. Original
commits, project assignments, label/build logic, header bridges and harness
remain unchanged. Existing source checkouts are reused; no download or
overwrite of the first manifest/results was performed. New implementation
snapshots bind the corrected preparer. Portable v2 preparation passed;
the complete native v2 inventory subsequently passed in
`labels-20261119T220848049235Z`. Training stays disabled until
graph/value-readout validation and the intended data checks complete.

All twelve native profiles completed. The primary O0 denominator is 90
source-owned functions and 391 mapped source-variable records. Training
contains 135 records across 11 classes, development 55 across eight, and
evaluation 201 across 11. The union contains 13 of the declared 75 labels;
this is not complete-vocabulary coverage. `i32*` is absent from training
but appears in development/evaluation, and `u64*` appears only in evaluation.
Project assignments are retained rather than changed to close those gaps.
O0 has 391 location attributes; O1 has 387. Attribute presence still does
not establish valid use-site or value-row correspondence.

Independent host replay checked all twelve ELF identities and full
function/variable inventories against the pinned source/conversion rules,
reconstructed split label histograms, and reproduced zero clone-screening
groups and zero unavailable source fingerprints. O1 is not counted as an
additional independent sample. No neural framework was imported or model
executed. Source-variable records are not asserted to be GNN value rows,
and this six-project panel does not establish generalization performance.

The next engineering panel is fixed in `mapping-probe-plan.json` and its
separate `mapping-probe-offline-labels.json`: `ini_find_chars_or_comment`,
`map_hash`, `jsmn_alloc_token` and `optparse_error`, one from each
train/development project. A common rule selects bounded functions with
located pointer/scalar pairs, at most eight inventoried variables and at
most 256 source-body tokens. Eight variable DIEs are selected. No evaluation
project is selected and no graph mapping has run. The offline labels must
not enter graph features, inference or scheduler inputs. This panel scopes
the next mapping validation; it does not unlock training or Variant E.

The mapping collector is implemented in `scripts/run_type_mapping.py`,
the standalone Python 3.8 `scripts/capture_type_mapping.py`, and passive
`src/selective_analysis/variable_mapping.py`. Portable preparation in
`route-b-type-mapping-20261119T222853346909Z` produced four requests.
Independent ELF reading confirms entry CFA = RSP + 8 and one fixed
`DW_OP_fbreg` expression for each selected variable. Reference type
attributes are not used to compute those location facts.

The original-runtime worker selects only the four frozen functions. It
uses the external registered-field/AFTER read-hook adapter and retains
lookup calls, pre/post-splice graphs, normalization maps, step exceptions
and the actual collated data. New preprocessing is explicitly x64 with
31 feature columns and the complete 60-relation vocabulary. This is a
documented new data-generation variant, not admission to the old 44-slot
model. No weight file is read; torch loading and neural module calls are
denied during collection. Original TYGR files are checked before/after.

Passive review reconstructs CFA addresses, location-range graph matches,
node normalization, retained topology, variable membership and value-row
gather/scatter groups. It separately checks graph-node/feature-row order
and x64 encoding. Missing nodes, unsupported locations, step exceptions
and order mismatches remain unresolved rather than being filled or dropped.
These are correspondence checks on recorded partial execution, not a
proof of value equivalence at every use or on every path.

Twenty-six targeted tests passed, including all eight retained CFA
locations, wrong slots/lifetimes/readouts, retained-node substitution,
row-order/architecture/domain mismatches, read-hook restoration and
original observer behavior. Four host inspection-API deprecation warnings
concern the retained legacy hook API. Python 3.8 worker syntax and prepared
request identity checks passed. Original-runtime graph collection completed
as described below. Evaluation projects remain unexecuted, offline labels remain
separate, and training/Variant E are still disabled.

`route-b-type-mapping-20261119T223020304246Z` captured and reviewed all
four fixed functions. All eight selected source variables pass the
recorded CFA-location, graph-membership and readout correspondence
checks. Node/feature-row ordering and gather/scatter groups align in
each function. No step exceptions, observer/location errors, weight
loads or neural forwards were recorded. Original sources are unchanged;
the new data preprocessing uses explicit x64 architecture features and
the complete 60-relation domain.

Independent review rechecked 102 unique artifact hashes, reconstructed
exact ancestor/descendant splicing, retained node labels/edges, all eight
independent ELF CFA facts, prepared relation endpoints and value-row
membership. The selected location sets are disjoint within each function.
The eight selected source variables produce 80 flattened value rows.
Across the full four captures, 14 retained source variables produce 149
rows. These are different counting axes, not additional independent
source samples. The observed total is 684 retained graph nodes.

This closes the small fixed-CFA correspondence check, not full semantic
use-site correctness or whole-corpus training admission. Execution is the
original partial/concretized graph-generation strategy. No property
decision, prediction quality, scheduling benefit or evaluation-project
execution was measured. The next fixed input denominator is retained in
`next-export-inputs.json`: 43 O0 train/development functions and 190
candidate source-variable records. Graph/label coverage, structured-member
provenance and failures must be reported before creating a trainable
dataset. Evaluation projects remain reserved and Variant E deferred.

The bulk exporter `scripts/export_type_graph_dataset.py` now prepares all 43
fixed train/development functions. Its host preparation decoded fixed CFA
locations for 188 of the 190 candidate variables; the other two require
separate struct-member supervision. This is preparation coverage, not graph
availability. The collector reuses the unchanged model-free mapping worker.
Separate feature and supervision files preserve source-variable identities,
flattened row groups and weights totaling one per source variable. Unsupported
locations, capture failures, duplicate row claims and conflicting labels on
shared values retain explicit exclusions. All 190 candidates stay in the
coverage denominator. Evaluation projects are not selected.

Thirty-nine targeted dataset, correspondence, hook and observer tests passed
with four legacy inspection deprecation warnings. The dataset regression
reconstructs all eight previously reviewed source-variable targets and their
80 value rows from retained real captures. Prepared requests contain no
offline class labels. Bulk collection still requires the original WSL runtime;
no new graph availability, model training or neural gain is claimed yet.
See the [bulk export command](../benchmarks/selective_analysis/route_b/README.md#bulk-traindevelopment-graph-export).

The completed WSL export `route-b-type-graphs-20261119T225215150614Z`
reviewed all 43 functions and exported 41. Training has 26 functions, 129
admitted source variables and 1,998 supervised value rows; development has
15 functions, 52 variables and 813 rows. The two failed functions are
`ini_parse_string` (node/feature ordering) and `map_iter_` (no selected
function graph returned). All nine excluded source variables remain in
the 190-variable denominator. The independent passive export audit rechecked
317 artifact hashes, target row ownership, source-variable unit weights,
graph-location membership, finite features and complete-domain relation IDs.
The two development `i32*` variables have no training-class counterpart.

`scripts/train_type_graph_pilot.py` now prepares a new, explicitly admitted
feasibility run without changing the historical dataset's disabled-training
flags. It fixes a two-layer, width-64, eight-basis RGCN with all 60 relation
slots, plus the same parameter initialization and architecture with messages
disabled. Both arms use source-variable mean logits and one cross-entropy
term per variable. Three seeds each run 30 epochs; checkpoints always come
from the fixed final epoch. Development scores never select a checkpoint.
The frequency prior is fitted only on training variables and achieves 11/52
development Top-1 decisions. Its Top-3 coverage is 47/52, a relevant baseline
for future candidate-set claims.

Thirty-eight targeted tests passed; one neural runtime check is skipped on
Windows because Torch DLL initialization fails in this workspace. On 20
November the smoke run and the fixed full pilot were executed in WSL
`angr-env`. The relation-59, invalid-ID, identical-initialization, finite-loss,
parameter-change and checkpoint-replay checks all passed, and pinned sources
and data were unchanged. Development Top-1 was 28/25/28 of 52 with graph
messages and 25/25/25 with messages disabled (seeds 17/29/43), against 11/52
for the frequency prior. Both unseen-class variables were wrong in every run.
No evaluation project or scheduling comparison was run.

A passive coverage diagnosis (`scripts/analyze_type_pilot_coverage.py`)
shows that the models act as bit-width classifiers: 32-bit values become
`i32` and 64-bit values become `struct*`, including 20-22 of 22 development
`char*`. Readout features are a concretized-zero signature that differs only in
width, and the 8-bit dereferences that separate `char*` from `struct*` lie
beyond the two-layer receptive field for 21/25 training and 20/22 development
`char*`. The present scores therefore mostly restate value width, which the
type-blind arm already observes. A remedy must be fixed in advance and judged
on data not used in this diagnosis. See
[training results](../benchmarks/selective_analysis/route_b/README.md#training-pilot-results)
and [coverage diagnosis](../benchmarks/selective_analysis/route_b/README.md#coverage-and-representation-diagnosis).
The follow-up is fixed in the
[v2 pre-registration](../benchmarks/selective_analysis/route_b/type_pilot_v2_preregistration.md):
unchanged training data, a four-layer remedy arm, a structural non-neural
baseline, and three newly pinned development projects (sds, tiny-regex-c,
json-parser; parson as backup). In execution, json-parser and parson failed to
link with the fixed recipe (missing libm), leaving sds and tiny-regex-c with 200
admitted development variables. The single pre-registered run reproduced all six
v1 A1/A2 digests. Its decision was **No R1**: the four-layer RGCN beat the
two-layer model by +39, +6 and -7 of 200 variables, with worse NLL in two seeds.
The deterministic structural baseline A5 reached 121/200, ahead of every GNN arm.
Neural type scores therefore show no incremental value here; the next step is a
separately pre-registered training-coverage expansion. See
[v2 results](../benchmarks/selective_analysis/route_b/README.md#type-pilot-v2-results).
That expansion is now fixed in the
[v3 pre-registration](../benchmarks/selective_analysis/route_b/type_pilot_v3_preregistration.md):
roughly tenfold training coverage, a fresh three-project development set,
training-only depth selection, and decision rules on coverage (H1), GNN versus
structure (H2) and stacked scores versus structure (H3). Its projects are
pinned. The completed v3 run (1,460 training and 571 fresh development variables)
decided **Neither**: more coverage did not reliably improve the four-layer RGCN (+29, +40,
+11 against a margin of 29), and neither the GNN nor the stacked model beat the
structural baseline. Neural type information shows no incremental value at this scale;
Variant E is not pursued. See
[v3 results](../benchmarks/selective_analysis/route_b/README.md#type-pilot-v3-results).
[Native input preparation](../benchmarks/selective_analysis/route_b/README.md#native-debugstripped-input-preparation).
[Two-function neural probe](../benchmarks/selective_analysis/route_b/README.md#two-function-native-neural-probe).
[Native coverage and baseline gate](../benchmarks/selective_analysis/route_b/README.md#twelve-function-neural-coverage-audit).
[Local results and information assessment](../benchmarks/selective_analysis/route_b/README.md#local-information-assessment).

The corrected repair and v23 audit need no further WSL run to close their current gate.
New data collection would be a new experiment.

See the [architecture](architecture.md), [OPM views](architecture/README.md),
[pilot guide](../benchmarks/selective_analysis/README.md),
[chronological evidence](pilot_evidence.md) and [documentation map](README.md).
