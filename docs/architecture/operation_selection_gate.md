# Development gate: useful operation choices

> **Chronological development decision log.** Stage-specific next steps below retain
> their original context; the latest completed checkpoint is now the
> [v23 representation audit](../pilot_evidence.md#v23-retained-type-information-collision-audit).
> Use [current status](../STATUS.md) for the active research decision and
> [reproducibility](../REPRODUCIBILITY.md) for local-artifact replay requirements.

The first real end-to-end run validates the measurement boundary but finds no neural net
benefit on the reviewed query. Before adding a learned selector, new GNN training or more
benchmarks, establish that the operation catalog offers a meaningful choice.

This is a development decision following the recorded v3 result. It changes neither the
frozen A-D protocol nor the operations used in that result.

**Update:** the [v4 diagnostic](pilot_revision_v4.md) has implemented the controls below.
The Windows run retained all 144 records; the fixed bounds-first fallback matched expanded-only
coverage with 30.7% lower total wall time. It uses no neural information. See
[the measured result](../pilot_evidence.md#development-v4-operation-choice-controls).
The [WSL replication](../pilot_evidence.md#wsl-replication-of-v4-and-routing-headroom) retained
the same source/query identities and all conclusions with 23.4% lower total wall time.
Its 24 failed cheap attempts total only 1.255 s. The next gate is to identify substantial
avoidable analysis work for neural information to target, before integrating it into these
controls. Merely skipping these cheap attempts offers little recorded repayment headroom.

[Development v5](pilot_revision_v5.md) therefore measures the acquisition boundary before
new scheduling work. Existing expanded checks spend about 94.8 ms per trial in execution
plus validation; they have not exposed a multi-second solve that neural information could
avoid. The opt-in profiler separates graph extraction from model forward and imports from
loading. The [real stage results](../pilot_evidence.md#real-v5-acquisition-costs) now identify
imports as the largest cold-process cost, followed by graph generation. Forward takes
0.082-0.102 s and only 1.4%-1.8% of acquisition wall time. Its optimization alone offers
little total saving. A persistent process could be a separately measured engineering
hypothesis; it does not establish useful neural selection or make graph generation free.
The current single-query cold configuration still has no demonstrated neural net benefit.

The [v6 information-only replication](../pilot_evidence.md#v6-wsl-replication-and-input-scope)
also found no extra conclusion on the same reviewed query, after excluding acquisition.
At 0.5 s, C/D perform paid definition recovery before the same expanded check B selects
directly. This is a negative result for the present view/policy/query combination, not
for all neural type information. The input audit shows that only the base-pointer
contributor is projected; the index has a separate raw prediction but no independent
operand view. Next establish property-operand coverage and additional reviewed queries,
preserving raw predictions and separate variable identities. Do not combine different
variables' candidate scores into a single type distribution or tune on this one outcome.

The [v7 mapping replication](../pilot_evidence.md#v7-wsl-mapping-replication) now fills the
independent base/index view gap on the same probe. Windows and WSL share identical source,
query, input and canonical evidence/bundle identities. Shared program facts contain no
neural candidates. Coverage remains two operands of one query. Next add a small number of
independent reviewed queries and check the verifier's supported scope before a separately
declared role-aware selection comparison; existing v6 results are not retroactively changed.

## What the current catalog permits

`bounded_paths` and `expanded_paths` call the same executor, with depth caps of 8 and 128.
Both stop early on a decisive result. The larger cap does not force 128 steps of work.
`definitions` can prepare a paid exact prefix for reuse; it does not independently decide
the property. Fresh final validation must still run.

An audit ran both path operations from fresh states on the **same 12 existing mechanisms**,
without type information or prepared prefixes. The Windows backend was Python 3.13.10 with
angr 9.2.217. The 8-step operation resolved 11 queries; the 128-step operation resolved 12.
On every query resolved by both, the status and executed-prefix step count were identical.
On `m07`, the smaller cap returned unknown after 8 steps, and the larger cap found a modeled
violation after 14 steps.

This is a semantic-counter diagnostic, not a wall-clock comparison or a general dominance
proof. State management and solver costs can vary. Nevertheless, the current menu gives
little demonstrated reason to prefer the smaller cap. On the compiled integration query,
the no-type selector already selects the expanded check directly; C/D add preparation
without gaining a conclusion. More elaborate scoring cannot repair this lack of headroom.

The local report is
`D:/AI_Models/symbolic/.scratch/selective_analysis/operation-menu-audit-v3/report.json`;
the captured diagnostic is `.scratch/wsl/audit_operation_menu_v3.py` in the parent workspace.
No additional cases or model calls were introduced for this audit.

## Implementation plan recorded before v4

1. Add an **expanded-check-only** diagnostic baseline before claiming scheduling gains.
   Measure complete wall time and fresh validation under the same query contract. An
   improvement over an unnecessarily staged baseline would not establish useful selection.
2. Investigate at most one complementary cheap operation alongside the existing path
   checker. A narrow, instruction-derived bound check is a candidate: return a checkable
   bound certificate or unknown, retaining the path checker for cases it cannot settle.
   This is a proposed operation, not an implemented capability or a claim of novelty.
3. Record each eligible operation from the same checkpoint, with independent state/cache,
   its result, validated evidence and total cost. Keep all 12 developer mechanisms and
   failures; do not select only cases favorable to neural guidance. Use these records to
   determine whether genuinely different operations win on different queries.
4. Only if such a tradeoff exists, repeat the shared-selector B/C/D ablation. Type predictions
   remain ranking features. Checker facts and certificates must come from program semantics.

Changing the catalog or selector requires a documented development revision **before** its
next comparison. Keep the v3 artifacts and report its negative result. This development
gate uses existing hardware and fixtures, with no new neural training or rented compute.

## Costs and stopping decisions

Keep information-only and end-to-end comparisons separate. A persistent model or multiple
queries per binary could amortize acquisition, but that would need a declared batch unit,
charged model startup and real total costs. Cached predictions cannot become free online
inference. Such engineering would not by itself demonstrate better operation selection.

If the no-type expanded checker remains best, simplify the menu or reconsider scheduling
as the main contribution. If complementary operations exist but neural information does
not help choose between them, report that distinction rather than adding modules to force
a positive result. Only then consider learned cost models or more complex dependence groups.

## V8 post-hoc compiled-query applicability checkpoint

Both additional authored C queries now have genuine exported types and verified physical
base/index mappings. The WSL run obtained one modeled violation and one complete scoped
exclusion, with fresh validation. Acquisition/mapping success is separate from the operation
selection question.

A subsequent Windows applicability check on those exact binaries found the same gap in
both cases: the first write follows ten prefix instructions, the eight-step operation
returns unknown without reaching it, and the local-bound checker returns
`unsupported_instruction:push` at the function prologue. Definition recovery alone does
not discharge a property query. The expanded checker supplies both validated outcomes.
This one-run post-hoc check does not measure a scheduling benefit or an optimal strategy.
Its records are `operation-readiness.json` in the retained v8 run directory.

Before introducing a role-aware policy, extend the local checker only with explicit,
conservative contracts for the supported compiler stack-frame operations. Require fresh
validation and unknown on unsupported aliasing, stack-slot overlap, calls or precision
loss. Reuse the mapped developer queries to test applicability; keep predicted types out
of the checker and preserve the existing selector. Only then measure whether a useful
local/full-check tradeoff exists and whether type information adds selection value beyond
the same structural and conventional-type inputs. These three authored queries remain
development inputs and cannot establish held-out generalization.

## V9 compiler-frame control checkpoint

A separate frame-aware operation now supports the declared straight-line compiler subset.
It derives entry RSP from the reference program model, rejects overlap with the program
image/declared object, and propagates initialized aligned stack slots without reading any
neural input. All preparation, failed checks and fresh validation are paid. Unknown frame
checks may fall back to a fresh full check using the already paid project, never a reused
symbolic prefix. The old operation/catalog and selector stay unchanged.

The 27-record Windows run used the same three compiled queries, three methods and three
rotated repetitions at 5 s end to end. Full and frame-first fallback each retained 9/9
correct repeated outcomes, with no timeouts; frame-only retained 3/9 scoped exclusions
and six unknowns. Total full/fallback wall times were 17.217/17.121 s, while median times
were 1.903/1.914 s. Applicability is established for the masked compiled case, but this
small mixed cost difference does not demonstrate a stable speed advantage. WSL replication
is the next check before advancing the scheduling claim. No neural value is measured.

The WSL replication now validates all sources, inputs, actions and conclusions. The lower
fallback total (9.214 s versus 10.610 s) is driven by the first full run at 2.732 s. It is
the only one of nine matched pairs favoring fallback; median full/fallback costs are
0.978/1.030 s. A post-hoc sensitivity calculation excluding that same query/repetition
from both methods reverses the aggregate sign. The primary result retains every record;
the sensitivity calculation is not a replacement estimate. Functional applicability is
confirmed, but no stable speed advantage or neural value follows. The next cost diagnostic
should declare a shared-process batch as its budget unit and keep all startup/finalization
costs; it must not subtract imports post hoc or treat repeated queries as new examples.

## V10 completed cost infrastructure and next scientific gate

The declared three-query batch diagnostic now runs on Windows and WSL with matching
sources, inputs, orders and proof semantics. In WSL, full/fallback both retain 9/9
correct outcomes with no timeout. Totals are 4.770/3.835 s, but medians are 1.239/1.292 s.
Only repetition 0 favors fallback; the two later matched batches are slower. The
post-hoc paired sensitivity changes the aggregate sign while retaining all original
records as primary. This is functional and accounting validation, not stable speed or
neural-value evidence. The file/loader guard correction is separately versioned.

Freeze the existing cost infrastructure while pursuing the next scientific question:
whether local operation value is sufficiently diverse and predictable to justify
selection. Use fixed queries and comparable initial checkpoints; record each operation's
new validated evidence, uncertainty left unresolved and full execution/reanalysis cost.
Include the selection cost whenever comparing a policy. First establish a useful
tradeoff against fixed full checking and fixed fallback. Then test whether genuine
type labels/candidate scores add information beyond the same structural features and
ordinary type information. Do not infer that benefit from type accuracy or mapping alone.

The current three compiled inputs are integration/developer evidence, not a sufficient
training or held-out evaluation set. Preserve the frozen RQs and small case budget;
choose any further development mechanisms for declared analysis needs, independently
of neural scores or favorable outcomes. Lack of operation tradeoff should trigger a
scope decision rather than another layer of scheduling complexity.

## V11 operation evidence checkpoint

The Windows gate now measures all five alternatives from fresh checkpoints on all twelve
original mechanisms, with no neural inputs or imported operand proofs. All 180 rows and
36 separately charged query workers are retained; no validated decision is wrong.

Bounded checking resolves eleven unique inputs; its 33 shared successes with expanded
checking have identical observed execution/validation work. The smaller cap therefore
shows a depth limit on the remaining long-prefix input, not a useful cheaper algorithm
on shared successes. Both prefix composites also retain the full total counted execution
steps, including preparation and fresh validation. RDA adds planning work and has a
higher per-query median cost than full or direct-prefix checking on all twelve inputs.
These observations are specific to this one-query/one-follow-up menu, not a claim about
RDA or prefix reuse in general.

Local bounds supplies the genuine alternate analysis: four stable exclusions with
descriptively separated probe costs. Unknowns remain a mixture of unsupported behavior
and insufficient precision, not decisions of a different kind. The direct-prefix probe
also has a few separated observed cost ranges, but unchanged execution work and a case
with no prepared prefix prevent treating those ranges as an algorithmic contribution.

The separate compiled proof panel derives all three answers from previously paid facts
without neural candidates: direct witness 8, offset witness 4, mask exclusion. This is a
conditional deduction, not new program validation. Prior A-D runs did not consume these
complete facts; nevertheless future selectors cannot treat target-reaching semantic
mapping verification as free preparation. Use location-only correspondence, or include
a paid facts-to-decision baseline before discussing incremental neural value.

WSL now replicates all decisions, checkpoints and counted work, and all 26 measured
sources match. RDA composite per-query median costs are higher on all twelve inputs in
both environments. This gate is complete. Retain the local/full complementary analysis;
treat the depth cap as a limit and RDA/prefix preparation as planning rather than an
established utility contribution for this workload. Next remove target-semantic proof
from correspondence preparation before another B/C/D experiment. Preserve RQs and the
small primary case budget; no trained selector is justified by these integration inputs.

## V12 correspondence boundary

The next implementation isolates physical location correspondence from target-semantic
proof. A small static frame parser associates surviving write-address load occurrences
with exact raw CFA locations and covering function/PC ranges. Candidate values are projected
only after association; no solver, property checker, old semantic anchors or expected
outcomes participate. Keep unsupported/missing/ambiguous records, and keep the original
three compiled inputs separate from the primary mechanisms. This closes a preparation
boundary; it does not establish neural information value or justify a trained selector.
After validating this interface, choose a small menu with genuinely different analysis
capabilities before another B/C/D experiment. Budget and evidence accounting remain frozen.

The restricted interface now passes on Windows and WSL: all three compiled integration
inputs retain two neutral load bindings, and normalized candidate views/traces agree with
unchanged raw exports and source hashes. No property engine or old proof participates in
projection. The next gate is no longer correspondence plumbing: identify genuinely different
operation capabilities, then test conditional type information against the same type-blind
structural selector and fixed controls. Existing integration successes do not establish that
such additional information exists. Keep the case budget and frozen research questions.

## V13 routing sensitivity checkpoint

The next declared gate uses the existing frame/full alternatives and the same function
for B/C/D; type information is an additive, explicitly heuristic compatibility signal.
A structural mask cue already gives B frame-first preference. Five fixed weights retain
all 45 rows on the three known inputs, with no B/C/D order differences. This is an order
observation, not an execution, property quality or end-to-end cost result.

The direct input has zero C/D mixture signal. The offset input has zero C signal but a
nonzero D signal of 0.105496, producing a strict weight threshold 2.369751, outside the
declared [0,2] grid. The masked input has C=1 and D=0.994957 support, while the structural
baseline already chooses frame-first for all nonnegative weights. Do not tune above the
grid merely to create a difference or conclude D supplies no information. It changes
scores without changing these observed orders. All source/input hashes and raw scores
are preserved. The old frozen runner and checkers remain unchanged.

No repeated property checks or learned selector are warranted by this gate alone. Further
work requires a declared operation-specific reason that types could improve a decision
beyond strong structure, tested with a small independent development panel chosen for
analysis needs rather than favorable predictions. Keep the original integration cases
as integration tests, not a training or held-out data set. The research direction's
independent algorithm contribution remains unestablished.

WSL now replicates every source/input identity and every non-timing case record, including
the offset D signal and threshold. All 45 rows and 30 available comparisons remain, with
zero changed orders. The current heuristic's replication gate is complete. Its result
does not identify whether other operations, type features or independent programs could
benefit from neural information. Preserve this negative result; the next design must
explain a concrete operation-value mechanism before another same-panel execution study.

## V14 readonly-indirection capability checkpoint

The declared mechanism study now separates the capabilities of the existing interval
domain and a new bounded finite-value/readonly-load implementation. On three authored
inputs, intervals discharge the 1024-element scalar span while the 32-value domain
saturates to Top; finite readonly resolution discharges the two-level safe pointer chain
while the current interval implementation refuses that memory load. The matching unsafe
chain remains unknown to both, and full checking produces a freshly reexecuted witness.
The fixed interval-then-finite control discharges both safe inputs. All decisive outputs
agree with separate modeled references; twelve method records and three references remain.

This gives a concrete operation-capability mechanism, not neural information value or a
new abstract interpretation theory. The scalar contrast reflects the declared bounded
finite domain; it does not establish that all value-set methods lose large ranges. The
interval contrast concerns this implementation's memory support, and a combined domain
or strong fixed fallback may already suffice. Static load structure/cardinality controls
must therefore accompany any later neural choice. New fixtures have no GNN predictions
and are not a held-out set. Keep them separate from the old primary/integration panels.

WSL now replicates the complete capability pattern with identical twelve source hashes,
program/query contracts, abstract certificates and reference modes/domains. Interval-then-
finite and expanded-only both resolve 2/3, but the former resolves scalar+safe-chain while
the latter resolves scalar+unsafe-chain. Their total costs are therefore not a matched-
quality speed comparison. Preserve all unknowns and the different resolved query sets.
A future separately declared strong baseline should actually execute interval, then finite
readonly, then full checking after unknowns, and measure complete costs. Any neural selector
must demonstrate value beyond that simple control and structural load/cardinality cues.

## V15 complete fixed baseline checkpoint

The separately declared control now executes interval, finite readonly, then expanded
checking after unknowns or failed attempts. All attempts start fresh and share one query
budget. On the same three retained authored mechanisms, Windows records three correct
cascade resolutions in each repetition, versus two for expanded-only. All eighteen
method trials and three newly obtained separate references pass audit. The safe chain
is cascade-only; both methods discharge scalar and unsafe-chain queries. No prior
result, gold label or neural prediction enters a runtime request.

The fixed baseline is therefore concrete rather than a proposed competitor. Its success
does not establish that learned routing is useful. Keep strong structural/cardinality
controls and charge information acquisition before claiming an incremental neural result.
Do not tune the v13 heuristic to manufacture a routing difference on these known cases.

The clock now includes detailed trial-payload persistence and observed worker-version
lookup; final accounting-receipt work, aggregate copying and offline evaluation remain
explicitly excluded. Six matched correct query/repetition pairs retain all first trials.
Method ordering alternates globally but is not fully counterbalanced per query: the
unsafe chain has expanded-only first in all three repetitions. Ordinary filesystem
caches were not reset. These observations establish no stable speed or generalization.
Retain the original measurements and this timing limitation. WSL now replicates all
source/input identities, eighteen method outcomes and sequences, fifteen abstract attempt
results and three fresh reference modes/domains/outcomes. Both pure evaluations recompute
exactly. The unsafe cascade costs 0.054–0.106 s more in its three WSL matched pairs;
aggregate scalar savings do not make it faster on every query. The fixed baseline gate
is complete on these known mechanisms. Next require a concrete operation-value signal
that neural information might supply beyond this baseline and static load/cardinality
controls; another repetition of the same routing heuristic cannot establish that signal.
See [the WSL evidence](../pilot_evidence.md#v15-wsl-fixed-cascade-replication).

## V16 information readiness and economic mechanism

The retrospective gate verifies three frozen genuine exports with six existing syntactic
bindings, then matches by binary/query/use-site identity against all three complementary
mechanisms. The intersection is zero. This is missing experimental input, not a failed
neural comparison. The current locator needs DWARF, the mapper supports CFA frames, and
the sectionless register mechanisms have neither interface. The upstream block/final-state
action summary cannot supply a new reliable instruction-level bridge merely by exporting
more register labels. No mapping is rerun and no program metadata is added to force coverage.

A revealed-outcome deletion of every unknown prefix in the nine retained WSL cascade
traces removes 0.420041 s while holding other costs fixed: zero for scalar, approximately
0.062 s for the safe chain and 0.078 s for the unsafe chain per repetition. Shared imports
can migrate to the retained attempt, so this is not a real-time upper bound or deployable
oracle. The historical 5.154144 s cold acquisition concerns a different binary; it is
context only and is never subtracted from this panel's costs. Static load/cardinality
controls still compete for this small potential saving without neural acquisition.

Do not add a trained scheduler to the current menu or reinterpret missing C/D inputs as
zero information value. Before a new bridge, specify instruction/read-write/width/overwrite
provenance and identify the operation-value uncertainty that types could reduce beyond
static structure. The safe and unsafe chains share instruction/type structure and differ
in readonly numeric contents; types do not automatically explain that bounds difference.
Keep RQ1/RQ2 and the original panels frozen. No additional WSL repetition is needed for
this offline gate. See [the audit](../pilot_evidence.md#v16-information-readiness-and-trace-cost-gate).

## V17 provenance prerequisite

The new separate recorder now gives instruction-scoped temps and event-time register-byte
sources on the same three original binaries, without a model or property parameters.
It avoids upstream final-state/block-summary identities rather than silently repairing
them. Independent machine-byte/fresh-IR auditing verifies all three Windows records and
the two intermediate/overwritten RAX pairs. The safe/outside syntax graphs remain equal,
as expected when readonly numerical contents are not interpreted. Keep that equality.

This closes only the restricted syntax identity prerequisite. WSL now reproduces all
complete graph objects exactly, including byte/temporary versions and address bindings,
with identical source/input hashes and separately observed runtime versions. It does not
turn the new nodes into valid TYGR readout nodes or provide the conditional type information
absent from v16. Require an explicit feature/context compatibility check before any
genuine prediction. A new type-aware scheduler still
needs a concrete operation-value signal beyond static structure/cardinality and must
pay for acquisition. Keep the old negative routing results and original panels unchanged.
The existing WSL `angr-env` replication does not validate TYGR's separate older model
environment. No additional repetition is needed to close this syntax gate. See
[the WSL audit](../pilot_evidence.md#v17-wsl-instruction-provenance-replication).

## V18 frozen model-interface constraint

Passive metadata and parameter inspection confirms that dimensions alone do not close
the bridge. The checkpoint saves 31 input features and 75 output classes consistently,
but its 29-label vocabulary plus unknown and inverse offset 30 yields IDs 0..59, whereas
all eight saved RGCN layers have num_relations 44 and comp[44,10]. The potential inverse
IDs 44..59 are outside that domain. Under the current saved encoding, inverse And is 53
and inverse unknown is 59. No historical prepared edge IDs were retained; this does not
prove those IDs occurred or that past forward calls failed. Future observed IDs require
an explicit domain guard; silently clipping, renumbering or using unknown changes the
input contract and does not repair trained semantics.

The v17 graph is an event/byte-version prefix graph, while the trained interface uses
value/annotation features, AST deduplication/context and GlowVar node groups. Its 221
nonliteral nodes do not provide the upstream ast_val, and all 238 dependencies/twelve
readout candidates remain unprojected. Thirty-eight literal candidates are not evidence
of compatible feature values or annotation PCs. No placeholder feature/readout is made.

The direct bridge is not ready. Next establish actual native preprocessing relation IDs
and trained feature/context/readout provenance before another prediction. Preserve model
identity and original raw outputs; do not enlarge layers or reassign learned relation
weights merely to fit the new representation. A compatible projection would still need
to justify incremental scheduling value beyond fixed and static controls. No new WSL
prediction is needed to bypass this offline constraint. See
[the audit](../pilot_evidence.md#v18-frozen-model-interface-audit).
