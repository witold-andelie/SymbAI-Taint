# OPM DOT modeling profile

There are **22 DOT/SVG views** as of development v23 (13 November 2026).
The first three describe **frozen pilot v1**; the others record separate diagnostics,
not additional operations silently added to the frozen A-D experiment. They cover
operation controls, information value, mapping, compiled queries, frame/batch checks,
operation effects, location/routing, indirection/cascades, readiness/provenance and the
model interface. The newest views describe native preprocessing (v19), readout
correspondence (v20), typed readiness (v21), location repair (v22/v22.1) and the retained
representation audit (v23). See [current status](../STATUS.md) and
[artifact availability](../REPRODUCIBILITY.md).
A partial development prototype implements the
core boundary; the diagrams also include remaining work. See [implementation status](../architecture.md#components-and-implementation-boundary)
and the [pilot guide](../../benchmarks/selective_analysis/README.md).
OPM denotes Object-Process Methodology.

## Supported notation

| Element | DOT attributes | Meaning |
|---|---|---|
| Object | `kind="object", shape="box"` | An information artifact or stateful runtime object. |
| Process | `kind="process", shape="ellipse"` | An activity that creates, consumes or affects objects. |
| Instrument | object -> process, `relation="instrument", arrowhead="odot"` | Required and read without transformation. |
| Consumption | object -> process, `relation="consumption", arrowhead="normal"` | A transient item is consumed. Its archival record can persist separately. |
| Result | process -> object, `relation="result", arrowhead="onormal"` | An object is produced. |
| Effect | object -> process, `relation="effect", dir="both", arrowhead="normal", arrowtail="onormal"` | The process affects a stateful object; state detail is suppressed in this view. |

Objects with effect links declare `stateful="true"` and `states`. Consumable work items
declare `consumable="true"`. Colors are visual aids and carry no additional semantics.
Every visible link has a relation and matching label. Layout order is not execution order.
The subset excludes agent, invocation and structural links; no automatic process is modeled
as a human agent. Clusters only group a view's components and are not aggregation links.

This is an explicit Graphviz rendering profile. It preserves the selected entity/link
semantics, with Graphviz arrowheads as graphical approximations. It does not implement the
full state, event, structural, executable OPL or tool interchange specifications of OPM.
Background: [OPCAT 3.0 guide, sections 2 and 3.9](https://web.mit.edu/deweck/Public/opcat/OPCAT_Manual_3.0.pdf).

## Views and selected OPL statements

- `system.dot`: Program Preparing yields Program Facts. Query Freezing requires Program
  Facts and yields Query Manifest and Operation Catalog. Type Information Preparing requires
  Run Specification and yields Type Feature View. Analysis Running yields Run Bundle.
  Results Evaluating requires Gold Labels and Run Bundle and yields Evaluation Report.
- `scheduling.dot` refines Analysis Running. Action Selecting requires Type Feature View,
  Program Facts, Query Manifest, Operation Catalog and Run State. Operation Executing consumes
  Action Request and yields Unchecked Outcome. Evidence Validating consumes Unchecked Outcome
  and yields Validated Outcome. State Updating affects Run State and Run Ledger. Query
  Finalizing requires Run State and yields Run Bundle.
- `evaluation.dot` refines Results Evaluating. Run Matching requires Run Bundle and yields
  Matched Runs. Outcome Evaluating requires Matched Runs and Gold Labels and yields Query
  Metrics. Cost Summarizing requires Matched Runs and yields Cost Metrics. Report Producing
  requires both metric objects and yields Evaluation Report.
- `operation_controls.dot` is the separate v4 diagnostic view, not a refinement of A-D
  selection. Fixed Stage Selecting yields a Control Action Request. Guarded Local Bounds
  Executing or Expanded Paths Executing consumes it. Fresh Evidence Validating yields a
  Validated Outcome. Stage and Cost Updating affects Control Run State and Run Ledger.
  Operation Gate Evaluating requires measured control/reference bundles and offline labels.
  The alternative consumption links have mutually exclusive request guards; layout does
  not imply both operations consume one request.
- `information_value.dot` describes the v6 information-only diagnostic. Common Checker
  Preparing yields the same Program Facts and Prepared Checkers for every method. Type
  View Projecting yields a view and value-free readiness. Information Budget Starting
  requires readiness and common facts; only Action Selecting reads Type Feature View.
  Fresh Evidence Validating requires program bytes and query, not predicted types or a
  prepared symbolic prefix. Checkpoint Updating and Query Finalizing affect the paid
  information budget. Preparation Costs are recorded separately outside that budget.
- `operand_mapping.dot` describes the v7 mapping diagnostic. Operand Plan Proposing uses
  reviewed physical slots and locator metadata without candidate values. Program Relations
  Verifying yields evidence; Fresh Program Evidence Rechecking independently reconstructs
  it. Raw Predictions Binding requires that validated evidence and yields an Operand Type
  Bundle. Common Program Facts Projecting has no raw-candidate input. Per-Role Candidate
  Views Projecting yields separate future ranking views; they do not enter the old selector.
  The validator rejects a raw-candidate path into either proof process or common facts.
  These are structural model checks; runtime plan validation and symbolic rechecking
  establish the actual one-case bindings.

These sentences are hand-maintained summaries, not output from an OPL engine. Canonical
node IDs name the same conceptual objects across views. The `refines` graph attribute and
`interface="input"` / `interface="output"` nodes record boundary consistency. Per-run input
bundles and protocols are shared unchanged between a parent process and its detailed view.

`compiled_queries.dot` describes the separate v8 entry. Source Compiling and Query
Extracting produce a binary/query or failure status. Unlabeled Predictions Acquiring
produces raw candidates and separate physical locator metadata. Only metadata and
program specifications reach Assignments Verifying and Freshly Rechecking. Property
Checking and Freshly Validating reads no predictions. Planned Case Records Retaining
preserves both planned queries even when a stage fails. Offline Outcomes Evaluating is
the only process that reads expected outcomes. These authored queries are not held-out
evaluation and their role bundles do not enter A-D selection.

`frame_bounds.dot` describes v9's three fixed controls. Reference Project Preparing yields
a paid project; Entry Stack Context Checking reads that project and query to establish a
unique RSP and memory separation. Restricted Frame Intervals Checking consumes a frame
request and yields an unchecked certificate or unknown. Fresh Entry Context and Bytes
Rechecking constructs its own context from the reference model; it does not use the
original prepared context as proof. The alternative request consumer performs fresh
expanded checks and validation. The request guards are mutually exclusive. Stage and
Cost Updating affects the control state and measured ledger. Cold-Process Run Finalizing
yields all planned records, and only Offline Controls Evaluating reads expected outcomes.
This view contains no neural input or learned selector.

`frame_batch.dot` describes v10's different accounting unit. Cold Batch Starting produces
the measured parent clock and batch state. Fixed Next Query Selecting consumes no model
information; each query control uses copied bytes/contracts and the corrected byte/loader
guard. Complete Query Record Flushing produces crash-recoverable records and advances
the fixed batch state. Parent Recovery and Budget Finalizing uses those records, process
status, the original specification and full parent clock to retain all three identities.
Late decisive results remain evidence but count as unknown. Only Offline Batch Costs and
Outcomes Evaluating reads labels. Layout and links do not assert a GNN warm service.

`operation_effects.dot` enumerates fixed alternatives from an empty entry checkpoint.
Pre-action structural features are recorded separately and do not select the probe pool.
Independent Fresh Probe Executing yields planning artifacts and an unchecked property
outcome. Fresh Property Evidence Validating creates a decision record; planning artifacts
never become property evidence by themselves. Finalizing retains all primary rows plus
the separately charged query worker. Offline Operation Effects Evaluating alone reads
the primary gold labels. Paid-Proof Consequences Auditing uses the three separate existing
compiled inputs and prior proof to produce a conditional panel. The validator rejects
any route from those retained proofs into runtime feature capture or probing. Combining
panel findings for reporting does not pool their query denominators or establish neural
information value.

`location_correspondence.dot` describes v12's restricted static interface. Frozen Inputs
Snapshotting separates raw physical metadata from candidate values. Static CFA / Load
Identities Corresponding uses relocation-covered bytes, without program execution or
property proving. Physical Location Records Binding uses only those origins and raw
function/CFA/PC metadata. Independent Candidate Views Projecting preserves each prediction
separately; the views do not enter the frozen selector. Complete Projection Attempts
Recording retains all three integration inputs. Prior semantic proofs enter only a separate
post-hoc identity comparison. The validator rejects any route from candidate values into
static matching, and any retained-proof route into runtime processing.

`routing_sensitivity.dot` describes v13's order-only gate. Raw-Free Structural Syntax
Capturing yields the shared features. Same Policy Without Types Ordering produces B
orders before Location-Only C/D Views Preparing parses the frozen candidates. The
correspondence and projection create no property proof. Both ordering processes read
the same policy/weight grid and operation catalog; only C/D ordering receives type views.
Complete Orders and Costs Recording retains all 45 rows, including unavailable arms.
Fixed-Grid Order Differences Comparing reads no expected outcomes and reports no executed
analysis benefit. The validator rejects a raw-candidate route to B or structural capture.

`indirection_gate.dot` describes a separate three-case authored capability panel. Mechanism
Generating yields hashed program/query contracts and separate offline labels. Fixed Method
Requests Dispatching reads no labels or predictions. Fresh Interval / Finite / Full
Executing and Fresh Byte/Data or Symbolic Evidence Rechecking retain actual attempts;
Parent Records Recovering preserves all twelve outcomes and process charges. Only after
runtime completion does label-free Independent Modeled Input Domains Referencing construct
three separate reference records. Its readiness input is not prior query evidence. Offline
Capability and Correctness Evaluating alone reads expected outcomes. No neural object or
trained selector is present; graph links do not assert throughput, completeness or novelty.

`fixed_cascade.dot` describes the strong v15 non-neural baseline. Immutable Inputs
Snapshotting copies only known binaries/contracts and opaque offline labels, without old
results. Fixed Scheduled Requests Dispatching creates the two-method, three-repetition
matrix. Fresh Fixed Method and Validation Executing pays for provenance and every failed
attempt; no operation state/fact is reused. Complete Trial Evidence Persisting writes
all detailed bytes before Parent Clock and Availability Finalizing closes the primary
clock and emits an authoritative status/receipt. A late candidate remains in the payload
but counts as unknown. Fresh Modeled Input Domains Referencing starts after runtime
readiness; only offline Same-Identity Coverage and Costs Evaluating reads expected labels.
It distinguishes query-level coverage changes from paired latency on common correct results.

`information_readiness.dot` is an offline view. Retained Inputs and Sources Snapshotting
preserves two separate panels. Complete Historical Evidence Validating reads gold only
for retrospective correctness. Exact Existing Information Inventorying checks binary/query/
use-site identities and ELF metadata without a model or new mapping. Revealed Outcome
Trace Costs Accounting deletes unknown prefixes under an explicit fixed-cost assumption;
its oracle is not an online selector or real-time upper bound. Separate Historical
Acquisition Contextualizing never supplies a new-panel cost estimate. Reporting retains
unavailable information and the structural/cardinality controls needed before new research.

`instruction_provenance.dot` describes a separate prerequisite without a neural model.
Property Parameters Stripping leaves a strict binary/entry/target-store request. One-
instruction Lifting and event Recording preserve VEX byte offsets, instruction-scoped
temps and earlier byte definitions. Direct Address Syntax Binding compares only the
restricted current-address expression with decoded operands, stopping at current Gets.
Loads remain opaque. Parent graph validation checks complete structure and versions before
persistence/finalization. Availability is a syntax result, not a property decision or
TYGR readout claim. Input preparation is shown inside the general runtime boundary;
the declared per-process clock begins at request writing, not at global snapshot setup.

`model_interface.dot` remains entirely offline. Bounded Symbolic Metadata Parsing keeps
checkpoint GLOBAL/REDUCE/BUILD operations passive. Extraction reports actual saved
configuration and parameter/storage shapes rather than source defaults. Directional
Relation Domain Coverage Checking compares potential IDs with saved layer capacities;
it does not observe historical input usage. Inventory retains missing value/annotation,
typed-edge/context and readout contracts without synthesizing adapted tensors. Reporting
can mark the direct bridge not ready while preserving valid structural facts and the
possibility of a future explicitly validated projection.

`native_preprocessing.dot` is v19's separate compiled integration panel. CPU Configuration
Loading and Forward Guarding yields the actual saved configuration; Original Native Graph
Generating uses the unchanged DWARF-assisted feature generator. Original Preprocessing
and Collation Recording preserves tensors and readout membership without executing model
forward. Pure Correspondence Checking and Cost Accounting retains failed, partial and
timed-out payloads under the parent-owned 60 s interval. Complete Matrix Evaluating reports
newly observed IDs and domain findings only. It does not project v17 graphs, infer historical
inputs or evaluate neural benefit. See [the view](native_preprocessing.svg) and
[the frozen development specification](pilot_revision_v19.md).
The WSL three-case matrix is now audited. Its 103 native edges are all single-label and
all 206 relation entries fit the saved capacity. The original specification/validator's
last-label rule is superseded by [the first-label erratum](pilot_revision_v19_erratum.md);
the graph view's data-flow scope is unchanged. Twenty readout rows still describe six
original variables in three integration cases, not twenty independent samples.

## Frozen variant contract

`typed_readiness.dot` adds v21's prospective one-binary/three-function gate. Fixed
sources are compiled and fixed symbol/store identities extracted. Original native input
preparation is separate from fixed checking. A complete CPU batch must pass all saved
feature/relation/readout domains before unlabeled model forwarding. Genuine logits,
control/reference records and failures meet only in offline readiness/cost evaluation;
gold has no runtime path. The output is a coverage intersection, not a new selector or
same-budget neural gain. See [the view](typed_readiness.svg),
[specification](pilot_revision_v21.md) and
[preparation evidence](../pilot_evidence.md#v21-compiled-typed-complementarity-preparation).

`native_readout.dot` is v20's separate offline correspondence view. Fresh Canonical
Address Load Decoding uses only binary/hash, entry/write RVAs and capture identity.
Unique Physical Location Associating matches CFA metadata/lifetime and retains complete
original groups. Native Value-Graph Frontier Tracing excludes location/unknown edges and
stops at first readout members, retaining candidates and witnesses without modifying
prediction aggregation. Annotation Context Inspecting keeps mixed BBL/direct-hook
addresses and missing event identity explicit. Group availability and event status
have separate meanings; exact-event typing is not a prerequisite for testing coarse
whole-variable ranking features. See [the view](native_readout.svg),
[specification](pilot_revision_v20.md) and
[evidence](../pilot_evidence.md#v20-native-readout-group-and-frontier-correspondence).

[pilot_contract.json](pilot_contract.json) records the research freeze in machine-readable
form. It is a design/validation input, not configuration already supported by `src/pipeline.py`.
Changes to the questions, variant isolation, checker boundary or accounting constitute a new
protocol version and require documenting the reason before held-out experiments.

[Development revision v2](pilot_revision_v2.md) keeps those boundaries while adding a
query-bound, paid exact prefix to Run State and retaining candidate identities/scores for
Action Selecting. The selector and checker remain common to B/C/D. Live prefix reuse is
measured execution; final evidence validation always starts fresh.

## Reproduction

`type_information.dot` adds v23's offline retained-data comparison. Retained Acquisition
Evidence Validating supplies original groups and actual tensors. Identity-Free
Whole-Function Views Projecting yields separate Top-1, Top-K and full-logit views.
Exact Representations and Tensors Comparing yields pair equality before Frozen
Historical Capabilities Joining adds prior operation outcomes. Separate Paid Stages
Reporting keeps acquisition/control costs descriptive. No outcome enters projection;
no selector/model/property execution occurs. See [the view](type_information.svg),
[specification](pilot_revision_v23.md) and
[evidence](../pilot_evidence.md#v23-retained-type-information-collision-audit).

`location_repair.dot` adds v22's same-ELF, external DWARF4 location-base repair and
v22.1's explicit old/new entry-API checking before native preparation. Actual version,
tuple layout and errors before upstream suppression remain recorded.
Retained ELF Ranges Projecting yields an offline location trace; Repaired Native
Locations Preparing yields native inputs and a persisted runtime adapter trace.
Actual Saved Input Domains Guarding precedes Frozen Unlabeled CPU Model Forwarding.
Trace, Identity and Coverage Evaluating compares the same three-query denominator
with v21's historical coverage, retaining failures and paid acquisition cost. It
performs no new property trial, selector or neural-benefit inference. Original TYGR
files and weights stay intact. See [the view](location_repair.svg),
[specification](pilot_revision_v22.md), [compatibility correction](pilot_revision_v22_1.md)
and [evidence](../pilot_evidence.md#v221-old-pyelftools-compatibility-correction).

From the repository root:

```powershell
py -3 scripts/validate_architecture.py
py -3 scripts/validate_architecture.py --render
```

`--render` writes SVG previews next to DOT sources only after the validation pass.
Graphviz JSON is captured in memory. The validator places process temporary files under
the workspace's `.scratch/architecture/` directory and disables Python bytecode output.
No network or model inference is performed.
