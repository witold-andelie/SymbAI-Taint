# Development revision v18: frozen model-interface audit

Declared on 12 November 2026 after v17 replication and preliminary non-executing local
checkpoint/source inspection. This is a compatibility diagnostic, not a blind experiment
or a new type-inference method. Preserve every prior runtime source/specification, model,
raw export and measurement. Do not run a new prediction, solver, TYGR graph generator,
compiler, package install, network/API call or GPU job.

## Fixed inputs and structural facts

Use the verified frozen `x64.O0.base.model` with SHA-256
`f592caaa6c685f291f576b16fbf8b752a95e7cb757ea620751830563b77f67c8`
and the same three audited v17 WSL graph records. Copy/hash immutable inputs and all
diagnostic/source-evidence dependencies. Extract only passive checkpoint metadata with
`pickletools`: globals, reductions, object construction, persistence and BUILD are symbolic
data, never resolved, instantiated or executed as framework/model classes. Interpret only
explicitly supported opcodes, bound resources and reject malformed/unsupported streams.
Read ZIP storage descriptors/shapes without loading tensor arrays or importing torch.

Report actual saved preprocessing/model configuration, ordered edge vocabulary, direction
offsets, readout settings, input/output weight shapes and saved per-layer relation capacities.
Do not replace saved values with current source defaults. Compare advertised encoded IDs
against actual layer shapes/counts. Preliminary inspection found 31 input features and a
potential 60-versus-44 relation-domain mismatch; verify the actual checkpoint layers before
calling this a confirmed constraint. Do not infer historical edge usage from successful
forward calls or claim past predictions failed. Historical prepared tensors were not
retained by the raw-logit adapter, so preserve that observability limit.

## Semantic compatibility boundary

Inventory every v17 node kind, operation and address readout event. Constants expose their
literal bit-vector value; Get/Put/temp/load/entry events do not automatically supply the
upstream concrete `ast_val` semantics. Count that distinction without filling unknown
values with zero or evaluating readonly memory. Explain the 18 value/address features,
architecture-token handling, AST node deduplication/context slicing, typed edge directions
and `GlowVar.nodes`/flattened output-row semantics using hashed source excerpts.

V17 dependence edges and `Iop_*` operations have no declared mapping to the trained
Claripy/annotation relation vocabulary. Do not map them all to unknown or borrow a
same-size tensor shape to mark them compatible. No feature tensor, adapted model input,
readout group or type label is synthesized in this diagnostic. Report both structural
constraints and missing value/context/relation/readout contracts. A node passing a
dimension check alone does not establish semantic or training-distribution compatibility.

## Deliverables and decision

Implement/test a passive metadata reader and a pure interface-analysis/reporting function;
main-agent review is required for delegated code. Run an offline CLI on original identities,
retain all three graphs and per-node/per-relation diagnostics, and independently audit the
result/source/input hashes. Count actual diagnostic time only as offline work, not neural
acquisition or deployment cost. Keep all artifacts/caches on D and update the OPM/evidence.

If a necessary mapping/value/readout contract is absent, mark the direct v17-to-frozen-model
bridge as not ready. Do not claim that every possible TYGR bridge is impossible or that
neural information has zero value. Before any new forward, require (1) a complete projected
feature/edge/readout provenance contract and observed relation-domain guard, and (2) a
concrete operation-value hypothesis beyond the fixed and structural/cardinality controls.
RQ1/RQ2 remain unchanged. No new WSL prediction is requested to bypass a static blocker.
