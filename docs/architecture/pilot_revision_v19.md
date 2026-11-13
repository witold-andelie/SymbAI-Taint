# Development revision v19: native preprocessing receipts without prediction

Declared on 12 November 2026 after v18's passive audit, before implementation or new
native collection. The saved 60-ID/44-capacity constraint is known; actual old prepared
IDs remain unobserved. Preserve all earlier sources/specifications, weights, inputs,
exports and measurements. Do not patch the original exporter, TYGR code or relation IDs.

## Fixed panel and allowed execution

Use only the existing three compiled native-integration binaries/query identities from
the retained v12 panel: direct_index, offset_index and masked_index. This panel is separate
from the three sectionless v17 capability mechanisms and supplies no new program or
held-out sample. Runtime requests contain binary/hash, declared function-entry RVA,
verified model and external source paths; no object bounds, input ranges, expected outcome,
raw predictions or old mapping proof enter native generation/preprocessing.

The parent runs in existing WSL angr-env; isolated CPU children use existing tygr-orig
Python 3.8. Load only the pinned checkpoint to obtain its real preprocessing configuration
and saved layer structure. Run the same unmodified DWARF-assisted serial TYGR generator,
discard its accompanying GlowOutput and filter empty node groups as the original exporter
does. Run preproc_input and collate_inputs, but never model/encoder/GNN/decoder forward.
Block forward methods on every loaded model module and report any attempted call as a
failed capture. No new prediction, training, GPU, compiler, installation, download or API.

## Capture before interpreting

Retain every generated nonempty function in a binary, not only the requested function;
mark the target function explicitly and require exactly one matching function for query
identity. For each, record actual architecture token, complete graph node iteration order,
NodeLabel bit width/annotation address/value kind and value representation, native graph
edge order and full label sets, prepared node features/edge endpoints/relation IDs, original
and flattened variable-node groups, and complete collated gather/scatter/num_vars arrays.
Store dtype/device/shape with all tensor values, on CPU and under declared size limits.
The generator uses symbolic execution for features, not a property checker or decision.

Record positional correspondences rather than sorting/reordering nodes, groups or edges
to make them align. Note that the current edge encoder overwrites idx throughout its
sorted label loop, so its returned ID comes from the **last sorted label**, not the first.
Retain the actual native return values and source hash; do not infer a corrected mapping.
Record any noncontiguous graph-ID/feature-row alignment, architecture-token zero encoding,
unknown label encoding and relation IDs outside declared/saved layer domains as findings.
Such a finding does not erase a successfully captured receipt and must not cause model
forward. Failed/missing/timed-out cases stay in the complete three-case denominator.

Variable records preserve DWARF locations, original node groups, flattened row ranges,
prepared var_nodes and batched row membership. They establish what the native pipeline
readout would consume, not source-variable type truth or a mapping from v17 events.
The original exporter averages raw logits across an original variable's value-node rows;
this audit records those row groups but computes no logits or new candidate type scores.

## Provenance, budget and decision

Hash/copy the exact three binaries, original query manifests, pinned model and all worker/
project/upstream source dependencies. Runtime model/package versions and the installed
RGCN forward source/hash are evidence only; no RGCN behavior for bad IDs is executed or
inferred. All model tensors are mapped to CPU. Each child shares a 60 s parent-owned
request-to-persisted-payload budget, including request writing, startup, imports, model
loading, graph generation, preparation, capture, parent validation/recovery and cleanup.
Final receipt work, aggregate/offline evaluation and global snapshot setup are explicit
exclusions. Diagnostic cost is not policy throughput or an end-to-end neural-benefit test.

Implement meaningful pure receipt validation/evaluation and counterexample tests. Main
agent reviews delegated code. Complete tests before collection. Windows can validate the
protocol and mocked runner paths but cannot substitute for the original Linux environment;
do not retry the known sandbox-denied WSL launcher. Provide a single user-run WSL command.
Keep every output/cache on D and retain partial artifacts on errors. Update OPM/evidence.

If actual unsupported IDs occur, report them as newly observed native preprocessing input,
not as proof of historical use or model failure. If none occur, the full declared-domain
constraint still exists. Neither outcome validates v17 feature/context/readout projection,
prediction accuracy, scheduler benefit or novelty. RQ1/RQ2 and all frozen panels remain.
