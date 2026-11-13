# Development revision v3: charged online TYGR acquisition

The frozen research questions, A-D type views, selector and checker remain unchanged.
Selection still uses `deterministic-pilot-v2`; symbolic operations still use
`exact_prefix_v2`. This revision implements the previously missing online acquisition
boundary rather than another scheduling policy.

## Input and measurement scope

The integration entry uses the already compiled ELF and explicitly scoped query. It also
takes the existing reviewed base-pointer locator plan as a fixed input. That plan contains
the function address, DWARF location range/class/argument and review provenance. Matching
fresh output to this identity is paid inside each neural run. The prior human review,
fixed object bounds/query creation and harness setup are outside the per-query clock.
This is not general automatic mapping or fully stripped operation.

Each run starts its clock in the parent before request writing and worker startup. A/B
do not load or validate a model/provider configuration. C/D hash the frozen model, start
a fresh `tygr-orig` process, load weights, extract the graph, infer, serialize raw logits,
match locations, construct the requested type view, run the common analysis and independently
validate its result. These costs and worker exit/finalization remain inside the budget.

## Freshness and isolation

- Every neural run gets a new acquisition directory and nonce, echoed by the exporter.
  A previous JSON file cannot stand in for fresh inference. No model process is shared.
- Raw output must match the nonce, model hash, binary hash and unlabeled independent-decoder
  contract. Selected candidates must match the common configured Top-K.
- A reviewed prediction ID alone is insufficient: function and physical location fields
  must still match the fixed identity anchor. A relocation mismatch retains unknown.
- C and D run the same Top-3 export and mapping. Only the final view differs: C has one label
  and no scores; D has candidates and scores. Neither supplies neural facts to the checker.
- Exporter caches, temporary files, raw results and logs live under each D-drive run directory.
  CPU/BLAS thread counts are one; `PYTHONHASHSEED=0` is recorded. OS file caches are not flushed,
  so the accounting unit is a cold process, not a cold machine.

## Deadlines and process lifecycle

The isolated POSIX worker owns a new process group. Its exporter inherits that group.
The outer deadline kills the whole group, including the model process; cleanup also
removes residual group members when the worker exits. The inner export deadline stops
that subprocess and records the failure when time remains. Windows tests use native
process-tree termination for their controlled subprocess fixtures.

Hard timeouts retain partial flushed events and an unknown result. If a worker is killed
before it returns a cost breakdown, model-acquisition time is reported as unknown rather
than zero; full elapsed wall time is still charged. A late candidate result is never
counted as a successful in-budget conclusion.

## First real validation, declared before the run

Run the same reviewed integration query at **3, 10 and 20 seconds**, once per A-D arm.
The smaller limit exercises acquisition timeouts; the larger limits allow actual inference
and analysis to complete if the machine is fast enough. Retain all records regardless of
outcome. The fixed order is budget, query, A/B/C/D; this one-case run is not a statistical
comparison and will not establish publication readiness.

The entry first performs a small POSIX descendant-cleanup check outside query budgets.
Then each query uses the bounded worker; labels are joined only after workers terminate.
No compilation, model download, new case generation, training or external API is needed.
The user-controlled WSL run completed on 11 November 2026. Its twelve records, fresh model
exports and process-group cleanup receipt were audited against the recorded source hashes.
C/D timed out during export at 3 s; at 10/20 s they obtained the same modeled violation as
A/B but took longer. See [the evidence log](../pilot_evidence.md#first-real-end-to-end-run).
The operation catalog and selector remain unchanged; [operation complementarity](operation_selection_gate.md)
must be checked before investing in more complex scheduling.
