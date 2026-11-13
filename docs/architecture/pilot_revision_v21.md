# Development revision v21: compiled typed-complementarity readiness

Declared on 13 November 2026 before implementation or collection of this revision.
RQ1/RQ2, B/C/D, prior inputs/outputs and operation implementations remain unchanged.
The existing typed three-query panel and complementary-operation panel have no exact
input intersection. Do not pool them or claim their separate results measure neural gain.

## Small prospective panel

Prepare exactly three new authored functions in one AMD64 PIE ELF: a bounded scalar
span, a readonly offset-table access with values {2,6}, and the same table-access shape
with values {2,12}. Their declared output objects have capacities 1024, 8 and 8; entry
RDI ranges are [0,1023], [0,15] and [0,15]. The table functions mask the index to one bit.
These are related capability mechanisms, not identical binaries or replications of v14.
They are a separate development panel, not additional primary/held-out samples.

Use two C translation units without LTO, so the compiler cannot replace external readonly
table loads with their source constants. Keep a normal trivial main for standard PIE
linkage. Explicit 64-bit AND inline assembly avoids making the finite checker's unsupported
32-bit form the intended mechanism; an empty register barrier keeps the pointer access
materialized. These authored choices are fixed before observing predictions/results,
apply equally to every operation and do not modify original TYGR or any checker.
Record compiler/version, flags, complete sources, ELF symbols, DWARF and disassembly.
Optimized DWARF availability and actual operation support are hypotheses, not guarantees.

## One batch acquisition and fixed operation controls

The existing Linux GCC compiles the sources with -O1, DWARF4, PIE, no LTO/inline/builtins
or stack protector. Extract three fixed queries from declared function/object symbols and
one unique constant byte store per function. Check object sizes, ELF format and addresses.
No program is run natively. Gold outcomes are separate and loaded only after runtime.

Acquire genuine Top-K raw logits once for the shared binary in the existing tygr-orig
CPU environment, using the unchanged serial DWARF-assisted generator, saved preprocessing
and original whole-variable mean aggregation. Discard GlowOutput labels. Before each
model forward, persist native graph/group/tensor input and verify saved feature width,
CPU tensors, endpoint/gather/scatter domains and every observed relation against all
saved layer capacities. Refuse incompatible inputs without remapping/zero filling/layer
expansion. Retain every nonempty generated function, failed/partial acquisitions and any
earlier completed genuine predictions. No new training, installation, GPU, download/API.

Independently of acquisition success, run interval-only, finite-readonly-only,
expanded-only and fixed interval/finite/expanded cascade on every query. Reuse the
existing operation execution/validation bodies. Run separate modeled references. Rotate
control order by query. Each operation-control/reference has a 30 s parent-owned
request-through-payload-persistence cap; one cold shared acquisition has a 120 s cap.
No type label, probability, gold or prior result influences operation selection.

Record source/input identities and all attempts. Three queries, not functions/variables/
rows/repeats, are the sample denominator. Missing query extraction, unsupported DWARF,
capacity failures, unknowns and timeout remain visible. Function-level genuine-output
availability is not yet an exact variable/use-site mapping or semantic-role proof.

## Readiness and cost interpretation

Report per-query type-output coverage and operation applicability/decisions separately,
then their intersection. This is a readiness gate; there is no learned/new selector,
same-budget A-D comparison, speedup or held-out claim. The old strong fixed cascade
remains an explicit control. Compare the paid cold acquisition for one binary/three
queries descriptively with the total fixed-control cost. State per-query amortization
and startup/serialization exclusions. A single pass provides neither a runtime bound
nor a stable net-benefit estimate. Do not count cached information as free.

Snapshot every loaded project source/package initializer, original TYGR source and
pinned model; recheck originals/copies and input identities after running. Preserve
partial artifacts and logs. All outputs, caches, binaries and temporary files stay on D.
The agent cannot launch WSL; prepare/test the protocol locally and give one user-run
WSL command. Windows preparation is not a successful Linux compile/acquisition/control.
Complete meaningful unit/full checks before collection; main agent reviews delegated
work and takes over if agent quota is unavailable. Update OPM/status/evidence honestly.
