# Development revision v17: instruction-level syntax provenance

Declared on 12 November 2026 after v16 and a local PyVEX API inspection, before implementing
or collecting this diagnostic. This closes a prerequisite for a possible future type
bridge; it does not supply the information-value hypothesis missing in v16. Preserve
every prior runner, source/specification, model, raw prediction and measured result.

## Minimal label-free interface

Use only the same three copied v15 ELF/query identities. Parent preparation strips the
query down to binary path/hash, function-entry RVA and target-store RVA. Runtime requests
reject all other fields, including capacity, object location, input bounds, labels, raw
types and old evidence. No new fixture, compiler, DWARF annotation or model is introduced.
Hashing reads the full file for identity, but no readonly data values are interpreted or
loaded into the graph. Runtime inspects executable bytes only and records syntax, not
path feasibility, target addresses, object bounds or a property decision.

Lift one instruction at a time with PyVEX optimization level zero. Require a matching
single IMark, exact Capstone instruction length, ordinary straight-line next-PC semantics,
and a fixed maximum of 64 instructions/4096 graph nodes. Conditional/indirect control flow,
unsupported IR, special memory effects and imprecise correspondence remain unavailable.
Temps are scoped by instruction and every RdTmp resolves a prior WrTmp. Register locations
use VEX byte offsets and explicit bit widths, never DWARF numbers. Each Put creates a new
definition for its exact byte span. Get records its event-time byte sources from earlier
Puts or entry-byte nodes. Subregister writes preserve untouched bytes; zero extension
must be represented by the lifted full-width write. Do not obtain values from final state.

Keep nodes/edges for constants, operations, loads, temps, reads/writes and stores, with
instruction RVA, statement/operand identity, direction and width. Load values are opaque
syntax nodes, not evaluated memory. A target Store is recorded, never executed.

## Independent address correspondence

For each ordinary load/store, compare a solver-free affine normalization of the IR address
against Capstone's base/index/scale/displacement form modulo 2^64. Stop normalization at
current-instruction register reads; do not traverse their previous-definition edges when
matching the address's direct operands. Match register byte span/width and retain the
read-event IDs plus their distinct version sources. Reject ambiguous repeated base/index,
unsupported width/address-size, multiple memory effects and non-affine direct addresses.
RIP-relative constants may be checked against the instruction's end PC and displacement.

A matching syntax address does not prove what a pointer points to. The new provenance
nodes are not automatically compatible with TYGR's trained readout/features. No existing
TYGR graph is silently repaired or reused, and no prediction or new preprocessing claim
is made. A later bridge must explicitly validate its context/features and identity mapping.

## Validation and reporting

Report all three planned inputs, including partial/unavailable artifacts, actual versions,
neutral graph fingerprints, operation counts and isolated parent-observed diagnostic costs.
Every process has a 30 s parent-owned cap; complete payload persistence is inside the clock,
while final accounting receipt/aggregate serialization are explicit exclusions. This is
a provenance diagnostic, not a policy timing experiment. All artifacts/caches remain on D.

Test temporary identities, intermediate overwritten RAX/RDI definitions, partial-byte
updates, EAX zero extension, affine correspondence and rejected branch/special-effect
inputs. Unit byte fragments are fabricated checks, not extra benchmark programs. Complete
tests before retained collection. Independently audit persisted graphs and source/input
hashes. Update the OPM and evidence. Keep safe/outside chains' identical executable syntax
visible: differences only in readonly numerical contents cannot distinguish these syntax
graphs. This is not a claim that general TYGR inference is insensitive to memory contents.

No SMT/angr state, graph generator from TYGR, model, training, API or GPU is used. No neural
benefit, novelty, native replay, held-out performance or journal readiness is established.
The main goal is a precise event identity contract; RQ1/RQ2 remain unchanged and unanswered.
