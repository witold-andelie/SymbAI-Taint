# Development revision v14: bounded readonly-indirection mechanism

Declared before implementation/measurement on 11 November 2026, following the replicated
v13 negative routing result. Retain all previous sources/results and the frozen selector.
This is a three-case authored mechanism panel, not independent evaluation or algorithm
novelty. It tests operation capabilities before trying another neural routing score.

## Concrete hypothesis and cases

A bounded finite-value domain can resolve readonly pointer chains that the existing
interval checker does not model. Conversely, a large scalar input range may be cheap
for intervals while exceeding a finite-set cardinality budget. This could supply two
meaningfully different analyses, rather than two path-depth limits. The later neural
hypothesis would be that pointer-related uncertainty at an intermediate load predicts
the value of such resolution. **That neural hypothesis is not tested here**: static
load structure and cardinality may already provide all useful information. Strong fixed
and structural controls remain necessary before claiming incremental neural value.

Add exactly three tiny compiler-independent AMD64 ELF mechanisms, with declared readonly
tables and separate writable target storage:

1. Scalar range 0..1023 into a declared 1024-byte object. Intervals can retain that range;
   the finite domain's globally fixed cardinality cap is 32, so the input starts at Top.
2. Input 0..15, masked to two indices, selects two readonly pointers, then reads offsets
   2 or 6 through them before a byte write into an eight-byte object.
3. The same pointer-chain shape with offsets 2 or 12, as a conservative negative control.

The third case must not receive an abstract exclusion. Cases are chosen for declared
analysis needs before any model outputs; no model runs or type predictions exist for
them. Keep this panel separate from the original 12 mechanisms and three compiled inputs.
No packages, downloads, compilation, training, API, GPU or WSL access by the agent is needed.

## Finite readonly operation

Implement an independent register finite-set domain, with Top and a global 32-value cap.
Support a narrow straight-line 64-bit move/lea/add/sub/and/xor subset, machine-width wrap,
and bounded finite-address reads of initialized file-backed readonly ELF bytes. A small
constant mask may refine Top to its complete finite image when that image fits the cap;
do not artificially disable that transfer to manufacture complementarity.

Retain correlation losses as overapproximations; saturation returns Top, never a sampled
set. Unknown registers/addresses, mutable or uninitialized reads, address wrapping,
ambiguous load segments, relocations affecting read bytes, unsupported instructions,
calls, branches or non-target stores cannot justify an exclusion. Reuse the existing
ELF relocation coverage guard and verify complete read spans against relocation writes.
There are no path predicates, type assumptions, case-ID switches, source names or labels
inside the checker. It reports only scoped exclusion or unknown, not an abstract witness.

An exclusion requires every abstract target-address/access-size possibility to be inside
the declared object. Rebuild bytes/readonly data and rerun abstract transfer for a fresh
certificate recheck; record that this is same-implementation validation, not native replay.
Record cap, Top/saturation observations, instructions, readonly accesses and provenance.

## Comparisons and correctness reference

Run interval-only, finite-readonly-only, expanded-only and an actually executed fixed
interval-then-finite fallback, once each on all three inputs from fresh entry checkpoints.
The fallback pays for failed interval attempts and uses no neural routing. Do not replay
old operation records to fabricate policy costs. Preserve unknowns, errors and all twelve
planned method/case records. Keep costs for preparation/execution/fresh validation and
parent recording/recovery explicit; no speed/significance claim follows from one pass.

After all method workers finish, obtain separate label-free modeled correctness references.
For explicit input-domain product cardinality <=32, enumerate the entire domain using
fresh angr states with literal BVV input registers (not constrained BVS inputs), preserving
concretization/unsupported guards. Freshly reexecute any witness; an exclusion requires
all inputs fully discharged. For a larger domain use fresh expanded symbolic checking
and validation. Do not relax the old BinaryChecker's exclusion/concretization policy.
Reference costs are separate validation-panel costs, never free runtime features.
No native witness replay or general external-call model is claimed.

Offline authored expected outcomes are loaded only after runtime workers and references
finish. An unsound exclusion, reference disagreement or incomplete source identity blocks
scientific interpretation. Unknown is not a wrong conclusion. Report three unique inputs,
not twelve independent examples. There is no neural benefit, held-out, or deployment
performance evaluation. If capabilities are not complementary, record that and reconsider
the mechanism; do not alter the panel or cap based on a preferred result. All caches,
temporary files, generated binaries, logs, snapshots and reports remain on D.
