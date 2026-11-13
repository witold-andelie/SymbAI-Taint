# Development revision v7: independent operand mappings

Declared before implementation and validation on 11 November 2026. The frozen A-D
selector, parameters, v6 base-pointer input and prior measurement artifacts remain as
recorded. This revision adds a separate mapping/projection diagnostic, not a new selector.

## Scope and identities

Reuse the existing reviewed compiled query and a genuine completed v5 raw export. Its
address is base pointer plus index, with a constant one-byte write. Assign distinct IDs
`<query use-site>:base_pointer` and `<query use-site>:index`. Candidate lists, logits and
conditional Top-K weights remain separate per prediction; never average different
variables' scores into one type distribution. A/B expose no views; C exposes a label
per operand without scores; D exposes candidates and scores per operand.
Export operand roles, locations and proven program relations separately as common facts
for all future comparison arms, including the no-type baseline. Model candidates are the
only additional information in C/D; extra program evidence is not attributed to the GNN.

The plan declares a physical CFA-relative location, a prediction identity and a semantic
anchor for each role. The first supported form is AMD64 ELF, one eight-byte CFA location
per operand, index scale one, finite linked-address location ranges and a single-successor
prefix of at most 64 instructions. The base anchor is the query's declared object address;
the index anchor is an explicit entry register from the query. Locator names and predicted
type labels do not select the binding. The specific probe retains its existing reviewed
CFA-24 and CFA-40 anchors; this is not a general automatic mapping claim.

## Independent program evidence

The verifier accepts only the query and a strict, type-score-free plan. It starts a fresh
symbolic entry state, checks a nonempty target state and proves by UNSAT of negations:
base-slot equals object base; index-slot equals the declared entry input; target address
equals base-slot plus index-slot; and the observed write length equals one. Capture the
write before address concretization. Unmodeled calls, forks, precision loss, unsupported
locations, exhausted work/time or solver failure cannot produce verified evidence.

Recompute the evidence from another fresh entry state before accepting the mapping.
The diagnostic gives both passes a shared ten-second verification cap and checks the
binary content before and after each pass.
Bind the raw record only after function/location identity and query/binary/model provenance
checks. Preserve a versioned role bundle with raw output, plan, validated proof and binding
fingerprints. The new bundle must not be accepted as the old single-view artifact.
Program evidence validates location/use relationships, not predicted type correctness.

## Small validation and decision boundary

Use existing D-drive artifacts. No compilation, new GNN call, training, model download,
environment change, API or additional independent program is required. Archive the plan,
raw inputs and runtime sources before validation. Report both role IDs, separate C/D views,
proof checks, actual validation costs and unchanged candidate values. Retain failures and
never manufacture a missing role or repair a prediction with a source type label.

Run meaningful unit checks for wrong/swapped slots, duplicate roles/predictions, changed
PC ranges and binaries, forged/partial evidence, deadlines, label/score isolation and
cross-variable score mixing. Recheck actual mappings on the existing probe in Windows;
WSL replication uses the same diagnostic. Coverage remains two operands of one query.

Do not rerun or relabel v6 using this richer input. Future selection experiments need a
separately declared policy interface and independent reviewed queries. Online use would
have to pay any new verification/mapping cost; this diagnostic does not establish neural
information value, end-to-end improvement or broad dependency completeness.
