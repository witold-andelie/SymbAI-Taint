# Research write-up: claims, evidence and missing experiments

Updated 13 November 2026, development v23. This replaces the earlier 13-stage talk
outline as the current writing guide. Historical implementation/results remain in
[GNN_INTEGRATION](GNN_INTEGRATION.md), [JULIET_PILOT](JULIET_PILOT.md) and Git history.
It is a research plan, not a validated publication abstract.

## Positioning

Working title: **Neural Type Information for Property-Directed Binary Analysis Scheduling**.

The project studies whether frozen neural type predictions can help a shared scheduler
choose local program-analysis operations under an equal total budget. Neural information
may influence priorities without changing symbolic semantics; that is a legitimate
experimental question. A useful signal and an original algorithm are separate claims.

RQ1 asks whether genuine type information adds end-to-end value over the same scheduler
without it. RQ2 asks whether candidate sets and model scores add beyond Top-1. A, B, C
and D are defined in the [frozen architecture](architecture.md). The first prototype
requires no new neural training or LLM.

## Defensible observations

| Evidence | Supported statement | Unsupported extension |
|---|---|---|
| Twelve authored ELF mechanisms | Restricted checker/contracts and failure handling can be exercised. | Generalization to real projects or benchmark superiority. |
| Early real end-to-end probe | Genuine acquisition and charged timeouts work; no gain on that query. | A neural speedup. |
| Complementary non-neural controls | Different local analyses resolve different known mechanisms; a fixed cascade is a strong control. | A novel analysis theory or neural contribution. |
| Corrected v22.1 acquisition | Three functions in one retained ELF yield seven genuine variable outputs with guarded input/output identities. | Type accuracy, event mapping completeness or three independent programs. |
| v23 exact collision | Two table queries share actual model inputs and all 75-class output rows despite different historical operation capabilities. | All neural methods are incapable of useful guidance. |
| Cold acquisition 8.305 s; previous cascade total 2.162 s | Costs motivate checking deployment overhead. | A paired speed comparison, runtime bound or warm-service result. |

The [evidence index](pilot_evidence.md) preserves failures and corrections. Raw local
bundles and weights are excluded; the [reproducibility guide](REPRODUCIBILITY.md)
states what a public checkout can run. Software tests and diagram validation establish
implementation properties, not scientific novelty.

## Candidate contribution, still to be demonstrated

A future contribution would be a specific, reproducible selection mechanism whose
incremental information and complete cost can be measured against strong alternatives.
Combining a GNN, dependency graph and cost score is not itself evidence of novelty.
Neither selection by uncertainty nor expected value divided by cost is an original
principle on its own.

Related-work assessment must examine Manta's demand-driven/context- and flow-sensitive
type refinement, OSPREY's probabilistic type recovery, TYGR's neural representation,
traditional binary type inference, CEGAR refinement selection and learned analysis
scheduling. The detailed algorithmic overlap must be checked against primary papers
before claiming a new method. This document does not make a first-of-its-kind claim.

## Minimum evaluation for a formal paper

1. Freeze fixed property queries and modeling assumptions. Count all queries, including
   failures, missing mappings, timeouts and unresolved cases.
2. Split by program/project before tuning. The known authored panels remain development
   controls; repeated runs and multiple variable rows do not increase sample independence.
3. Hold B/C/D's selector, parameters, non-type features, operation set and checker fixed.
   Compare hidden types, Top-1, Top-K without scores and Top-K with actual scores.
4. Include traditional recovered types with the same selector, fixed cascades, structural
   scheduling and confidence-only selection as appropriate reproducible controls.
5. Separate information-only ablation from full acquisition cost. Report model/graph/mapping,
   selection, checking, validation, memory and total wall time with explicit cache treatment.
6. Report resolved queries, scoped exclusions, violations, unknowns, wrong decisions and
   budget curves. Repetition measures runtime variability; it is not independent data.
7. Treat neural scores as uncalibrated unless calibration is independently evaluated.
   Do not tune on test labels or use neural labels to exclude feasible paths.

The initial information-value experiment should remain small and interpretable. A new
benefit predictor or dependence-group optimizer is premature unless simpler controls
show useful incremental information and cost headroom.

## Scope wording

Use “modeled witness” and “excluded within the declared query scope.” Native input
replay is not implemented. A single path exclusion does not prove the entire query
excluded; a scoped query exclusion does not prove the program correct.

Use “DWARF-assisted acquisition,” rather than claiming end-to-end fully stripped type
recovery. Ground-truth type labels are not supplied to the model, but variable-location
metadata is still an input to extraction.

The legacy Juliet scores came from another pipeline and include asymmetric positive-only
rechecking. Preserve them as historical observations, rather than citing them as RQ1/RQ2
evidence or an unbiased neural gain. No journal quartile or acceptance outcome follows
from the current pilot.

## Next decision

The repair is complete. Retain the three typed cases as regression/cost controls and
design a small independent panel with an explicit information-value hypothesis. If the
same scheduler gains no stable end-to-end advantage, report that result and investigate
its cause before increasing system complexity. See [STATUS](STATUS.md).
