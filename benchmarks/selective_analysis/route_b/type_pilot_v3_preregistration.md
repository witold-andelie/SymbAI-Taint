# Type pilot v3: pre-registered training-coverage expansion

Written on 20 November 2026, after the [v2 result](README.md#type-pilot-v2-results)
("No R1") and before any v3 project was labelled, graph-extracted or scored.
The SHA-256 of this file is recorded in the v3 `selection.json`; later v3
runners must refuse to start if it changes. Any change after that point needs
a new, separately versioned pre-registration.

## Question

v2 found that neither a deeper RGCN nor the original 129 training variables
gave stable neural type predictions. A deterministic structural baseline (A5)
beat every GNN arm. v3 asks two questions under one fixed protocol:

1. Does a roughly tenfold larger and more varied training set make the GNN
   better on unseen projects?
2. Do neural type scores then carry information beyond the structural
   features that a type-blind scheduler can compute directly?

Only the second question bears on Route B. Type accuracy alone is not a
scheduling result.

## Data

**Sealed:** utf8.h and b64 remain sealed and are not compiled, labelled or scored.

**Training (expanded).** All of the following, project-level, as one training split:

| Source | Projects | State |
| --- | --- | --- |
| v1 reviewed export | inih, rxi/map, jsmn | 129 admitted variables (unchanged) |
| v1 inspected development | optparse | 52 admitted variables, audited |
| v2 inspected development | sds, tiny-regex-c | 200 admitted variables, audited |
| New | tidwall/hashmap.c, tidwall/btree.c, fragglet/c-algorithms, kokke/tiny-AES-c, attractivechaos/klib (`kstring.c` only), cesanta/slre, antirez/linenoise, rxi/log.c, troydhanson/tpl | to be built, labelled and exported |

Moving optparse, sds and tiny-regex-c into training is allowed because they
can no longer serve as clean development data. The original 129-variable
training split is kept as a separately identified subset ("original").

**Fresh development:** json-parser/json-parser and kgabis/parson (pinned in
`route-b-type-dev-extension-20261120T192757085592Z`, never labelled because they
failed to link under the v1 recipe), plus mity/md4c (`src/md4c.c` only). No
author family of a development project appears in training, and no author
family of training or development appears in the sealed evaluation set.
There is no development backup. If fewer than 150 development source
variables are admitted, v3 stops and is reported as uninterpretable; no
project is substituted.

**Expanded-training minimum:** if fewer than 600 training source variables
(original plus reused plus new) are admitted, v3 stops and is reported.

**Build recipe v3** = the v1 command plus `-lm` at the end of the link line.
Compilation flags, harness and DWARF settings are unchanged. Before this file
was written, every listed new project and both pinned development projects
were linked once with this recipe in WSL (no DWARF or label was read). All
twelve linked. Directory layout, line counts and symbol counts were also
inspected. The recipe applies to all new v3 builds; existing v1/v2 binaries and
exports are reused unchanged.

**Function cap:** for each new project (training or development) with more
than 60 source-owned O0 functions, keep the 60 functions with the smallest
`sha256(project_id + ":" + function_name)`. The rule uses names only, not labels.

**Admission:** v1 rules and the v2 exporter/audit, unchanged: fixed CFA
correspondence, whole-struct exclusion, readout-order and graph failures
excluded but kept in denominators. Development functions in a cross-split clone
group with any training function are excluded from development and reported.

## Arms

Shared settings come from v1/v2: hidden width 64, eight bases, 60 relations,
75 outputs, CPU, one thread, Adam at 0.003, gradient clipping at one, 30
full-batch epochs, the fixed final epoch, mean value-row logits per source
variable, and seeds 17, 29 and 43. A5 features and the logistic-regression
settings are those of v2 (48 features, zero initialization, Adam at 0.05,
weight decay 1e-4, 300 epochs).

**Depth selection (training only).** Run leave-one-project-out over all
training projects, seed 17, at depths 2 and 4 (graph messages on). Choose the
depth with the larger pooled held-out Top-1 count; a tie selects 2. No
development data is used. Call the chosen model G.

| Arm | Description |
| --- | --- |
| D0 | Frequency prior on expanded training. |
| D5 | A5 structural logistic regression on expanded training. |
| D5o | A5 on the original 129 variables (secondary). |
| DG | G on expanded training. |
| DGo | G on the original 129 variables. Its final digests must equal the v1 A1 run (depth 2) or the v2 A3 run (depth 4). |
| DN | G with messages disabled, expanded training (secondary control). |
| DS | Stacked logistic regression on A5 features plus the 75 log-softmax values of G's mean logits (123 inputs), with A5 settings. Training inputs use out-of-fold G scores from the leave-one-project-out models of the same seed and depth; development inputs use DG of the same seed. |

Leave-one-project-out runs for seeds 29 and 43 at the chosen depth are needed
only to build the DS training inputs.

## Metrics and decision rules

N is the number of admitted fresh-development source variables, and the
margin is m = max(3, ceil(0.05 N)). The primary metric is development Top-1
over all N variables, including unseen-class variables, for every seed.

- **H1 (coverage helps the GNN):** DG beats DGo by at least m in all three seeds.
- **H2 (GNN beats structure):** DG beats D5 by at least m in all three seeds.
- **H3 (neural scores add to structure):** DS beats D5 by at least m in all three seeds.

| Outcome | Next step |
| --- | --- |
| H2 or H3 | Neural scores carry incremental information here. Design the fixed-query Route B scheduling comparison. The type-blind arm receives A5 features; the typed arm receives DS scores if H3 holds, otherwise DG scores. |
| H1 without H2 or H3 | More coverage helps the GNN, but it adds nothing beyond structure. Close the neural-type branch at this scale; Route B continues with structural, type-blind features. Variant E is not pursued. |
| Neither | Report a negative result for neural type information at this scale and stop. |

Secondary reports, which never decide an outcome: Top-3, NLL, per-class recall
(`char*`, `struct*` named), unseen-class counts, per-project results, the seed
range of each arm, the leave-one-project-out table, D5o versus D5, and DN.
Hyperparameters are never tuned on development data. The fresh development set
is not reused for another decision without a new pre-registration that
declares the reuse.

## Execution order

1. Pin the new training and development projects (versioned v3 preparer).
2. Build with recipe v3, inventory labels, screen clones, and apply the
   function cap (versioned v3 builder).
3. Export graphs for the new training and development functions and run the
   passive audit (versioned v3 exporter and verifier).
4. Implement the v3 trainer (depth selection, arms, stacking, decision) as new
   versioned files; check the DGo digest reproduction first.
5. Run once and report every seed under the rules above.
