# Type pilot v2: pre-registered remedy and new development set

Written on 20 November 2026, after the
[coverage diagnosis](README.md#coverage-and-representation-diagnosis) and before
any new development project was compiled, labelled, graph-extracted or scored.
The SHA-256 of this file is recorded in the development-extension
`selection.json`; later runners must refuse to start if it changes. A change
after that point requires a new, separately versioned pre-registration.

## Why a v2 is needed

The v1 pilot's models separated 32-bit from 64-bit values and little else.
Readout features are a concretized-zero signature that differs only in width.
The structural evidence separating `char*` from `struct*` is the width of the
memory accesses that dereference the value, and it mostly lies beyond the
two-layer receptive field. In v1 the optparse development project was used
for this diagnosis, so it can no longer support model or design decisions.

## Fixed inputs

- **Training data:** unchanged. The reviewed 26-function, 129-variable
  training split of `route-b-type-graphs-20261119T225215150614Z` (inih,
  rxi/map, jsmn). optparse is not moved into training, because changing the
  training set would confound the representation comparison.
- **New development set:** three new projects, pinned before labels.

  | Project | Repository | Order |
  | --- | --- | --- |
  | sds | [antirez/sds](https://github.com/antirez/sds) | Primary |
  | tiny_regex_c | [kokke/tiny-regex-c](https://github.com/kokke/tiny-regex-c) | Primary |
  | json_parser | [json-parser/json-parser](https://github.com/json-parser/json-parser) | Primary |
  | parson | [kgabis/parson](https://github.com/kgabis/parson) | Backup |

  Selection rule: small C libraries with permissive licenses that build with
  gcc from one or two translation units and the existing link-only harness,
  have no external dependency, and come from author families outside every
  existing split and the known-diagnostic exclusion list. The domain (string,
  regular-expression and JSON handling) resembles the training projects and
  was chosen deliberately; no type label of these projects was read before
  this file was written. mpaland/printf was considered and rejected because
  linking requires a user-supplied `_putchar`, which would change the harness.
  Directory layout and line counts were inspected only to confirm buildability.
- **Backup rule:** parson replaces a primary project that fails pinning,
  compilation or graph export. parson is also added in full if the three
  primary projects together admit fewer than 100 development source
  variables. No other substitution is allowed.
- **Function and variable scope:** all source-owned O0 functions, with the
  same admission rules, exclusion reasons and passive audit as v1. A function
  flagged by the cross-split clone screen against training is excluded from
  development and reported. O1 builds are not additional samples.
- **Sealed data:** utf8.h and b64 remain sealed. optparse results are reported
  as a secondary, already-inspected panel and never decide an outcome.

## Arms

All neural arms use the v1 settings: hidden width 64, eight bases, all 60
relations, 75 outputs, CPU, one thread, Adam at 0.003, gradient clipping at
one, 30 epochs, seeds 17, 29 and 43, the fixed final epoch, mean value-row
logits per source variable and one cross-entropy term per variable.

| Arm | Description |
| --- | --- |
| A0 | Training-only smoothed frequency prior (v1 definition). |
| A1 | v1 reference RGCN, two layers, graph messages. |
| A2 | A1 with messages disabled (node-only control). |
| A3 | **Remedy:** RGCN with four layers, graph messages; otherwise identical to A1. |
| A4 | A3 with messages disabled. |
| A5 | Deterministic structural baseline (below); no graph neural network. |

The layer count of A3 follows a rule applied to training statistics only.
Take the smallest k in {2, ..., 6} such that at least 60% of training
`char*` variables have an 8-bit access node within undirected distance k.
The training counts are 4/25 within 2, 8/25 within 3 and 16/25 within 4, so
k = 4. All 37 training `struct*` variables have a 32/64-bit access within 4.
Honesty note: the 60% threshold was written while these training counts and
the optparse diagnosis were both visible.

A1 and A2 retrain from the same seeds and data as v1. Their final parameter
digests must equal the v1 checkpoints. A mismatch is a reproducibility failure
to report before any comparison.

**A5 features** are label-free and computed from the same exported graphs. For
each readout node they are: the 8-way width one-hot; for each access width in
{8, 16, 32, 64}, a one-hot of the minimum undirected distance to an access node
of that width, in buckets {1, 2, 3, 4, absent within 4}; and, for the same
widths, a one-hot of the first forward dereference depth from the node, in
the same buckets. That gives 48 features, averaged over a variable's readout
rows. An access node is the target of a forward `mem_loc` edge. A5 is a
multinomial logistic regression with 75 outputs, zero initialization,
full-batch Adam at 0.05, weight decay 1e-4 and 300 epochs. It is
deterministic, so one fit serves all seeds. A5 approximates information that
a type-blind scheduler could compute directly from program structure.

## Metrics and decision rules

N is the number of admitted new-development source variables, and the margin
is m = max(3, ceil(0.05 N)). The primary metric is new-development Top-1 over
all N variables, including unseen-class variables, for every seed.

- **R1 (representation remedy):** A3 beats A1 by at least m Top-1 variables,
  and has lower development NLL, in each of the three seeds.
- **R2 (incremental information over structure):** A3 beats A5 by at least m
  Top-1 variables in each of the three seeds.

| Outcome | Next step |
| --- | --- |
| R1 and R2 | Design the fixed-query Route B scheduling comparison using A3 scores. The type-blind arm must have access to A5 features. |
| R1 without R2 | The deeper GNN mostly restates structure. Report that neural type scores show no incremental information here. Neither a scheduling claim nor Variant E follows. |
| No R1 | Stop representation iteration on this corpus. The next step is a separately pre-registered training-coverage expansion. |

Secondary reports, which never decide an outcome: Top-3, NLL, per-class recall
(in particular `char*` and `struct*`), unseen-class counts, per-project
breakdowns, the optparse panel and the A4 versus A2 control. Seeds are
repetitions, not independent samples. Hyperparameters are never tuned on the
new development set, and it is not reused for a v3 decision without a new
pre-registration that declares the reuse.

## Execution order

1. Pin the development extension (`scripts/prepare_type_dev_extension.py`).
2. Build the O0/O1 profiles and the label inventory in WSL, together with
   the training projects for the clone screen. This needs a versioned builder,
   because the v1 builder is pinned to twelve builds.
3. Review variable locations and readouts, then export graphs for the new
   development functions with a versioned exporter, followed by a passive
   audit. The v1 exporter is pinned to the 43-function scope.
4. Implement the v2 trainer with arms A0-A5 as a new, versioned script.
   Verify the A1 and A2 reproductions first.
5. Run all arms once and report every seed under the rules above.
