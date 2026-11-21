# Related work for the type-information pilots (v1-v3)

Compiled on 21 November 2026 to position the [v1-v3 type pilot results](README.md#type-pilot-v3-results).
"Verified" means the quoted fact was read in the paper's text or abstract page during compilation;
"abstract only" means only the abstract page was read. No other claim is made about these works.

## Neural type inference on stripped binaries

- **TYGR** (Zhu et al., USENIX Security 2024; [paper](https://www.usenix.org/conference/usenixsecurity24/presentation/zhu-chang),
  [code](https://github.com/sefcom/TYGR)). Verified in the paper text: per-function data-flow graphs
  with a GNN; 76.6% overall and 45.2% struct accuracy on x64 O0-O3. Functions are deduplicated by
  SHA-256 of sanitized disassembly before train/test/validation splits are created; the
  generalization test uses random functions from the larger TYDA corpus that are not in TYDAMIN.
  The paper states that accuracy peaks at around 80% as training size grows, partly because
  "some variable types cannot be effectively differentiated by only observing how the variables
  are used," and names caller/callee access patterns as future work.
  *Relevance:* our pilots use TYGR's graph construction and features, and split by project
  family instead of by deduplicated function. Our diagnosis (readout features differ only in
  width; distinguishing dereference evidence lies several hops away) is consistent with the
  limitation TYGR itself reports.
- **Dataset duplication.** Verified in the TYGR text: it cites Pal et al. ("len or index or
  count, anything but v1", on variable naming in decompilation) for 52% duplicate functions in
  the DIRT dataset, and reports that the DIRTY dataset has 56.9% duplicate functions and 65.5%
  train/test overlap, and that the STATEFORMER dataset averages 90% duplicates. TYGR states that
  such rates "will lead to inflated prediction accuracy."
  *Relevance:* supports project-level splits and clone screening as used here; results under
  such splits are not directly comparable with function-level benchmark accuracies.
- **XTRIDE** (Seidel, Thomas, Rieck; arXiv [2603.08225](https://arxiv.org/abs/2603.08225), accepted
  at CODASPY 2026; abstract only). An "improved n-gram-based approach", reporting 90.15% type
  inference accuracy on the DIRT dataset. *Relevance:* a non-neural statistical method that is
  competitive on a standard benchmark, in line with our structural baseline (A5) outperforming
  the GNN arms.
- **InterType** (Wang, Cui, McCamant, Zhai, Yew; arXiv [2610.26906](https://arxiv.org/abs/2610.26906);
  abstract only). Adds caller-callee data flow to a fine-tuned CodeArt Transformer and reports
  recall on O1 coreutils rising from 89.00% (intra-procedural CodeArt) to 91.76%. *Relevance:*
  inter-procedural context is the direction TYGR names; our graphs remain intra-procedural.

## Learned selection of analysis precision

- **Oh, Yang, Yi**, "Learning a Strategy for Adapting a Program Analysis via Bayesian
  Optimisation", OOPSLA 2015 ([paper](https://prl.korea.ac.kr/papers/oopsla15-ohyayi.pdf)), and the
  TOPLAS journal version by Heo, Oh, Yang, Yi
  ([paper](https://kihongheo.kaist.ac.kr/publications/toplas18.pdf)). Seen in search excerpts only: a
  parameterized strategy, learned from a codebase, decides for each program part whether to apply
  a precision-improving technique; the reported analyser answered about 75% of the queries needing
  flow or context sensitivity. *Relevance:* the closest precedent for Route B's property-directed
  selection of analysis operations, driven by cheap syntactic and semantic program features
  rather than neural type predictions.
- **Jeong, Jeon, Cha, Oh**, "Data-Driven Context-Sensitivity for Points-to Analysis", OOPSLA 2017
  ([paper](https://prl.korea.ac.kr/papers/oopsla17-oopsla242.pdf)); search excerpts only. Same
  data-driven selective-precision idea for context-sensitive points-to analysis.
- **Algorithm selection for verification with GNNs** (arXiv [2201.11711](https://arxiv.org/pdf/2201.11711));
  search excerpt only: a GNN predicts which verification algorithm, including symbolic execution,
  will succeed on a program. *Relevance:* learned selection between whole analyses rather than
  between fine-grained operations under one budget.

## Simple baselines versus graph neural networks

- General graph-learning studies report structure-agnostic or simple heuristic baselines tying or
  beating GNNs under controlled protocols, for example "Graph as a feature: improving node
  classification with non-neural graph-aware logistic regression" (arXiv
  [2411.12330](https://arxiv.org/pdf/2411.12330)) and "On the Power of Heuristics in Temporal Graphs"
  (arXiv [2502.04910](https://arxiv.org/html/2502.04910)); titles and search excerpts only.
  *Relevance:* our A5/D5 result (a logistic regression on deterministic graph-structural features
  beating a small RGCN) matches this pattern. It is not presented here as a general claim.

## Downstream value of recovered types

Searches found that type-recovery work mostly reports type accuracy and treats downstream benefit
qualitatively (for example, decompilation readability case studies). No equal-budget ablation of
recovered types for analysis scheduling was found. This gap is the question Route B was designed to
test; v1-v3 found no incremental value of neural type scores over structure at this scale.
