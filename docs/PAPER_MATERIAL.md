# SymbAI-Taint — Paper / Talk Material

> Material for a technical talk and as a paper skeleton, plus an anticipated technical Q&A.
> **Tone: honest, defensible, no overclaiming.** A technical audience sees through inflation; we trade
> clear analysis assumptions and honest limitations for credibility.
>
> One-line positioning: **a neuro-symbolic (GNN + symbolic execution + LLM) automated taint-analysis
> system for stripped binaries.**

---

## 1. Abstract

Taint analysis for program correctness on stripped binaries is hard because of **missing semantics**: there
are no reliable cues for variable names, types, or function boundaries, so traditional function-name-based
source-sink matching degrades when symbols are gone. We present **SymbAI-Taint**, a 13-stage pipeline that
orchestrates three complementary capabilities: (1) **GNN type recovery** (integrating TYGR/GlowGNN) to
recover pointer/buffer/struct semantics when debug information is absent; (2) **symbolic execution**
(angr/claripy) to produce **mathematically verifiable hard evidence** for suspicious paths (e.g. that a
`strncpy` size is in fact unconstrained, or that a `gets` is an unconditional stack overflow); and (3)
**LLM adjudication** (a reasoning model with chain-of-thought) to make final source-sink decisions on top
of hard evidence and a soft threshold, suppressing false positives. On 6 programs covering buffer
overflow / format string / command injection / UAF / double-free, it reaches P/R/F1 = 100% (27/0/0)
end-to-end; on a **real third-party benchmark (NIST Juliet)** the metrics honestly drop, and the GNN
quantifiably lifts recall — which is the system's distinguishing value over pure heuristics.

---

## 2. Problem & Motivation

- **Why stripped binaries**: real-world targets (firmware, closed-source commercial software, compiled libraries) are
  usually source-less and frequently `strip --strip-all`-ed. Program analysis must work at the binary level.
- **Taint analysis depends on semantics**: source/sink identification traditionally relies on **function
  names** (libc: `gets`/`strcpy`/`system`/`printf`). Dynamic (imported) symbols survive even `--strip-all`
  (dynamic relocation needs them), but **local/custom function names are gone** → a custom unchecked buffer
  operation becomes a nameless `sub_xxxx`, and name matching fails.
- **The value of type semantics**: knowing that "the argument of `sub_4011e9` is a `char*` buffer written
  out of bounds" is what lets us flag it as a sink candidate. **Type recovery** fills this gap.
- **No single technique suffices**: the GNN gives types but no proof that a defect is reproducible; symbolic execution
  gives constraints but suffers path explosion and lacks high-level semantics; the LLM has semantic
  intuition but hallucinates. **Orchestrating all three** is what makes it robust.

## 3. Analysis Assumptions & Scope — honest statement

| Dimension | Assumption / scope |
|---|---|
| Input | x86-64 ELF; the current type-recovery stage needs DWARF (`-g`) to *locate* variables (see §8) |
| Target bugs | buffer overflow, format string, command injection, UAF, double-free (memory-safety + injection) |
| No guarantees | **neither sound nor complete**: heuristics + ML + probabilistic adjudication; the goal is high-quality bug finding, not formal verification |
| Evaluation scale | 6 hand-written programs + a 38-case Juliet pilot — we explicitly do **not** claim this is large-scale validity evidence (§7, §8) |

---

## 4. System Architecture (13-stage pipeline)

```
Source / Binary
 1 Compile&strip   gcc -g → keep -g copy (type recovery) + stripped copy (analysis)
 2 Ground Truth    extract expected bugs from source (scope-aware; evaluation only)
 3 Code lifting    angr → VEX IR
 4 CFG recovery    angr CFGFast
 5 DFG + callgraph data flow + function calls
 6 GNN types       ★ TYGR GlowGNN (official model) → per-variable char*/ptr/array/struct
 7 Type injection  inject type metadata into TypedIR (PIE base-aligned)
 8 Symbolic exec   angr/claripy, path prioritization + heuristic pruning
 9 Taint analysis  ★ scope-aware source-sink + lifecycle state machine (UAF/double-free)
10 Source-sink     path enumeration + reachability filter + .rodata format-string guard
11 LLM adjudicate  ★ reasoning-model CoT over symbolic hard evidence + soft threshold
12 Evaluation      P/R/F1 vs ground truth
13 Reporting       JSON / Markdown
```
★ = the three core "intelligent" components.

## 5. Core Technical Contributions

### 5.1 Engineering the GNN type-recovery integration (neural component)
- Integrates [TYGR](https://github.com/sefcom/TYGR)'s **GlowGNN**: graph message passing over the "glow"
  computation graph derived from angr symbolic execution (nodes = values/ops, edges = VEX operation
  classes), predicting the type at each variable location.
- **Directly uses the official weights** trained on the real TYDA dataset (Gentoo C/C++ binaries),
  yielding rich types (`char*`/`f32*`/`array`/`struct`).
- **Key engineering challenge (defensible point)**: the official model is pinned to angr/pyvex 9.0.7491 +
  PyG 1.7 — both because of whole-object pickle across PyG versions and because the **VEX edge-operation
  vocabulary** must match training (giving `edge_dim = 44`). Solution: reproduce an isolated `tygr-orig`
  environment, called from the main pipeline as a **subprocess** (see VERSION_COMPAT.md).
- **PIE base alignment**: GNN types attach at DWARF `low_pc`; angr uses PIE-rebased addresses; we map via
  `mapped_base` so types attach to the correct named CFG functions.

### 5.2 Symbolic "hard evidence" (formal component)
Assess potential defects using **verifiable evidence** from constraint solving:
- `strncpy(dst, src, n)`: extract `n`'s symbolic constraints and prove `n` is **not bounded by dst's size**
  (the safety illusion is broken).
- `gets(buf)`: construct **unconditional stack-overflow** evidence (no upper bound on input length).
These become **facts** handed to the LLM, preventing it from deciding in a vacuum.

### 5.3 Scope-aware taint + lifecycle state machine
- **Scope awareness** eliminates "phantom ground truth" — a global name-indexed map mislinks same-named
  locals across functions (this once caused an apparent 83% recall). Both source-sink and GT extraction are
  scope-isolated.
- **Lifecycle state machine** models heap objects as `allocated → freed → use` to truly detect **UAF /
  double-free** (not string matching).
- **Conservative guards**: a `printf` whose format string points to a `.rodata` literal is not counted as a
  format-string sink; data-flow paths unreachable from `main` are dropped.

### 5.4 Engineering lessons for LLM adjudication (defensible point)
- Uses a **reasoning model** for chain-of-thought adjudication of source-sink chains.
- **Pitfall**: a reasoning model's hidden tokens count against `max_tokens`; at 1024 the visible JSON is
  truncated to empty → parse fails → every path defaults to 0.5 / accept → silent failure. Fix:
  `max_tokens ≥ 4096` + tolerant parsing + decision field first. This is real "use a reasoning model
  correctly" experience.

## 6. Implementation
- Language/frameworks: Python; angr 9.2 (main) / 9.0.7491 (tygr-orig); PyTorch + PyG; claripy solving.
- Dual environments: `angr-env` (modern, main pipeline) + `tygr-orig` (reproduced, official GNN), bridged
  by subprocess. Reproducible via `output/tygr/build_orig_env.sh`.

## 7. Evaluation — with honest framing

### 7.0 Six hand-written programs
| Program | Bug | P/R/F1 |
|---|---|---|
| vulnerable / buffer_overflow / format_string / command_injection / memory_vuln / taint_flow | overflow / format / cmd-inj / UAF+double-free / complex flows | all 100/100/100 |

- Aggregate TP/FP/FN = **27/0/0**.
- **Honest note ①**: these are a toy benchmark and **cannot** be taken as large-scale validity evidence.
  They verify that the components cooperate correctly, not real-world recall.
- **Honest note ②**: these are only `--strip-debug` (names survive), so the 100% is mostly from name/
  structure heuristics; **the GNN is not necessary for these cases**.

### 7.1 The GNN's irreplaceable value (fully-stripped + detection)
- **Semantic recovery** (`demo_fullstrip.py`): after `strip --strip-all`, names become `sub_xxxx`; the GNN
  still recovers char*/struct/pointer semantics (even `main`'s argc/argv).
- **Detection capability (full closed loop)**: a hand-rolled buffer copy `store_record` that calls no libc
  — pure name/structure heuristics score **P/R/F1 = 0/0/0** (0 sinks, 0 paths); with GNN type-driven
  detection it finds the sink, builds the `argv → store_record` path, and reaches **P/R/F1 = 1.0**.

### 7.2 Real benchmark pilot: NIST Juliet (the most important credibility evidence)
38 cases selected from **NIST SARD Juliet C/C++ 1.3** (CWE121/122/134/78, matching our target bugs). Using
Juliet's good/bad structure + `OMITGOOD/OMITBAD` macros to compile positive/negative binaries; positives
should be detected, negatives not (see [JULIET_PILOT.md](JULIET_PILOT.md)).

**Four-way ablation** (LLM endpoint: FreeModel `gpt-5.4-mini`; the MiMo endpoint was blocked by 451
cross-border isolation):

| Configuration | Precision | Recall | F1 |
|---|---|---|---|
| ① Standard (name/structure) | 0.794 | 0.711 | 0.750 |
| ② Standard + LLM adjudication | 0.794 | 0.711 | 0.750 (no change) |
| **③ + GNN type-driven** | **0.833** | **0.921** | **0.875** |
| ④ + GNN type-driven + LLM | 0.522 | 0.921 | 0.667 ⬇ |

**Three key conclusions (incl. a negative result)**:
1. **Metrics drop honestly**: from the 6-program 100% to a ~75% baseline on real data — honest, externally
   meaningful (toy 100% does not extrapolate).
2. **The GNN recall gain is real** (③): type-driven detection raises recall **0.711 → 0.921** (+21 pts),
   recovering 8 **CWE121 stack overflows** (buffer index out-of-bounds writes with no libc sink name,
   entirely missed by name/structure heuristics). This quantifies "the GNN is useful."
3. **The LLM precision gain did not materialize in this configuration (negative result)**: in ② the LLM is
   a no-op (filtered 0/7 false positives, killed 0/27 true positives); ④ naive stacking drops precision to
   0.522. **Root cause**: the batch ablation fed the LLM only GNN-type evidence, **without the angr
   symbolic constraints** (the hard evidence that distinguishes "safe" from "potentially invalid" sinks). So it
   proves **"LLM + types-only = no-op," not "LLM is useless."** A full neuro-symbolic + LLM evaluation
   (with symbolic hard evidence) on Juliet is the next step (§8).

## 8. Limitations — proactively exposed
1. **Type recovery currently depends on DWARF to locate variables**: TYGR uses DWARF to find "where the
   variables are," and the GNN predicts "what type they are." On a fully DWARF-less binary, a variable
   recovery pass (angr `VariableRecovery` or similar) must run first — a known next step; currently we use
   a `-g` copy. Honestly: the current demos hold under "a fully-stripped analysis binary + a DWARF-carrying
   type-recovery binary."
2. **LLM value not yet realized (negative result)**: the Juliet ablation shows the LLM (types-only) is a
   no-op, and stacking with type-sinks hurts precision (§7.2). The root cause is the missing angr symbolic
   evidence in batch; feeding it in is the next step.
3. **Precision cost of type-driven sinks**: symmetric application produces many false positives on negatives
   (P = 0.522). A stronger trigger is needed (in-function evidence of an unbounded write with a tainted
   index), not "any char* parameter ⇒ sink."
4. **Scale**: a 38-case Juliet pilot done (baseline F1 = 0.75 → GNN 0.875); still need hundreds of cases +
   real-world defect/fix pairs, more CWEs and flow variants (02–54). Currently only single-file baseline variant `_01`.
5. **LLM latency**: ~30–40 s/path, a throughput bottleneck.
6. **Not sound/complete**: see the analysis assumptions.

## 9. Related Work & Novelty
- **TYGR** (whose type inference we reuse): type inference only, not end-to-end defect analysis. Our
  contribution is **orchestrating it into a neuro-symbolic taint pipeline** and solving its cross-version
  engineering.
- **ORACAL-style multimodal fusion**: architectural inspiration.
- Classic taint (libdft/Triton/angr's own): purely static/dynamic, lacking high-level semantic adjudication.
- **Novelty claim (restrained)**: not a new GNN or solver, but a **systematic method that orchestrates GNN
  type semantics + symbolic hard evidence + LLM adjudication for stripped-binary defect discovery**,
  plus a reproducible engineering implementation.

---

## 10. Anticipated Technical Q&A

> Principle: **admitting limits earns points**. The audience trusts a system that knows its boundaries.

**Q: Is 100% on 6 programs overfitting / meaningless?**
A: Agreed — it only proves the components cooperate correctly (type recovery → injection → symbolic
evidence → adjudication → evaluation, no bugs in the loop). So we **ran a real benchmark pilot**: NIST
Juliet, 38 cases, with metrics honestly dropping to a **baseline F1 = 0.75 (R = 0.71)** — extrapolatable
data. More importantly, **GNN type-driven detection raises recall to 0.92**, recovering 8 CWE121 stack
overflows that libc-name matching entirely misses. We don't avoid the drop; we use it to quantify the GNN's
value (§7.2). Next is scaling to hundreds of cases + real-world defect/fix pairs.

**Q: How much does the GNN actually help on real data?**
A: On the Juliet pilot, **recall +21 pts (0.711 → 0.921), F1 +12.5 pts (0.750 → 0.875)**. The gain comes
entirely from CWE121 stack overflows — buffer index out-of-bounds writes with no libc sink name, scored 0
by name/structure heuristics, where the GNN-recovered char*/array types identify them as buffer sinks.
Honest caveats: 1 `alloca+fgets` case makes TYGR's datagen symbolic execution assert (GNN falls back), and
2 `vprintf` cases are format strings (out of type-sink scope) — known hardening points.

**Q: Does your LLM adjudication actually help on the real benchmark? (ablation)**
A: Honestly — in this configuration it did not deliver a precision gain; **this is a negative result**.
On Juliet, standard+LLM F1 is unchanged (the LLM filtered 0/7 false positives and killed 0/27 true
positives); GNN+type-sink+LLM actually drops precision from 0.833 to 0.522. **But the root cause is an
experimental limitation, not the LLM being inherently useless**: to save time, the batch ablation fed the
LLM **only GNN-type evidence, without the angr symbolic constraints** — and those constraints (whether a
sink is bounded/safe) are exactly what would let the LLM reject the goodB2G "tainted source → safe sink"
false positives. A full neuro-symbolic + LLM evaluation is an explicit next step. We list this negative
result as roadmap item #1 rather than hiding it.

**Q: Real-world binaries have no DWARF; how does your type recovery work?**
A: Honestly, TYGR (and our current integration) uses DWARF to **locate variables**, then the GNN predicts
their types. Without DWARF, a variable-recovery pass (angr VariableRecovery) must first produce variable
locations to feed the GNN. The current demos use a `-g` copy for variable locations; the analysis binary
itself may be fully stripped. Wiring in variable recovery is a clear engineering next step, not a
theoretical barrier — the GNN's features come from the symbolic glow graph and don't depend on symbol names.

**Q: Will the LLM hallucinate defects?**
A: The LLM **does not decide alone** — it adjudicates on top of symbolic hard evidence + path scores and
records its CoT for auditability. But we empirically found the opposite problem: **when evidence is
insufficient, the LLM is biased toward "real"** (see the ablation), so it is more likely to miss "should be
rejected" false positives than to invent bugs. The fix is to give it enough symbolic evidence to "reject,"
rather than relying on its prior.

**Q: Why TYGR instead of Ghidra/IDA type inference?**
A: Ghidra/IDA type recovery is rule/data-flow heuristic; TYGR is a GNN **learned** on large real binaries,
whose generalization to the stripped setting is its selling point. We also keep an interface to swap/compare
models (env-var model switch).

**Q: Why maintain two conda environments? Inelegant.**
A: Because the official model is pinned to angr/pyvex 9.0.7491 + PyG 1.7 — both a cross-version pickle issue
and a **VEX edge-vocabulary** issue (the model's feature dimension is locked). Forcing it into the modern
environment either breaks pickle or mismatches features. Subprocess isolation of the two environments is the
cleanest, most reproducible engineering choice. We also provide a modern-environment self-training fallback
(Acc 0.887).

**Q: Performance / scalability?**
A: The bottleneck is LLM adjudication (~30–40 s/path). Optimizations: only call the LLM for "ambiguous"
paths, batch them, or use a local model. GNN inference is ~10 it/s on CPU; symbolic execution is controlled
by path prioritization + heuristic pruning.

**Q: Soundness / completeness?**
A: Neither is guaranteed. This is a bug-finding system, not a verifier. The design goal is high-quality
discovery + low false positives (via symbolic hard evidence + adjudication), with explicit analysis assumptions.

**Q: Reproducibility?**
A: All versions are pinned (`environment.yml` + `req_rest.txt`), a one-click script builds `tygr-orig`, the
official model lives in TYGR's `model/`. Docs: VERSION_COMPAT / GNN_INTEGRATION.

**Q: How is this different from "wrapping an LLM"?**
A: The LLM is only the 11th-stage adjudicator and depends on **structured formal/learned evidence** produced
by the first 10 stages (VEX, CFG/DFG, GNN types, symbolic constraints). Remove that evidence and the LLM has
nothing to judge on. The core is **evidence generation**, not prompting.

---

## 11. Talk Takeaways (3 sentences)
1. The bottleneck of stripped-binary defect analysis is **missing semantics**; we use **GNN type
   recovery** to restore type semantics even under full stripping (demonstrated).
2. We assess potential defects through explainable, auditable decisions with **symbolic hard evidence + LLM
   adjudication** — though, honestly, the LLM precision gain is not yet realized on real benchmarks (a
   negative result we report openly).
3. We know our boundaries: toy scale, DWARF-locate dependency, LLM not yet delivering — these are clear,
   in-progress next steps, not hidden weaknesses.

---
*Companion docs: [GNN_INTEGRATION.md](GNN_INTEGRATION.md) (integration) · [VERSION_COMPAT.md](VERSION_COMPAT.md)
(environment) · [JULIET_PILOT.md](JULIET_PILOT.md) (benchmark) · [STATUS.md](STATUS.md) (status) ·
[architecture.md](architecture.md) (architecture)*
