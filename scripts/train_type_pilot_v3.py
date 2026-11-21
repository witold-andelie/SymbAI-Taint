#!/usr/bin/env python3
"""Run the frozen type pilot v3 (training-coverage expansion) once, or prepare it without torch.

Phases: (A) DGo reproduction gate at depths 2 and 4; (B) leave-one-project-out depth
selection on training only (seed 17); (C) out-of-fold models for the remaining seeds at the
chosen depth, DG and DN; (D) D0, D5, D5o and DS logistic regressions and the H1-H3 decision.
Every neural fit calls the pinned v1 run_model unchanged. Independent fits run in a spawn
process pool; each process uses one deterministic CPU thread.
"""
import argparse
import gc
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone
import inspect
import json
import multiprocessing
import os
from pathlib import Path
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.selective_analysis.type_corpus import runtime_path, sha
from src.selective_analysis.type_training import frequency_scores, read, state_digest, tensor_batch
from src.selective_analysis.type_training_v2 import detailed_scores, structural_variables
from src.selective_analysis.type_training_v3 import (DEPTHS, PREREGISTRATION, PREREGISTRATION_SHA256, SEEDS,
    assemble, choose_depth, decision_rules, folds, minimum_check, stacked_vectors)
from scripts.train_type_graph_pilot import evaluate as v1_evaluate
from scripts.train_type_graph_pilot import run_model, runtime_contract

NODE_BUDGET = 4000  # nodes per gradient-accumulation chunk (memory only; see run_accumulated)
EQUIVALENCE_TOLERANCE = 1e-3
V1_RUN_DEFAULT = "route-b-type-training-20261120T191335375352Z"
V2_RUN_DEFAULT = "route-b-type-training-v2-20261120T200823775624Z"
_DATA = {}


def write(path, value):
    Path(path).write_bytes((json.dumps(value, indent=2, allow_nan=False, ensure_ascii=True) + "\n").encode("ascii"))


class Stop(ValueError):
    def __init__(self, status, message):
        ValueError.__init__(self, message)
        self.status = status


def pin_tree(directory):
    return {str(p): sha(p) for p in sorted(Path(directory).rglob("*")) if p.is_file()}


def verify_pins(pins):
    for path, expected in pins.items():
        if sha(path) != expected:
            raise ValueError("Pinned source or input changed: " + path)


def seen_classes(samples):
    return {t["class_id"] for s in samples for t in s["supervision"]["targets"]}


# ----------------------------------------------------------------------------- full-batch gradient by accumulation

def chunk_samples(samples, budget=NODE_BUDGET):
    """Deterministic contiguous partition of function graphs into chunks of at most `budget` nodes.

    Function graphs are disjoint components, so every node's representation, every pooled
    variable logit and every loss term depends only on its own function. The full-batch loss
    is therefore exactly the sum of per-chunk sums divided by the total variable count.
    """
    chunks, current, size = [], [], 0
    for sample in samples:
        n = len(sample["features"]["x"])
        if current and size + n > budget:
            chunks.append(current)
            current, size = [], 0
        current.append(sample)
        size += n
    if current:
        chunks.append(current)
    return chunks


def run_accumulated(torch, train, held, seen, vocabulary, config, seed, messages, directory, budget=NODE_BUDGET):
    """The v1 run_model loop with the full-batch gradient accumulated over disjoint chunks.

    Identical seeding, construction, initial evaluation, Adam, one clip and one step per epoch,
    evaluation cadence, fixed final epoch, checkpoint replay and exports. Only the order of
    floating-point summation differs from a single full batch. Needed because the full
    expanded batch exceeds WSL memory (PyG RGCNConv keeps per-relation activations).
    """
    import torch.nn.functional as functional
    from src.selective_analysis.type_training import build_model, pool_variables
    directory.mkdir()
    started = time.monotonic()
    batches = {"train": tensor_batch(train), "development": tensor_batch(held)}
    pieces = [tensor_batch(c) for c in chunk_samples(train, budget)]
    total = sum(len(p["targets"]) for p in pieces)
    if total != len(batches["train"]["targets"]):
        raise ValueError("Chunking lost source variables")
    torch.manual_seed(seed)
    model = build_model(config["hidden"], config["layers"], config["bases"], messages=messages)
    initial_digest = state_digest(model)
    _, initial_metrics = v1_evaluate(torch, model, batches, seen)
    history = [{"epoch": 0, "metrics": initial_metrics}]
    optimizer = torch.optim.Adam(model.parameters(), lr=config["learning_rate"])
    for epoch in range(1, config["epochs"] + 1):
        model.train()
        optimizer.zero_grad()
        loss_value = 0.
        for piece in pieces:
            logits = pool_variables(model(*piece["arguments"]), piece)
            loss = functional.cross_entropy(logits, piece["labels"], reduction="sum") / total
            if not bool(torch.isfinite(loss)):
                raise ValueError("Training loss is nonfinite")
            loss.backward()
            loss_value += float(loss.detach())
        norm = torch.nn.utils.clip_grad_norm_(model.parameters(), 1.)
        if not bool(torch.isfinite(norm)):
            raise ValueError("Training gradients are nonfinite")
        optimizer.step()
        if epoch == 1 or epoch % 5 == 0 or epoch == config["epochs"]:
            _, metrics = v1_evaluate(torch, model, batches, seen)
            history.append({"epoch": epoch, "gradient_norm_before_clipping": float(norm),
                            "accumulated_training_loss": loss_value, "metrics": metrics})
            write(directory / "history.json", history)
    scores, metrics = v1_evaluate(torch, model, batches, seen)
    final_digest = state_digest(model)
    if final_digest == initial_digest:
        raise ValueError("Optimization did not change any parameter")
    checkpoint = directory / "checkpoint.pt"
    torch.save({"state_dict": model.state_dict(), "config": config, "seed": seed,
                "messages": messages, "vocabulary": vocabulary}, checkpoint)
    checkpoint_sha = sha(checkpoint)
    reloaded = build_model(config["hidden"], config["layers"], config["bases"], messages=messages)
    reloaded.load_state_dict(checkpoint_load(torch, checkpoint)["state_dict"], strict=True)
    if v1_evaluate(torch, reloaded, batches, seen)[0] != scores or sha(checkpoint) != checkpoint_sha:
        raise ValueError("Saved checkpoint does not reproduce exported logits")
    exported = []
    for split, values in scores.items():
        for target, row in zip(batches[split]["targets"], values):
            order = sorted(range(75), key=lambda k: (-row[k], k))[:3]
            exported.append({"split": split, "source_variable_id": target["source_variable_id"],
                "function_id": target["function_id"], "project_id": target["project_id"],
                "readout_rows_aggregated": len(target["readout_rows"]), "raw_scores": row,
                "top3": [{"class_id": k, "label": vocabulary[k], "raw_score": row[k]} for k in order]})
    write(directory / "predictions.json", {"schema": "symbai.type_pilot_predictions.v1", "records": exported,
        "score_definition": "Mean raw class logits over the source variable's reviewed value rows.",
        "calibrated_probabilities": False, "gold_labels_supplied_to_model": False,
        "checkpoint_sha256": checkpoint_sha, "checkpoint_reload_reproduces_scores": True})
    return {"seed": seed, "mode": "graph" if messages else "no_messages", "metrics": metrics,
            "initial_metrics": initial_metrics, "initial_state_sha256": initial_digest,
            "final_state_sha256": final_digest, "parameter_count": sum(p.numel() for p in model.parameters()),
            "checkpoint_sha256": checkpoint_sha, "checkpoint_reload_reproduces_scores": True,
            "gradient_accumulation_chunks": len(pieces), "node_budget": budget,
            "parent_elapsed_seconds": time.monotonic() - started,
            "training_loss_decreased": metrics["train"]["mean_nll"] < initial_metrics["train"]["mean_nll"]}


# ----------------------------------------------------------------------------- workers

def _init_worker(paths):
    import torch
    torch.set_num_threads(1)
    torch.set_num_interop_threads(1)
    torch.use_deterministic_algorithms(True)
    _DATA["assembled"] = assemble(*paths)


def _job(spec):
    """Train one neural model with the pinned v1 loop. Returns run_model's result plus metadata."""
    import torch
    original, expanded, development, vocabulary, _ = _DATA["assembled"]
    if spec["train"] == "original":
        train, held = original, development
    elif spec["train"] == "expanded":
        train, held = expanded, development
    else:
        project = spec["train"][1]
        train = [s for s in expanded if s["project_id"] != project]
        held = [s for s in expanded if s["project_id"] == project]
    config = {"hidden": 64, "layers": spec["layers"], "bases": 8, "epochs": spec["epochs"], "learning_rate": .003}
    start = time.monotonic()
    if spec.get("accumulate"):
        result = run_accumulated(torch, train, held, seen_classes(train), vocabulary, config, spec["seed"],
                                 spec["messages"], Path(spec["directory"]), spec.get("budget", NODE_BUDGET))
    else:
        # Exact pinned v1 loop (used for the small original set and the digest gate).
        batches = {"train": tensor_batch(train), "development": tensor_batch(held)}
        result = run_model(torch, batches, seen_classes(train), vocabulary, config, spec["seed"], spec["messages"],
                           Path(spec["directory"]), lambda: None)
    result.update(job=spec["name"], layers=spec["layers"], train_set=spec["train"] if isinstance(spec["train"], str)
                  else "fold_without_" + spec["train"][1], worker_elapsed_seconds=time.monotonic() - start)
    write(Path(spec["directory"]) / "metrics.json", result)
    return result


def run_jobs(specs, paths, jobs):
    if not specs:
        return {}
    context = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(max_workers=min(jobs, len(specs)), mp_context=context,
                             initializer=_init_worker, initargs=(paths,)) as pool:
        results = list(pool.map(_job, specs))
    for spec, result in zip(specs, results):
        print("{}: train NLL {:.4f}; held-out {}/{}".format(spec["name"], result["metrics"]["train"]["mean_nll"],
              result["metrics"]["development"]["correct_top1"], result["metrics"]["development"]["source_variables"]),
              flush=True)
    return {spec["name"]: result for spec, result in zip(specs, results)}


def spec(output, name, train, layers, messages, seed, epochs, accumulate=True, budget=NODE_BUDGET):
    return {"name": name, "train": train, "layers": layers, "messages": messages, "seed": seed,
            "epochs": epochs, "directory": str(output / name), "accumulate": accumulate, "budget": budget}


def max_score_difference(a, b):
    left, right = held_out_scores(a), held_out_scores(b)
    if set(left) != set(right):
        raise ValueError("Equivalence check panels differ")
    return max(abs(x - y) for k in left for x, y in zip(left[k], right[k]))


def held_out_scores(directory):
    """Raw mean logits of the 'development' panel of a run_model directory, keyed by variable id."""
    records = read(Path(directory) / "predictions.json")["records"]
    return {r["source_variable_id"]: r["raw_scores"] for r in records if r["split"] == "development"}


# ----------------------------------------------------------------------------- logistic regressions

def checkpoint_load(torch, checkpoint):
    options = {"map_location": "cpu"}
    if "weights_only" in inspect.signature(torch.load).parameters:
        options["weights_only"] = True
    return torch.load(str(checkpoint), **options)


def fit_logistic(torch, name, width, train_vectors, train_labels, panels, epochs, directory):
    """Zero-initialized multinomial logistic regression with the pre-registered A5 settings."""
    import torch.nn.functional as functional
    directory.mkdir()
    model = torch.nn.Linear(width, 75)
    with torch.no_grad():
        model.weight.zero_()
        model.bias.zero_()
    inputs = {k: torch.tensor(v, dtype=torch.float32) for k, v in panels.items()}
    x = torch.tensor(train_vectors, dtype=torch.float32)
    y = torch.tensor(train_labels, dtype=torch.long)
    optimizer = torch.optim.Adam(model.parameters(), lr=.05, weight_decay=1e-4)
    for _ in range(epochs):
        model.train()
        optimizer.zero_grad()
        loss = functional.cross_entropy(model(x), y)
        if not bool(torch.isfinite(loss)):
            raise ValueError(name + " loss is nonfinite")
        loss.backward()
        optimizer.step()

    def evaluate(current):
        current.eval()
        with torch.no_grad():
            return {k: current(v).cpu().tolist() for k, v in inputs.items()}

    scores = evaluate(model)
    checkpoint = directory / "checkpoint.pt"
    torch.save({"state_dict": model.state_dict(), "feature_width": width, "epochs": epochs}, checkpoint)
    checkpoint_sha = sha(checkpoint)
    reloaded = torch.nn.Linear(width, 75)
    reloaded.load_state_dict(checkpoint_load(torch, checkpoint)["state_dict"], strict=True)
    if evaluate(reloaded) != scores or sha(checkpoint) != checkpoint_sha:
        raise ValueError(name + " checkpoint replay differs")
    return scores, {"final_state_sha256": state_digest(model), "checkpoint_sha256": checkpoint_sha,
                    "checkpoint_reload_reproduces_scores": True, "final_training_loss": float(loss)}


def export(directory, name, scores, targets, vocabulary, seen, extra=None):
    metrics = {k: detailed_scores(v, targets[k], seen, vocabulary) for k, v in scores.items()}
    records = []
    for split, values in scores.items():
        for target, row in zip(targets[split], values):
            order = sorted(range(75), key=lambda c: (-row[c], c))[:3]
            records.append({"split": split, "source_variable_id": target["source_variable_id"],
                "project_id": target["project_id"], "raw_scores": row,
                "top3": [{"class_id": c, "label": vocabulary[c], "raw_score": row[c]} for c in order]})
    write(directory / "predictions.json", {"schema": "symbai.type_pilot_predictions.v1", "records": records,
        "calibrated_probabilities": False, "gold_labels_supplied_to_model": False})
    result = dict(extra or {}, arm=name, metrics=metrics)
    write(directory / "metrics.json", result)
    return result


# ----------------------------------------------------------------------------- main

def reference_digests(v1_run, v2_run):
    refs, pins = {}, {}
    for depth, run, prefix in ((2, v1_run, "graph-"), (4, v2_run, "A3-")):
        summary = read(run / "summary.json")
        if summary["status"] != "completed" or summary.get("smoke_only") or summary.get("prepare_only"):
            raise ValueError("Completed full reference runs are required")
        pins[str(run / "summary.json")] = sha(run / "summary.json")
        for seed in SEEDS:
            path = run / (prefix + str(seed)) / "metrics.json"
            metrics = read(path)
            if metrics["seed"] != seed or metrics.get("mode", "graph") != "graph":
                raise ValueError("Reference seed or mode differs")
            refs[(depth, seed)] = metrics["final_state_sha256"]
            pins[str(path)] = sha(path)
    return refs, pins


def execute(args):
    start = time.monotonic()
    scratch = ROOT.parent / ".scratch/selective_analysis"
    preregistration = ROOT / PREREGISTRATION
    if sha(preregistration) != PREREGISTRATION_SHA256:
        raise ValueError("Frozen v3 pre-registration differs")
    sources = [Path(__file__), ROOT / "src/selective_analysis/type_training_v3.py",
               ROOT / "src/selective_analysis/type_training_v2.py", ROOT / "src/selective_analysis/type_training.py",
               ROOT / "src/selective_analysis/type_corpus.py", ROOT / "scripts/train_type_graph_pilot.py", preregistration]
    paths = tuple(str(runtime_path(p).resolve()) for p in (args.v1_dataset, args.v2_dataset, args.v3_dataset))
    data_pins = {}
    for p in paths:
        data_pins.update(pin_tree(p))
    original, expanded, development, vocabulary, admission = assemble(*paths)
    counts = admission["v3_counts"]
    fold_projects = [p for p, _, _ in folds(expanded)]
    # Release the parent's copy before process pools start (memory only); phase D reloads it.
    del original, expanded, development
    gc.collect()
    refs, ref_pins = reference_digests(runtime_path(args.v1_run).resolve(), runtime_path(args.v2_run).resolve())
    output = scratch / ("route-b-type-training-v3-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    output.mkdir()
    temp, snapshots = output / "temp", output / "source_snapshot"
    temp.mkdir()
    snapshots.mkdir()
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME", "TORCH_HOME", "MPLCONFIGDIR", "NUMBA_CACHE_DIR"):
        os.environ[key] = str(temp)
    os.environ["CUDA_VISIBLE_DEVICES"] = ""
    pins = dict(data_pins, **ref_pins)
    for path in sources:
        (snapshots / path.name).write_bytes(path.read_bytes())
        pins[str(path)] = pins[str(snapshots / path.name)] = sha(path)
    smoke = args.smoke_only
    epochs, lr_epochs = (2, 2) if smoke else (30, 300)
    seeds = [17] if smoke else list(SEEDS)
    config = {"hidden": 64, "bases": 8, "relations": 60, "classes": 75, "epochs": epochs, "learning_rate": .003,
              "gradient_clip": 1., "optimizer": "Adam", "threads_per_process": 1, "processes": args.jobs,
              "seeds": seeds, "depth_candidates": list(DEPTHS), "depth_selection": "leave-one-project-out, seed 17, "
              "pooled held-out Top-1; tie selects 2", "logistic_regression": {"init": "zero", "intercept": True,
              "optimizer": "Adam", "learning_rate": .05, "weight_decay": 1e-4, "epochs": lr_epochs, "full_batch": True},
              "stacking_inputs": "48 A5 features + 75 log-softmax values of G mean logits (out-of-fold on training)"}
    summary = {"schema": "symbai.type_training_summary.v3", "status": "prepared", "prepare_only": args.prepare_only,
               "smoke_only": smoke, "preregistration_sha256": PREREGISTRATION_SHA256, "admission": admission,
               "configuration": config, "evaluation_projects_executed": False,
               "neural_scheduling_benefit_measured": False, "development_used_for_selection": False,
               "decisions_computed": False, "scope": "Pre-registered coverage expansion; seeds are repetitions."}
    write(output / "plan.json", {"schema": "symbai.type_training_plan.v3", "datasets": paths,
        "configuration": config, "source_pins": pins, "reference_digests": {"{}-{}".format(*k): v for k, v in refs.items()},
        "preregistration_sha256": PREREGISTRATION_SHA256})
    write(output / "summary.json", summary)
    print("Type training v3 output: " + str(output), flush=True)
    print("Counts: " + json.dumps(counts), flush=True)
    try:
        failures = minimum_check(counts)
        if failures:
            raise Stop("stopped_minimum", "; ".join(failures))
        if not args.prepare_only:
            import torch
            import torch_geometric
            from src.selective_analysis.type_training import build_model
            summary["runtime"] = {"python": sys.version, "torch": str(torch.__version__),
                                  "torch_geometric": str(torch_geometric.__version__), "device": "cpu"}
            contract = runtime_contract(torch)
            for depth in DEPTHS:
                model = build_model(64, depth, 8)
                if len(model.convs) != depth or any(c.num_relations != 60 for c in model.convs):
                    raise ValueError("Layer or relation capacity differs")
            summary["runtime_contract"] = dict(contract, depths_checked=list(DEPTHS))
            summary["status"] = "running"
            write(output / "summary.json", summary)
            # Phase A: DGo reproduction gate (original 129 variables, both depths).
            gate = [spec(output, "DGo-d{}-s{}".format(d, s), "original", d, True, s, epochs, accumulate=False)
                    for d in DEPTHS for s in seeds]
            # Accumulation equivalence: the same original fits, split into small chunks.
            gate += [spec(output, "EQ-d{}-s17".format(d), "original", d, True, 17, epochs, budget=1500) for d in DEPTHS]
            results = run_jobs(gate, paths, args.jobs)
            equivalence = {}
            for d in DEPTHS:
                eq = results["EQ-d{}-s17".format(d)]
                diff = max_score_difference(output / "DGo-d{}-s17".format(d), output / "EQ-d{}-s17".format(d))
                equivalence[str(d)] = {"max_abs_development_logit_difference": diff,
                                       "chunks": eq["gradient_accumulation_chunks"],
                                       "same_development_top1": eq["metrics"]["development"]["correct_top1"]
                                       == results["DGo-d{}-s17".format(d)]["metrics"]["development"]["correct_top1"]}
                if not diff < EQUIVALENCE_TOLERANCE:
                    summary["accumulation_equivalence"] = equivalence
                    raise Stop("accumulation_not_equivalent", "Chunked training differs from v1 run_model")
            summary["accumulation_equivalence"] = equivalence
            if not smoke:
                mismatches = [{"depth": d, "seed": s, "expected": refs[(d, s)],
                               "actual": results["DGo-d{}-s{}".format(d, s)]["final_state_sha256"]}
                              for d in DEPTHS for s in SEEDS
                              if results["DGo-d{}-s{}".format(d, s)]["final_state_sha256"] != refs[(d, s)]]
                summary["reproduction"] = {"status": "failed" if mismatches else "passed",
                                           "matched_final_digests": 6 - len(mismatches), "mismatches": mismatches}
                if mismatches:
                    raise Stop("reproduction_failed", "DGo digests differ from v1/v2 references")
            # Phase B: depth selection, training only.
            selection = [spec(output, "lopo-d{}-s17-{}".format(d, p), ("fold", p), d, True, 17, epochs)
                         for d in DEPTHS for p in fold_projects]
            results.update(run_jobs(selection, paths, args.jobs))
            pooled = {d: sum(results["lopo-d{}-s17-{}".format(d, p)]["metrics"]["development"]["correct_top1"]
                             for p in fold_projects) for d in DEPTHS}
            depth = choose_depth(pooled)
            summary["depth_selection"] = {"pooled_held_out_correct_top1": {str(d): pooled[d] for d in DEPTHS},
                "held_out_variables": counts["expanded_training"], "chosen_depth": depth,
                "per_fold": {p: {str(d): results["lopo-d{}-s17-{}".format(d, p)]["metrics"]["development"]["correct_top1"]
                                 for d in DEPTHS} for p in fold_projects}}
            write(output / "summary.json", summary)
            print("Chosen depth: {} (pooled {})".format(depth, pooled), flush=True)
            # Phase C: remaining out-of-fold seeds, DG and DN.
            main_specs = [spec(output, "lopo-d{}-s{}-{}".format(depth, s, p), ("fold", p), depth, True, s, epochs)
                          for s in seeds if s != 17 for p in fold_projects]
            main_specs += [spec(output, "DG-s{}".format(s), "expanded", depth, True, s, epochs) for s in seeds]
            main_specs += [spec(output, "DN-s{}".format(s), "expanded", depth, False, s, epochs) for s in seeds]
            results.update(run_jobs(main_specs, paths, args.jobs))
            for s in seeds:
                if (results["DG-s{}".format(s)]["initial_state_sha256"] != results["DN-s{}".format(s)]["initial_state_sha256"]
                        or results["DG-s{}".format(s)]["parameter_count"] != results["DN-s{}".format(s)]["parameter_count"]):
                    raise ValueError("DG/DN initial parameters or capacity differ")
            # Phase D: frequency prior, logistic regressions, stacking, decision.
            original, expanded, development, vocabulary, _ = assemble(*paths)
            dev_vectors, dev_targets = structural_variables(development)
            exp_vectors, exp_targets = structural_variables(expanded)
            org_vectors, org_targets = structural_variables(original)
            seen_exp, seen_org = seen_classes(expanded), seen_classes(original)
            arms = {}
            prior, _ = frequency_scores([dict(s, split="train") for s in expanded])
            d0_dir = output / "D0"
            d0_dir.mkdir()
            arms["D0"] = export(d0_dir, "D0", {"development": [prior] * len(dev_targets)},
                                {"development": dev_targets}, vocabulary, seen_exp)
            for name, vectors, targets, seen in (("D5", exp_vectors, exp_targets, seen_exp),
                                                 ("D5o", org_vectors, org_targets, seen_org)):
                scores, extra = fit_logistic(torch, name, 48, vectors, [t["class_id"] for t in targets],
                                             {"train": vectors, "development": dev_vectors}, lr_epochs, output / name)
                arms[name] = export(output / name, name, scores, {"train": targets, "development": dev_targets},
                                    vocabulary, seen, extra)
            for s in seeds:
                oof = {}
                for p in fold_projects:
                    oof.update(held_out_scores(output / "lopo-d{}-s{}-{}".format(depth, s, p)))
                train_scores = [oof[t["source_variable_id"]] for t in exp_targets]
                dg_dev = held_out_scores(output / "DG-s{}".format(s))
                dev_scores = [dg_dev[t["source_variable_id"]] for t in dev_targets]
                train_x = stacked_vectors(exp_vectors, train_scores)
                dev_x = stacked_vectors(dev_vectors, dev_scores)
                name = "DS-s{}".format(s)
                scores, extra = fit_logistic(torch, name, 123, train_x, [t["class_id"] for t in exp_targets],
                                             {"train": train_x, "development": dev_x}, lr_epochs, output / name)
                arms[name] = export(output / name, name, scores, {"train": exp_targets, "development": dev_targets},
                                    vocabulary, seen_exp, dict(extra, seed=s, depth=depth))
            for prefix, train_set, seen in (("DG", "expanded", seen_exp), ("DN", "expanded", seen_exp),
                                            ("DGo-d{}".format(depth), "original", seen_org)):
                for s in seeds:
                    name = "{}-s{}".format(prefix, s)
                    dev = held_out_scores(output / name)
                    arms[name] = {"arm": name, "train_set": train_set, "seed": s, "depth": depth,
                                  "final_state_sha256": results[name]["final_state_sha256"],
                                  "metrics": {"development": detailed_scores([dev[t["source_variable_id"]] for t in dev_targets],
                                                                             dev_targets, seen, vocabulary)}}
            summary["arms"] = {k: {"development": v["metrics"]["development"]} for k, v in arms.items()}
            summary["seed_range_development_top1"] = {prefix: [arms["{}-s{}".format(prefix, s)]["metrics"]["development"]["correct_top1"]
                for s in seeds] for prefix in ("DG", "DN", "DGo-d{}".format(depth), "DS")}
            summary["lopo_runs"] = {k: {"held_out": v["metrics"]["development"]["correct_top1"],
                                        "held_out_variables": v["metrics"]["development"]["source_variables"]}
                                    for k, v in results.items() if k.startswith("lopo-")}
            if not smoke:
                dev_of = lambda prefix: {s: arms["{}-s{}".format(prefix, s)]["metrics"]["development"] for s in SEEDS}
                summary["decision"] = decision_rules(counts["development"], dev_of("DG"), dev_of("DGo-d{}".format(depth)),
                                                     arms["D5"]["metrics"]["development"], dev_of("DS"))
            summary["status"] = "completed"
    except Stop as stop:
        summary.update(status=stop.status, stop_reason=str(stop))
    except Exception as error:
        summary.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
        raise
    finally:
        try:
            verify_pins(pins)
            current = {}
            for p in paths:
                current.update(pin_tree(p))
            if current != data_pins:
                raise ValueError("Dataset file inventory changed")
            assemble(*paths)
            summary["source_and_data_integrity_unchanged"] = True
        except Exception as error:
            summary.pop("decision", None)
            summary.update(status="failed", source_and_data_integrity_unchanged=False,
                           integrity_error={"type": type(error).__name__, "message": str(error)})
            raise
        finally:
            summary["parent_elapsed_seconds"] = time.monotonic() - start
            write(output / "summary.json", summary)
    if "decision" in summary:
        write(output / "decision.json", summary["decision"])
        summary["decisions_computed"] = True
        write(output / "summary.json", summary)
    print("Type training v3 status: " + summary["status"], flush=True)
    return output


def main(argv=None):
    scratch = ROOT.parent / ".scratch/selective_analysis"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v1-dataset", type=Path, default=scratch / "route-b-type-graphs-20261119T225215150614Z")
    parser.add_argument("--v2-dataset", type=Path, default=scratch / "route-b-type-dev-graphs-20261120T195202135627Z")
    parser.add_argument("--v3-dataset", type=Path, required=True)
    parser.add_argument("--v1-run", type=Path, default=scratch / V1_RUN_DEFAULT)
    parser.add_argument("--v2-run", type=Path, default=scratch / V2_RUN_DEFAULT)
    parser.add_argument("--jobs", type=int, default=3)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--prepare-only", action="store_true")
    mode.add_argument("--smoke-only", action="store_true", help="Seed 17, two epochs, all phases, no decision")
    args = parser.parse_args(argv)
    if not 1 <= args.jobs <= 8:
        parser.error("--jobs must be between 1 and 8")
    execute(args)


if __name__ == "__main__":
    main()
