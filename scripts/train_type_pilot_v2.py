#!/usr/bin/env python3
"""Run the frozen A0-A5 type pilot, or prepare its pinned inputs without torch."""
import argparse
from datetime import datetime, timezone
import inspect
import json
import os
from pathlib import Path
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.selective_analysis.type_corpus import runtime_path, sha
from src.selective_analysis.type_training import (build_model, frequency_scores,
    load_reviewed_dataset, pool_variables, read, state_digest, tensor_batch)
from src.selective_analysis.type_training_v2 import (PREREGISTRATION,
    PREREGISTRATION_SHA256, SEEDS, decision_rules, detailed_scores,
    load_dev_extension, structural_variables)
from scripts.train_type_graph_pilot import run_model, runtime_contract


def write(path, value):
    Path(path).write_bytes((json.dumps(value, indent=2, allow_nan=False, ensure_ascii=True) + "\n").encode("ascii"))


class ReproductionFailed(ValueError):
    pass


def checkpoint_load(torch, checkpoint):
    options = {"map_location": "cpu"}
    if "weights_only" in inspect.signature(torch.load).parameters:
        options["weights_only"] = True
    return torch.load(str(checkpoint), **options)


def runtime_contract_layers(torch, layers):
    result = runtime_contract(torch)
    model = build_model(64, layers, 8)
    if len(model.convs) != layers or any(c.num_relations != 60 for c in model.convs):
        raise ValueError("Layer/relation capacity differs")
    features = torch.zeros((2, 31))
    edge = torch.tensor([[0], [1]], dtype=torch.long)
    for invalid in (-1, 60):
        try:
            model(features, edge, torch.tensor([invalid]), torch.tensor([1]))
        except ValueError:
            continue
        raise ValueError("Out-of-domain relation was not rejected")
    result.update(layers=layers, hidden=64, bases=8)
    return result


def prediction_export(directory, scores, panels, vocabulary, checkpoint_sha=None, replay=None):
    records = []
    for split, values in scores.items():
        for target, row in zip(panels[split]["targets"], values):
            order = sorted(range(75), key=lambda k: (-row[k], k))[:3]
            records.append({"split": split, "source_variable_id": target["source_variable_id"],
                "function_id": target["function_id"], "project_id": target["project_id"],
                "readout_rows_aggregated": len(target["readout_rows"]), "raw_scores": row,
                "inspected": split == "optparse",
                "top3": [{"class_id": k, "label": vocabulary[k], "raw_score": row[k]} for k in order]})
    write(directory / "predictions.json", {"schema": "symbai.type_pilot_predictions.v1", "records": records,
        "score_definition": "Raw class logits; neural logits are mean-pooled over reviewed value rows; "
                            "A5 logits use mean-pooled structural features; A0 uses log smoothed counts.",
        "calibrated_probabilities": False, "gold_labels_supplied_to_model": False,
        "checkpoint_sha256": checkpoint_sha, "checkpoint_reload_reproduces_scores": replay,
        "panels": {"development": {"primary": True, "inspected": False},
                   "optparse": {"primary": False, "inspected": True}}})


def panel_metrics(scores, panels, seen, vocabulary):
    result = {}
    for split, values in scores.items():
        result[split] = detailed_scores(values, panels[split]["targets"], seen, vocabulary)
        result[split].update(primary=split == "development", inspected=split == "optparse")
    return result


def neural_scores(torch, model, batches):
    model.eval()
    with torch.no_grad():
        return {split: pool_variables(model(*batch["arguments"]), batch).cpu().tolist()
                for split, batch in batches.items()}


def finish_neural(torch, directory, result, arm, batches, panels, seen, vocabulary):
    """Add primary development only after the A1/A2 reproduction gate passes."""
    checkpoint = directory / "checkpoint.pt"
    checkpoint_sha = sha(checkpoint)
    saved = checkpoint_load(torch, checkpoint)
    config = saved["config"]
    model = build_model(config["hidden"], config["layers"], config["bases"], saved["messages"])
    model.load_state_dict(saved["state_dict"], strict=True)
    scores = neural_scores(torch, model, batches)
    reloaded = build_model(config["hidden"], config["layers"], config["bases"], saved["messages"])
    reloaded.load_state_dict(checkpoint_load(torch, checkpoint)["state_dict"], strict=True)
    if (scores != neural_scores(torch, reloaded, batches) or sha(checkpoint) != checkpoint_sha
            or state_digest(model) != result["final_state_sha256"]):
        raise ValueError("Neural checkpoint replay differs on a v2 panel")
    previous = read(directory / "predictions.json")["records"]
    # v1's 'development' panel was optparse. Retain its exact scores on replay.
    old = {(r["split"], r["source_variable_id"]): r["raw_scores"] for r in previous}
    for split in ("train", "optparse"):
        original_split = "development" if split == "optparse" else split
        for target, row in zip(panels[split]["targets"], scores[split]):
            if row != old[(original_split, target["source_variable_id"])]:
                raise ValueError("v1 scores changed during v2 export")
    result.update(arm=arm, metrics=panel_metrics(scores, panels, seen, vocabulary))
    result["initial_metrics"]["optparse"] = result["initial_metrics"].pop("development")
    result["initial_metrics"]["optparse"].update(inspected=True, primary=False)
    history = read(directory / "history.json")
    for entry in history:
        entry["metrics"]["optparse"] = entry["metrics"].pop("development")
        entry["metrics"]["optparse"].update(inspected=True, primary=False)
    history[-1]["metrics"] = result["metrics"]
    prediction_export(directory, scores, panels, vocabulary, checkpoint_sha, True)
    write(directory / "history.json", history)
    write(directory / "metrics.json", result)
    return result


def run_structural(torch, panels, seen, vocabulary, directory, epochs, on_step):
    import torch.nn.functional as functional
    directory.mkdir()
    # Bias is included: multinomial logistic regression has an intercept.
    model = torch.nn.Linear(48, 75)
    with torch.no_grad():
        model.weight.zero_()
        model.bias.zero_()
    initial = state_digest(model)
    inputs = {split: torch.tensor(panel["vectors"], dtype=torch.float32) for split, panel in panels.items()}
    labels = torch.tensor([t["class_id"] for t in panels["train"]["targets"]], dtype=torch.long)

    def evaluate(current):
        current.eval()
        with torch.no_grad():
            scores = {split: current(values).cpu().tolist() for split, values in inputs.items()}
        return scores, panel_metrics(scores, panels, seen, vocabulary)

    _, initial_metrics = evaluate(model)
    history = [{"epoch": 0, "metrics": initial_metrics}]
    optimizer = torch.optim.Adam(model.parameters(), lr=.05, weight_decay=1e-4)
    for epoch in range(1, epochs + 1):
        model.train()
        optimizer.zero_grad()
        loss = functional.cross_entropy(model(inputs["train"]), labels)
        if not bool(torch.isfinite(loss)):
            raise ValueError("A5 loss is nonfinite")
        loss.backward()
        if any(not bool(torch.isfinite(p.grad).all()) for p in model.parameters()):
            raise ValueError("A5 gradient is nonfinite")
        optimizer.step()
        on_step()
        if epoch == 1 or epoch % 5 == 0 or epoch == epochs:
            _, metrics = evaluate(model)
            history.append({"epoch": epoch, "metrics": metrics})
    scores, metrics = evaluate(model)
    checkpoint = directory / "checkpoint.pt"
    torch.save({"state_dict": model.state_dict(), "feature_width": 48, "classes": 75,
                "epochs": epochs, "vocabulary": vocabulary}, checkpoint)
    checkpoint_sha = sha(checkpoint)
    reloaded = torch.nn.Linear(48, 75)
    reloaded.load_state_dict(checkpoint_load(torch, checkpoint)["state_dict"], strict=True)
    if scores != evaluate(reloaded)[0] or sha(checkpoint) != checkpoint_sha:
        raise ValueError("A5 checkpoint replay differs")
    result = {"arm": "A5", "seed": None, "fitted_once": True, "metrics": metrics,
              "initial_metrics": initial_metrics, "initial_state_sha256": initial,
              "final_state_sha256": state_digest(model), "parameter_count": 49 * 75,
              "checkpoint_sha256": checkpoint_sha, "checkpoint_reload_reproduces_scores": True}
    prediction_export(directory, scores, panels, vocabulary, checkpoint_sha, True)
    write(directory / "history.json", history)
    write(directory / "metrics.json", result)
    return result


def v1_reference(directory, dataset_sha):
    summary = read(directory / "summary.json")
    if (summary["status"] != "completed" or summary["smoke_only"] or summary["prepare_only"]
            or summary["admission"]["dataset_sha256"] != dataset_sha
            or summary["evaluation_projects_executed"] is not False):
        raise ValueError("A completed v1 full run on this training dataset is required")
    references = {}
    pins = {str(directory / "summary.json"): sha(directory / "summary.json")}
    for seed in SEEDS:
        for mode in ("graph", "no_messages"):
            path = directory / (mode + "-" + str(seed)) / "metrics.json"
            result = read(path)
            if result["seed"] != seed or result["mode"] != mode:
                raise ValueError("v1 metric seed or mode differs")
            references[(seed, mode)] = result["final_state_sha256"]
            pins[str(path)] = sha(path)
    return references, pins


def pin_tree(directory):
    return {str(p): sha(p) for p in sorted(directory.rglob("*")) if p.is_file()}


def verify_pins(pins):
    for path, expected in pins.items():
        if sha(path) != expected:
            raise ValueError("Pinned source or input changed: " + path)


def require_reproduction(result, expected, arm, seed, summary):
    if result["final_state_sha256"] != expected:
        summary["reproduction"].update(status="failed", arm=arm, seed=seed,
            expected=expected, actual=result["final_state_sha256"])
        raise ReproductionFailed("v1 final parameter digest mismatch: " + arm + " seed " + str(seed))


def execute(args, scratch=None):
    """scratch injection is for fixture tests; the CLI always uses ROOT.parent."""
    start = time.monotonic()
    preregistration = ROOT / PREREGISTRATION
    if sha(preregistration) != PREREGISTRATION_SHA256:
        raise ValueError("Frozen preregistration SHA-256 differs")
    sources = (Path(__file__), ROOT / "src/selective_analysis/type_training_v2.py",
        ROOT / "src/selective_analysis/type_training.py", ROOT / "src/selective_analysis/type_corpus.py",
        ROOT / "scripts/train_type_graph_pilot.py", preregistration)
    source_hashes = {str(p): sha(p) for p in sources}
    scratch = Path(scratch) if scratch is not None else ROOT.parent / ".scratch/selective_analysis"
    training = runtime_path(args.training_dataset).resolve()
    development = runtime_path(args.dev_dataset).resolve()
    previous = runtime_path(args.v1_run).resolve()
    # Pin before admission so even a concurrent change during loading is detected.
    training_pins, development_pins = pin_tree(training), pin_tree(development)
    dataset_pins = dict(training_pins, **development_pins)
    samples, vocabulary, admission = load_reviewed_dataset(training)
    if any(s["project_id"] != "optparse" for s in samples if s["split"] == "development"):
        raise ValueError("The v1 secondary development panel must be optparse")
    dev_samples = load_dev_extension(development, PREREGISTRATION_SHA256, training)
    references, reference_pins = v1_reference(previous, admission["dataset_sha256"])
    output = scratch / ("route-b-type-training-v2-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    output.mkdir(parents=True)
    temp, snapshots = output / "temp", output / "source_snapshot"
    temp.mkdir()
    snapshots.mkdir()
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME", "TORCH_HOME", "MPLCONFIGDIR", "NUMBA_CACHE_DIR"):
        os.environ[key] = str(temp)
    os.environ["CUDA_VISIBLE_DEVICES"] = ""
    pins = dict(dataset_pins, **reference_pins)
    for path in sources:
        expected = source_hashes[str(path)]
        copied = snapshots / path.name
        copied.write_bytes(path.read_bytes())
        pins[str(path)] = pins[str(copied)] = expected
    verify_pins(pins)
    config = {"hidden": 64, "bases": 8, "relations": 60, "classes": 75,
        "epochs": 2 if args.smoke_only else 30, "learning_rate": .003,
        "seeds": [17] if args.smoke_only else list(SEEDS), "threads": 1,
        "optimizer": "Adam", "gradient_clip": 1., "checkpoint_selection": "fixed_final_epoch",
        "loss": "Mean cross entropy over source variables after averaging their value-row logits.",
        "device": "cpu", "arms": {"A0": "training-only smoothed frequency prior",
            "A1": {"layers": 2, "messages": True}, "A2": {"layers": 2, "messages": False},
            "A3": {"layers": 4, "messages": True}, "A4": {"layers": 4, "messages": False},
            "A5": {"features": 48, "classes": 75, "zero_initialization": True, "intercept": True,
                   "learning_rate": .05, "weight_decay": 1e-4, "optimizer": "Adam",
                   "epochs": 2 if args.smoke_only else 300, "full_batch": True, "fits": 1}}}
    summary = {"schema": "symbai.type_training_summary.v2", "status": "prepared",
        "prepare_only": args.prepare_only, "smoke_only": args.smoke_only,
        "admission": admission, "development_admission": {
            "dataset_sha256": sha(development / "dataset.json"),
            "audit_sha256": sha(development / "independent-export-audit.json"),
            "source_variables": sum(len(s["supervision"]["targets"]) for s in dev_samples)},
        "preregistration_sha256": PREREGISTRATION_SHA256, "configuration": config, "runs": [],
        "model_training_performed": False, "evaluation_projects_executed": False,
        "neural_scheduling_benefit_measured": False,
        "reproduction": {"status": "not_compared_in_smoke" if args.smoke_only else "pending"},
        "decisions_computed": False, "development_used_for_checkpoint_selection": False,
        "panels": {"development": {"primary": True, "inspected": False},
                   "optparse": {"primary": False, "inspected": True}},
        "scope": "Pre-registered representation comparison. Seeds are repetitions, not independent samples."}
    write(output / "plan.json", {"schema": "symbai.type_training_plan.v2", "training_dataset": str(training),
        "dev_dataset": str(development), "v1_run": str(previous), "configuration": config,
        "source_pins": pins, "evaluation_projects_selected": False, "pretrained_weights_used": False,
        "preregistration_sha256": PREREGISTRATION_SHA256, "development_used_for_checkpoint_selection": False})
    write(output / "summary.json", summary)
    print("Type training v2 output: " + str(output), flush=True)
    try:
        if not args.prepare_only:
            import torch
            import torch_geometric
            torch.set_num_threads(1)
            torch.set_num_interop_threads(1)
            torch.use_deterministic_algorithms(True)
            summary["runtime"] = {"python": sys.version, "torch": str(torch.__version__),
                "torch_geometric": str(torch_geometric.__version__), "device": "cpu"}
            summary["runtime_contract"] = {str(n): runtime_contract_layers(torch, n) for n in (2, 4)}
            baseline, seen = frequency_scores(samples)
            selected = {"train": [s for s in samples if s["split"] == "train"],
                "development": dev_samples, "optparse": [s for s in samples if s["split"] == "development"]}
            batches = {split: tensor_batch(items) for split, items in selected.items()}
            # Invoke the pinned v1 implementation unchanged, including its initial
            # evaluation and its literal optparse '/52' progress line.
            reference_batches = {"train": batches["train"], "development": batches["optparse"]}

            def record_step():
                summary.update(status="running", model_training_performed=True)
                write(output / "summary.json", summary)

            references_done = []
            for seed in config["seeds"]:
                pair = []
                for arm, messages in (("A1", True), ("A2", False)):
                    mode = "graph" if messages else "no_messages"
                    directory = output / (arm + "-" + str(seed))
                    result = run_model(torch, reference_batches, seen, vocabulary,
                        dict(config, layers=2), seed, messages, directory, record_step)
                    if not args.smoke_only:
                        require_reproduction(result, references[(seed, mode)], arm, seed, summary)
                    pair.append(result)
                    references_done.append((directory, result, arm))
                if (pair[0]["initial_state_sha256"] != pair[1]["initial_state_sha256"]
                        or pair[0]["parameter_count"] != pair[1]["parameter_count"]):
                    raise ReproductionFailed("A1/A2 initial parameters or capacity differ")
            if not args.smoke_only:
                summary["reproduction"] = {"status": "passed", "matched_final_digests": 6}
            panels = {}
            for split, items in selected.items():
                vectors, targets = structural_variables(items)
                panels[split] = {"vectors": vectors, "targets": targets}
            for directory, result, arm in references_done:
                summary["runs"].append(finish_neural(torch, directory, result, arm, batches, panels, seen, vocabulary))
            directory = output / "A0"
            directory.mkdir()
            prior_scores = {split: [baseline] * len(panel["targets"]) for split, panel in panels.items()}
            prior = {"arm": "A0", "seed": None, "metrics": panel_metrics(prior_scores, panels, seen, vocabulary)}
            prediction_export(directory, prior_scores, panels, vocabulary)
            write(directory / "metrics.json", prior)
            write(directory / "history.json", [{"epoch": 0, "metrics": prior["metrics"]}])
            summary["frequency_baseline"] = prior["metrics"]
            summary["runs"].append(prior)
            for seed in config["seeds"]:
                pair = []
                for arm, messages in (("A3", True), ("A4", False)):
                    directory = output / (arm + "-" + str(seed))
                    result = run_model(torch, reference_batches, seen, vocabulary,
                        dict(config, layers=4), seed, messages, directory, record_step)
                    pair.append(result)
                    summary["runs"].append(finish_neural(torch, directory, result, arm, batches, panels, seen, vocabulary))
                if (pair[0]["initial_state_sha256"] != pair[1]["initial_state_sha256"]
                        or pair[0]["parameter_count"] != pair[1]["parameter_count"]):
                    raise ValueError("A3/A4 initial parameters or capacity differ")
            structural = run_structural(torch, panels, seen, vocabulary, output / "A5",
                config["arms"]["A5"]["epochs"], record_step)
            summary["runs"].append(structural)
            by_arm = {(r["arm"], r["seed"]): r for r in summary["runs"]}
            summary["A4_versus_A2"] = [{"seed": seed, "panels": {
                split: {"correct_top1_difference": by_arm[("A4", seed)]["metrics"][split]["correct_top1"]
                        - by_arm[("A2", seed)]["metrics"][split]["correct_top1"],
                        "mean_nll_difference": by_arm[("A4", seed)]["metrics"][split]["mean_nll"]
                        - by_arm[("A2", seed)]["metrics"][split]["mean_nll"],
                        "top3_accuracy_difference": by_arm[("A4", seed)]["metrics"][split]["top3_accuracy"]
                        - by_arm[("A2", seed)]["metrics"][split]["top3_accuracy"],
                        "inspected": split == "optparse"} for split in panels}} for seed in config["seeds"]]
            if not args.smoke_only:
                primary = lambda arm: {seed: by_arm[(arm, seed)]["metrics"]["development"] for seed in SEEDS}
                summary["decision"] = decision_rules(summary["development_admission"]["source_variables"],
                    primary("A1"), primary("A3"), structural["metrics"]["development"])
                # Decisions are published only after final source/data verification.
            summary["status"] = "completed"
    except Exception as error:
        summary.update(status="reproduction_failed" if isinstance(error, ReproductionFailed) else "failed",
                       error={"type": type(error).__name__, "message": str(error)})
        raise
    finally:
        try:
            verify_pins(pins)
            if pin_tree(training) != training_pins:
                raise ValueError("Training dataset file inventory changed")
            if pin_tree(development) != development_pins:
                raise ValueError("Development dataset file inventory changed")
            load_reviewed_dataset(training)
            load_dev_extension(development, PREREGISTRATION_SHA256, training)
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
    print("Type training v2 status: " + summary["status"], flush=True)
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--training-dataset", type=Path, required=True, help="Reviewed v1 dataset directory")
    parser.add_argument("--dev-dataset", type=Path, required=True, help="Audited new development dataset directory")
    parser.add_argument("--v1-run", type=Path, required=True, help="Completed v1 full run with per-seed metrics")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--prepare-only", action="store_true", help="Validate and snapshot inputs without importing torch")
    mode.add_argument("--smoke-only", action="store_true", help="Every arm, seed 17, two epochs; no reproduction comparison or decisions")
    execute(parser.parse_args(argv))


if __name__ == "__main__":
    main()
