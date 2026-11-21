#!/usr/bin/env python3
"""Train a fixed small 60-relation pilot and an otherwise identical message ablation."""
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
from src.selective_analysis.type_training import (load_reviewed_dataset, frequency_scores,
    summarize_scores, build_model, tensor_batch, pool_variables, state_digest)


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def runtime_contract(torch):
    """The last relation must actually propagate and receive a gradient."""
    from torch_geometric.nn import RGCNConv
    layer = RGCNConv(2, 2, 60, num_bases=2, bias=False, root_weight=False)
    with torch.no_grad():
        layer.weight.zero_()
        layer.weight[0].copy_(torch.eye(2))
        layer.comp.zero_()
        layer.comp[59, 0] = 1.
    x = torch.tensor([[1., 2.], [3., 4.]])
    edge = torch.tensor([[0], [1]], dtype=torch.long)
    output = layer(x, edge, torch.tensor([59], dtype=torch.long))
    if not torch.equal(output[1], x[0]):
        raise ValueError("Relation 59 did not propagate the controlled message")
    output.sum().backward()
    if not bool(layer.comp.grad[59].abs().sum() > 0):
        raise ValueError("Relation 59 did not receive a gradient")
    model = build_model(hidden=4, layers=1, bases=2)
    features = torch.zeros((2, 31))
    for invalid in (-1, 60):
        try:
            model(features, edge, torch.tensor([invalid]), torch.tensor([1]))
        except ValueError:
            continue
        raise ValueError("Out-of-domain relation was not rejected")
    return {"relation_capacity": 60, "relation_59_message_verified": True,
        "relation_59_gradient_verified": True, "invalid_ids_rejected": [-1, 60]}


def evaluate(torch, model, batches, seen):
    model.eval()
    scores, metrics = {}, {}
    with torch.no_grad():
        for split, batch in batches.items():
            values = pool_variables(model(*batch["arguments"]), batch)
            if not bool(torch.isfinite(values).all()):
                raise ValueError("Nonfinite predicted logits")
            scores[split] = values.cpu().tolist()
            metrics[split] = summarize_scores(scores[split], batch["labels"].tolist(), seen)
    return scores, metrics


def run_model(torch, batches, seen, vocabulary, config, seed, messages, directory, on_step):
    import torch.nn.functional as functional
    directory.mkdir()
    started = time.monotonic()
    torch.manual_seed(seed)
    model = build_model(config["hidden"], config["layers"], config["bases"], messages=messages)
    initial_digest = state_digest(model)
    _, initial_metrics = evaluate(torch, model, batches, seen)
    history = [{"epoch": 0, "metrics": initial_metrics}]
    optimizer = torch.optim.Adam(model.parameters(), lr=config["learning_rate"])
    batch = batches["train"]
    for epoch in range(1, config["epochs"] + 1):
        model.train()
        optimizer.zero_grad()
        logits = pool_variables(model(*batch["arguments"]), batch)
        loss = functional.cross_entropy(logits, batch["labels"])
        if not bool(torch.isfinite(loss)):
            raise ValueError("Training loss is nonfinite")
        loss.backward()
        norm = torch.nn.utils.clip_grad_norm_(model.parameters(), 1.)
        if not bool(torch.isfinite(norm)):
            raise ValueError("Training gradients are nonfinite")
        optimizer.step()
        on_step()
        if epoch == 1 or epoch % 5 == 0 or epoch == config["epochs"]:
            _, metrics = evaluate(torch, model, batches, seen)
            history.append({"epoch": epoch, "gradient_norm_before_clipping": float(norm), "metrics": metrics})
            write(directory / "history.json", history)
            print("seed {} {} epoch {}/{}: train NLL {:.4f}; dev {}/52".format(seed,
                "graph" if messages else "no_messages", epoch, config["epochs"], metrics["train"]["mean_nll"],
                metrics["development"]["correct_top1"]), flush=True)
    scores, metrics = evaluate(torch, model, batches, seen)
    final_digest = state_digest(model)
    if final_digest == initial_digest:
        raise ValueError("Optimization did not change any parameter")
    checkpoint = directory / "checkpoint.pt"
    torch.save({"state_dict": model.state_dict(), "config": config, "seed": seed,
        "messages": messages, "vocabulary": vocabulary}, checkpoint)
    checkpoint_sha = sha(checkpoint)
    # Reload only the checkpoint just created by this process; never upstream weights.
    load_options = {"map_location": "cpu"}
    if "weights_only" in inspect.signature(torch.load).parameters:
        load_options["weights_only"] = True
    restored = torch.load(str(checkpoint), **load_options)
    reloaded = build_model(config["hidden"], config["layers"], config["bases"], messages=messages)
    reloaded.load_state_dict(restored["state_dict"], strict=True)
    reloaded_scores, _ = evaluate(torch, reloaded, batches, seen)
    if scores != reloaded_scores or sha(checkpoint) != checkpoint_sha:
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
    result = {"seed": seed, "mode": "graph" if messages else "no_messages", "metrics": metrics,
        "initial_metrics": initial_metrics, "initial_state_sha256": initial_digest,
        "final_state_sha256": final_digest, "parameter_count": sum(p.numel() for p in model.parameters()),
        "checkpoint_sha256": checkpoint_sha, "checkpoint_reload_reproduces_scores": True,
        "parent_elapsed_seconds": time.monotonic() - started,
        "training_loss_decreased": metrics["train"]["mean_nll"] < initial_metrics["train"]["mean_nll"]}
    write(directory / "metrics.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--smoke-only", action="store_true", help="Two epochs and one seed; not the full pilot")
    args = parser.parse_args()
    dataset_path = runtime_path(args.dataset).resolve()
    scratch = (ROOT.parent / ".scratch/selective_analysis").resolve()
    dataset_path.relative_to(scratch)
    start = time.monotonic()
    samples, vocabulary, admission = load_reviewed_dataset(dataset_path)
    output = scratch / ("route-b-type-training-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    output.mkdir()
    temp, snapshots = output / "temp", output / "source_snapshot"
    temp.mkdir()
    snapshots.mkdir()
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME", "TORCH_HOME", "MPLCONFIGDIR", "NUMBA_CACHE_DIR"):
        os.environ[key] = str(temp)
    os.environ["CUDA_VISIBLE_DEVICES"] = ""
    pins = {}
    for path in (Path(__file__), ROOT / "src/selective_analysis/type_training.py", ROOT / "src/selective_analysis/type_corpus.py"):
        copied = snapshots / path.name
        copied.write_bytes(path.read_bytes())
        pins[str(path)] = pins[str(copied)] = sha(path)
    pins[str(dataset_path / "independent-export-audit.json")] = sha(dataset_path / "independent-export-audit.json")
    config = {"hidden": 64, "layers": 2, "bases": 8, "relations": 60, "classes": 75,
        "epochs": 2 if args.smoke_only else 30, "learning_rate": .003,
        "seeds": [17] if args.smoke_only else [17, 29, 43], "threads": 1,
        "optimizer": "Adam", "gradient_clip": 1., "checkpoint_selection": "fixed_final_epoch",
        "loss": "Mean cross entropy over source variables after averaging their value-row logits.",
        "modes": ["graph", "no_messages"], "device": "cpu"}
    write(output / "plan.json", {"schema": "symbai.type_training_plan.v1", "dataset": str(dataset_path),
        "admission": admission, "configuration": config, "source_pins": pins,
        "evaluation_projects_selected": False, "pretrained_weights_used": False,
        "development_used_for_checkpoint_selection": False})
    print("Type training pilot output: " + str(output), flush=True)
    baseline, seen = frequency_scores(samples)
    baselines = {}
    for split in ("train", "development"):
        gold = [t["class_id"] for s in samples if s["split"] == split for t in s["supervision"]["targets"]]
        baselines[split] = summarize_scores([baseline] * len(gold), gold, seen)
    results = []
    summary = {"schema": "symbai.type_training_summary.v1", "status": "prepared", "prepare_only": args.prepare_only,
        "smoke_only": args.smoke_only, "admission": admission, "configuration": config,
        "frequency_baseline": baselines, "runs": results, "model_training_performed": False,
        "evaluation_projects_executed": False, "neural_scheduling_benefit_measured": False,
        "scope": "Small type-prediction pipeline feasibility; one development project, 52 development variables. Seeds are repetitions, not independent samples."}
    write(output / "summary.json", summary)
    if not args.prepare_only:
        try:
            import torch
            import torch_geometric
            torch.set_num_threads(1)
            torch.set_num_interop_threads(1)
            torch.use_deterministic_algorithms(True)
            summary["runtime"] = {"python": sys.version, "torch": str(torch.__version__),
                "torch_geometric": str(torch_geometric.__version__), "device": "cpu"}
            summary["runtime_contract"] = runtime_contract(torch)
            batches = {split: tensor_batch([s for s in samples if s["split"] == split]) for split in ("train", "development")}

            def record_step():
                if not summary["model_training_performed"]:
                    summary.update(status="running", model_training_performed=True)
                    write(output / "summary.json", summary)

            for seed in config["seeds"]:
                pair = []
                for messages in (True, False):
                    mode = "graph" if messages else "no_messages"
                    result = run_model(torch, batches, seen, vocabulary, config, seed, messages,
                        output / (mode + "-" + str(seed)), record_step)
                    pair.append(result)
                    results.append(result)
                    summary.update(status="running", model_training_performed=True)
                    write(output / "summary.json", summary)
                if pair[0]["initial_state_sha256"] != pair[1]["initial_state_sha256"] or pair[0]["parameter_count"] != pair[1]["parameter_count"]:
                    raise ValueError("Message ablation changed parameter initialization or capacity")
            summary.update(status="completed", paired_development_correct_differences=[
                {"seed": config["seeds"][i // 2], "graph_minus_no_messages": results[i]["metrics"]["development"]["correct_top1"]
                    - results[i + 1]["metrics"]["development"]["correct_top1"]} for i in range(0, len(results), 2)])
        except Exception as error:
            summary.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
            raise
        finally:
            summary["parent_elapsed_seconds"] = time.monotonic() - start
            write(output / "summary.json", summary)
    for path, expected in pins.items():
        if sha(path) != expected:
            raise ValueError("Pinned training source or admission changed")
    # Check all dataset/audit identities again, including training-independent source receipts.
    load_reviewed_dataset(dataset_path)
    summary.update(source_and_data_integrity_unchanged=True, parent_elapsed_seconds=time.monotonic() - start)
    write(output / "summary.json", summary)
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
