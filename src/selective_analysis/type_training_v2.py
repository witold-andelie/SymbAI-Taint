"""Frozen type-pilot v2 admission, structural features and decision arithmetic.

This module deliberately has no import-time dependency on torch.
"""
from collections import defaultdict
import math
from pathlib import Path, PureWindowsPath

from .type_corpus import sha
from .type_training import (load_reviewed_dataset, read, safe_file,
                            summarize_scores, validate_sample)


ROOT = Path(__file__).resolve().parents[2]
PREREGISTRATION = Path("benchmarks/selective_analysis/route_b/type_pilot_v2_preregistration.md")
PREREGISTRATION_SHA256 = "945832e331c1c90cb345d3476cf174b46def6140b3b4694ac4635521b3ff3fdf"
V1_DATASET = ROOT.parent / ".scratch/selective_analysis/route-b-type-graphs-20261119T225215150614Z"
WIDTHS = ("1", "8", "16", "32", "64", "128", "256", "unaligned")
ACCESS_WIDTHS = ("8", "16", "32", "64")
SEEDS = (17, 29, 43)
OUTCOMES = {
    "R1 and R2": "Design the fixed-query Route B scheduling comparison using A3 scores. "
                 "The type-blind arm must have access to A5 features.",
    "R1 without R2": "The deeper GNN mostly restates structure. Report that neural type scores "
                     "show no incremental information here. Neither a scheduling claim nor Variant E follows.",
    "No R1": "Stop representation iteration on this corpus. The next step is a separately "
             "pre-registered training-coverage expansion.",
}


def relative_artifact(directory, name):
    if (not isinstance(name, str) or Path(name).is_absolute()
            or PureWindowsPath(name).drive):
        raise ValueError("Dataset artifacts must have relative paths")
    return safe_file(directory, name)


def load_dev_extension(directory, expected_preregistration_sha256, training_directory=None):
    """Return v1-shaped samples after checking the entire development contract.

    The optional training directory binds --training-dataset to the overlap and
    vocabulary checks; the two-argument API uses the frozen reviewed v1 export.
    """
    directory = Path(directory).resolve()
    training_directory = Path(training_directory or V1_DATASET).resolve()
    previous, vocabulary, _ = load_reviewed_dataset(training_directory)
    previous_ids = {t["source_variable_id"] for s in previous for t in s["supervision"]["targets"]}
    dataset = read(directory / "dataset.json")
    audit = read(directory / "independent-export-audit.json")
    if (dataset["schema"] != "symbai.type_dev_graph_dataset.v1"
            or dataset["preregistration_sha256"] != expected_preregistration_sha256
            or dataset["relation_count"] != 60 or dataset["feature_width"] != 31
            or dataset["labels_separate_from_features"] is not True
            or dataset["evaluation_projects_executed"] is not False):
        raise ValueError("Development dataset contract differs")
    selection_hash = dataset["selection_sha256"]
    if (not isinstance(selection_hash, str) or len(selection_hash) != 64
            or any(c not in "0123456789abcdef" for c in selection_hash)):
        raise ValueError("Invalid selection SHA-256")
    if (audit["schema"] != "symbai.type_dev_graph_export_audit.v1"
            or audit["evaluation_projects_executed"] is not False
            or audit["training_performed"] is not False):
        raise ValueError("Development audit contract differs")
    for name, expected in audit["sha256"].items():
        if sha(relative_artifact(directory, name)) != expected:
            raise ValueError("Development audit artifact changed: " + name)
    reference = read(training_directory / "dataset.json")["vocabulary"]["sha256"]
    entry = dataset["vocabulary"]
    if entry["sha256"] != reference or sha(relative_artifact(directory, entry["path"])) != reference:
        raise ValueError("Development vocabulary differs from v1 bytes")
    samples, functions, targets_seen = [], set(), set()
    for item in dataset["samples"]:
        if item["split"] != "development":
            raise ValueError("Only development samples are admitted")
        if item["project_id"] in {"inih", "rxi_map", "jsmn", "optparse", "utf8_h", "b64"}:
            raise ValueError("Excluded development project")
        if item["function_id"] in functions:
            raise ValueError("Duplicate function sample")
        functions.add(item["function_id"])
        loaded = {}
        for key in ("features", "supervision"):
            path = relative_artifact(directory, item[key]["path"])
            if sha(path) != item[key]["sha256"]:
                raise ValueError("Development sample changed")
            loaded[key] = read(path)
        if loaded["supervision"]["schema"] != "symbai.type_graph_supervision.v1":
            raise ValueError("Development supervision schema differs")
        validate_sample(loaded["features"], loaded["supervision"], vocabulary)
        for target in loaded["supervision"]["targets"]:
            identity = target["source_variable_id"]
            if identity in targets_seen or identity in previous_ids:
                raise ValueError("Duplicate or v1-overlapping source variable")
            targets_seen.add(identity)
        samples.append(dict(item, **loaded))
    count = len(targets_seen)
    rows = sum(len(t["readout_rows"]) for s in samples for t in s["supervision"]["targets"])
    if (not count or dataset["admitted_source_variables"] != count
            or audit["admitted_source_variables"] != count
            or dataset["supervised_value_rows"] != rows
            or audit["exported_functions"] != len(samples)):
        raise ValueError("Development audit denominators differ")
    return samples


def width(row):
    hits = [WIDTHS[i] for i in range(8) if row[5 + i]]
    if len(hits) != 1:
        raise ValueError("A5 requires exactly one width flag per node")
    return hits[0]


def structural_readout_features(features):
    """48 features per readout, using only graph features and edges.

    Layout: eight widths, four five-bucket undirected distances, then four
    five-bucket forward dereference depths. The last bucket is absent within 4.
    """
    x = features["x"]
    widths = [width(row) for row in x]
    forward, undirected, accessed = defaultdict(list), defaultdict(set), {}
    for src, dst, rel in zip(*features["edge_index"], features["edge_type"]):
        undirected[src].add(dst)
        undirected[dst].add(src)
        if rel < 30:
            forward[src].append((dst, rel))
        if rel == 1:
            accessed[dst] = widths[dst]
    result = []
    for node in features["readout_nodes"]:
        distances, depths = {}, {}
        frontier, seen = {node}, {node}
        for depth in range(1, 5):
            frontier = {v for u in frontier for v in undirected[u] if v not in seen}
            seen |= frontier
            for v in frontier:
                if v in accessed:
                    distances.setdefault(accessed[v], depth)
        frontier, seen = {node}, {node}
        for depth in range(1, 5):
            for u in frontier:
                for v, rel in forward[u]:
                    if rel == 1:
                        depths.setdefault(widths[v], depth)
            frontier = {v for u in frontier for v, rel in forward[u] if rel != 1 and v not in seen}
            seen |= frontier
        row = [float(widths[node] == w) for w in WIDTHS]
        for evidence in (distances, depths):
            for w in ACCESS_WIDTHS:
                bucket = evidence.get(w, 5)
                row.extend(float(bucket == d) for d in range(1, 6))
        result.append(row)
    return result


def structural_variables(samples):
    """Return averaged A5 features and targets in tensor_batch variable order."""
    vectors, targets = [], []
    for sample in samples:
        rows = structural_readout_features(sample["features"])
        for target in sample["supervision"]["targets"]:
            group = target["readout_rows"]
            vectors.append([sum(rows[r][i] for r in group) / len(group) for i in range(48)])
            targets.append(dict(target, function_id=sample["function_id"], project_id=sample["project_id"]))
    return vectors, targets


def class_scores(scores, targets, seen_classes, vocabulary):
    gold = [t["class_id"] for t in targets]
    result = summarize_scores(scores, gold, seen_classes)
    predictions = [max(range(75), key=lambda i: (row[i], -i)) for row in scores]
    recalls = {}
    for label in sorted({vocabulary[c] for c in gold} | {"char*", "struct*"}):
        indices = [i for i, t in enumerate(targets) if t["label"] == label]
        correct = sum(predictions[i] == gold[i] for i in indices)
        recalls[label] = {"source_variables": len(indices), "correct_top1": correct,
                          "recall": correct / len(indices) if indices else None}
    result["per_class_recall"] = recalls
    result["unseen_gold_classes"] = [vocabulary[c] for c in sorted(set(gold) - set(seen_classes))]
    result["unseen_gold_class_count"] = len(result["unseen_gold_classes"])
    return result


def detailed_scores(scores, targets, seen_classes, vocabulary):
    result = class_scores(scores, targets, seen_classes, vocabulary)
    result["per_project"] = {}
    for project in sorted({t["project_id"] for t in targets}):
        indices = [i for i, t in enumerate(targets) if t["project_id"] == project]
        result["per_project"][project] = class_scores(
            [scores[i] for i in indices], [targets[i] for i in indices], seen_classes, vocabulary)
    return result


def decision_rules(n, a1, a3, a5):
    """Apply only the pre-registered, all-three-seed primary rules."""
    if type(n) is not int or n <= 0:
        raise ValueError("A positive admitted development denominator is required")
    if set(a1) != set(SEEDS) or set(a3) != set(SEEDS):
        raise ValueError("All three pre-registered seeds are required")
    margin = max(3, (n + 19) // 20)
    for metrics in list(a1.values()) + list(a3.values()) + [a5]:
        if (metrics["source_variables"] != n
                or type(metrics["correct_top1"]) is not int
                or not 0 <= metrics["correct_top1"] <= n
                or not math.isfinite(metrics["mean_nll"]) or metrics["mean_nll"] < 0):
            raise ValueError("Invalid primary metrics or denominator")
    rows = []
    for seed in SEEDS:
        d1 = a3[seed]["correct_top1"] - a1[seed]["correct_top1"]
        d5 = a3[seed]["correct_top1"] - a5["correct_top1"]
        lower = a3[seed]["mean_nll"] < a1[seed]["mean_nll"]
        rows.append({"seed": seed, "A3_minus_A1_correct_top1": d1,
                     "A3_minus_A5_correct_top1": d5,
                     "A3_minus_A1_mean_nll": a3[seed]["mean_nll"] - a1[seed]["mean_nll"],
                     "A3_has_lower_nll_than_A1": lower,
                     "R1": d1 >= margin and lower, "R2": d5 >= margin})
    r1, r2 = all(r["R1"] for r in rows), all(r["R2"] for r in rows)
    outcome = "R1 and R2" if r1 and r2 else ("R1 without R2" if r1 else "No R1")
    return {"schema": "symbai.type_pilot_v2_decision.v1", "N": n, "m": margin,
            "per_seed": rows, "R1": r1, "R2": r2, "outcome": outcome,
            "next_step": OUTCOMES[outcome], "outcome_row": outcome + " | " + OUTCOMES[outcome]}
