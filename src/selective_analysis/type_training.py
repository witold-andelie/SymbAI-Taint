"""Small full-relation type-prediction pilot; independent of the legacy checkpoint."""
from collections import Counter
import hashlib
import json
import math
from pathlib import Path

from .type_corpus import runtime_path, sha


def read(path):
    return json.loads(Path(path).read_bytes())


def safe_file(directory, relative):
    path = (directory / relative).resolve()
    path.relative_to(directory.resolve())
    if not path.is_file():
        raise ValueError("Dataset artifact missing")
    return path


def load_reviewed_dataset(directory):
    """Admit a new pilot run without rewriting historical training-disabled flags."""
    directory = Path(directory).resolve()
    audit_path = directory / "independent-export-audit.json"
    audit, dataset, summary = (read(directory / p) for p in
        ("independent-export-audit.json", "dataset.json", "summary.json"))
    if (audit["schema"] != "symbai.type_graph_export_audit.v1"
            or audit["planned_functions"] != 43 or audit["exported_functions"] != 41
            or audit["admitted_source_variables"] != 181
            or audit["supervised_value_rows"] != 2811
            or audit["evaluation_projects_executed"] or audit["training_performed"]):
        raise ValueError("The reviewed fixed pilot export is required")
    for name, expected in audit["sha256"].items():
        if sha(runtime_path(name)) != expected:
            raise ValueError("Reviewed export evidence changed: " + name)
    if (dataset["schema"] != "symbai.type_graph_dataset.v1"
            or dataset["relation_count"] != 60 or dataset["feature_width"] != 31
            or dataset["evaluation_projects_executed"] or not dataset["labels_separate_from_features"]
            or summary["prepare_only"] or summary["completed_functions"] != 43):
        raise ValueError("Dataset contract differs")
    vocabulary_path = safe_file(directory, dataset["vocabulary"]["path"])
    if sha(vocabulary_path) != dataset["vocabulary"]["sha256"]:
        raise ValueError("Vocabulary changed")
    vocabulary = read(vocabulary_path)
    if len(vocabulary) != 75 or len(set(vocabulary)) != 75:
        raise ValueError("Expected the fixed 75-class vocabulary")
    samples, projects, identities, targets_seen = [], {}, set(), set()
    for item in dataset["samples"]:
        if item["split"] not in ("train", "development"):
            raise ValueError("Evaluation data cannot enter the training pilot")
        if item["function_id"] in identities:
            raise ValueError("Duplicate function sample")
        identities.add(item["function_id"])
        project = item["project_id"]
        if project in projects and projects[project] != item["split"]:
            raise ValueError("Project crosses a split")
        projects[project] = item["split"]
        loaded = {}
        for key in ("features", "supervision"):
            path = safe_file(directory, item[key]["path"])
            if sha(path) != item[key]["sha256"]:
                raise ValueError("Dataset sample changed")
            loaded[key] = read(path)
        validate_sample(loaded["features"], loaded["supervision"], vocabulary)
        for target in loaded["supervision"]["targets"]:
            if target["source_variable_id"] in targets_seen:
                raise ValueError("Source target appears more than once")
            targets_seen.add(target["source_variable_id"])
        samples.append(dict(item, **loaded))
    for split, expected in (("train", (26, 129, 1998)), ("development", (15, 52, 813))):
        selected = [s for s in samples if s["split"] == split]
        actual = (len(selected), sum(len(s["supervision"]["targets"]) for s in selected),
            sum(len(t["readout_rows"]) for s in selected for t in s["supervision"]["targets"]))
        if actual != expected:
            raise ValueError("Reviewed split denominator differs")
    return samples, vocabulary, {"dataset_sha256": sha(directory / "dataset.json"),
        "audit_sha256": sha(audit_path), "reviewed_hashes": len(audit["sha256"]),
        "project_splits": projects, "pilot_training_admitted": True,
        "basis": "Completed passive export review; historical dataset flags are unchanged.",
        "scope": "Pipeline feasibility only; development is not held-out publication evidence."}


def validate_sample(features, supervision, vocabulary):
    if (features["schema"] != "symbai.type_graph_features.v1" or features["feature_width"] != 31
            or features["relation_count"] != 60 or supervision["labels_in_graph_features"]):
        raise ValueError("Feature/target contract differs")
    if {"targets", "class_id", "label", "logits"} & set(features):
        raise ValueError("Gold labels cannot be model inputs")
    n, edges = len(features["x"]), features["edge_index"]
    if not n or any(len(row) != 31 or any(not math.isfinite(v) for v in row) for row in features["x"]):
        raise ValueError("Invalid feature matrix")
    relations = features["edge_type"]
    if (len(edges) != 2 or any(len(row) != len(relations) for row in edges)
            or any(type(v) is not int or not 0 <= v < n for row in edges for v in row)
            or any(type(v) is not int or not 0 <= v < 60 for v in relations)):
        raise ValueError("Invalid edge endpoints or relation IDs")
    readouts = features["readout_nodes"]
    if any(type(v) is not int or not 0 <= v < n for v in readouts):
        raise ValueError("Invalid readout node")
    occupied = set()
    for target in supervision["targets"]:
        rows, cls = target["readout_rows"], target["class_id"]
        if (type(cls) is not int or not 0 <= cls < len(vocabulary) or target["label"] != vocabulary[cls]
                or not rows or len(rows) != len(set(rows)) or set(rows) & occupied
                or any(type(v) is not int or not 0 <= v < len(readouts) for v in rows)
                or not math.isclose(target["per_row_loss_weight"] * len(rows), 1., abs_tol=1e-12)):
            raise ValueError("Invalid variable label, row ownership or unit weight")
        occupied.update(rows)


def summarize_scores(scores, gold, seen_classes):
    """One row per source variable; include unseen development classes in totals."""
    if len(scores) != len(gold) or not gold:
        raise ValueError("A score vector is required for each source variable")
    predictions, top3, losses = [], [], []
    for row, target in zip(scores, gold):
        if (type(target) is not int or not 0 <= target < 75
                or len(row) != 75 or any(not math.isfinite(v) for v in row)):
            raise ValueError("Expected 75 finite raw scores")
        order = sorted(range(75), key=lambda k: (-row[k], k))
        predictions.append(order[0])
        top3.append(target in order[:3])
        maximum = max(row)
        losses.append(maximum + math.log(sum(math.exp(v - maximum) for v in row)) - row[target])
    recalls, f1s = [], []
    for cls in sorted(set(gold)):
        tp = sum(t == cls and p == cls for t, p in zip(gold, predictions))
        fn = sum(t == cls and p != cls for t, p in zip(gold, predictions))
        fp = sum(t != cls and p == cls for t, p in zip(gold, predictions))
        recalls.append(tp / (tp + fn))
        f1s.append(2 * tp / (2 * tp + fp + fn))
    seen = [i for i, cls in enumerate(gold) if cls in seen_classes]
    unseen = [i for i, cls in enumerate(gold) if cls not in seen_classes]
    return {"source_variables": len(gold), "correct_top1": sum(p == t for p, t in zip(predictions, gold)),
        "accuracy": sum(p == t for p, t in zip(predictions, gold)) / len(gold),
        "top3_accuracy": sum(top3) / len(gold), "mean_nll": sum(losses) / len(losses),
        "macro_recall_over_gold_classes": sum(recalls) / len(recalls),
        "macro_f1_over_gold_classes": sum(f1s) / len(f1s),
        "seen_class_variables": len(seen), "seen_class_correct_top1": sum(predictions[i] == gold[i] for i in seen),
        "unseen_class_variables": len(unseen), "unseen_class_correct_top1": sum(predictions[i] == gold[i] for i in unseen)}


def frequency_scores(samples):
    counts = Counter(t["class_id"] for s in samples if s["split"] == "train" for t in s["supervision"]["targets"])
    return [math.log(counts[i] + 1) for i in range(75)], set(counts)


def build_model(hidden=64, layers=2, bases=8, messages=True):
    """New RGCN with an explicit 60-slot capacity; no upstream code or weights."""
    import torch
    from torch import nn
    from torch_geometric.nn import RGCNConv

    class FullRelationPilot(nn.Module):
        def __init__(self):
            super().__init__()
            self.encoder = nn.Linear(31, hidden)
            self.convs = nn.ModuleList([RGCNConv(hidden, hidden, 60, num_bases=bases) for _ in range(layers)])
            self.decoder = nn.Linear(hidden, 75)
            self.messages = messages
            if any(layer.num_relations != 60 for layer in self.convs):
                raise ValueError("Relation capacity differs")

        def forward(self, x, edge_index, edge_type, readout_nodes):
            if (x.ndim != 2 or x.shape[1] != 31 or edge_index.shape != (2, edge_type.numel())
                    or not bool(torch.isfinite(x).all())
                    or (edge_type.numel() and (int(edge_type.min()) < 0 or int(edge_type.max()) >= 60))
                    or (edge_index.numel() and (int(edge_index.min()) < 0 or int(edge_index.max()) >= x.shape[0]))
                    or (readout_nodes.numel() and (int(readout_nodes.min()) < 0 or int(readout_nodes.max()) >= x.shape[0]))):
                raise ValueError("Neural input contract differs")
            if not self.messages:
                edge_index, edge_type = edge_index[:, :0], edge_type[:0]
            x = torch.relu(self.encoder(x))
            for layer in self.convs:
                x = torch.relu(layer(x, edge_index, edge_type))
            return self.decoder(x[readout_nodes])

    return FullRelationPilot()


def tensor_batch(samples):
    """Disjoint union of functions. Labels stay outside the four model arguments."""
    import torch
    x, edges, relations, readouts, groups, targets = [], [[], []], [], [], [], []
    node_offset, row_offset = 0, 0
    for sample in samples:
        f = sample["features"]
        x.extend(f["x"])
        for i in (0, 1):
            edges[i].extend(v + node_offset for v in f["edge_index"][i])
        relations.extend(f["edge_type"])
        readouts.extend(v + node_offset for v in f["readout_nodes"])
        for target in sample["supervision"]["targets"]:
            groups.append([v + row_offset for v in target["readout_rows"]])
            targets.append(dict(target, function_id=sample["function_id"], project_id=sample["project_id"]))
        node_offset += len(f["x"])
        row_offset += len(f["readout_nodes"])
    arguments = (torch.tensor(x, dtype=torch.float32), torch.tensor(edges, dtype=torch.long),
        torch.tensor(relations, dtype=torch.long), torch.tensor(readouts, dtype=torch.long))
    # This pooling map contains correspondence only, not class labels.
    group_rows = torch.tensor([v for g in groups for v in g], dtype=torch.long)
    group_ids = torch.tensor([i for i, g in enumerate(groups) for _ in g], dtype=torch.long)
    counts = torch.tensor([len(g) for g in groups], dtype=torch.float32).unsqueeze(1)
    labels = torch.tensor([t["class_id"] for t in targets], dtype=torch.long)
    return {"arguments": arguments, "group_rows": group_rows, "group_ids": group_ids,
        "counts": counts, "labels": labels, "targets": targets}


def pool_variables(row_logits, batch):
    import torch
    pooled = torch.zeros((len(batch["targets"]), 75), dtype=row_logits.dtype, device=row_logits.device)
    pooled.index_add_(0, batch["group_ids"], row_logits[batch["group_rows"]])
    return pooled / batch["counts"]


def state_digest(model):
    result = hashlib.sha256()
    for name, tensor in sorted(model.state_dict().items()):
        result.update(name.encode("utf-8"))
        result.update(tensor.detach().cpu().contiguous().numpy().tobytes())
    return result.hexdigest()
