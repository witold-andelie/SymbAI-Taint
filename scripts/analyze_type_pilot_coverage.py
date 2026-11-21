#!/usr/bin/env python3
"""Passive coverage/representation analysis of the reviewed type pilot.

Reads the audited graph dataset and one completed training run. It loads no
neural framework, trains nothing and never touches evaluation projects.
Feature layout (TYGR glow preproc, x64): 5 architecture flags, 8 bit-width
flags (1, 8, 16, 32, 64, 128, 256, unaligned) and 18 value properties.
Relations 0..29 are forward reduced operations, 30..59 their inverses.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.selective_analysis.type_corpus import runtime_path, sha
from src.selective_analysis.type_training import load_reviewed_dataset

WIDTHS = ["1", "8", "16", "32", "64", "128", "256", "unaligned"]
FLAGS = ["is_float", "is_bool", "starts_with_f", "many_f_s", "msb", "is_zero", "is_one",
         "is_neg_one", "is_two", "close_to_sp", "is_very_small", "is_small", "is_large",
         "is_arg_reg", "is_reg", "is_artificial_reg", "is_ret_reg", "has_addr"]
OPS = ["mem_data", "mem_loc", "reg_data", "reg_loc", "Concat", "Extract", "__sub__", "__add__",
       "__mul__", "__floordiv__", "SDiv", "__ge__", "SLE", "__lt__", "ULE", "SignExt", "ZeroExt",
       "LShR", "__lshift__", "__rshift__", "If", "Or", "Not", "And", "Xor", "Eq",
       "fp_conv", "fp_op", "fp_cmp", "other"]
RELATIONS = OPS + ["inv_" + o for o in OPS]
MAX_DEPTH = 6


def width(row):
    hits = [WIDTHS[i] for i in range(8) if row[5 + i]]
    return hits[0] if len(hits) == 1 else "invalid"


def signature(row):
    return (width(row),) + tuple(FLAGS[i] for i in range(18) if row[13 + i])


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def fractions(counter):
    total = sum(counter.values())
    return {k: round(v / total, 4) for k, v in sorted(counter.items(), key=lambda kv: -kv[1])} if total else {}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--training-run", type=Path, required=True)
    args = parser.parse_args()
    dataset = runtime_path(args.dataset).resolve()
    run = runtime_path(args.training_run).resolve()
    scratch = (ROOT.parent / ".scratch/selective_analysis").resolve()
    dataset.relative_to(scratch)
    run.relative_to(scratch)
    summary = json.loads((run / "summary.json").read_bytes())
    if summary["status"] != "completed" or summary["admission"]["dataset_sha256"] != sha(dataset / "dataset.json"):
        raise ValueError("A completed run on this exact dataset is required")
    samples, vocabulary, admission = load_reviewed_dataset(dataset)
    names = {v["source_variable_id"]: (r["function_name"], v["name"])
             for r in json.loads((dataset / "records.json").read_bytes())
             for v in r.get("variables", []) if "source_variable_id" in v}

    variables = []
    for s in samples:
        f = s["features"]
        x, nodes = f["x"], f["readout_nodes"]
        incident = defaultdict(Counter)
        neighbour_width = defaultdict(Counter)
        for src, dst, rel in zip(f["edge_index"][0], f["edge_index"][1], f["edge_type"]):
            incident[src][RELATIONS[rel]] += 1
            neighbour_width[src][width(x[dst])] += 1
        forward, undirected, accessed = defaultdict(list), defaultdict(set), {}
        for src, dst, rel in zip(f["edge_index"][0], f["edge_index"][1], f["edge_type"]):
            undirected[src].add(dst)
            if rel < 30:
                forward[src].append((dst, rel))
            if rel == 1:  # src --mem_loc--> dst: dst is a memory access addressed through src
                accessed[dst] = width(x[dst])
        for t in s["supervision"]["targets"]:
            rows = [nodes[r] for r in t["readout_rows"]]
            # Forward data flow (excluding address edges): first hop at which a reached
            # value is used as an address, keyed by the access width.
            frontier, seen, forward_deref = set(rows), set(rows), {}
            for depth in range(1, MAX_DEPTH + 1):
                for u in frontier:
                    for v, rel in forward[u]:
                        if rel == 1:
                            forward_deref.setdefault(width(x[v]), depth)
                frontier = {v for u in frontier for v, rel in forward[u] if rel != 1 and v not in seen}
                seen |= frontier
            # Undirected hop distance (RGCN uses forward and inverse relations) to an access node.
            frontier, seen, undirected_deref = set(rows), set(rows), {}
            for depth in range(1, MAX_DEPTH + 1):
                frontier = {v for u in frontier for v in undirected[u] if v not in seen}
                seen |= frontier
                for v in frontier:
                    if v in accessed:
                        undirected_deref.setdefault(accessed[v], depth)
            w = 1. / len(rows)
            sigs, widths, rels, nwidths = Counter(), Counter(), Counter(), Counter()
            for n in rows:
                sigs[signature(x[n])] += w
                widths[width(x[n])] += w
                for k, v in incident[n].items():
                    rels[k] += w * v
                for k, v in neighbour_width[n].items():
                    nwidths[k] += w * v
            fn, var = names.get(t["source_variable_id"], ("?", "?"))
            variables.append({"id": t["source_variable_id"], "split": s["split"], "project": s["project_id"],
                "function": fn, "name": var, "label": t["label"], "rows": len(rows),
                "distinct_readout_nodes": len(set(rows)), "signatures": sigs, "widths": widths,
                "relations": rels, "neighbour_widths": nwidths,
                "forward_deref_depth": forward_deref, "undirected_deref_distance": undirected_deref})

    # Dereference evidence per class and hop budget.
    def bucket(depth):
        return "none_within_%d" % MAX_DEPTH if depth is None else ("<=2" if depth <= 2 else str(depth))
    dereference = {}
    for v in variables:
        entry = dereference.setdefault(v["label"], {}).setdefault(v["split"], {"variables": 0,
            "forward_any_deref_first_depth": Counter(), "forward_deref_width_first_depth": defaultdict(Counter),
            "undirected_byte_access_distance": Counter(), "undirected_wide_access_distance": Counter()})
        entry["variables"] += 1
        fd = v["forward_deref_depth"]
        entry["forward_any_deref_first_depth"][bucket(min(fd.values()) if fd else None)] += 1
        for w, d in fd.items():
            entry["forward_deref_width_first_depth"][w][str(d)] += 1
        ud = v["undirected_deref_distance"]
        entry["undirected_byte_access_distance"][bucket(ud.get("8"))] += 1
        wide = [ud[w] for w in ("32", "64") if w in ud]
        entry["undirected_wide_access_distance"][bucket(min(wide) if wide else None)] += 1
    dereference = json.loads(json.dumps(dereference))

    # Class coverage.
    coverage = {}
    for split in ("train", "development"):
        coverage[split] = {"by_class": dict(Counter(v["label"] for v in variables if v["split"] == split).most_common()),
            "by_project_class": {p: dict(Counter(v["label"] for v in variables if v["project"] == p).most_common())
                for p in sorted({v["project"] for v in variables if v["split"] == split})}}

    # Readout-node representation per class (row weight sums to one per variable).
    representation = {}
    for split in ("train", "development"):
        for label in sorted({v["label"] for v in variables}):
            chosen = [v for v in variables if v["split"] == split and v["label"] == label]
            if not chosen:
                continue
            total = lambda key: sum((v[key] for v in chosen), Counter())
            representation.setdefault(label, {})[split] = {"variables": len(chosen),
                "mean_rows": round(sum(v["rows"] for v in chosen) / len(chosen), 2),
                "readout_width": fractions(total("widths")),
                "readout_signature_top": [[list(k), round(c / len(chosen), 4)]
                    for k, c in total("signatures").most_common(6)],
                "mean_incident_relations_top": {k: round(c / len(chosen), 3)
                    for k, c in total("relations").most_common(10)},
                "neighbour_width": fractions(total("neighbour_widths"))}

    # Can readout features alone separate classes? Train class mass per signature.
    signature_classes = defaultdict(Counter)
    for v in variables:
        if v["split"] == "train":
            for sig, c in v["signatures"].items():
                signature_classes[sig][v["label"]] += c
    ambiguity = []
    for sig, classes in sorted(signature_classes.items(), key=lambda kv: -sum(kv[1].values())):
        ambiguity.append({"signature": list(sig), "train_variable_mass": round(sum(classes.values()), 3),
            "train_class_fractions": fractions(classes)})
    dev_char = [v for v in variables if v["split"] == "development" and v["label"] == "char*"]
    unseen_mass = sum(c for v in dev_char for sig, c in v["signatures"].items() if sig not in signature_classes)

    # Per-variable predictions for the development set, every run.
    predictions = {}
    for directory in sorted(p for p in run.iterdir() if (p / "predictions.json").is_file()):
        records = json.loads((directory / "predictions.json").read_bytes())["records"]
        predictions[directory.name] = {r["source_variable_id"]: [t["label"] for t in r["top3"]] for r in records}
    development = []
    for v in variables:
        if v["split"] != "development":
            continue
        development.append({"id": v["id"], "function": v["function"], "name": v["name"], "gold": v["label"],
            "rows": v["rows"], "readout_width": dict(v["widths"]),
            "forward_deref_depth": v["forward_deref_depth"], "undirected_deref_distance": v["undirected_deref_distance"],
            "top3": {run_name: p[v["id"]] for run_name, p in predictions.items()}})

    confusion = {}
    for run_name, p in predictions.items():
        pairs = Counter((v["label"], p[v["id"]][0]) for v in variables if v["split"] == "development")
        confusion[run_name] = {g + " -> " + q: c for (g, q), c in sorted(pairs.items(), key=lambda kv: -kv[1])}

    output = scratch / ("route-b-type-coverage-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    output.mkdir()
    snapshot = output / "source_snapshot"
    snapshot.mkdir()
    (snapshot / Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    report = {"schema": "symbai.type_pilot_coverage.v1", "dataset": str(dataset), "training_run": str(run),
        "dataset_sha256": admission["dataset_sha256"], "training_summary_sha256": sha(run / "summary.json"),
        "analysis_script_sha256": sha(Path(__file__)), "neural_framework_loaded": "torch" in sys.modules,
        "evaluation_projects_executed": False, "models_trained": 0,
        "class_coverage": coverage, "representation_by_class": representation,
        "train_signature_class_mass": ambiguity, "dereference_evidence_by_class": dereference,
        "dereference_definition": "Access node = target of a forward mem_loc edge; its width is the access width. "
            "Forward depth follows non-address forward edges from the readout nodes; undirected distance "
            "uses all edges, as the two-layer RGCN does. A two-layer model sees at most distance 2.",
        "development_char_pointer_signature_mass_unseen_in_train": round(unseen_mass, 4),
        "development_confusion_top1": confusion, "development_variables": development,
        "scope": "Descriptive diagnostics on 129 train / 52 development variables; no causal or benchmark claim."}
    write(output / "report.json", report)
    print("Coverage analysis output: " + str(output))
    print(json.dumps({"confusion": confusion, "dev_char_pointer_unseen_signature_mass": round(unseen_mass, 4),
        "dereference": {k: dereference[k] for k in ("char*", "struct*", "i32") if k in dereference}}, indent=1))


if __name__ == "__main__":
    main()
