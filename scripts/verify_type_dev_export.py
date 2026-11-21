"""Independent passive audit of a v2 development-extension graph export.

Copied into the dataset directory and run from there. It imports no project helper,
neural framework or analysis engine, and executes no graph or model. It generalizes
the v1 verify_export.py checks to a development-only export of variable size.
"""
from collections import Counter, defaultdict
import hashlib
import json
import math
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
root = Path(__file__).resolve().parent
internal, external = {}, {}
FORBIDDEN_PROJECTS = {"inih", "rxi_map", "jsmn", "optparse", "utf8_h", "b64"}


def read(path):
    return json.loads(path.read_bytes())


def local(path):
    if os.name == "nt" and path.startswith("/mnt/d/"):
        return Path("D:/" + path[7:])
    if os.name != "nt" and path[:3].lower() in ("d:/", "d:\\"):
        return Path("/mnt/d/" + path[3:].replace("\\", "/"))
    return Path(path)


def check(path, expected=None):
    path = Path(path)
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if expected is not None:
        assert actual == expected, str(path)
    try:
        internal[path.resolve().relative_to(root).as_posix()] = actual
    except ValueError:
        external[str(path)] = actual
    return actual


plan, dataset, summary, records = (read(root / p) for p in ("plan.json", "dataset.json", "summary.json", "records.json"))
assert dataset["schema"] == "symbai.type_dev_graph_dataset.v1" and plan["schema"] == "symbai.type_dev_graph_dataset_plan.v1"
assert dataset["preregistration_sha256"] == plan["preregistration_sha256"]
for path, digest in plan["pins"].items():
    check(local(path), digest)
v1_dataset = [p for p in plan["pins"] if p.endswith("route-b-type-graphs-20261119T225215150614Z/dataset.json")]
assert len(v1_dataset) == 1
vocabulary = read(root / dataset["vocabulary"]["path"])
check(root / dataset["vocabulary"]["path"], dataset["vocabulary"]["sha256"])
assert dataset["vocabulary"]["sha256"] == read(local(v1_dataset[0]))["vocabulary"]["sha256"]
assert len(vocabulary) == len(set(vocabulary)) == 75
assert len(records) == plan["planned_functions"] == summary["planned_functions"]
assert sum(r["candidate_source_variables"] for r in records) == plan["candidate_source_variables"]
assert all(r["split"] == "development" and r["project_id"] not in FORBIDDEN_PROJECTS for r in records)
assert summary["source_integrity_unchanged"] and not summary["evaluation_projects_executed"]
assert not dataset["evaluation_projects_executed"] and dataset["labels_separate_from_features"]
rows_by_id = {r["function_id"]: r for r in records}
assert len(rows_by_id) == len(records)
counts, histogram, project_counts = Counter(), Counter(), defaultdict(Counter)
observed_relations, failure_details, source_ids = set(), [], set()
original_inventory = None
for record in records:
    directory = root / record["directory"]
    check(directory / "offline-source.json")
    check(directory / "request.json")
    request = read(directory / "request.json")
    if original_inventory is None:
        original_inventory = request["source_inventory"]
        for relative, digest in original_inventory.items():
            check(local(request["tygr_root"]) / relative, digest)
    else:
        assert request["source_inventory"] == original_inventory
    assert set(request) == {"schema", "binary", "binary_sha256", "function_address", "tygr_root",
                           "source_inventory", "implementation", "scratch_dir"}
    source = read(directory / "offline-source.json")
    assert source["case"]["function_id"] == record["function_id"]
    assert len(source["variables"]) == record["candidate_source_variables"] == len(record["variables"])
    raw_path = directory / "raw.json"
    raw = None
    if raw_path.is_file():
        check(raw_path)
        raw = read(raw_path)
        assert raw["model_loaded"] is False and raw["model_load_attempts"] == raw["model_forward_attempts"] == 0
        assert raw["binary_sha256"] == request["binary_sha256"]
        assert raw["function_address"] == request["function_address"]
    if record["status"] != "exported":
        assert all(v["status"] == "excluded" for v in record["variables"])
        failure_details.append({"function_id": record["function_id"], "function_name": record["function_name"],
                                "status": record["status"], "error": record.get("error"),
                                "worker_error": raw.get("error") if raw else None})

for sample in dataset["samples"]:
    record = rows_by_id[sample["function_id"]]
    assert record["status"] == "exported" and sample["split"] == "development" == record["split"]
    for key in ("features", "supervision"):
        check(root / sample[key]["path"], sample[key]["sha256"])
    f, s = (read(root / sample[key]["path"]) for key in ("features", "supervision"))
    directory = root / record["directory"]
    source, raw = read(directory / "offline-source.json"), read(directory / "raw.json")
    native = raw["native_input"]
    batch = native["batch"]
    assert raw["status"] == "captured" and raw["original_sources_rechecked"]
    assert not raw["stage"]["step_exceptions"] and not raw["observer_errors"] and not raw["location_errors"]
    assert f["binary_sha256"] == raw["binary_sha256"] and f["function_address"] == raw["function_address"]
    assert f["x"] == batch["node_labels"]["values"] and f["readout_nodes"] == batch["var_gather"]["values"]
    assert f["edge_index"] == batch["edges"]["values"] and f["edge_type"] == batch["edge_labels"]["values"]
    n, m = len(f["x"]), len(f["edge_type"])
    assert native["graph_node_order"] == list(range(n))
    assert f["feature_width"] == 31 and f["relation_count"] == 60
    assert all(len(x) == 31 and x[:5] == [1., 0., 0., 0., 0.] and all(math.isfinite(v) for v in x) for x in f["x"])
    assert len(f["edge_index"]) == 2 and all(len(x) == m for x in f["edge_index"])
    assert all(type(v) is int and 0 <= v < n for row in f["edge_index"] for v in row)
    assert all(type(v) is int and 0 <= v < 60 for v in f["edge_type"])
    observed_relations.update(f["edge_type"])
    assert batch["labels_supplied_to_model"] is False and s["labels_in_graph_features"] is False
    assert not ({"targets", "class_id", "label", "logits"} & set(f))
    source_by_die = {v["variable_die_offset"]: v for v in source["variables"]}
    facts_by_die = {v["die_offset"]: v for v in source["locations"]["facts"]["variables"]}
    admitted = {v["die_offset"] for v in record["variables"] if v["status"] == "admitted"}
    assert {t["die_offset"] for t in s["targets"]} == admitted
    assert len(admitted) == len(s["targets"]) == record["admitted_source_variables"]
    occupied, shared = set(), defaultdict(set)
    mapping, = raw["stage"]["splices"]
    remap = {int(k): v for k, v in mapping["mapping"].items()}
    graph = mapping["before"]
    nodes = {v["id"]: v for v in graph["nodes"]}
    for target in s["targets"]:
        die = target["die_offset"]
        variable, facts = source_by_die[die], facts_by_die[die]
        assert variable["before_normalization"] != "struct"
        assert target["class_id"] == variable["class_id"] and target["label"] == variable["label"] == vocabulary[target["class_id"]]
        assert target["source_variable_id"] == sample["function_id"] + ":" + str(die)
        assert target["source_variable_id"] not in source_ids
        source_ids.add(target["source_variable_id"])
        rows = target["readout_rows"]
        assert rows and len(rows) == len(set(rows)) and not (set(rows) & occupied)
        assert math.isclose(target["per_row_loss_weight"] * len(rows), 1., abs_tol=1e-12)
        occupied.update(rows)
        actual_address = raw["configured_initial_sp"] + 8 + facts["cfa_offset"]
        located = set()
        for edge in graph["edges"]:
            if "mem_loc" not in edge["labels"]:
                continue
            a, b = nodes[edge["source"]], nodes[edge["target"]]
            try:
                address = int(a["value"], 0)
            except (TypeError, ValueError):
                continue
            pc = b["annotation_address"]
            if address == actual_address and isinstance(pc, int) and facts["range"][0] <= pc < facts["range"][1]:
                located.add(b["id"])
        assert located and located.issubset(remap)
        assert {remap[v] for v in located} == {f["readout_nodes"][r] for r in rows}
        lookups = [v for v in raw["lookup_calls"] if v["name"] == variable["name"] and v["prepared_locations"] == [
            {"low_pc": facts["range"][0], "high_pc": facts["range"][1], "form": "addr", "value": actual_address}]]
        assert len(lookups) == 1 and set(lookups[0]["pre_splice_nodes"]) == located
        for r in rows:
            shared[f["readout_nodes"][r]].add(target["class_id"])
        histogram[str(target["class_id"])] += 1
    assert all(len(labels) == 1 for labels in shared.values())
    assert len(occupied) == record["supervised_value_rows"]
    counts.update(functions=1, source_variables=len(s["targets"]), value_rows=len(occupied))
    project_counts[sample["project_id"]].update(functions=1, source_variables=len(s["targets"]), value_rows=len(occupied))

assert counts["functions"] == summary["exported_functions"] == len(dataset["samples"])
assert counts["source_variables"] == summary["admitted_source_variables"] == dataset["admitted_source_variables"]
assert counts["value_rows"] == summary["supervised_value_rows"] == dataset["supervised_value_rows"]
for project, values in project_counts.items():
    expected = summary["projects"][project]
    assert values["functions"] == expected["exported_functions"]
    assert values["source_variables"] == expected["admitted_source_variables"]
for name in ("plan.json", "dataset.json", "summary.json", "records.json", "verify_type_dev_export.py"):
    check(root / name)
assert not (set(sys.modules) & {"torch", "angr", "torch_geometric"})
result = {"schema": "symbai.type_dev_graph_export_audit.v1", "planned_functions": len(records),
          "exported_functions": counts["functions"], "candidate_source_variables": plan["candidate_source_variables"],
          "admitted_source_variables": counts["source_variables"], "supervised_value_rows": counts["value_rows"],
          "projects": {k: dict(v) for k, v in sorted(project_counts.items())},
          "observed_relation_ids": sorted(observed_relations), "failed_or_empty_functions": failure_details,
          "hashes_rechecked": len(internal) + len(external), "frameworks_imported": [],
          "model_or_graph_execution_performed": False, "training_performed": False,
          "evaluation_projects_executed": False,
          "scope": "Passive artifact, graph-location/readout, supervision and count review; not all-path semantic mapping or model-quality evidence. Class histogram deliberately omitted.",
          "sha256": internal, "external_sha256": external}
(root / "independent-export-audit.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print(json.dumps({k: v for k, v in result.items() if k not in ("sha256", "external_sha256")}, indent=2))
