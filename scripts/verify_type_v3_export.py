"""Independent passive audit of a two-split type pilot v3 graph export.

Copied into the dataset directory and run from there. It imports no project helper,
neural framework or analysis engine, and executes no graph or model. It generalizes
the v1/v2 checks to new training and development exports of variable size.
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
FORBIDDEN_PROJECTS = {"inih", "rxi_map", "jsmn", "optparse", "sds", "tiny_regex_c", "utf8_h", "b64"}
SPLITS = ("train", "development")
PREREGISTRATION_SHA256 = "efb974c46039dfb14219687f6390f1d7b45a6226142141a69d42388716bf9392"


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
assert dataset["schema"] == "symbai.type_v3_graph_dataset.v1" and plan["schema"] == "symbai.type_v3_graph_dataset_plan.v1"
assert summary["schema"] == "symbai.type_v3_graph_dataset_summary.v1"
assert dataset["preregistration_sha256"] == plan["preregistration_sha256"] == PREREGISTRATION_SHA256
assert plan["evaluation_projects_selected"] is False
for path, digest in plan["pins"].items():
    check(local(path), digest)
preregistrations = [p for p in plan["pins"] if p.endswith("/type_pilot_v3_preregistration.md")]
assert preregistrations and all(plan["pins"][p] == PREREGISTRATION_SHA256 for p in preregistrations)
inventory = local(plan["inventory"])
scope_path = inventory / "export-scope.json"
selection_path, manifest_path = inventory.parent / "selection.json", inventory.parent / "manifest.json"
scope, selection, manifest = (read(p) for p in (scope_path, selection_path, manifest_path))
inventory_summary = read(inventory / "summary.json")
for path in (scope_path, selection_path, manifest_path, inventory / "summary.json"):
    assert path.resolve() in {local(p).resolve() for p in plan["pins"]}, "Missing input pin"
assert scope["schema"] == "symbai.type_v3_export_scope.v1"
assert scope["evaluation_projects_selected"] is scope["labels_in_scope"] is False
assert scope["preregistration_sha256"] == selection["preregistration_sha256"] == PREREGISTRATION_SHA256
assert dataset["selection_sha256"] == plan["selection_sha256"] == check(selection_path)
assert manifest["selection_sha256"] == check(selection_path)
assert scope["manifest_sha256"] == check(manifest_path)
assert inventory_summary["schema"] == "symbai.type_v3_inventory.v1"
assert all(type(inventory_summary[k]) is int and inventory_summary[k] >= 0
           for k in ("failed_builds", "inventoried_builds", "planned_builds"))
assert inventory_summary["failed_builds"] == 0
assert inventory_summary["inventoried_builds"] == inventory_summary["planned_builds"]
for container, fields in ((scope, ("candidate_functions", "candidate_source_variable_records")),
                          (dataset, ("exported_functions", "admitted_source_variables", "supervised_value_rows")),
                          (summary, ("planned_functions", "completed_functions", "candidate_source_variables",
                                     "exported_functions", "admitted_source_variables", "supervised_value_rows"))):
    for field in fields:
        assert set(container[field]) == set(SPLITS)
        assert all(type(n) is int and n >= 0 for n in container[field].values())
scope_by_id = {c["function_id"]: c for c in scope["cases"]}
assert len(scope_by_id) == len(scope["cases"])
v1_dataset = [p for p in plan["pins"] if p.endswith("route-b-type-graphs-20261119T225215150614Z/dataset.json")]
assert len(v1_dataset) == 1
vocabulary = read(root / dataset["vocabulary"]["path"])
check(root / dataset["vocabulary"]["path"], dataset["vocabulary"]["sha256"])
assert dataset["vocabulary"]["sha256"] == read(local(v1_dataset[0]))["vocabulary"]["sha256"]
assert len(vocabulary) == len(set(vocabulary)) == 75
assert len(records) == plan["planned_functions"] == sum(summary["planned_functions"].values())
assert sum(r["candidate_source_variables"] for r in records) == plan["candidate_source_variables"]
assert all(r["split"] in SPLITS and r["project_id"] not in FORBIDDEN_PROJECTS for r in records)
assert summary["source_integrity_unchanged"] and not summary["evaluation_projects_executed"]
assert not dataset["evaluation_projects_executed"] and dataset["labels_separate_from_features"]
assert dataset["training_allowed"] is summary["model_loaded"] is summary["training_performed"] is False
assert dataset["relation_count"] == 60 and dataset["feature_width"] == 31
rows_by_id = {r["function_id"]: r for r in records}
assert len(rows_by_id) == len(records)
assert set(rows_by_id) == set(scope_by_id)
counts, project_counts = {s: Counter() for s in SPLITS}, defaultdict(Counter)
candidate_ids, project_splits, record_counts = set(), {}, {s: Counter() for s in SPLITS}
observed_relations, failure_details, source_ids = set(), [], set()
original_inventory = None
for record in records:
    case = scope_by_id[record["function_id"]]
    assert all(case[k] == record[k] for k in ("function_id", "function_name", "project_id", "split"))
    assert case["profile"] == "O0"
    project, split = record["project_id"], record["split"]
    assert project_splits.get(project, split) == split
    project_splits[project] = split
    assert record["status"] in ("exported", "failed", "no_admissible_targets")
    for values in (record_counts[split], project_counts[project]):
        values.update(planned_functions=1, completed_functions=1,
                      candidate_source_variables=record["candidate_source_variables"])
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
    assert source["case"] == case
    assert request["binary_sha256"] == case["binary_sha256"]
    assert request["function_address"] == case["function_address"]
    assert len(source["variables"]) == record["candidate_source_variables"] == len(record["variables"])
    assert len(source["variables"]) == case["source_variable_records"]
    assert sum(v["status"] == "mapped" for v in source["variables"]) == case["mapped_source_variable_records"]
    source_dies = {v["variable_die_offset"] for v in source["variables"]}
    assert len(source_dies) == len(source["variables"])
    assert {v["die_offset"] for v in record["variables"]} == source_dies
    for variable in source["variables"]:
        assert variable["function_id"] == record["function_id"]
    for variable in record["variables"]:
        identity = record["function_id"] + ":" + str(variable["die_offset"])
        assert variable.get("source_variable_id", identity) == identity
        assert identity not in candidate_ids, "Duplicate source-variable id"
        candidate_ids.add(identity)
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
        assert record["admitted_source_variables"] == record["supervised_value_rows"] == 0
        failure_details.append({"function_id": record["function_id"], "function_name": record["function_name"],
                                "project_id": project, "split": split,
                                "status": record["status"], "error": record.get("error"),
                                "worker_error": raw.get("error") if raw else None})

sample_ids = [s["function_id"] for s in dataset["samples"]]
assert len(sample_ids) == len(set(sample_ids)), "Duplicate sample function"
assert set(sample_ids) == {r["function_id"] for r in records if r["status"] == "exported"}
for sample in dataset["samples"]:
    record = rows_by_id[sample["function_id"]]
    assert record["status"] == "exported" and sample["split"] in SPLITS
    assert sample["split"] == record["split"] == scope_by_id[sample["function_id"]]["split"], "Split mismatch"
    assert sample["project_id"] == record["project_id"]
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
    assert admitted
    occupied, shared = set(), defaultdict(set)
    mapping, = raw["stage"]["splices"]
    remap = {int(k): v for k, v in mapping["mapping"].items()}
    graph = mapping["before"]
    nodes = {v["id"]: v for v in graph["nodes"]}
    for target in s["targets"]:
        die = target["die_offset"]
        variable, facts = source_by_die[die], facts_by_die[die]
        assert variable["before_normalization"] != "struct"
        assert type(target["class_id"]) is int and 0 <= target["class_id"] < 75
        assert target["class_id"] == variable["class_id"] and target["label"] == variable["label"] == vocabulary[target["class_id"]]
        assert target["source_variable_id"] == sample["function_id"] + ":" + str(die)
        assert target["source_variable_id"] not in source_ids
        source_ids.add(target["source_variable_id"])
        rows = target["readout_rows"]
        assert rows and len(rows) == len(set(rows)) and not (set(rows) & occupied)
        assert all(type(r) is int and 0 <= r < len(f["readout_nodes"]) for r in rows)
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
    assert all(len(labels) == 1 for labels in shared.values())
    assert len(occupied) == record["supervised_value_rows"]
    counts[sample["split"]].update(exported_functions=1, admitted_source_variables=len(s["targets"]),
                                   supervised_value_rows=len(occupied))
    project_counts[sample["project_id"]].update(exported_functions=1, admitted_source_variables=len(s["targets"]),
                                               supervised_value_rows=len(occupied))

for split in SPLITS:
    for key in ("exported_functions", "admitted_source_variables", "supervised_value_rows"):
        assert counts[split][key] == summary[key][split] == dataset[key][split], "Split count mismatch: " + key
    for key in ("planned_functions", "completed_functions", "candidate_source_variables"):
        assert record_counts[split][key] == summary[key][split], "Split denominator mismatch"
    assert record_counts[split]["planned_functions"] == scope["candidate_functions"][split]
    assert record_counts[split]["candidate_source_variables"] == scope["candidate_source_variable_records"][split]
projects = {s: sorted(p for p in project_splits if project_splits[p] == s) for s in SPLITS}
assert dataset["projects"] == projects
assert set(summary["projects"]) == set(dataset["project_counts"]) == set(project_counts)
keys = ("planned_functions", "completed_functions", "exported_functions", "candidate_source_variables",
        "admitted_source_variables", "supervised_value_rows")
for project, values in project_counts.items():
    expected = summary["projects"][project]
    assert expected == dataset["project_counts"][project]
    assert expected["split"] == project_splits[project]
    assert all(values[key] == expected[key] for key in keys), "Project count mismatch"
assert summary["development_minimum_met"] is (counts["development"]["admitted_source_variables"] >= 150)
assert summary["new_training_admitted"] == counts["train"]["admitted_source_variables"]
assert summary["exclusion_reasons"] == dict(Counter(reason for r in records for v in r["variables"] for reason in v["reasons"]))
assert summary["exclusion_reasons_by_split"] == {split: dict(Counter(reason for r in records if r["split"] == split
    for v in r["variables"] for reason in v["reasons"])) for split in SPLITS}
for name in ("plan.json", "dataset.json", "summary.json", "records.json", "verify_type_v3_export.py"):
    check(root / name)
assert not (set(sys.modules) & {"torch", "angr", "torch_geometric"})
result = {"schema": "symbai.type_v3_graph_export_audit.v1", "planned_functions": len(records),
          **{key: {split: counts[split][key] for split in SPLITS} for key in
             ("exported_functions", "admitted_source_variables", "supervised_value_rows")},
          "candidate_source_variables": scope["candidate_source_variable_records"],
          "projects": projects, "project_counts": summary["projects"],
          "observed_relation_ids": sorted(observed_relations), "failed_or_empty_functions": failure_details,
          "hashes_rechecked": len(internal) + len(external), "frameworks_imported": [],
          "model_or_graph_execution_performed": False, "training_performed": False,
          "evaluation_projects_executed": False,
          "scope": "Passive artifact, graph-location/readout, supervision and count review; not all-path semantic mapping or model-quality evidence. Class histogram deliberately omitted.",
          "sha256": internal, "external_sha256": external}
(root / "independent-export-audit.json").write_bytes((json.dumps(result, indent=2) + "\n").encode("ascii"))
print(json.dumps({k: v for k, v in result.items() if k not in ("sha256", "external_sha256")}, indent=2))
