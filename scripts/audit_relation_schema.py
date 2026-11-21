#!/usr/bin/env python3
"""Audit saved relation provenance and an independent synthetic RGCN, not TYGR inference."""
import argparse
import ast
from collections import Counter
from datetime import datetime, timezone
import hashlib
from importlib import metadata
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_bytes())


def write(path, data):
    Path(path).write_text(json.dumps(data, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def relation_table(saved, reduced_ops, reduce_map):
    """Report domains; never infer a historical mapping or manufacture a remapping."""
    config = saved["preproc_config"]
    operations = config["all_ops"]
    if (operations != reduced_ops or len(set(operations)) != len(operations)
            or config["num_all_ops"] != len(operations) + 1
            or config["num_edge_ops"] != 2 * config["num_all_ops"]
            or any(target not in operations for target in reduce_map.values())):
        raise ValueError("Saved/current operation vocabulary differs")
    capacities = [layer["parameter_relation_capacity"] for layer in saved["relation_layers"]]
    if len(capacities) != 8 or any(type(c) is not int or c != 44 for c in capacities):
        raise ValueError("Frozen relation capacities differ")
    rows = [{"operation": label, "direction": direction, "relation_id": index + offset,
             "inside_all_saved_layers": all(index + offset < c for c in capacities)}
            for direction, offset in (("forward", 0), ("inverse", config["num_all_ops"]))
            for index, label in enumerate([*operations, "<unknown>"])]
    return {"relations": rows, "reduction_map": reduce_map, "saved_operations_match_current_source": True,
        "outside_saved_domain_ids": [r["relation_id"] for r in rows if not r["inside_all_saved_layers"]],
        "training_relation_mapping_proven": False, "remapping_proposed": False}


def interpret_toy(rows):
    by_name = {row["name"]: row for row in rows}
    expected = {"empty", "valid_0", "valid_43", "valid_pair", "negative", "id_44", "id_50", "id_55", "id_59", "valid_plus_50", "valid_plus_55"}
    if set(by_name) != expected or len(rows) != len(expected):
        raise ValueError("Synthetic probe denominator differs")
    for name in ("empty", "valid_0", "valid_43", "valid_pair"):
        if by_name[name]["status"] != "returned":
            raise ValueError("Synthetic positive/empty control failed")
    zero = [[0.0, 0.0], [0.0, 0.0]]
    if (by_name["empty"]["output"] != zero or by_name["valid_0"]["output"] == zero
            or by_name["valid_0"]["output"] != by_name["valid_43"]["output"]
            or by_name["valid_pair"]["output"] == by_name["valid_0"]["output"]):
        raise ValueError("Synthetic controls have no discriminating message signal")
    findings = []
    for name in ("negative", "id_44", "id_50", "id_55", "id_59"):
        row = by_name[name]
        kind = "raised" if row["status"] == "raised" else (
            "zero_single_edge_message" if row["output"] == zero else "nonzero_single_edge_message")
        findings.append({"name": name, "behavior": kind})
    mixed = {name: by_name[name]["status"] == "returned" and by_name[name]["output"] == by_name["valid_0"]["output"]
             for name in ("valid_plus_50", "valid_plus_55")}
    return {"positive_controls_passed": True, "single_edge_findings": findings,
        "mixed_output_equals_valid_only": mixed,
        "scope": "Constructed CPU basis-decomposed RGCN only. No trained weights or historical training behavior validated."}


def runtime_worker(request_path, output):
    request = read(request_path)
    if (set(request) != {"schema", "worker_sha256", "scratch_dir", "expected_runtime"}
            or request["schema"] != "symbai.relation_runtime_request.v1"
            or digest(__file__) != request["worker_sha256"]):
        raise ValueError("Synthetic worker identity differs")
    scratch = Path(request["scratch_dir"]).resolve()
    if not sys.platform.startswith("linux") or not str(scratch).startswith("/mnt/d/"):
        raise ValueError("Collect the original-runtime probe in WSL on D")
    scratch.mkdir(parents=True, exist_ok=True)
    for key in ("TEMP", "TMP", "TMPDIR", "TORCH_HOME", "XDG_CACHE_HOME", "MPLCONFIGDIR"):
        os.environ[key] = str(scratch)
    os.environ["CUDA_VISIBLE_DEVICES"] = ""
    result = {"schema": "symbai.relation_runtime_probe.v1", "status": "collecting",
        "checkpoint_loaded": False, "checkpoint_forward_attempts": 0,
        "worker_sha256": digest(__file__), "synthetic_forward_attempts": 0, "probes": []}
    try:
        import torch
        from torch_geometric.nn import RGCNConv
        observed = {"python": list(sys.version_info[:2]), "torch": str(torch.__version__),
                    "torch-geometric": metadata.version("torch-geometric")}
        result["runtime"] = {**observed, **{key: metadata.version(key) for key in ("torch-scatter", "torch-sparse")}}
        if observed != request["expected_runtime"]:
            raise ValueError("The requested original runtime differs")
        source = Path(inspect.getfile(RGCNConv))
        copy = output.parent / "rgcn_conv.py"
        copy.write_bytes(source.read_bytes())
        result["runtime_source"] = {"path": str(source), "sha256": digest(source),
            "retained_copy": str(copy), "copy_sha256": digest(copy)}
        result["constructor_signature"] = str(inspect.signature(RGCNConv.__init__))
        result["forward_source"] = inspect.getsource(RGCNConv.forward)
        result["message_source"] = inspect.getsource(RGCNConv.message)
        torch.manual_seed(0)
        # Match the saved basis-count/capacity branch; use tiny, deliberately non-trained parameters.
        layer = RGCNConv(2, 2, 44, num_bases=10, bias=True)
        layer.eval()
        with torch.no_grad():
            layer.weight.fill_(1.0)
            layer.comp.fill_(0.1)
            layer.root.zero_()
            layer.bias.zero_()
        original = {name: value.detach().clone() for name, value in layer.state_dict().items()}
        result["synthetic_config"] = {"channels": 2, "num_relations": 44, "num_bases": 10,
            "aggregation": layer.aggr, "root_and_bias_zero": True,
            "features": [[1.0, 2.0], [3.0, 4.0]], "all_parameters_artificial": True}
        x = torch.tensor([[1.0, 2.0], [3.0, 4.0]], dtype=torch.float32)
        cases = [("empty", []), ("valid_0", [0]), ("valid_43", [43]), ("valid_pair", [0, 43]),
                 ("negative", [-1]), ("id_44", [44]), ("id_50", [50]), ("id_55", [55]), ("id_59", [59]),
                 ("valid_plus_50", [0, 50]), ("valid_plus_55", [0, 55])]
        for name, ids in cases:
            edges = torch.tensor([[0, 1][:len(ids)], [1, 0][:len(ids)]], dtype=torch.long)
            labels = torch.tensor(ids, dtype=torch.long)
            row = {"name": name, "relation_ids": ids}
            result["synthetic_forward_attempts"] += 1
            try:
                with torch.no_grad():
                    value = layer(x, edges, labels)
                if list(value.shape) != [2, 2] or not bool(torch.isfinite(value).all()):
                    raise ValueError("Synthetic output shape/value differs")
                row.update(status="returned", output=value.tolist())
            except Exception as error:
                row.update(status="raised", error={"type": type(error).__name__, "message": str(error)})
            if labels.tolist() != ids or edges.tolist() != [[0, 1][:len(ids)], [1, 0][:len(ids)]]:
                raise ValueError("Synthetic inputs were mutated")
            result["probes"].append(row)
        if any(not torch.equal(value, original[name]) for name, value in layer.state_dict().items()):
            raise ValueError("Synthetic parameters were mutated")
        result["interpretation"] = interpret_toy(result["probes"])
        result["status"] = "captured"
    except Exception as error:
        result.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
    write(output, result)
    print("Synthetic relation runtime: " + result["status"], flush=True)
    if result["status"] != "captured":
        raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hook-controls", type=Path, required=True)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--tygr-python", type=Path, default=Path("/root/miniconda3/envs/tygr-orig/bin/python"))
    args = parser.parse_args()
    if not args.prepare_only and (not sys.platform.startswith("linux") or not args.tygr_python.is_file()):
        parser.error("Collect with WSL angr-env and existing tygr-orig, or use --prepare-only")
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))
    from scripts import measure_native_pair_baseline as base
    from src.selective_analysis import checkpoint_metadata
    prior = base.within(args.hook_controls, base.SCRATCH)
    summary, plan, audit = (read(prior / name) for name in ("summary.json", "plan.json", "independent-audit.json"))
    if summary["prepare_only"] or summary["reviewed"] != 6 or audit["captures_rechecked"] != 6:
        raise ValueError("The complete independently reviewed intervention is required")
    base.require_pins(plan["pins"])
    for name, expected in audit["sha256"].items():
        if digest(prior / name) != expected:
            raise ValueError("Reviewed intervention evidence changed")
    output = base.SCRATCH / ("route-b-relation-schema-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    output.mkdir()
    temp, copies = output / "temp", output / "source_snapshot"
    temp.mkdir()
    copies.mkdir()
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME", "MPLCONFIGDIR"):
        os.environ[key] = str(temp)
    model = root / "tygr_original/model/MODEL_base/x64.O0.base.model"
    saved = checkpoint_metadata.inspect_frozen_checkpoint(model)
    write(output / "checkpoint-metadata.json", saved)
    source = root / "tygr_original/src/analysis/angr/edge.py"
    definitions = {node.targets[0].id: ast.literal_eval(node.value) for node in ast.parse(source.read_bytes()).body
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)}
    contract = relation_table(saved, definitions["REDUCED_OPS"], definitions["REDUCE_OP_MAP"])
    write(output / "relation-contract.json", contract)
    pins = dict(plan["pins"])
    for name in ("plan.json", "summary.json", "records.json", "independent-audit.json", "verify.py"):
        path = prior / name
        pins[base.linux_path(path)] = digest(path)
    for path in (Path(__file__), Path(checkpoint_metadata.__file__), source,
                 root / "tygr_original/src/methods/glow/model.py", root / "tygr_original/src/methods/glow/preproc.py"):
        copy = copies / path.name
        copy.write_bytes(path.read_bytes())
        pins[base.linux_path(path)] = pins[base.linux_path(copy)] = digest(path)
    panel = []
    for case in plan["cases"]:
        for variant in plan["variants"]:
            raw_path = prior / case / variant / "raw.json"
            raw = read(raw_path)
            native = read(raw_path.with_name("request.json"))["native_request"]
            for relative, expected in native["source_sha256"].items():
                path = base.runtime_path(native["tygr_root"]) / relative
                if digest(path) != expected:
                    raise ValueError("Original TYGR source changed")
                pins[base.linux_path(path)] = expected
            pins[base.linux_path(raw_path)] = digest(raw_path)
            for name in ("binary", "model"):
                path = base.runtime_path(native[name])
                if digest(path) != native[name + "_sha256"]:
                    raise ValueError("Original input/model changed")
                pins[base.linux_path(path)] = digest(path)
            function, = raw["functions"]
            counts = Counter(function["native_input"]["batch"]["edge_labels"]["values"])
            panel.append({"case_id": case, "variant": variant, "prepared_messages": sum(counts.values()),
                "outside_saved_domain_messages": sum(counts[i] for i in counts if i >= 44),
                "outside_saved_domain_histogram": {str(i): counts[i] for i in sorted(counts) if i >= 44},
                "guard_status": function["saved_model_input_guard"]["status"],
                "scope": "Static message-label counts, not observed RGCN omissions."})
    write(output / "observed-relations.json", panel)
    git_env = dict(os.environ, GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0")
    def git(*arguments, data=None):
        result = subprocess.run(["git", "-c", "protocol.allow=never", "-C", str(root / "tygr_original"), *arguments],
            input=data, text=True, capture_output=True, check=True, timeout=20, env=git_env)
        return result.stdout.strip()
    refs = ["HEAD:model/MODEL_base/x64.O" + str(i) + ".base.model" for i in range(4)]
    provenance = {"commit": git("rev-parse", "HEAD"), "shallow": git("rev-parse", "--is-shallow-repository") == "true",
        "tracked_model_paths": git("ls-tree", "-r", "--name-only", "HEAD", "model").splitlines(),
        "local_x64_object_availability": git("cat-file", "--batch-check", data="\n".join(refs) + "\n").splitlines(),
        "network_protocols_disabled": True, "downloads_performed": False,
        "training_mapping_proven": False}
    write(output / "provenance.json", provenance)
    worker = copies / Path(__file__).name
    request = {"schema": "symbai.relation_runtime_request.v1", "worker_sha256": digest(worker),
        "scratch_dir": base.linux_path(temp),
        "expected_runtime": {"python": [3, 8], "torch": "1.8.1+cpu", "torch-geometric": "1.7.0"}}
    write(output / "runtime-request.json", request)
    write(output / "plan.json", {"schema": "symbai.relation_schema_plan.v1", "pins": pins,
        "prior_hook_controls": base.linux_path(prior), "worker": base.linux_path(worker),
        "scope": "Passive frozen metadata and synthetic two-node basis RGCN. No checkpoint loading/forward, altered guard, remapping, training, dataset download or property analysis."})
    print("Relation schema output: " + str(output), flush=True)
    runtime = None
    if not args.prepare_only:
        with (output / "runtime.log").open("w", encoding="utf-8") as stream:
            subprocess.run([str(args.tygr_python), "-B", str(worker), "--runtime-worker",
                str(output / "runtime-request.json"), str(output / "runtime.json")], cwd=output,
                stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=90)
        runtime = read(output / "runtime.json")
        source_receipt = runtime["runtime_source"]
        if (runtime["status"] != "captured" or runtime["worker_sha256"] != request["worker_sha256"]
                or runtime["checkpoint_loaded"] or runtime["checkpoint_forward_attempts"] != 0
                or runtime["synthetic_forward_attempts"] != 11
                or runtime["runtime"]["torch-geometric"] != "1.7.0"
                or digest(output / "rgcn_conv.py") != source_receipt["sha256"]
                or source_receipt["copy_sha256"] != source_receipt["sha256"]
                or runtime["interpretation"] != interpret_toy(runtime["probes"])):
            raise ValueError("Original-runtime synthetic receipt differs")
    base.require_pins(pins)
    result = {"schema": "symbai.relation_schema_summary.v1", "prepare_only": args.prepare_only,
        "declared_relation_count": saved["preproc_config"]["num_edge_ops"],
        "saved_layer_capacities": [r["parameter_relation_capacity"] for r in saved["relation_layers"]],
        "outside_saved_domain_ids": contract["outside_saved_domain_ids"],
        "observed_panel": panel, "runtime_interpretation": None if runtime is None else runtime["interpretation"],
        "checkpoint_forward_attempts": 0, "training_mapping_proven": False,
        "guard_changed": False, "downloads_performed": False, "output": str(output)}
    write(output / "summary.json", result)
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--runtime-worker":
        runtime_worker(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        main()
