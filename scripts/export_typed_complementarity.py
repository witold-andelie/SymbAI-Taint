#!/usr/bin/env python3
"""Python 3.8 standalone native acquisition with a pre-forward saved-domain guard."""

import argparse
import hashlib
import importlib.util
from importlib import metadata
import inspect
import json
import math
import os
from pathlib import Path
import sys
import time

MODEL_HASH = "f592caaa6c685f291f576b16fbf8b752a95e7cb757ea620751830563b77f67c8"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + ".partial")
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False), encoding="utf-8")
    os.replace(str(temporary), str(path))


def validate_request(request):
    fields = {"schema", "binary", "binary_sha256", "model", "model_sha256", "tygr_root", "source_sha256",
              "helpers", "scratch_dir", "worker_sha256"}
    if (not isinstance(request, dict) or set(request) != fields
            or request["schema"] != "symbai.typed_acquisition_request.v1"
            or request["model_sha256"] != MODEL_HASH or sha(request["model"]) != MODEL_HASH
            or sha(request["binary"]) != request["binary_sha256"] or sha(__file__) != request["worker_sha256"]):
        raise ValueError("Strict native acquisition identity differs; query/gold/type fields are forbidden")
    root = Path(request["tygr_root"])
    inventory = {path.relative_to(root).as_posix() for path in (root / "src").rglob("*.py")}
    if not isinstance(request["source_sha256"], dict) or not inventory or inventory != set(request["source_sha256"]):
        raise ValueError("Original TYGR source inventory differs")
    for name, digest in request["source_sha256"].items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts or sha(root / relative) != digest:
            raise ValueError("Original TYGR source differs")
    if set(request["helpers"]) != {"capture", "export"}:
        raise ValueError("Unexpected helper modules")
    for entry in request["helpers"].values():
        if set(entry) != {"path", "sha256"} or sha(entry["path"]) != entry["sha256"]:
            raise ValueError("Helper source differs")


def load_helper(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def guard_native_input(native, contract):
    """Check the actual collated input before any model call, using passive JSON data."""
    width, capacities = contract["feature_width"], contract["layer_relation_capacities"]
    if (width != 31 or contract["type_count"] != 75 or contract["declared_relation_count"] != 60
            or len(capacities) != 8 or any(cap != 44 for cap in capacities)):
        raise ValueError("Pinned saved model dimensions differ")
    batch = native["batch"]
    features, ids, edges, gather, scatter = [batch[key] for key in
        ("node_labels", "edge_labels", "edges", "var_gather", "var_scatter")]
    n = features["shape"][0]
    expected_shapes = ((features, [n, width], "torch.float32"), (ids, [len(ids["values"])], "torch.int64"),
                       (edges, [2, len(ids["values"])], "torch.int64"),
                       (gather, [len(gather["values"])], "torch.int64"), (scatter, [len(gather["values"])], "torch.int64"))
    for tensor, shape, dtype in expected_shapes:
        if tensor["device"] != "cpu" or tensor["shape"] != shape or tensor["dtype"] != dtype:
            raise ValueError("Native batch shape/device/dtype differs")
    if (not 0 < n <= 4096 or len(features["values"]) != n
            or any(len(row) != width or any(type(v) not in (int, float) or not math.isfinite(v) for v in row)
                   for row in features["values"])):
        raise ValueError("Native features are invalid")
    if any(type(value) is not int or value < 0 or value >= contract["declared_relation_count"]
           or any(value >= cap for cap in capacities) for value in ids["values"]):
        raise ValueError("Observed native relation outside declared/saved layer domains; forward refused")
    if (len(edges["values"]) != 2 or any(len(row) != len(ids["values"]) for row in edges["values"])
            or any(type(value) is not int or not 0 <= value < n for row in edges["values"] for value in row)
            or any(type(value) is not int or not 0 <= value < n for value in gather["values"])):
        raise ValueError("Native endpoint/gather domain differs")
    rows = native["prepared"]["var_nodes"]
    expected_gather = [node for group in rows for node in group]
    expected_scatter = [index for index, group in enumerate(rows) for _ in group]
    if (batch["num_vars"] != [len(rows)] or gather["values"] != expected_gather
            or scatter["values"] != expected_scatter or batch["labels_supplied_to_model"] is not False):
        raise ValueError("Native readout membership or label-free batch differs")
    if any(batch[key] != native["prepared"][key] for key in ("node_labels", "edge_labels", "edges")):
        raise ValueError("Single-function collation changed prepared input")
    return {"status": "passed", "observed_relation_ids": sorted(set(ids["values"])),
            "nodes": n, "rows": len(rows), "native_input_semantics_changed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    request = json.loads(args.request.read_text(encoding="utf-8"))
    output = args.output.resolve()
    payload = {"schema": "symbai.typed_acquisition.v1", "status": "collecting", "runtime": {},
        "binary_sha256": request.get("binary_sha256"), "model_sha256": request.get("model_sha256"),
        "functions": [], "records": [], "forward_calls_attempted": 0, "forward_calls_completed": 0,
        "provenance": {"source": "tygr_glowgnn", "locator": "dwarf_assisted", "decoder": "independent",
                       "datagen_predict_phase": False, "ground_truth_labels_supplied_to_model": False},
        "ground_truth_labels_supplied_to_model": False, "device": "cpu"}
    started = time.monotonic()
    try:
        validate_request(request)
        if not sys.platform.startswith("linux"):
            raise ValueError("Native acquisition requires existing Linux tygr-orig")
        scratch = Path(request["scratch_dir"]).resolve()
        scratch.mkdir(parents=True, exist_ok=True)
        for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME", "TORCH_HOME", "HF_HOME", "MPLCONFIGDIR", "NUMBA_CACHE_DIR"):
            os.environ[key] = str(scratch)
        os.environ["CUDA_VISIBLE_DEVICES"] = ""
        sys.dont_write_bytecode = True
        sys.path.insert(0, str(Path(request["tygr_root"]).resolve()))
        os.chdir(str(scratch))
        capture_helper = load_helper("native_capture_helpers_v21", request["helpers"]["capture"]["path"])
        export_helper = load_helper("native_export_helpers_v21", request["helpers"]["export"]["path"])
        write(output, payload)
        import torch
        from src.methods.glow import datagen, preproc, predict
        payload["runtime"] = {"python": sys.version, "torch": str(torch.__version__),
            **{name: metadata.version(name) for name in ("angr", "torch-geometric", "pyvex", "numpy")}}
        if (sys.version_info[:2] != (3, 8) or str(torch.__version__) != "1.8.1+cpu"
                or payload["runtime"]["angr"] != "9.0.7491" or payload["runtime"]["torch-geometric"] != "1.7.0"):
            raise ValueError("Existing old native stack differs")
        model = torch.load(request["model"], map_location="cpu")
        model.eval()
        config = model.config.preproc_config
        if model.config.decoder_type != "independent":
            raise ValueError("Only the saved independent decoder is supported")
        vocabulary = [str(config.type_set.index_to_type(i)) for i in range(config.type_set.num_types())]
        if len(set(vocabulary)) != len(vocabulary):
            raise ValueError("Ambiguous native vocabulary")
        contract = {"feature_width": int(config.node_label_encoding_dim), "type_count": len(vocabulary),
            "declared_relation_count": int(config.num_edge_ops),
            "layer_relation_capacities": [int(layer.num_relations) for layer in model.rgcns]}
        payload["model_contract"] = contract
        options = datagen.Options(parallel=False, pool_size=1, ignore_functions=False, predict_phase=False)
        with torch.no_grad():
            for glow, _discarded_gold in datagen.generate_glow_dataset_no_parallel(request["binary"], str(scratch), options):
                glow.vars = [variable for variable in glow.vars if variable.nodes]
                if not glow.vars:
                    continue
                if len(payload["functions"]) >= 64:
                    raise ValueError("Function resource limit")
                entry = {"function_address": int(glow.low_high_pc[0]), "status": "preparing",
                         "forward_attempted": False, "forward_completed": False}
                payload["functions"].append(entry)
                write(output, payload)
                entry["native_input"] = capture_helper.capture_native_function(glow, config, preproc.encode_edge_label, int(glow.low_high_pc[0]))
                write(output, payload)
                prepared = preproc.preproc_input(glow, config)
                batch = predict.collate_inputs([prepared])
                entry["native_input"] = capture_helper.capture_function(glow, prepared, batch, config,
                    preproc.encode_edge_label, int(glow.low_high_pc[0]), entry["native_input"])
                entry["input_guard"] = guard_native_input(entry["native_input"], contract)
                write(output, payload)
                # Exactly the validated collated tensors are forwarded; the seventh input is always None.
                actual = tuple(batch) + (None,)
                entry["forward_attempted"] = True
                payload["forward_calls_attempted"] += 1
                write(output, payload)
                prediction = model(actual) if len(inspect.signature(model.forward).parameters) == 1 else model(*actual)
                entry["forward_completed"] = True
                payload["forward_calls_completed"] += 1
                logits = prediction[0] if isinstance(prediction, tuple) else prediction
                counts = [len(var.nodes) if config.flatten_vars else 1 for var in glow.vars]
                if not torch.is_tensor(logits) or logits.ndim != 2 or list(logits.shape) != [sum(counts), len(vocabulary)]:
                    raise ValueError("Native logits/readout dimensions differ")
                cursor = 0
                for index, (variable, count) in enumerate(zip(glow.vars, counts)):
                    packed = export_helper.pack_logits(logits[cursor:cursor + count].detach().cpu().tolist(), vocabulary, 3)
                    native_var = entry["native_input"]["variables"][index]
                    packed.update({"prediction_id": native_var["prediction_id"], "function_address": entry["function_address"],
                        "locator_variable_name": variable.name, "locations": native_var["locations"],
                        "value_nodes": native_var["original_value_nodes"],
                        "raw_row_axis": "value_node" if config.flatten_vars else "variable_readout"})
                    payload["records"].append(packed)
                    cursor += count
                entry["status"] = "completed"
                write(output, payload)
        validate_request(request)
        if not payload["records"]:
            raise ValueError("No genuine variable logits produced")
        payload["status"] = "completed"
        payload["identities_rechecked"] = True
    except Exception as error:
        payload["status"] = "failed"
        payload["error"] = {"type": type(error).__name__, "message": str(error)}
    payload["script_elapsed_seconds"] = time.monotonic() - started
    payload["clock_scope"] = "child_script_includes_imports_loading_generation_guards_forward_export_not_interpreter_startup"
    write(output, payload)
    print("Typed acquisition {}: {} functions, {} variable records".format(payload["status"],
          len(payload["functions"]), len(payload["records"])), flush=True)


if __name__ == "__main__":
    main()
