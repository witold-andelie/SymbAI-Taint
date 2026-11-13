#!/usr/bin/env python3
"""Original-environment native preprocessing capture, with every model forward blocked.

Standalone Python 3.8 entry: project 'src' must not collide with the external TYGR 'src'.
"""

import argparse
from contextlib import contextmanager
import hashlib
import inspect
import json
import math
import os
from pathlib import Path
import sys
import time

MODEL_SHA256 = "f592caaa6c685f291f576b16fbf8b752a95e7cb757ea620751830563b77f67c8"
MAX_NODES, MAX_EDGES, MAX_ROWS, MAX_FUNCTIONS = 4096, 20000, 4096, 64


@contextmanager
def timed_stage(capture, name):
    started = time.monotonic()
    try:
        yield
    finally:
        timings = capture["timings_seconds"]
        timings[name] = timings.get(name, 0.0) + time.monotonic() - started


def file_hash(path):
    result = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".partial")
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False), encoding="utf-8")
    os.replace(str(temporary), str(path))


def validate_request(request):
    fields = {"schema", "binary", "binary_sha256", "entry_rva", "tygr_root", "model", "model_sha256",
              "scratch_dir", "source_sha256", "worker_sha256"}
    if (not isinstance(request, dict) or set(request) != fields or request["schema"] != "symbai.native_preprocessing_request.v1"
            or type(request["entry_rva"]) is not int or request["entry_rva"] < 0
            or request["model_sha256"] != MODEL_SHA256 or not isinstance(request["source_sha256"], dict)
            or not request["source_sha256"]):
        raise ValueError("Invalid native request; property/label/prediction fields are forbidden")
    if file_hash(request["binary"]) != request["binary_sha256"] or file_hash(request["model"]) != MODEL_SHA256:
        raise ValueError("Frozen binary/model identity differs")
    if file_hash(__file__) != request["worker_sha256"]:
        raise ValueError("Worker source identity differs")
    root = Path(request["tygr_root"])
    actual_names = {path.relative_to(root).as_posix() for path in (root / "src").rglob("*.py")}
    if actual_names != set(request["source_sha256"]):
        raise ValueError("TYGR source inventory differs")
    for name, digest in request["source_sha256"].items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts or relative.suffix != ".py":
            raise ValueError("Invalid TYGR source path")
        if file_hash(root / relative) != digest:
            raise ValueError("TYGR source differs: " + name)


def tensor_snapshot(tensor):
    shape = [int(value) for value in tensor.shape]
    if str(tensor.device) != "cpu" or len(shape) > 2 or math.prod(shape) > 2000000:
        raise ValueError("Native tensor is not bounded CPU data")
    return {"dtype": str(tensor.dtype), "device": str(tensor.device), "shape": shape,
            "values": tensor.detach().cpu().tolist()}


def scalar_value(value):
    if isinstance(value, bool):
        return {"kind": "bool", "value": value}
    if isinstance(value, int):
        return {"kind": "int", "value": str(value)}
    if isinstance(value, float):
        return {"kind": "float", "value": value.hex()}
    raise ValueError("Unsupported actual NodeLabel value class: " + type(value).__name__)


def block_model_forwards(model, capture):
    def deny_forward(*_args, **_kwargs):
        capture["forward_attempts"] += 1
        raise RuntimeError("Model forward is forbidden in native preprocessing capture")
    modules = list(model.modules())
    if not modules:
        raise ValueError("No modules available for forward guards")
    for module in modules:
        module.forward = deny_forward
    return len(modules)


def capture_native_function(glow, config, encode_edge, entry_rva):
    order = [int(node) for node in glow.ast_graph.graph.nodes]
    native_edges = list(glow.ast_graph.graph.edges)
    row_count = sum(len(variable.nodes) if config.flatten_vars else 1 for variable in glow.vars)
    if not 0 < len(order) <= MAX_NODES or len(native_edges) > MAX_EDGES or not 0 < row_count <= MAX_ROWS:
        raise ValueError("Native function capture exceeds declared limits")
    nodes = []
    for node in order:
        label = glow.ast_graph.node_to_label[node]
        nodes.append({"graph_node_id": node, "bitsize": int(label.bitsize),
                      "annotation_address": int(label.addr) if label.addr is not None else None,
                      "ast_value": scalar_value(label.ast_val)})
    edges = []
    for index, (source, target) in enumerate(native_edges):
        labels = glow.ast_graph.edge_to_labels[(source, target)]
        edges.append({"source": int(source), "target": int(target), "labels": sorted(labels),
                      "forward_id": int(encode_edge(labels, False, config)),
                      "inverse_id": int(encode_edge(labels, True, config)),
                      "prepared_columns": [2 * index, 2 * index + 1]})
    variables, cursor, groups = [], 0, []
    low, high = glow.low_high_pc
    for index, variable in enumerate(glow.vars):
        original = [int(node) for node in variable.nodes]
        count = len(original) if config.flatten_vars else 1
        assigned = list(range(cursor, cursor + count))
        groups.append(assigned)
        locations = [{"low_pc": int(lo), "high_pc": int(hi) if hi is not None else None,
                      "location_class": type(location).__name__,
                      "location_value": int(getattr(location, "reg_num", getattr(location, "arg", 0))),
                      "location_register": int(location.reg_num) if hasattr(location, "reg_num") else None,
                      "location_argument": int(location.arg) if hasattr(location, "arg") else None}
                     for lo, hi, location in variable.locs]
        variables.append({"prediction_id": "{:x}:{}".format(int(low), index),
                          "locator_variable_name": variable.name, "function_address": int(low),
                          "locations": locations, "original_value_nodes": original,
                          "flattened_output_rows": assigned})
        cursor += count
    return {"function_address": int(low), "function_high_pc": int(high) if high is not None else None,
            "is_target": int(low) == entry_rva, "arch_token": str(getattr(glow, "arch", None)),
            "graph_node_order": order, "node_labels": nodes, "graph_edges": edges, "variables": variables,
            "capture_stage": "native_before_preprocessing", "prepared": None, "batch": None,
            "readout_contract": {"original_variable_count": len(variables), "prepared_readout_rows": row_count,
                                 "exporter_value_row_groups": groups,
                                 "row_axis": "value_node" if config.flatten_vars else "variable_readout",
                                 "logits_computed": False}}


def capture_function(glow, prepared, batch, config, encode_edge, entry_rva, native=None):
    result = dict(native) if native is not None else capture_native_function(glow, config, encode_edge, entry_rva)
    rows = [list(map(int, group)) for group in prepared.var_nodes]
    if not 0 < len(rows) <= MAX_ROWS:
        raise ValueError("Native readout capture exceeds declared limits")
    num_vars, features, relations, endpoints, gather, scatter = batch
    result.update({"capture_stage": "prepared_and_collated",
            "prepared": {"node_labels": tensor_snapshot(prepared.node_labels),
                         "edge_labels": tensor_snapshot(prepared.edge_labels), "edges": tensor_snapshot(prepared.edges),
                         "var_nodes": rows},
            "batch": {"num_vars": list(map(int, num_vars)), "node_labels": tensor_snapshot(features),
                      "edge_labels": tensor_snapshot(relations), "edges": tensor_snapshot(endpoints),
                      "var_gather": tensor_snapshot(gather), "var_scatter": tensor_snapshot(scatter),
                      "labels_supplied_to_model": False}})
    result["readout_contract"] = {**result["readout_contract"], "prepared_readout_rows": len(rows)}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    request = json.loads(args.request.read_text(encoding="utf-8"))
    args.output = args.output.resolve()
    capture = {"schema": "symbai.native_preprocessing.v1", "status": "collecting", "receipt_origin": "native_worker",
               "request_identity": {key: request.get(key) for key in ("binary_sha256", "entry_rva")},
               "provenance": {"model_sha256": request.get("model_sha256"), "locator": "dwarf_assisted",
                              "datagen_predict_phase": False, "ground_truth_labels_forwarded": False},
               "runtime": {}, "model_contract": None, "forward_attempts": 0, "model_forward_performed": False,
               "functions": [], "timings_seconds": {},
               "timing_scope": "selected_stage_diagnostics_not_additive_full_cost_parent_charge_is_authoritative",
               "source_sha256": request.get("source_sha256", {}),
               "rgcn_implementation": None, "integrity": {}, "limits": {
                   "max_nodes_per_function": MAX_NODES, "max_native_edges_per_function": MAX_EDGES,
                   "max_readout_rows_per_function": MAX_ROWS, "max_functions": MAX_FUNCTIONS}}
    try:
        validate_request(request)
        if not sys.platform.startswith("linux"):
            raise ValueError("Native capture requires the existing Linux TYGR environment")
        scratch = Path(request["scratch_dir"]).resolve()
        scratch.mkdir(parents=True, exist_ok=True)
        for name in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME", "TORCH_HOME", "HF_HOME"):
            os.environ[name] = str(scratch)
        for name, subdir in (("MPLCONFIGDIR", "matplotlib"), ("TORCH_EXTENSIONS_DIR", "torch-extensions"), ("NUMBA_CACHE_DIR", "numba")):
            location = scratch / subdir
            location.mkdir(exist_ok=True)
            os.environ[name] = str(location)
        os.environ["CUDA_VISIBLE_DEVICES"] = ""
        sys.dont_write_bytecode = True
        sys.path.insert(0, str(Path(request["tygr_root"]).resolve()))
        os.chdir(str(scratch))
        write(args.output, capture)
        started = time.monotonic()
        import torch
        from importlib import metadata
        from src.methods.glow import datagen, preproc, predict
        capture["runtime"] = {"python": sys.version, "executable": sys.executable, "platform": sys.platform,
                              "torch": str(torch.__version__), **{name: metadata.version(name) for name in
                                  ("angr", "claripy", "pyvex", "archinfo", "torch-geometric", "networkx", "numpy")}}
        capture["timings_seconds"]["imports"] = time.monotonic() - started
        if (sys.version_info[:2] != (3, 8) or str(torch.__version__) != "1.8.1+cpu"
                or capture["runtime"]["angr"] != "9.0.7491" or capture["runtime"]["torch-geometric"] != "1.7.0"):
            raise ValueError("Native runtime differs from the existing verified tygr-orig stack")
        started = time.monotonic()
        parameters = {"map_location": "cpu"}
        if "weights_only" in inspect.signature(torch.load).parameters:
            parameters["weights_only"] = False
        model = torch.load(request["model"], **parameters)
        capture["forward_guarded_modules"] = block_model_forwards(model, capture)
        model.eval()
        config = model.config.preproc_config
        layers = list(model.rgcns)
        if not layers:
            raise ValueError("No saved relation layers")
        implementation = inspect.getsource(type(layers[0]).forward)
        if len(implementation.encode("utf-8")) > 131072:
            raise ValueError("RGCN source exceeds capture limit")
        implementation_path = inspect.getsourcefile(type(layers[0]))
        capture["rgcn_implementation"] = {"class": type(layers[0]).__module__ + "." + type(layers[0]).__name__,
            "source_file": implementation_path, "source_file_sha256": file_hash(implementation_path),
            "forward_source": implementation, "forward_source_sha256": hashlib.sha256(implementation.encode("utf-8")).hexdigest(),
            "behavior_executed_or_inferred": False}
        capture["model_contract"] = {"model_sha256": MODEL_SHA256,
            "node_label_encoding_dim": int(config.node_label_encoding_dim), "all_ops": list(config.all_ops),
            "num_all_ops": int(config.num_all_ops), "num_edge_ops": int(config.num_edge_ops),
            "flatten_vars": bool(config.flatten_vars), "use_arch": bool(config.use_arch),
            "arch_fields": list(config.arch_fields), "type_count": int(config.type_set.num_types()),
            "decoder_type": str(model.config.decoder_type), "node_aggregation": str(model.config.node_aggregation),
            "layer_relation_capacities": [int(layer.num_relations) for layer in layers],
            "edge_reduce_op_map": dict(preproc.REDUCE_OP_MAP)}
        capture["timings_seconds"]["model_loading_and_guards"] = time.monotonic() - started
        write(args.output, capture)
        options = datagen.Options(parallel=False, pool_size=1, ignore_functions=False, predict_phase=False)
        generated = iter(datagen.generate_glow_dataset_no_parallel(request["binary"], str(scratch), options))
        with torch.no_grad():
            while True:
                try:
                    with timed_stage(capture, "graph_generation"):
                        glow, _unused_gold_output = next(generated)
                except StopIteration:
                    break
                glow.vars = [variable for variable in glow.vars if variable.nodes]
                if not glow.vars:
                    continue
                if len(capture["functions"]) >= MAX_FUNCTIONS:
                    raise ValueError("Too many generated functions")
                # Persist identity before conversion, and complete native data before preprocessing.
                # A later preparation/collation failure must not erase a generated function.
                with timed_stage(capture, "native_capture_and_stage_persistence"):
                    low, high = glow.low_high_pc
                    capture["functions"].append({"function_address": int(low),
                        "function_high_pc": int(high) if high is not None else None,
                        "is_target": int(low) == request["entry_rva"], "capture_stage": "generated",
                        "node_count": len(glow.ast_graph.graph.nodes), "original_variable_count": len(glow.vars)})
                    write(args.output, capture)
                    native = capture_native_function(glow, config, preproc.encode_edge_label, request["entry_rva"])
                    capture["functions"][-1] = native
                    write(args.output, capture)
                with timed_stage(capture, "preprocessing"):
                    prepared = preproc.preproc_input(glow, config)
                    batch = predict.collate_inputs([prepared])
                with timed_stage(capture, "prepared_capture"):
                    captured = capture_function(glow, prepared, batch, config, preproc.encode_edge_label, request["entry_rva"], native)
                    capture["functions"][-1] = captured
                write(args.output, capture)
        if sum(function["is_target"] for function in capture["functions"]) != 1:
            raise ValueError("Exactly one declared target function must be captured")
        if capture["forward_attempts"]:
            raise ValueError("A guarded forward call was attempted")
        validate_request(request)
        capture["integrity"] = {"binary_unchanged": True, "model_unchanged": True, "upstream_sources_unchanged": True}
        capture["status"] = "captured"
    except Exception as error:
        capture["status"] = "failed"
        capture["error"] = {"type": type(error).__name__, "message": str(error)}
    write(args.output, capture)
    print("Native preprocessing {}: {} functions; {} guarded forward attempts".format(
          capture["status"], len(capture["functions"]), capture["forward_attempts"]), flush=True)


if __name__ == "__main__":
    main()
