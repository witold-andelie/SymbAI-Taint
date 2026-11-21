#!/usr/bin/env python3
"""No-forward hook intervention capture; keep strict saved-model rejections as data."""
import argparse
from importlib import metadata
import importlib.util
import json
import os
from pathlib import Path
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    envelope = json.loads(args.request.read_bytes())
    entries = envelope["implementation"]
    spec = importlib.util.spec_from_file_location("frozen_stage_helpers", entries["stages"]["path"])
    stages = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stages)
    if (set(envelope) != {"schema", "variant", "native_request", "implementation"}
            or envelope["schema"] != "symbai.hook_variant_request.v1"
            or set(entries) != {"worker", "stages", "variant_adapter", "guard", "adapter"}
            or any(stages.sha(e["path"]) != e["sha256"] for e in entries.values())
            or stages.sha(__file__) != entries["worker"]["sha256"]):
        raise ValueError("Hook variant implementation identity differs")
    variants = stages.load("read_interventions", entries["variant_adapter"]["path"])
    variant = envelope["variant"]
    if variant not in variants.VARIANTS:
        raise ValueError("Unknown variant")
    guard = stages.load("variant_guard", entries["guard"]["path"])
    native = envelope["native_request"]
    guard.validate_request(native)
    scratch = Path(native["scratch_dir"]).resolve()
    if not sys.platform.startswith("linux") or not str(scratch).startswith("/mnt/d/"):
        raise ValueError("Hook capture requires existing TYGR on the D mount")
    scratch.mkdir(parents=True, exist_ok=True)
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME", "TORCH_HOME", "MPLCONFIGDIR", "NUMBA_CACHE_DIR"):
        os.environ[key] = str(scratch)
    os.environ["CUDA_VISIBLE_DEVICES"] = ""
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(Path(native["tygr_root"]).resolve()))
    payload = {"schema": "symbai.hook_variant_capture.v1", "status": "collecting", "variant": variant,
        "binary_sha256": native["binary_sha256"], "model_sha256": native["model_sha256"],
        "functions": [], "forward_attempts": 0, "model_forward_performed": False,
        "location_records": [], "location_errors": [],
        "guard_semantics": "The original guard runs unchanged. Rejections are retained for no-forward diagnosis; rejected inputs are never admitted or forwarded."}
    started = time.monotonic()
    try:
        import torch
        import angr
        from src.methods.glow import datagen, preproc, predict
        from src.analysis.angr import sim_exec, ast_graph
        from src.analysis.dwarf import location, lookup
        inspection = importlib.import_module("angr.state_plugins.inspect")
        payload["inspection_attributes"] = sorted(inspection.inspect_attributes)
        payload["runtime"] = {"python": sys.version, "torch": str(torch.__version__),
            **{key: metadata.version(key) for key in ("angr", "pyvex", "torch-geometric", "pyelftools")}}
        if (sys.version_info[:2] != (3, 8) or str(torch.__version__) != "1.8.1+cpu"
                or payload["runtime"]["angr"] != "9.0.7491" or payload["runtime"]["torch-geometric"] != "1.7.0"):
            raise ValueError("Original runtime differs")
        adapter = stages.load("variant_location_adapter", entries["adapter"]["path"])
        payload["location_api"] = adapter.install(location, lookup,
            payload["location_records"].append, payload["location_errors"].append)
        capture = stages.load("variant_capture_helpers", native["helpers"]["capture"]["path"])
        model = torch.load(native["model"], map_location="cpu")
        model.eval()
        capture.block_model_forwards(model, payload)
        config = model.config.preproc_config
        contract = {"feature_width": int(config.node_label_encoding_dim), "type_count": int(config.type_set.num_types()),
            "declared_relation_count": int(config.num_edge_ops),
            "layer_relation_capacities": [int(layer.num_relations) for layer in model.rgcns]}
        payload["model_contract"] = contract
        observer = stages.StageObserver()
        options = datagen.Options(parallel=False, pool_size=1, ignore_functions=False, predict_phase=False)
        with variants.install(sim_exec.SimExecStrategy, variant, angr.BP_BEFORE, angr.BP_AFTER) as intervention:
            with observer.install(datagen, sim_exec, ast_graph.AstGraph, angr.SimState):
                for glow, _discarded_gold in datagen.generate_glow_dataset_no_parallel(native["binary"], str(scratch), options):
                    glow.vars = [v for v in glow.vars if v.nodes]
                    if not glow.vars:
                        continue
                    address = int(glow.low_high_pc[0])
                    original = capture.capture_native_function(glow, config, preproc.encode_edge_label, address)
                    prepared = preproc.preproc_input(glow, config)
                    batch = predict.collate_inputs([prepared])
                    observed = capture.capture_function(glow, prepared, batch, config, preproc.encode_edge_label, address, original)
                    try:
                        guard_result = guard.guard_native_input(observed, contract)
                    except ValueError as rejection:
                        guard_result = {"status": "rejected", "reason": str(rejection)}
                    stage, = [f for f in observer.functions if f["function_address"] == address]
                    before, after = observer.graph_objects[address]
                    stage.update(native_input=observed, saved_model_input_guard=guard_result,
                        encoded_before=stages.encoded_graph(before, glow.arch, config, preproc, torch),
                        encoded_after=stages.encoded_graph(after, glow.arch, config, preproc, torch))
                    if stage["encoded_after"]["node_features"] != observed["batch"]["node_labels"]["values"]:
                        raise ValueError("Recorded encoding differs from native input")
                    payload["functions"].append(stage)
            payload["intervention"] = intervention
        payload["observer_errors"] = observer.errors
        if not payload["functions"] or observer.errors or payload["location_errors"] or payload["forward_attempts"]:
            raise ValueError("Incomplete no-forward variant capture")
        guard.validate_request(native)
        payload["original_identities_rechecked"] = True
        payload["status"] = "captured"
    except Exception as error:
        payload["status"] = "failed"
        payload["error"] = {"type": type(error).__name__, "message": str(error)}
    payload["diagnostic_seconds"] = time.monotonic() - started
    guard.write(args.output, payload)
    print("Hook variant {}: {}; forward attempts {}".format(variant, payload["status"], payload["forward_attempts"]), flush=True)
    if payload["status"] != "captured":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
