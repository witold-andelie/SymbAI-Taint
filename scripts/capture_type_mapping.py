#!/usr/bin/env python3
"""Standalone Python 3.8 collection of a fixed function; never load/forward a model."""
import argparse
import hashlib
import importlib.util
from importlib import metadata
import json
import os
from pathlib import Path
import sys


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    request = json.loads(args.request.read_bytes())
    if set(request) != {"schema", "binary", "binary_sha256", "function_address", "tygr_root", "source_inventory", "implementation", "scratch_dir"}:
        raise ValueError("Unexpected request fields; offline gold labels forbidden")
    if request["schema"] != "symbai.type_mapping_request.v1" or sha(request["binary"]) != request["binary_sha256"]:
        raise ValueError("Mapping input identity differs")
    if set(request["implementation"]) != {"worker", "capture", "stages", "hooks", "locations"}:
        raise ValueError("Unexpected mapping helper set")
    for entry in request["implementation"].values():
        if sha(entry["path"]) != entry["sha256"]:
            raise ValueError("Mapping helper identity differs")
    if sha(__file__) != request["implementation"]["worker"]["sha256"]:
        raise ValueError("Mapping worker identity differs")
    root, scratch = Path(request["tygr_root"]), Path(request["scratch_dir"]).resolve()

    def unchanged():
        inventory = {path.relative_to(root).as_posix(): sha(path) for path in (root / "src").rglob("*.py")}
        if inventory != request["source_inventory"]:
            raise ValueError("Original TYGR source inventory changed")
    unchanged()
    if not sys.platform.startswith("linux") or not str(scratch).startswith("/mnt/d/"):
        raise ValueError("Use the existing WSL runtime and D-drive scratch")
    scratch.mkdir(parents=True, exist_ok=True)
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME", "TORCH_HOME", "MPLCONFIGDIR", "NUMBA_CACHE_DIR"):
        os.environ[key] = str(scratch)
    os.environ["CUDA_VISIBLE_DEVICES"] = ""
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(root))
    payload = {"schema": "symbai.type_mapping_capture.v1", "status": "collecting",
        "binary_sha256": request["binary_sha256"], "function_address": request["function_address"],
        "model_loaded": False, "model_load_attempts": 0, "model_forward_attempts": 0,
        "lookup_calls": [], "location_records": [], "location_errors": []}
    try:
        import torch
        import angr
        from src.methods.glow import datagen, preproc, predict
        from src.analysis.angr import sim_exec, ast_graph
        from src.analysis.dwarf import location, lookup
        payload["runtime"] = {"python": list(sys.version_info[:2]), "torch": str(torch.__version__),
            **{name: metadata.version(name) for name in ("angr", "torch-geometric", "pyelftools")}}
        if (payload["runtime"]["python"] != [3, 8] or payload["runtime"]["torch"] != "1.8.1+cpu"
                or payload["runtime"]["angr"] != "9.0.7491" or payload["runtime"]["torch-geometric"] != "1.7.0"):
            raise ValueError("Original runtime differs")
        helpers = {name: load("mapping_" + name, entry["path"]) for name, entry in request["implementation"].items() if name != "worker"}
        helpers["locations"].install(location, lookup, payload["location_records"].append, payload["location_errors"].append)
        observer = helpers["stages"].StageObserver()
        old = {"programs": datagen.dwarf_info_to_subprograms, "task": datagen.sym_exec_one,
            "find": ast_graph.AstGraph.find_nodes_from_locs, "init": sim_exec.SimExecStrategy.init_symbolic_state,
            "load": torch.load, "call": torch.nn.Module.__call__}
        context = {"vars": []}

        def selected(info):
            for program in old["programs"](info):
                if int(program[3][0]) == request["function_address"]:
                    yield program

        def task(item):
            context["vars"] = item[1]
            return old["task"](item)

        def find(graph, locations):
            result = old["find"](graph, locations)
            index = len(payload["lookup_calls"])
            name = context["vars"][index][0]
            prepared = [{"low_pc": int(lo), "high_pc": int(hi), "form": form, "value": int(value)}
                        for ((lo, hi), (form, value)) in (locations or [])]
            payload["lookup_calls"].append({"name": name, "prepared_locations": prepared, "pre_splice_nodes": sorted(result)})
            return result

        def initial(strategy, *values, **kwargs):
            state = old["init"](strategy, *values, **kwargs)
            payload["configured_initial_sp"] = int(strategy.config["init_sp"])
            if strategy.arch.name != "AMD64" or strategy.arch.bytes != 8:
                raise ValueError("Unexpected architecture")
            return state

        def deny_load(*_args, **_kwargs):
            payload["model_load_attempts"] += 1
            raise RuntimeError("Model loading forbidden")

        def deny_forward(*_args, **_kwargs):
            payload["model_forward_attempts"] += 1
            raise RuntimeError("Neural module calls forbidden")

        config = preproc.Config(type_set="rstd", use_bitvector=False, use_raw_edges=False, flatten_vars=True, use_arch=True)
        payload["data_contract"] = {"feature_width": config.node_label_encoding_dim,
            "declared_relation_count": config.num_edge_ops, "type_count": config.type_set.num_types(),
            "scope": "Fresh full-60-relation preprocessing only; no admission to the frozen 44-slot checkpoint."}
        try:
            datagen.dwarf_info_to_subprograms, datagen.sym_exec_one = selected, task
            ast_graph.AstGraph.find_nodes_from_locs = find
            sim_exec.SimExecStrategy.init_symbolic_state = initial
            torch.load, torch.nn.Module.__call__ = deny_load, deny_forward
            options = datagen.Options(parallel=False, pool_size=1, ignore_functions=False, predict_phase=False)
            with helpers["hooks"].install(sim_exec.SimExecStrategy, "field_names_after", angr.BP_BEFORE, angr.BP_AFTER) as intervention:
                with observer.install(datagen, sim_exec, ast_graph.AstGraph, angr.SimState):
                    results = list(datagen.generate_glow_dataset_no_parallel(request["binary"], str(scratch), options))
                    if len(results) != 1:
                        raise ValueError("Expected one selected function graph; missing results retained as failure")
                    glow, _offline_gold_not_forwarded = results[0]
                    payload["original_arch_token"] = glow.arch
                    glow.arch = "x64"
                    native = helpers["capture"].capture_native_function(glow, config, preproc.encode_edge_label, request["function_address"])
                    prepared = preproc.preproc_input(glow, config)
                    batch = predict.collate_inputs([prepared])
                    payload["native_input"] = helpers["capture"].capture_function(glow, prepared, batch, config,
                        preproc.encode_edge_label, request["function_address"], native)
                payload["intervention"] = intervention
            payload["stage"], = observer.functions
            payload["observer_errors"] = observer.errors
            if observer.errors or payload["location_errors"] or payload["model_load_attempts"] or payload["model_forward_attempts"]:
                raise ValueError("Incomplete graph observation")
            unchanged()
            payload["original_sources_rechecked"] = True
            payload["status"] = "captured"
        finally:
            payload["observed_functions"] = observer.functions
            payload["observer_errors"] = observer.errors
            datagen.dwarf_info_to_subprograms, datagen.sym_exec_one = old["programs"], old["task"]
            ast_graph.AstGraph.find_nodes_from_locs = old["find"]
            sim_exec.SimExecStrategy.init_symbolic_state = old["init"]
            torch.load, torch.nn.Module.__call__ = old["load"], old["call"]
    except Exception as error:
        payload.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
    args.output.write_text(json.dumps(payload, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print("Type mapping capture: " + payload["status"], flush=True)
    if payload["status"] != "captured":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
