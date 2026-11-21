#!/usr/bin/env python3
"""Observe original TYGR execution and graph splicing without any model forward."""
import argparse
from collections import Counter
from contextlib import contextmanager
from functools import wraps
import hashlib
import importlib.util
from importlib import metadata
import json
import os
from pathlib import Path
import sys
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ast_description(value):
    value = getattr(value, "ast", value)
    if value is None or isinstance(value, (str, int, bool, float)):
        return value
    return {"op": str(getattr(value, "op", type(value).__name__)),
        "bits": getattr(value, "length", None), "depth": getattr(value, "depth", None),
        "symbolic": bool(getattr(value, "symbolic", False)),
        "annotations": [type(a).__name__ for a in getattr(value, "annotations", ())],
        "text": str(value)[:320]}


def graph_snapshot(graph):
    nodes = list(graph.graph.nodes)
    if len(nodes) > 4096 or graph.graph.number_of_edges() > 20000:
        raise ValueError("Graph capture resource limit")
    return {"node_order": [int(n) for n in nodes], "nodes": [{"id": int(n),
        "bitsize": int(graph.node_to_label[n].bitsize), "annotation_address":
        int(graph.node_to_label[n].addr) if graph.node_to_label[n].addr is not None else None,
        "value": str(graph.node_to_label[n].ast_val)} for n in nodes],
        "edges": [{"source": int(s), "target": int(t), "labels": sorted(graph.edge_to_labels[s, t])}
                  for s, t in graph.graph.edges],
        "node_count": len(nodes), "edge_count": graph.graph.number_of_edges()}


def action_snapshot(state):
    actions = list(state.history.actions.hardcopy)
    if len(actions) > 10000:
        raise ValueError("Action capture resource limit")
    records = []
    for action in actions:
        record = {"class": type(action).__name__, "type": getattr(action, "type", None),
            "action": getattr(action, "action", None), "instruction_address": getattr(action, "ins_addr", None),
            "block_address": getattr(action, "bbl_addr", None), "statement_index": getattr(action, "stmt_idx", None)}
        for key in ("offset", "addr", "data"):
            if hasattr(action, key):
                record[key] = ast_description(getattr(action, key))
        records.append(record)
    return records


class StageObserver:
    def __init__(self):
        self.functions = []
        self.current = None
        self.graph_objects = {}
        self.errors = []

    @contextmanager
    def install(self, datagen, sim_exec, graph_class, state_class):
        originals = []

        def replace(owner, name, wrap):
            original = getattr(owner, name)
            originals.append((owner, name, original))
            setattr(owner, name, wrap(original))

        def function_wrapper(original):
            @wraps(original)
            def observed(task):
                previous = self.current
                self.current = {"function_address": int(task[0]), "blocks": [], "step_exceptions": [],
                                "splices": [], "read_hook_events": []}
                self.functions.append(self.current)
                try:
                    return original(task)
                finally:
                    self.current = previous
            return observed

        def block_wrapper(original):
            @wraps(original)
            def observed(strategy, state, block):
                result = original(strategy, state, block)
                if self.current is not None:
                    self.current["blocks"].append({"planned_instruction_addresses":
                        [int(x) for x in block.instruction_addrs] if block is not None else [],
                        "returned_state": result is not None,
                        "actions": action_snapshot(result) if result is not None else []})
                return result
            return observed

        def step_wrapper(original):
            @wraps(original)
            def observed(state, *args, **kwargs):
                try:
                    return original(state, *args, **kwargs)
                except Exception as error:
                    if self.current is not None:
                        self.current["step_exceptions"].append({"type": type(error).__name__,
                            "message": str(error)[:1000], "instruction_address":
                            getattr(state.scratch, "ins_addr", None), "requested_num_inst": kwargs.get("num_inst")})
                    raise
            return observed

        def read_hook_wrapper(kind):
            def wrap(original):
                @wraps(original)
                def observed(strategy, state):
                    result = original(strategy, state)
                    if self.current is not None and len(self.current["read_hook_events"]) < 256:
                        fields = ("reg_read_expr", "register_read_expr") if kind == "register" else (
                            "mem_read_expr", "memory_read_expr")
                        try:
                            self.current["read_hook_events"].append({"kind": kind,
                                "instruction_address": getattr(state.scratch, "ins_addr", None),
                                "fields_after_original_hook": {key: ast_description(getattr(state.inspect, key, None))
                                                               for key in fields}})
                        except Exception as error:
                            # Observer failures must not become original step exceptions.
                            self.errors.append({"stage": "read_hook_observation", "type": type(error).__name__,
                                                "message": str(error)})
                    return result
                return observed
            return wrap

        def splice_wrapper(original):
            @wraps(original)
            def observed(graph, seeds):
                before = graph_snapshot(graph)
                result = original(graph, seeds)
                after = graph_snapshot(result[0])
                if self.current is not None:
                    address = self.current["function_address"]
                    self.current["splices"].append({"seed_nodes": sorted(int(x) for x in seeds),
                        "before": before, "after": after, "mapping": {str(k): int(v) for k, v in result[1].items()}})
                    self.graph_objects[address] = (graph, result[0])
                return result
            return observed

        try:
            replace(datagen, "sym_exec_one", function_wrapper)
            replace(sim_exec.SimExecStrategy, "sim_exec_block", block_wrapper)
            replace(state_class, "step", step_wrapper)
            replace(sim_exec.SimExecStrategy, "register_read_before_hook", read_hook_wrapper("register"))
            replace(sim_exec.SimExecStrategy, "memory_read_before_hook", read_hook_wrapper("memory"))
            replace(graph_class, "directed_splice_and_normalize", splice_wrapper)
            yield
        finally:
            for owner, name, original in reversed(originals):
                setattr(owner, name, original)


def encoded_graph(graph, arch, config, preproc, torch):
    order = list(graph.graph.nodes)
    arch_features = preproc.encode_arch(arch, config)
    return {"node_order": [int(n) for n in order], "node_features": [torch.cat([
        arch_features, preproc.encode_bit_vector(graph.node_to_label[n], config),
        preproc.encode_node_features(graph.node_to_label[n], config)]).tolist() for n in order],
        "edges": [{"source": int(s), "target": int(t), "forward_id": preproc.encode_edge_label(
            graph.edge_to_labels[s, t], False, config), "inverse_id": preproc.encode_edge_label(
            graph.edge_to_labels[s, t], True, config)} for s, t in graph.graph.edges]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    envelope = json.loads(args.request.read_bytes())
    implementation = envelope["implementation"]
    if (set(envelope) != {"schema", "native_request", "implementation"}
            or envelope["schema"] != "symbai.graph_stage_request.v1"
            or set(implementation) != {"worker", "guard", "adapter"}
            or any(sha(v["path"]) != v["sha256"] for v in implementation.values())
            or sha(__file__) != implementation["worker"]["sha256"]):
        raise ValueError("Graph observer implementation identity differs")
    guard = load("stage_guard", implementation["guard"]["path"])
    native = envelope["native_request"]
    guard.validate_request(native)
    scratch = Path(native["scratch_dir"]).resolve()
    if not sys.platform.startswith("linux") or not str(scratch).startswith("/mnt/d/"):
        raise ValueError("Capture requires the existing Linux TYGR runtime on D")
    scratch.mkdir(parents=True, exist_ok=True)
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME", "TORCH_HOME", "MPLCONFIGDIR", "NUMBA_CACHE_DIR"):
        os.environ[key] = str(scratch)
    os.environ["CUDA_VISIBLE_DEVICES"] = ""
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(Path(native["tygr_root"]).resolve()))
    payload = {"schema": "symbai.graph_stage_capture.v1", "status": "collecting", "functions": [],
        "binary_sha256": native["binary_sha256"], "model_sha256": native["model_sha256"],
        "forward_attempts": 0, "model_forward_performed": False, "location_records": [], "location_errors": []}
    started = time.monotonic()
    try:
        import torch
        import angr
        inspect_module = importlib.import_module("angr.state_plugins.inspect")
        from src.methods.glow import datagen, preproc, predict
        from src.analysis.angr import sim_exec, ast_graph
        from src.analysis.dwarf import location, lookup
        payload["runtime"] = {"python": sys.version, "torch": str(torch.__version__),
            **{key: metadata.version(key) for key in ("angr", "pyvex", "torch-geometric", "pyelftools")}}
        if (sys.version_info[:2] != (3, 8) or str(torch.__version__) != "1.8.1+cpu"
                or payload["runtime"]["angr"] != "9.0.7491" or payload["runtime"]["torch-geometric"] != "1.7.0"):
            raise ValueError("Original TYGR runtime differs")
        payload["inspection_attributes"] = sorted(getattr(inspect_module, "inspect_attributes"))
        payload["runtime_inspect_source"] = {"path": str(Path(inspect_module.__file__).resolve()),
                                             "sha256": sha(inspect_module.__file__)}
        adapter = load("stage_location_adapter", implementation["adapter"]["path"])
        payload["location_api"] = adapter.install(location, lookup,
            payload["location_records"].append, payload["location_errors"].append)
        capture = load("stage_capture_helpers", native["helpers"]["capture"]["path"])
        model = torch.load(native["model"], map_location="cpu")
        model.eval()
        capture.block_model_forwards(model, payload)
        config = model.config.preproc_config
        contract = {"feature_width": int(config.node_label_encoding_dim), "type_count": int(config.type_set.num_types()),
            "declared_relation_count": int(config.num_edge_ops),
            "layer_relation_capacities": [int(layer.num_relations) for layer in model.rgcns]}
        payload["model_contract"] = contract
        observer = StageObserver()
        options = datagen.Options(parallel=False, pool_size=1, ignore_functions=False, predict_phase=False)
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
                guard.guard_native_input(observed, contract)
                stage, = [f for f in observer.functions if f["function_address"] == address]
                before, after = observer.graph_objects[address]
                stage.update(native_input=observed, encoded_before=encoded_graph(before, glow.arch, config, preproc, torch),
                    encoded_after=encoded_graph(after, glow.arch, config, preproc, torch))
                if stage["encoded_after"]["node_features"] != observed["batch"]["node_labels"]["values"]:
                    raise ValueError("Observer encoding differs from the actual final batch")
                payload["functions"].append(stage)
        payload["observer_errors"] = observer.errors
        if not payload["functions"] or payload["forward_attempts"] or payload["location_errors"] or observer.errors:
            raise ValueError("Incomplete no-forward graph capture")
        guard.validate_request(native)
        payload["status"] = "captured"
        payload["original_identities_rechecked"] = True
    except Exception as error:
        payload["status"] = "failed"
        payload["error"] = {"type": type(error).__name__, "message": str(error)}
    payload["diagnostic_seconds"] = time.monotonic() - started
    guard.write(args.output, payload)
    print("Graph stages: {}; {} functions; {} forward attempts".format(
        payload["status"], len(payload["functions"]), payload["forward_attempts"]), flush=True)
    if payload["status"] != "captured":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
