#!/usr/bin/env python3
"""Export genuine GlowGNN logits in the external TYGR environment.

Run with TYGR's matching Python/torch stack. The upstream repository and weights are not
redistributed. This initial adapter supports independent classification decoders only and
uses the DWARF-assisted locator. Sequence beam scores are not per-variable class logits.
"""

import argparse
from contextlib import contextmanager, nullcontext
import hashlib
import inspect
import json
import math
import os
from pathlib import Path
import sys
import time


class StageTimings:
    """Flat CPU timings; generator consumption is measured separately from its consumers."""

    def __init__(self, clock=None):
        self.clock = clock or time.monotonic
        self.seconds, self.calls, self.active = {}, {}, None

    @contextmanager
    def measure(self, name):
        if self.active is not None:
            raise ValueError("Stage timings cannot overlap")
        self.active = name
        started = self.clock()
        try:
            yield
        finally:
            elapsed = self.clock() - started
            self.active = None
            if elapsed < 0:
                raise ValueError("Stage clock moved backwards")
            self.seconds[name] = self.seconds.get(name, 0.0) + elapsed
            self.calls[name] = self.calls.get(name, 0) + 1

    def items(self, iterable, name):
        iterator = iter(iterable)
        while True:
            with self.measure(name):
                try:
                    item = next(iterator)
                except StopIteration:
                    return
            yield item

    def snapshot(self, script_seconds):
        if self.active is not None:
            raise ValueError("Cannot finalize an active timing stage")
        accounted = sum(self.seconds.values())
        if accounted > script_seconds + 1e-6:
            raise ValueError("Stage times exceed the enclosing script clock")
        return {"stage_seconds": dict(self.seconds), "stage_calls": dict(self.calls),
                "accounted_stage_seconds": accounted, "script_elapsed_seconds": script_seconds,
                "unallocated_script_seconds": max(0.0, script_seconds - accounted)}


def stage(timings, name):
    return timings.measure(name) if timings is not None else nullcontext()


def sha256(path):
    value = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def pack_logits(rows, labels, top_k):
    """Retain original value-node logits and explicitly aggregate their arithmetic mean."""
    if not rows or not labels or not 1 <= top_k <= len(labels):
        raise ValueError("Invalid logits, vocabulary, or Top-K")
    if any(len(row) != len(labels) for row in rows):
        raise ValueError("Logit/vocabulary size mismatch")
    if not all(math.isfinite(float(x)) for row in rows for x in row):
        raise ValueError("Non-finite model logits")
    means = [sum(float(row[i]) for row in rows) / len(rows) for i in range(len(labels))]
    order = sorted(range(len(labels)), key=lambda i: (-means[i], i))[:top_k]
    return {"score_kind": "raw_logits", "normalization": "none",
            "aggregation": "mean_raw_logits_across_value_nodes",
            "raw_value_node_logits": rows, "vocabulary": labels,
            "candidates": [{"class_id": i, "label": labels[i], "rank": rank + 1,
                            "raw_score": means[i]} for rank, i in enumerate(order)]}


def forward_unlabeled(model, prepared, collate_inputs, device, timings=None):
    """Only graph/location features reach the model; no GlowOutput argument is accepted."""
    with stage(timings, "batch_preparation"):
        batch = collate_inputs([prepared])
        batch = tuple(value.to(device) if hasattr(value, "to") else value for value in batch) + (None,)
        parameters = inspect.signature(model.forward).parameters
    with stage(timings, "model_forward"):
        return model(batch) if len(parameters) == 1 else model(*batch)


def main():
    script_started = time.monotonic()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tygr-root", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--top-k", type=int, default=3)
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--scratch-dir", type=Path)
    parser.add_argument("--acquisition-id")
    parser.add_argument("--profile-output", type=Path, help="optional CPU-only stage receipt, separate from raw predictions")
    args = parser.parse_args()
    if args.profile_output and args.device != "cpu":
        parser.error("Stage profiling currently requires CPU")
    profile_path = args.profile_output.resolve() if args.profile_output else None
    timings = StageTimings() if profile_path else None
    root, model_path, binary, output = (p.resolve() for p in (args.tygr_root, args.model, args.binary, args.output))
    if profile_path == output:
        parser.error("Profile receipt and raw predictions require different output paths")
    if not (root / "src/methods/glow/preproc.py").is_file() or not model_path.is_file() or not binary.is_file():
        parser.error("External TYGR source, model and binary must exist")
    scratch = args.scratch_dir or Path(__file__).resolve().parents[2] / ".scratch" / "selective_analysis" / "tygr-export"
    scratch = scratch.resolve()
    scratch.mkdir(parents=True, exist_ok=True)
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME", "TORCH_HOME", "HF_HOME"):
        os.environ[key] = str(scratch)
    sys.dont_write_bytecode = True
    # This is a separate process: importing external 'src' cannot replace the pilot runtime.
    sys.path.insert(0, str(root))
    os.chdir(scratch)
    started = time.monotonic()
    with stage(timings, "imports"):
        import torch
        from src.methods.glow import datagen, preproc, predict
    with stage(timings, "model_loading"):
        parameters = {"map_location": args.device}
        if "weights_only" in inspect.signature(torch.load).parameters:
            parameters["weights_only"] = False
        model = torch.load(str(model_path), **parameters)
        model.eval()
        config = model.config.preproc_config
        if getattr(model.config, "decoder_type", None) != "independent":
            raise ValueError("Autoregressive/beam decoders require a separate documented scoring adapter; export refused")
        labels = [str(config.type_set.index_to_type(i)) for i in range(config.type_set.num_types())]
        if len(set(labels)) != len(labels):
            raise ValueError("Type vocabulary has ambiguous display labels; use a class-ID-aware adapter")
    # Upstream predict_phase=True is unfinished: sym_exec_one emits vars but no tys,
    # then the serial generator zips them and drops all variables. Reuse its existing
    # DWARF locator; the accompanying GlowOutput is discarded, never a model input.
    options = datagen.Options(parallel=False, pool_size=1, ignore_functions=False, predict_phase=False)
    records = []
    functions = 0
    with torch.no_grad():
        generated = datagen.generate_glow_dataset_no_parallel(str(binary), str(scratch), options)
        generated = timings.items(generated, "graph_generation") if timings else generated
        for glow_input, _unused_gold_output in generated:
            # Never pass source type labels to the model, even if the locator returns them.
            glow_input.vars = [v for v in glow_input.vars if v.nodes]
            if not glow_input.vars:
                continue
            with stage(timings, "graph_preprocessing"):
                prepared = preproc.preproc_input(glow_input, config)
            prediction = forward_unlabeled(model, prepared, predict.collate_inputs, args.device, timings)
            functions += 1
            with stage(timings, "logit_export"):
                logits = prediction[0] if isinstance(prediction, tuple) else prediction
                if not torch.is_tensor(logits) or logits.ndim != 2 or logits.shape[1] != len(labels):
                    raise ValueError("Model did not return an independent class-logit matrix")
                counts = [len(v.nodes) if config.flatten_vars else 1 for v in glow_input.vars]
                if sum(counts) != logits.shape[0]:
                    raise ValueError("Model row/variable identity mismatch; export refused")
                cursor = 0
                for variable_index, (variable, count) in enumerate(zip(glow_input.vars, counts)):
                    raw_rows = logits[cursor:cursor + count].detach().cpu().tolist()
                    cursor += count
                    record = pack_logits(raw_rows, labels, args.top_k)
                    locations = [{"low_pc": int(low), "high_pc": int(high) if high is not None else None,
                                  "location_class": type(loc).__name__,
                                  "location_value": int(getattr(loc, "reg_num", getattr(loc, "arg", 0))),
                                  "location_register": int(loc.reg_num) if hasattr(loc, "reg_num") else None,
                                  "location_argument": int(loc.arg) if hasattr(loc, "arg") else None}
                                 for low, high, loc in variable.locs]
                    record.update({"prediction_id": f"{int(glow_input.low_high_pc[0]):x}:{variable_index}",
                                   "function_address": int(glow_input.low_high_pc[0]),
                                   "locator_variable_name": variable.name,
                                   "upstream_arch_token": str(getattr(glow_input, "arch", None)),
                                   "locations": locations, "value_nodes": [int(n) for n in variable.nodes],
                                   "raw_row_axis": "value_node" if config.flatten_vars else "variable_readout"})
                    records.append(record)
    if not records:
        raise ValueError("No variable logits exported; DWARF locator/model compatibility must be checked")
    with stage(timings, "identity_hashing"):
        binary_hash, model_hash = sha256(binary), sha256(model_path)
    payload = {"schema": "symbai.tygr_raw.v1", "binary_sha256": binary_hash,
               "acquisition_id": args.acquisition_id,
               "provenance": {"source": "tygr_glowgnn", "model_sha256": model_hash,
                              "locator": "dwarf_assisted", "decoder": "independent",
                              "flatten_vars": bool(config.flatten_vars),
                              "datagen_predict_phase": False,
                              "ground_truth_labels_supplied_to_model": False},
               "measured_export_seconds": time.monotonic() - started, "records": records}
    with stage(timings, "raw_serialization"):
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if timings is not None:
        with timings.measure("identity_hashing"):
            raw_hash = sha256(output)
        receipt = {"schema": "symbai.tygr_stage_profile.v1", "device": "cpu", "clock": "monotonic",
                   "acquisition_id": args.acquisition_id, "binary_sha256": binary_hash,
                   "model_sha256": model_hash, "raw_artifact_sha256": raw_hash,
                   "functions_with_predictions": functions, "variable_records": len(records),
                   "ground_truth_labels_supplied_to_model": False,
                   "scope": "script_clock_excludes_interpreter_startup_and_own_receipt_writing",
                   **timings.snapshot(time.monotonic() - script_started)}
        profile_path.parent.mkdir(parents=True, exist_ok=True)
        profile_path.write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    print(f"Exported {len(records)} genuine raw-logit records to {output}")


if __name__ == "__main__":
    main()
