#!/usr/bin/env python3
"""Inspect a locally acquired official model in TYGR's original Python environment."""

import argparse
import hashlib
import inspect
import json
import os
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("tygr-root", "model", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    root, model_path, output = (path.resolve() for path in (args.tygr_root, args.model, args.output))
    raw = model_path.read_bytes()
    expected_blob = "d3a44c657e672ffc6d08a6b45bb343c91355eb37"
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if blob != expected_blob:
        raise ValueError("Inspection is restricted to the verified x64.O0.base.model Git blob")
    scratch = Path(__file__).resolve().parents[2] / ".scratch/wsl/model-inspection"
    scratch.mkdir(parents=True, exist_ok=True)
    for name in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME", "TORCH_HOME", "HF_HOME"):
        os.environ[name] = str(scratch)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(root))
    os.chdir(scratch)
    import torch
    kwargs = {"map_location": "cpu"}
    if "weights_only" in inspect.signature(torch.load).parameters:
        kwargs["weights_only"] = False
    model = torch.load(str(model_path), **kwargs)
    model.eval()
    config = model.config
    preproc = config.preproc_config
    labels = [str(preproc.type_set.index_to_type(i)) for i in range(preproc.type_set.num_types())]
    from importlib import metadata
    report = {"schema": "symbai.tygr_model_inspection.v1", "python": sys.version,
              "torch": torch.__version__, "angr": metadata.version("angr"),
              "torch_geometric": metadata.version("torch-geometric"),
              "model_class": type(model).__name__, "model_sha256": hashlib.sha256(raw).hexdigest(),
              "decoder_type": str(getattr(config, "decoder_type", None)),
              "flatten_vars": bool(preproc.flatten_vars), "type_count": len(labels),
              "unique_display_labels": len(set(labels)) == len(labels),
              "forward_signature": str(inspect.signature(model.forward)),
              "supported_by_current_exporter": getattr(config, "decoder_type", None) == "independent",
              "inference_performed": False, "vocabulary": labels}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("Model loaded for inspection; no inference performed. Report: {}".format(output))


if __name__ == "__main__":
    main()
