#!/usr/bin/env python3
"""Compile one direct-index integration fixture and export genuine TYGR logits in WSL."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tygr-python", type=Path, default=Path("/root/miniconda3/envs/tygr-orig/bin/python"))
    args = parser.parse_args()
    if not sys.platform.startswith("linux") or not str(ROOT).startswith("/mnt/d/"):
        parser.error("Run in WSL from the D-drive project")
    from src.selective_analysis.workspace import configure_workspace
    from src.selective_analysis.contracts import file_hash
    configure_workspace()
    for variable in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS"):
        os.environ[variable] = "1"
    output = ROOT.parent / ".scratch/wsl" / ("inference-" + time.strftime("%Y%m%d-%H%M%S") + "-" + str(os.getpid()))
    output.mkdir(parents=True, exist_ok=False)
    source = ROOT / "benchmarks/selective_analysis/inference_probe.c"
    binary = output / "probe.elf"
    commands = [
        ("compile", ["gcc", "-gdwarf-4", "-O0", "-fPIE", "-pie", "-fno-stack-protector",
                     "-fno-omit-frame-pointer", str(source), "-o", str(binary)], 30),
        ("symbols", ["nm", "-S", "--defined-only", str(binary)], 15),
        ("disassembly", ["objdump", "--disassemble=probe_write", str(binary)], 15),
        ("inference", [str(args.tygr_python), "-B", str(ROOT / "scripts/export_tygr_candidates.py"),
                       "--tygr-root", str(ROOT / "tygr_original"),
                       "--model", str(ROOT / "tygr_original/model/MODEL_base/x64.O0.base.model"),
                       "--binary", str(binary), "--top-k", "3", "--device", "cpu",
                       "--output", str(output / "raw-types.json")], 180),
    ]
    print("Inference integration output: " + str(output), flush=True)
    (output / "commands.json").write_text(json.dumps(commands, indent=2), encoding="utf-8")
    for stage, command, limit in commands:
        print("Running " + stage, flush=True)
        log = output / (stage + ".log")
        try:
            with log.open("w", encoding="utf-8") as stream:
                subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT,
                               timeout=limit, check=True)
        except (OSError, subprocess.SubprocessError):
            if log.exists():
                print("\n".join(log.read_text(encoding="utf-8", errors="replace").splitlines()[-30:]))
            print("Stage failed; logs retained on D: " + str(log))
            raise
    raw = json.loads((output / "raw-types.json").read_text(encoding="utf-8"))
    if raw.get("binary_sha256") != file_hash(binary) or not raw.get("records"):
        raise ValueError("Inference produced no matching variable records")
    summary = {"schema": "symbai.inference_probe.v1", "purpose": "single_mechanism_integration_only",
               "source_sha256": file_hash(source), "binary": str(binary),
               "binary_sha256": raw["binary_sha256"], "provenance": raw["provenance"],
               "measured_export_seconds": raw["measured_export_seconds"],
               "mapping_status": "awaiting_location_and_dependency_review",
               "records": [{"prediction_id": record["prediction_id"],
                            "locator_variable_name": record.get("locator_variable_name"),
                            "function_address": record["function_address"],
                            "locations": record["locations"], "candidates": record["candidates"],
                            "class_count": len(record["vocabulary"])} for record in raw["records"]]}
    (output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    print("Finished. Genuine logits exported; use-site mapping still requires review. Reports: " + str(output))


if __name__ == "__main__":
    main()
