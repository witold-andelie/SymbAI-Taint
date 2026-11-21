#!/usr/bin/env python3
"""Acquire three pinned upstream blobs via SSH and inspect metadata only."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.selective_analysis import candidate_checkpoint as candidate
from src.selective_analysis import checkpoint_metadata as frozen

COMMIT = "280320129a7f8bbfb9ee61b9a2155d2ddeac44c6"
ORIGIN = "git@github.com:sefcom/TYGR.git"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fetch", action="store_true", help="Allow the pinned three-model SSH acquisition")
    args = parser.parse_args()
    scratch = (ROOT.parent / ".scratch/selective_analysis").resolve()
    output = args.output.resolve()
    output.relative_to(scratch)
    output.mkdir(parents=True, exist_ok=True)
    cache = output / "upstream.git"
    if not cache.is_dir():
        parser.error("The isolated, filtered upstream.git cache is required")
    temp = output / "temp"
    temp.mkdir(exist_ok=True)
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME"):
        os.environ[key] = str(temp)
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    env.pop("GIT_SSH_COMMAND", None)
    if os.name == "nt":
        env.update(GIT_SSH="C:/Windows/System32/OpenSSH/ssh.exe", GIT_SSH_VARIANT="ssh")
    if args.fetch:
        env.pop("GIT_NO_LAZY_FETCH", None)
    else:
        env["GIT_NO_LAZY_FETCH"] = "1"
    command = ["git", "-c", "gc.auto=0", "-c", "maintenance.auto=false"]
    if not args.fetch:
        command += ["-c", "protocol.allow=never"]
    command += ["--git-dir", str(cache)]

    def git(*arguments):
        return subprocess.run([*command, *arguments], env=env, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=True, timeout=30).stdout.decode("utf-8").strip()

    if git("rev-parse", "HEAD") != COMMIT or git("remote", "get-url", "origin") != ORIGIN:
        raise ValueError("Isolated upstream commit/origin differs")
    tree = git("ls-tree", "-r", COMMIT, "model/MODEL_base").splitlines()
    blobs = {}
    for line in tree:
        fields, name = line.split("\t")
        mode, kind, identity = fields.split()
        if mode == "100644" and kind == "blob":
            blobs[name] = identity
    copies = output / "source_snapshot"
    copies.mkdir(exist_ok=True)
    sources = {}
    for path in (Path(__file__), Path(candidate.__file__), Path(frozen.__file__)):
        copy = copies / path.name
        if copy.exists() and copy.read_bytes() != path.read_bytes():
            raise ValueError("Do not replace an existing source snapshot")
        copy.write_bytes(path.read_bytes())
        sources[str(path)] = sources[str(copy)] = sha(path)
    baseline = ROOT / "tygr_original/model/MODEL_base/x64.O0.base.model"
    if sha(baseline) != frozen.FROZEN_SHA256:
        raise ValueError("Frozen baseline identity differs")
    reference = candidate.inspect_candidate(baseline, blobs["model/MODEL_base/x64.O0.base.model"])
    write(output / "reference-metadata.json", reference)
    paths = ["model/MODEL_base/x64.O" + str(i) + ".base.model" for i in (1, 2, 3)]
    write(output / "plan.json", {"schema": "symbai.candidate_checkpoint_plan.v1", "commit": COMMIT,
        "origin": ORIGIN, "fetch_enabled": args.fetch, "reference_sha256": frozen.FROZEN_SHA256,
        "candidates": [{"path": name, "git_blob_sha1": blobs[name]} for name in paths], "sources": sources,
        "scope": "Three upstream x64 base blobs at one commit; passive metadata, no pickle execution, tensor reads, checkpoint inference or input-guard changes."})
    print("Candidate checkpoint output: " + str(output), flush=True)
    results = []
    for name in paths:
        target = output / Path(name).name
        partial = target.with_name(target.name + ".partial")
        log = target.with_suffix(target.suffix + ".fetch.log")
        row = {"path": name, "git_blob_sha1": blobs[name]}
        try:
            if not target.exists():
                with partial.open("wb") as stream, log.open("wb") as errors:
                    subprocess.run([*command, "cat-file", "blob", blobs[name]], env=env,
                        stdout=stream, stderr=errors, check=True, timeout=180)
                if candidate.git_blob_identity(partial.read_bytes()) != blobs[name]:
                    raise ValueError("Retrieved model does not match the pinned Git object")
                partial.replace(target)
            value = candidate.inspect_candidate(target, blobs[name])
            write(target.with_suffix(target.suffix + ".metadata.json"), value)
            row.update(assessment=candidate.assess_candidate(value, reference), sha256=value["sha256"],
                bytes=value["bytes"], parameter_arrays_read=False, status="audited")
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            row.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
        results.append(row)
        write(output / "records.json", results)
        print(Path(name).name + ": " + row["status"] + (" / " + row["assessment"]["status"] if "assessment" in row else " / " + str(row["error"])), flush=True)
    for path, expected in sources.items():
        if sha(path) != expected:
            raise ValueError("Audited implementation changed")
    if sha(baseline) != frozen.FROZEN_SHA256:
        raise ValueError("Frozen baseline changed")
    frameworks = sorted({name.split(".")[0] for name in sys.modules if name.split(".")[0] in ("torch", "torch_geometric", "angr", "claripy")})
    if frameworks:
        raise ValueError("Passive audit imported a model framework")
    summary = {"schema": "symbai.candidate_checkpoint_summary.v1", "commit": COMMIT,
        "planned": 3, "audited": sum(r["status"] == "audited" for r in results),
        "metadata_candidates": sum(r.get("assessment", {}).get("status") == "metadata_candidate" for r in results),
        "cases": results, "checkpoint_forward_attempts": 0, "frameworks_imported": frameworks,
        "frozen_model_unchanged": True, "frozen_reader_unchanged": True, "inference_admitted": False,
        "completed_utc": datetime.now(timezone.utc).isoformat(), "output": str(output)}
    write(output / "summary.json", summary)
    print(json.dumps(summary, indent=2), flush=True)
    if summary["audited"] != 3:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
