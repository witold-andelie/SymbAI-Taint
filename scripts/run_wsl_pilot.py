#!/usr/bin/env python3
"""Use the existing WSL environment for a small pilot; optionally fetch pinned TYGR files."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True

TYGR_COMMIT = "280320129a7f8bbfb9ee61b9a2155d2ddeac44c6"
TYGR_ORIGIN = "git@github.com:sefcom/TYGR.git"
MODEL_RELATIVE = "model/MODEL_base/x64.O0.base.model"
MODEL_GIT_BLOB = "d3a44c657e672ffc6d08a6b45bb343c91355eb37"
# Verified against GitHub's published host keys on 2026-11-11. This is a public
# server key, not an account credential. Keep the fingerprint independent of the key.
GITHUB_HOST_KEYS_SOURCE = "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints"
GITHUB_ED25519_KEY = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
GITHUB_ED25519_FINGERPRINT = "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"


def github_ssh_command(directory):
    """Bootstrap strict host verification using a pinned official key in a task-local file."""
    raw = base64.b64decode(GITHUB_ED25519_KEY, validate=True)
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
    if fingerprint != GITHUB_ED25519_FINGERPRINT:
        raise ValueError("GitHub host key fingerprint does not match the verified pin")
    directory.mkdir(parents=True, exist_ok=True)
    known_hosts = directory / "known_hosts"
    known_hosts.write_text("github.com ssh-ed25519 " + GITHUB_ED25519_KEY + "\n",
                          encoding="ascii", newline="\n")
    metadata = {"source": GITHUB_HOST_KEYS_SOURCE, "fingerprint": fingerprint,
                "known_hosts": str(known_hosts), "strict_host_key_checking": True}
    (directory / "host-trust.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    # SSH parses this option's value separately from the shell; preserve spaces in both.
    quoted_path = known_hosts.as_posix().replace("\\", "\\\\").replace('"', '\\"')
    return shlex.join(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
                       "-o", "StrictHostKeyChecking=yes", "-o", "HostKeyAlgorithms=ssh-ed25519",
                       "-o", "UpdateHostKeys=no", "-o", 'UserKnownHostsFile="' + quoted_path + '"'])


def run_stage(name, command, output, timeout=300):
    log = output / (name + ".log")
    print("Running {} (log: {})".format(name, log), flush=True)
    try:
        with log.open("w", encoding="utf-8") as stream:
            subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT,
                           check=True, timeout=timeout)
    except (subprocess.SubprocessError, OSError):
        if log.exists():
            print("\n".join(log.read_text(encoding="utf-8", errors="replace").splitlines()[-25:]))
        raise


def fetch_tygr(output):
    """Create an ignored sparse checkout; existing copies are verified, never overwritten."""
    target = ROOT / "tygr_original"
    environment = os.environ.copy()
    environment["GIT_TERMINAL_PROMPT"] = "0"
    environment["GIT_SSH_COMMAND"] = github_ssh_command(output / "ssh")
    log = output / "tygr-fetch.log"
    with log.open("w", encoding="utf-8") as stream:
        def git(*args):
            return subprocess.run(["git", *args], env=environment, cwd=ROOT,
                                  stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=180)
        if not target.exists():
            git("clone", "--depth", "1", "--filter=blob:none", "--no-checkout", TYGR_ORIGIN, str(target))
            git("-C", str(target), "fetch", "--depth", "1", "--filter=blob:none", "origin", TYGR_COMMIT)
            git("-C", str(target), "config", "core.sparseCheckout", "true")
            # Non-cone patterns retain only the source and one 6 MB pretrained model.
            (target / ".git/info/sparse-checkout").write_text(
                "/src/\n/environment.yml\n/readme.md\n/TYGR\n/" + MODEL_RELATIVE + "\n", encoding="utf-8")
            git("-C", str(target), "checkout", "--detach", "FETCH_HEAD")
        commit = subprocess.check_output(["git", "-C", str(target), "rev-parse", "HEAD"],
                                         env=environment, text=True, timeout=15).strip()
        if commit != TYGR_COMMIT:
            raise ValueError("Existing TYGR checkout differs from the pinned commit; it was left untouched")
        clean = subprocess.run(["git", "-C", str(target), "diff", "--quiet", "HEAD", "--", "src"],
                               env=environment, stdout=stream, stderr=subprocess.STDOUT, timeout=15)
        if clean.returncode:
            raise ValueError("TYGR tracked source has local changes; it was left untouched")
        if not (target / "src/methods/glow/preproc.py").is_file():
            raise ValueError("Existing TYGR checkout lacks the required source; it was left untouched")
        model = target / MODEL_RELATIVE
        raw = model.read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        if blob != MODEL_GIT_BLOB:
            raise ValueError("Model content differs from the verified official Git blob")
    provenance = {"origin": TYGR_ORIGIN, "commit": commit, "model": str(model),
                  "model_size_bytes": len(raw), "model_git_blob": blob,
                  "model_sha256": hashlib.sha256(raw).hexdigest()}
    (output / "tygr-source.json").write_text(json.dumps(provenance, indent=2), encoding="utf-8")
    return target, model


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch-tygr", action="store_true",
                        help="Fetch source and one official model over SSH, then inspect it with tygr-orig")
    parser.add_argument("--prepare-only", action="store_true",
                        help="With --fetch-tygr, prepare/inspect TYGR without running the mechanism experiments")
    parser.add_argument("--tygr-python", type=Path,
                        default=Path("/root/miniconda3/envs/tygr-orig/bin/python"))
    args = parser.parse_args()
    if args.prepare_only and not args.fetch_tygr:
        parser.error("--prepare-only requires --fetch-tygr")
    if sys.version_info < (3, 10):
        parser.error("Use angr-env's Python 3.10+; tygr-orig runs in a separate subprocess")
    if not sys.platform.startswith("linux") or not str(ROOT).startswith("/mnt/d/"):
        parser.error("Run this entry point inside WSL from the D-drive workspace")
    from src.selective_analysis.workspace import configure_workspace
    configure_workspace()
    output = ROOT.parent / ".scratch/wsl" / ("pilot-" + time.strftime("%Y%m%d-%H%M%S") + "-" + str(os.getpid()))
    output.mkdir(parents=True, exist_ok=False)
    print("WSL pilot output: {}".format(output), flush=True)
    if args.fetch_tygr:
        try:
            target, model = fetch_tygr(output)
        except Exception:
            log = output / "tygr-fetch.log"
            if log.exists():
                print("\n".join(log.read_text(encoding="utf-8", errors="replace").splitlines()[-15:]))
            print("TYGR fetch/verification failed. Existing files were not overwritten. See {}".format(log))
            raise
        run_stage("tygr-model-inspection", [str(args.tygr_python), "-B",
                  str(ROOT / "scripts/inspect_tygr_model.py"), "--tygr-root", str(target),
                  "--model", str(model), "--output", str(output / "tygr-model.json")], output, timeout=90)
        print((output / "tygr-model.json").read_text(encoding="utf-8"))
        if args.prepare_only:
            print("TYGR preparation completed. Conda environments were not modified. Reports: {}".format(output))
            return
    from importlib.metadata import version
    environment = {"python": sys.version, "executable": sys.executable,
                   "angr": version("angr"), "claripy": version("claripy"), "pyvex": version("pyvex")}
    (output / "environment.json").write_text(json.dumps(environment, indent=2), encoding="utf-8")
    from benchmarks.selective_analysis.mechanisms import make_mechanisms
    manifest = make_mechanisms(output / "mechanisms")
    from scripts.evaluate_selective_pilot import evaluate
    gold = json.loads((manifest.parent / "gold.json").read_text(encoding="utf-8"))
    for regime, budget in (("information_only", "1"), ("end_to_end", "5")):
        destination = output / regime
        command = [sys.executable, "-B", str(ROOT / "scripts/run_selective_pilot.py"),
                   "--manifest", str(manifest), "--variants", "A", "B", "C", "D",
                   "--budgets", budget, "--regime", regime, "--output", str(destination)]
        run_stage(regime, command, output)
        report = evaluate(json.loads((destination / "runs.json").read_text(encoding="utf-8")), gold)
        (destination / "evaluation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        for row in report["comparisons"]:
            print("{} {}: {}/{} resolved, {} unknown, {} wrong, {} unavailable".format(
                regime, row["variant"], row["resolved"], row["queries"], row["unknown"],
                row["wrong_decisions"], row["unavailable"]), flush=True)
        if any(row["wrong_decisions"] for row in report["comparisons"]):
            raise RuntimeError("A mechanism produced an incorrect decisive outcome; inspect the evidence")
    print("Finished. Reports are under {}".format(output), flush=True)


if __name__ == "__main__":
    main()
