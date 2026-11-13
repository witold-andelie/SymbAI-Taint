#!/usr/bin/env python3
"""Locate existing TYGR installations without importing TYGR, installing or downloading."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True


def probe():
    # Run outside the project so its own 'src' package cannot mask an installed TYGR.
    info = {"python": sys.executable, "version": sys.version.split()[0],
            "prefix": sys.prefix, "modules": {}, "editable_paths": [], "packages": [],
            "entrypoints": [str(Path(sys.prefix) / "bin" / name) for name in ("TYGR", "tygr")
                            if (Path(sys.prefix) / "bin" / name).is_file()]}
    for name in ("tygr", "TYGR", "src"):
        try:
            spec = importlib.util.find_spec(name)
            if spec:
                info["modules"][name] = {"origin": spec.origin,
                    "locations": list(spec.submodule_search_locations or [])}
        except (ImportError, ValueError) as exc:
            info["modules"][name] = {"error": str(exc)}
    try:
        from importlib import metadata
        for distribution in metadata.distributions():
            name = distribution.metadata.get("Name", "")
            direct = distribution.read_text("direct_url.json")
            if "tygr" in name.lower() or (direct and "tygr" in direct.lower()):
                # Record local editable paths only, never remote URL credentials.
                from urllib.parse import urlparse, unquote
                url = urlparse(json.loads(direct).get("url", "")) if direct else None
                local = unquote(url.path) if url and url.scheme == "file" else None
                info["packages"].append({"name": name, "version": distribution.version,
                    "installed_at": str(distribution.locate_file("")), "local_source": local})
        for base in sys.path:
            directory = Path(base)
            if not directory.is_dir() or directory.name not in ("site-packages", "dist-packages"):
                continue
            for entry in list(directory.glob("*.egg-link")) + list(directory.glob("*.pth")):
                for line in entry.read_text(encoding="utf-8", errors="replace").splitlines():
                    if line.strip() and not line.startswith(("#", "import ")):
                        location = (directory / line.strip()).resolve()
                        if "tygr" in str(location).lower():
                            info["editable_paths"].append(str(location))
    except ImportError:
        info["metadata"] = "unavailable"
    return info


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--root", action="append", type=Path, default=[], help="Additional known source/model search root")
    args = parser.parse_args()
    if args.probe:
        print(json.dumps(probe()))
        return
    if not sys.platform.startswith("linux") or not str(ROOT).startswith("/mnt/d/"):
        parser.error("Run in WSL from the D-drive project")
    scratch = ROOT.parent / ".scratch/wsl"
    scratch.mkdir(parents=True, exist_ok=True)
    for name in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME", "TORCH_HOME", "HF_HOME"):
        cache = scratch / "locate-cache"
        cache.mkdir(exist_ok=True)
        os.environ[name] = str(cache)
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    envs = {Path(sys.prefix)}
    errors = []
    conda = shutil.which("conda") or "/root/miniconda3/bin/conda"
    try:
        result = subprocess.run([conda, "env", "list", "--json"], capture_output=True,
                                text=True, timeout=20, check=True)
        envs.update(Path(path) for path in json.loads(result.stdout)["envs"])
    except (OSError, subprocess.SubprocessError, ValueError, KeyError) as exc:
        errors.append("Conda registration scan: " + str(exc))
    for parent in (Path("/root/miniconda3/envs"), Path("/root/anaconda3/envs"), Path("/root/.conda/envs")):
        if parent.is_dir():
            envs.update(path for path in parent.iterdir() if path.is_dir())
    installations = []
    for env in sorted(envs):
        python = env / "bin/python"
        if not python.is_file():
            continue
        try:
            result = subprocess.run([str(python), "-B", str(Path(__file__).resolve()), "--probe"],
                                    cwd=scratch, capture_output=True, text=True, timeout=20, check=True)
            installations.append(json.loads(result.stdout))
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            errors.append(str(python) + ": " + str(exc))
    roots = {Path("/root"), Path("/home"), Path("/opt"), ROOT.parent, *args.root}
    roots.update(Path(item["prefix"]) for item in installations)
    for item in installations:
        roots.update(Path(p) for p in item["editable_paths"])
        roots.update(Path(p["local_source"]) for p in item["packages"] if p.get("local_source"))
        for module in item["modules"].values():
            roots.update(Path(p) for p in module.get("locations", []))
    sources, models, visited = set(), set(), set()
    deadline = time.monotonic() + 20
    incomplete = False
    skip = {".git", "pkgs", "__pycache__", ".cache", ".scratch", "node_modules", ".npm"}
    for root in sorted(roots):
        for directory, directories, files in os.walk(root, followlinks=False):
            if time.monotonic() > deadline:
                incomplete = True
                break
            directories[:] = [name for name in directories if name not in skip]
            if directory in visited:
                directories[:] = []
                continue
            visited.add(directory)
            here = Path(directory)
            if here.as_posix().endswith("/src/methods/glow") and "preproc.py" in files:
                sources.add(str(here.parents[2]))
            for filename in files:
                if filename.endswith(".model") and ("x64" in filename or "tygr" in directory.lower()):
                    models.add(str(here / filename))
        if incomplete:
            break
    report = {"schema": "symbai.tygr_location.v1", "installations": installations,
              "source_roots": sorted(sources), "model_files": sorted(models),
              "search_roots": sorted(str(p) for p in roots), "search_incomplete": incomplete,
              "errors": errors, "model_loaded": False, "downloads_performed": False}
    output = scratch / ("tygr-location-" + time.strftime("%Y%m%d-%H%M%S") + "-" + str(os.getpid()) + ".json")
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    print("Report: " + str(output))


if __name__ == "__main__":
    main()
