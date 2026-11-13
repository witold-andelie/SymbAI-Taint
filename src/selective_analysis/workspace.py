"""Keep process temporary files and library caches in the workspace."""

import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRATCH = ROOT.parent / ".scratch" / "selective_analysis"


def configure_workspace():
    SCRATCH.mkdir(parents=True, exist_ok=True)
    for name in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME", "TORCH_HOME", "HF_HOME"):
        location = SCRATCH / name.lower()
        location.mkdir(exist_ok=True)
        os.environ[name] = str(location)
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    return SCRATCH
