"""Charged, fresh TYGR export and matching against a fixed reviewed locator plan."""

import json
import math
import os
from pathlib import Path
import time
import uuid

from .contracts import file_hash, fingerprint
from .processes import run_bounded
from .types import TypeInformationUnavailable, load_type_view

ROOT = Path(__file__).resolve().parents[2]


class TypeAcquisitionTimeout(TimeoutError):
    pass


def _configuration(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    allowed = {"schema", "python", "tygr_root", "model", "model_sha256", "mapping", "top_k", "device"}
    required = {"schema", "python", "tygr_root", "model", "model_sha256", "mapping"}
    if data.get("schema") != "symbai.online_tygr.v1" or set(data) - allowed or not required.issubset(data):
        raise TypeInformationUnavailable("Invalid online provider configuration or unexpected fields")
    if data.get("device", "cpu") != "cpu" or not isinstance(data.get("top_k", 3), int) or data.get("top_k", 3) < 2:
        raise TypeInformationUnavailable("Pilot provider requires CPU and a common Top-K of at least two")
    for key in ("python", "tygr_root", "model", "mapping"):
        data[key] = str((path.parent / data[key]).resolve())
    if not Path(data["python"]).is_file() or not Path(data["tygr_root"], "src/methods/glow/preproc.py").is_file():
        raise TypeInformationUnavailable("TYGR interpreter or source is unavailable")
    if not Path(data["model"]).is_file() or not Path(data["mapping"]).is_file():
        raise TypeInformationUnavailable("Online model or reviewed mapping plan is unavailable")
    if file_hash(data["model"]) != data["model_sha256"]:
        raise TypeInformationUnavailable("Online model content differs from its frozen identity")
    return data


def _export_command(config, query, raw_path, scratch, acquisition_id):
    return [config["python"], "-B", str(ROOT / "scripts/export_tygr_candidates.py"),
            "--tygr-root", config["tygr_root"], "--model", config["model"],
            "--binary", query.binary, "--top-k", str(config.get("top_k", 3)), "--device", "cpu",
            "--output", str(raw_path), "--scratch-dir", str(scratch),
            "--acquisition-id", acquisition_id]


def validate_stage_profile(profile, query, config, raw_hash, acquisition_id, process_seconds):
    expected_stages = {"imports", "model_loading", "graph_generation", "graph_preprocessing",
                       "batch_preparation", "model_forward", "logit_export", "identity_hashing", "raw_serialization"}
    seconds, calls = profile.get("stage_seconds", {}), profile.get("stage_calls", {})
    if (profile.get("schema") != "symbai.tygr_stage_profile.v1" or profile.get("device") != "cpu"
            or profile.get("clock") != "monotonic"
            or profile.get("acquisition_id") != acquisition_id
            or profile.get("binary_sha256") != query.binary_sha256
            or profile.get("model_sha256") != config["model_sha256"]
            or profile.get("raw_artifact_sha256") != raw_hash
            or profile.get("ground_truth_labels_supplied_to_model") is not False):
        raise TypeInformationUnavailable("Stage profile identity or unlabeled CPU contract failed")
    if (set(seconds) != expected_stages or set(calls) != expected_stages
            or any(not isinstance(v, (float, int)) or isinstance(v, bool) or not math.isfinite(v) or v < 0 for v in seconds.values())
            or any(not isinstance(v, int) or isinstance(v, bool) or v <= 0 for v in calls.values())):
        raise TypeInformationUnavailable("Stage profile has invalid or missing timings")
    script = profile.get("script_elapsed_seconds", -1)
    accounted, unallocated = profile.get("accounted_stage_seconds", -1), profile.get("unallocated_script_seconds", -1)
    if (any(not isinstance(v, (float, int)) or isinstance(v, bool) or not math.isfinite(v) or v < 0 for v in (script, accounted, unallocated))
            or abs(sum(seconds.values()) - accounted) > 1e-6
            or abs(accounted + unallocated - script) > 1e-6 or script > process_seconds + 0.001
            or calls["imports"] != 1 or calls["model_loading"] != 1
            or calls["model_forward"] != profile.get("functions_with_predictions")
            or any(calls[name] != calls["model_forward"] for name in ("graph_preprocessing", "batch_preparation", "logit_export"))
            or calls["graph_generation"] < calls["model_forward"] + 1):
        raise TypeInformationUnavailable("Stage profile accounting or call counts are inconsistent")


def acquire_type_view(query, variant, config_path, output, deadline, emit, within_worker=False,
                      profile_stages=False):
    if variant not in ("C", "D"):
        raise ValueError("Only neural variants acquire online types")
    started = time.monotonic()
    if started >= deadline:
        raise TypeAcquisitionTimeout("Budget exhausted before online acquisition")
    config = _configuration(Path(config_path))
    mapping = json.loads(Path(config["mapping"]).read_text(encoding="utf-8"))
    links = [link for link in mapping["mappings"] if link.get("use_site_id") == query.use_site_id]
    if (len(links) != 1 or not links[0].get("expected_identity")
            or not links[0].get("reviewed_by") or not links[0].get("evidence")):
        raise TypeInformationUnavailable("Online mapping requires a reviewed function/location identity anchor")
    output.mkdir(parents=True, exist_ok=False)
    scratch = output / "cache"
    scratch.mkdir()
    raw_path, mapped_path = output / "raw-types.json", output / "mapped-types.json"
    acquisition_id = uuid.uuid4().hex
    environment = os.environ.copy()
    for key in ("TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME", "TORCH_HOME", "HF_HOME"):
        environment[key] = str(scratch)
    for key in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS"):
        environment[key] = "1"
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONHASHSEED"] = "0"
    emit("type_export_started", acquisition_id=acquisition_id,
         provider_hash=fingerprint(config), model_sha256=config["model_sha256"],
         mapping_plan_sha256=file_hash(config["mapping"]),
         exporter_sha256=file_hash(ROOT / "scripts/export_tygr_candidates.py"),
         remaining_seconds=max(0.0, deadline - time.monotonic()))
    command = _export_command(config, query, raw_path, scratch, acquisition_id)
    profile_path = output / "stage-profile.json"
    if profile_stages:
        command.extend(["--profile-output", str(profile_path)])
    process = run_bounded(command,
                          output / "export.log", deadline - time.monotonic(),
                          env=environment, isolated=not within_worker)
    emit("type_export_finished", acquisition_id=acquisition_id, returncode=process.returncode,
         timed_out=process.timed_out, elapsed_seconds=process.elapsed_seconds)
    if process.timed_out or time.monotonic() >= deadline:
        raise TypeAcquisitionTimeout("Budget exhausted during online TYGR export")
    if process.returncode or not raw_path.is_file():
        raise TypeInformationUnavailable("Online TYGR export failed; see " + str(output / "export.log"))
    raw = json.loads(raw_path.read_text(encoding="utf-8"))
    provenance = raw.get("provenance", {})
    if (raw.get("acquisition_id") != acquisition_id or raw.get("binary_sha256") != query.binary_sha256
            or raw.get("schema") != "symbai.tygr_raw.v1"
            or provenance.get("source") != "tygr_glowgnn"
            or provenance.get("decoder") != "independent"
            or provenance.get("model_sha256") != config["model_sha256"]
            or provenance.get("ground_truth_labels_supplied_to_model") is not False):
        raise TypeInformationUnavailable("Fresh export identity, source or unlabeled-inference contract failed")
    profile_hash = None
    if profile_stages:
        if not profile_path.is_file():
            raise TypeInformationUnavailable("Fresh exporter did not return its requested stage profile")
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        validate_stage_profile(profile, query, config, file_hash(raw_path), acquisition_id, process.elapsed_seconds)
        if profile.get("variable_records") != len(raw["records"]):
            raise TypeInformationUnavailable("Stage profile variable count differs from raw predictions")
        profile_hash = file_hash(profile_path)
    mapping_started = time.monotonic()
    from scripts.map_tygr_candidates import map_candidates
    mapped = map_candidates(raw, [query], {"mappings": links})
    if any(len(record.get("candidates", [])) != config.get("top_k", 3) for record in mapped["records"]):
        raise TypeInformationUnavailable("Fresh candidate count differs from the common configured Top-K")
    mapped["raw_artifact_sha256"] = file_hash(raw_path)
    mapped["acquisition_id"] = acquisition_id
    mapped_path.write_text(json.dumps(mapped, indent=2), encoding="utf-8")
    view = load_type_view(mapped_path, query, variant)
    summary = {"acquisition_id": acquisition_id, "model_sha256": config["model_sha256"],
               "raw_artifact_sha256": mapped["raw_artifact_sha256"],
               "mapped_artifact_sha256": file_hash(mapped_path),
               "export_wall_seconds": process.elapsed_seconds,
               "mapping_seconds": time.monotonic() - mapping_started,
               "elapsed_seconds": time.monotonic() - started,
               "python_hash_seed": 0,
               "cache_policy": "fresh_export_per_query_cold_process", "provider_hash": fingerprint(config)}
    if profile_hash is not None:
        summary["stage_profile_sha256"] = profile_hash
    emit("type_mapping_finished", **summary)
    if time.monotonic() >= deadline:
        raise TypeAcquisitionTimeout("Budget exhausted during online type mapping")
    return view, summary
