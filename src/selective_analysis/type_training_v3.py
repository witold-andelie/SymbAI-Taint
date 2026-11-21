"""Type pilot v3 (training-coverage expansion): data assembly, folds, stacking and decisions.

No import-time dependency on torch. Follows type_pilot_v3_preregistration.md literally.
"""
import math
from pathlib import Path, PureWindowsPath

from .type_corpus import sha
from .type_training import load_reviewed_dataset, read, safe_file, validate_sample
from .type_training_v2 import PREREGISTRATION_SHA256 as V2_PREREGISTRATION_SHA256
from .type_training_v2 import load_dev_extension

PREREGISTRATION = Path("benchmarks/selective_analysis/route_b/type_pilot_v3_preregistration.md")
PREREGISTRATION_SHA256 = "efb974c46039dfb14219687f6390f1d7b45a6226142141a69d42388716bf9392"
SEEDS = (17, 29, 43)
DEPTHS = (2, 4)
MIN_DEVELOPMENT = 150
MIN_EXPANDED_TRAINING = 600
REUSED_PROJECTS = ("inih", "rxi_map", "jsmn", "optparse", "sds", "tiny_regex_c")
SEALED_PROJECTS = ("utf8_h", "b64")
OUTCOMES = {
    "H2 or H3": "Neural scores carry incremental information here. Design the fixed-query Route B "
                "scheduling comparison. The type-blind arm receives A5 features; the typed arm "
                "receives DS scores if H3 holds, otherwise DG scores.",
    "H1 without H2 or H3": "More coverage helps the GNN, but it adds nothing beyond structure. Close the "
                           "neural-type branch at this scale; Route B continues with structural, "
                           "type-blind features. Variant E is not pursued.",
    "Neither": "Report a negative result for neural type information at this scale and stop.",
}


def _relative(directory, name):
    if not isinstance(name, str) or Path(name).is_absolute() or PureWindowsPath(name).drive:
        raise ValueError("Dataset artifacts must have relative paths")
    return safe_file(directory, name)


def _variables(samples):
    return [t["source_variable_id"] for s in samples for t in s["supervision"]["targets"]]


def load_v3_export(directory, vocabulary, vocabulary_sha256, previous_ids):
    """Admit the audited v3 export (new training and fresh development projects)."""
    directory = Path(directory).resolve()
    dataset = read(directory / "dataset.json")
    audit = read(directory / "independent-export-audit.json")
    if (dataset["schema"] != "symbai.type_v3_graph_dataset.v1"
            or dataset["preregistration_sha256"] != PREREGISTRATION_SHA256
            or dataset["relation_count"] != 60 or dataset["feature_width"] != 31
            or dataset["labels_separate_from_features"] is not True
            or dataset["evaluation_projects_executed"] is not False):
        raise ValueError("v3 dataset contract differs")
    if (audit["schema"] != "symbai.type_v3_graph_export_audit.v1"
            or audit["evaluation_projects_executed"] is not False or audit["training_performed"] is not False):
        raise ValueError("v3 audit contract differs")
    for name, expected in audit["sha256"].items():
        if sha(_relative(directory, name)) != expected:
            raise ValueError("v3 audit artifact changed: " + name)
    entry = dataset["vocabulary"]
    if entry["sha256"] != vocabulary_sha256 or sha(_relative(directory, entry["path"])) != vocabulary_sha256:
        raise ValueError("v3 vocabulary differs from v1 bytes")
    samples, functions, seen = [], set(), set()
    for item in dataset["samples"]:
        if item["split"] not in ("train", "development"):
            raise ValueError("Invalid v3 split")
        if item["project_id"] in REUSED_PROJECTS + SEALED_PROJECTS:
            raise ValueError("Reused or sealed project inside the v3 export")
        if item["function_id"] in functions:
            raise ValueError("Duplicate v3 function")
        functions.add(item["function_id"])
        loaded = {}
        for key in ("features", "supervision"):
            path = _relative(directory, item[key]["path"])
            if sha(path) != item[key]["sha256"]:
                raise ValueError("v3 sample changed")
            loaded[key] = read(path)
        validate_sample(loaded["features"], loaded["supervision"], vocabulary)
        for target in loaded["supervision"]["targets"]:
            identity = target["source_variable_id"]
            if identity in seen or identity in previous_ids:
                raise ValueError("Duplicate or overlapping v3 source variable")
            seen.add(identity)
        samples.append(dict(item, **loaded))
    split_projects = {}
    for s in samples:
        split_projects.setdefault(s["project_id"], set()).add(s["split"])
    if any(len(v) != 1 for v in split_projects.values()):
        raise ValueError("A v3 project crosses splits")
    for split in ("train", "development"):
        chosen = [s for s in samples if s["split"] == split]
        count = len(_variables(chosen))
        rows = sum(len(t["readout_rows"]) for s in chosen for t in s["supervision"]["targets"])
        if (dataset["admitted_source_variables"][split] != count or audit["admitted_source_variables"][split] != count
                or dataset["supervised_value_rows"][split] != rows
                or audit["exported_functions"][split] != len(chosen)):
            raise ValueError("v3 denominators differ: " + split)
    return samples


def assemble(v1_dir, v2_dir, v3_dir):
    """Return (original, expanded, development, vocabulary, admission).

    original = the reviewed 129-variable v1 training split, in v1 order (needed for digest
    reproduction). expanded = original + optparse + sds/tiny-regex-c + new v3 training, all
    relabelled 'train'. development = the fresh v3 development projects.
    """
    v1, vocabulary, admission = load_reviewed_dataset(v1_dir)
    vocabulary_sha256 = read(Path(v1_dir) / "dataset.json")["vocabulary"]["sha256"]
    v2 = load_dev_extension(v2_dir, V2_PREREGISTRATION_SHA256, v1_dir)
    previous = set(_variables(v1)) | set(_variables(v2))
    v3 = load_v3_export(v3_dir, vocabulary, vocabulary_sha256, previous)
    original = [dict(s, origin="v1_train") for s in v1 if s["split"] == "train"]
    reused = ([dict(s, split="train", origin="v1_optparse") for s in v1 if s["split"] == "development"]
              + [dict(s, split="train", origin="v2_development") for s in v2])
    new_training = [dict(s, origin="v3_train") for s in v3 if s["split"] == "train"]
    development = [dict(s, origin="v3_development") for s in v3 if s["split"] == "development"]
    expanded = original + reused + new_training
    if set(_variables(expanded)) & set(_variables(development)):
        raise ValueError("Training and development overlap")
    counts = {"original_training": len(_variables(original)), "expanded_training": len(_variables(expanded)),
              "development": len(_variables(development)),
              "expanded_training_projects": projects(expanded), "development_projects": projects(development)}
    return original, expanded, development, vocabulary, dict(admission, v3_counts=counts)


def projects(samples):
    order = []
    for s in samples:
        if s["project_id"] not in order:
            order.append(s["project_id"])
    return order


def minimum_check(counts):
    failures = []
    if counts["development"] < MIN_DEVELOPMENT:
        failures.append("development {} < {}".format(counts["development"], MIN_DEVELOPMENT))
    if counts["expanded_training"] < MIN_EXPANDED_TRAINING:
        failures.append("expanded training {} < {}".format(counts["expanded_training"], MIN_EXPANDED_TRAINING))
    return failures


def folds(expanded):
    """Leave-one-project-out folds over the expanded training projects, in first-appearance order."""
    result = []
    for project in projects(expanded):
        held = [s for s in expanded if s["project_id"] == project]
        kept = [s for s in expanded if s["project_id"] != project]
        result.append((project, kept, held))
    return result


def choose_depth(pooled_correct):
    """pooled_correct: {depth: pooled held-out Top-1 count}. Larger wins; a tie selects 2."""
    if set(pooled_correct) != set(DEPTHS):
        raise ValueError("Both depths are required")
    return 4 if pooled_correct[4] > pooled_correct[2] else 2


def log_softmax(row):
    top = max(row)
    total = top + math.log(sum(math.exp(v - top) for v in row))
    return [v - total for v in row]


def stacked_vectors(structural, scores):
    """Concatenate 48 A5 features with the 75 log-softmax values of G's mean logits."""
    if len(structural) != len(scores):
        raise ValueError("Stacking inputs differ in length")
    out = []
    for features, row in zip(structural, scores):
        if len(features) != 48 or len(row) != 75 or any(not math.isfinite(v) for v in row):
            raise ValueError("Invalid stacking input")
        out.append(list(features) + log_softmax(row))
    return out


def decision_rules(n, dg, dgo, d5, ds):
    """dg, dgo, ds: {seed: development metrics}; d5: development metrics (fitted once)."""
    if type(n) is not int or n <= 0:
        raise ValueError("A positive development denominator is required")
    for arm in (dg, dgo, ds):
        if set(arm) != set(SEEDS):
            raise ValueError("All three pre-registered seeds are required")
    margin = max(3, (n + 19) // 20)
    for metrics in list(dg.values()) + list(dgo.values()) + list(ds.values()) + [d5]:
        if (metrics["source_variables"] != n or type(metrics["correct_top1"]) is not int
                or not 0 <= metrics["correct_top1"] <= n):
            raise ValueError("Invalid primary metrics or denominator")
    rows = []
    for seed in SEEDS:
        h1 = dg[seed]["correct_top1"] - dgo[seed]["correct_top1"]
        h2 = dg[seed]["correct_top1"] - d5["correct_top1"]
        h3 = ds[seed]["correct_top1"] - d5["correct_top1"]
        rows.append({"seed": seed, "DG_minus_DGo": h1, "DG_minus_D5": h2, "DS_minus_D5": h3,
                     "H1": h1 >= margin, "H2": h2 >= margin, "H3": h3 >= margin})
    h1, h2, h3 = (all(r[k] for r in rows) for k in ("H1", "H2", "H3"))
    outcome = "H2 or H3" if (h2 or h3) else ("H1 without H2 or H3" if h1 else "Neither")
    return {"schema": "symbai.type_pilot_v3_decision.v1", "N": n, "m": margin, "per_seed": rows,
            "H1": h1, "H2": h2, "H3": h3, "outcome": outcome, "next_step": OUTCOMES[outcome],
            "typed_arm_scores_for_scheduling": ("DS" if h3 else "DG") if (h2 or h3) else None}
