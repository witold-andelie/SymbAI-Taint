"""Timing and CLI wiring tests; the dummy backend is never empirical neural evidence."""

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import uuid

import pytest

from src.selective_analysis.online_types import validate_stage_profile
from src.selective_analysis.types import TypeInformationUnavailable

ROOT = Path(__file__).resolve().parents[1]


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def tmp_path():
    path = ROOT.parent / ".scratch/selective_analysis/tests" / ("profile-" + uuid.uuid4().hex[:12])
    path.mkdir(parents=True)
    return path


def test_stage_timer_excludes_consumers_and_includes_generator_exhaustion():
    exporter = load_script("export_tygr_candidates")
    clock = [0.0]
    timings = exporter.StageTimings(lambda: clock[0])
    def source():
        clock[0] += 2
        yield "a"
        clock[0] += 3
        yield "b"
        clock[0] += 4
    for _ in timings.items(source(), "generation"):
        with timings.measure("consumer"):
            clock[0] += 100
    receipt = timings.snapshot(clock[0])
    assert receipt["stage_seconds"] == {"generation": 9, "consumer": 200}
    assert receipt["stage_calls"] == {"generation": 3, "consumer": 2}
    assert receipt["unallocated_script_seconds"] == 0
    with timings.measure("outer"):
        with pytest.raises(ValueError, match="overlap"):
            with timings.measure("inner"):
                pass


def test_profiled_forward_keeps_labels_absent_and_separates_batch_cost():
    exporter = load_script("export_tygr_candidates")
    clock = [0.0]
    timings = exporter.StageTimings(lambda: clock[0])
    def collate(values):
        assert values == ["graph"]
        clock[0] += 7
        return (1, 2, 3, 4, 5, 6)
    class Model:
        def forward(self, batch):
            assert batch == (1, 2, 3, 4, 5, 6, None)
            clock[0] += 3
            return "unaltered prediction"
        __call__ = forward
    assert exporter.forward_unlabeled(Model(), "graph", collate, "cpu", timings) == "unaltered prediction"
    assert timings.seconds == {"batch_preparation": 7, "model_forward": 3}


def profile_fixture(query):
    names = ("imports", "model_loading", "graph_generation", "graph_preprocessing",
             "batch_preparation", "model_forward", "logit_export", "identity_hashing", "raw_serialization")
    return {"schema": "symbai.tygr_stage_profile.v1", "device": "cpu", "clock": "monotonic", "acquisition_id": "fixture",
            "binary_sha256": query.binary_sha256, "model_sha256": "model", "raw_artifact_sha256": "raw",
            "ground_truth_labels_supplied_to_model": False, "functions_with_predictions": 1,
            "stage_seconds": {name: 0.01 for name in names},
            "stage_calls": {name: 2 if name == "graph_generation" else 1 for name in names},
            "accounted_stage_seconds": 0.09, "script_elapsed_seconds": 0.1, "unallocated_script_seconds": 0.01}


@pytest.mark.parametrize("change", ("nonce", "negative", "nan", "overlap", "missing_stage", "bad_counts"))
def test_profile_receipt_rejects_wrong_identity_or_accounting(change):
    query = SimpleNamespace(binary_sha256="binary")
    profile = profile_fixture(query)
    validate_stage_profile(profile, query, {"model_sha256": "model"}, "raw", "fixture", 0.2)
    if change == "nonce":
        profile["acquisition_id"] = "stale"
    elif change in ("negative", "nan"):
        profile["stage_seconds"]["model_forward"] = -1 if change == "negative" else float("nan")
    elif change == "overlap":
        profile["accounted_stage_seconds"] = 0.2
    elif change == "missing_stage":
        del profile["stage_seconds"]["graph_generation"]
    else:
        profile["stage_calls"]["model_forward"] = 2
    with pytest.raises(TypeInformationUnavailable, match="Stage profile"):
        validate_stage_profile(profile, query, {"model_sha256": "model"}, "raw", "fixture", 0.2)


def test_exporter_profile_wiring_with_explicitly_fake_backend(tmp_path):
    import subprocess
    import sys
    from src.selective_analysis.contracts import file_hash
    root = tmp_path / "controlled_exporter_fixture_only"
    glow = root / "src/methods/glow"
    glow.mkdir(parents=True)
    for folder in (root / "src", root / "src/methods", glow):
        (folder / "__init__.py").write_text("", encoding="utf-8")
    (root / "torch.py").write_text('''from contextlib import nullcontext
from types import SimpleNamespace as S
class Tensor:
    ndim=2
    def __init__(self,rows): self.rows=rows; self.shape=(len(rows),2)
    def __getitem__(self,part): return Tensor(self.rows[part])
    def detach(self): return self
    def cpu(self): return self
    def tolist(self): return self.rows
class Vocabulary:
    def num_types(self): return 2
    def index_to_type(self,i): return ["char*","u64"][i]
class Model:
    config=S(decoder_type="independent",preproc_config=S(type_set=Vocabulary(),flatten_vars=True))
    def eval(self): return self
    def forward(self,batch):
        assert batch==(1,2,3,4,5,6,None)
        return Tensor([[2.0,1.0],[1.0,2.0]])
    __call__=forward
def load(path,map_location=None): return Model()
def no_grad(): return nullcontext()
def is_tensor(value): return isinstance(value,Tensor)
''', encoding="utf-8")
    (glow / "preproc.py").write_text("def preproc_input(value,config): return value\n", encoding="utf-8")
    (glow / "predict.py").write_text("def collate_inputs(values): return (1,2,3,4,5,6)\n", encoding="utf-8")
    (glow / "datagen.py").write_text('''from types import SimpleNamespace as S
class Options:
    def __init__(self,**kw): assert kw["predict_phase"] is False
class CfaLocation:
    arg=-24
def generate_glow_dataset_no_parallel(binary,scratch,options):
    variables=[S(nodes=[i],locs=[(0x100,0x200,CfaLocation())],name="fixture"+str(i)) for i in (1,2)]
    yield S(vars=variables,low_high_pc=(0x100,0x200),arch="fixture"), "POISON_GOLD_NOT_MODEL_INPUT"
''', encoding="utf-8")
    weights, binary = tmp_path / "dummy_weights", tmp_path / "dummy_binary"
    weights.write_bytes(b"explicitly fake test weights")
    binary.write_bytes(b"explicitly fake test input")
    raw_path, profile_path = tmp_path / "raw.json", tmp_path / "profile.json"
    command = [sys.executable, "-B", str(ROOT / "scripts/export_tygr_candidates.py"),
               "--tygr-root", str(root), "--model", str(weights), "--binary", str(binary),
               "--output", str(raw_path), "--top-k", "2", "--scratch-dir", str(tmp_path / "cache"),
               "--acquisition-id", "fixture", "--profile-output", str(profile_path)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    raw, profile = json.loads(raw_path.read_text()), json.loads(profile_path.read_text())
    assert raw["records"][0]["raw_value_node_logits"] == [[2.0, 1.0]]
    assert profile["variable_records"] == 2 and profile["functions_with_predictions"] == 1
    query = SimpleNamespace(binary_sha256=file_hash(binary))
    validate_stage_profile(profile, query, {"model_sha256": file_hash(weights)}, file_hash(raw_path), "fixture", 10)
    # Optional timing must not change any prediction or the no-label contract.
    ordinary_path = tmp_path / "ordinary.json"
    ordinary_command = command[:-2]
    ordinary_command[ordinary_command.index("--output") + 1] = str(ordinary_path)
    ordinary = subprocess.run(ordinary_command, capture_output=True, text=True, timeout=10)
    assert ordinary.returncode == 0, ordinary.stderr
    assert json.loads(ordinary_path.read_text())["records"] == raw["records"]
    # Use the real provider command path as well, with the same explicitly fake backend.
    import time
    from src.selective_analysis.contracts import Query
    from src.selective_analysis.online_types import acquire_type_view
    query = Query("controlled-fixture", str(binary), file_hash(binary), 0x100, 0x110, 0x2000, 8, ())
    location = {"low_pc": 0x100, "high_pc": 0x200, "location_class": "CfaLocation",
                "location_register": None, "location_argument": -24}
    mapping_path = tmp_path / "reviewed-fixture.json"
    mapping_path.write_text(json.dumps({"mappings": [{"prediction_id": "100:0", "use_site_id": query.use_site_id,
        "reviewed_by": "controlled test only", "evidence": "dummy location anchor, not an empirical mapping",
        "expected_identity": {"function_address": 0x100, "locations": [location]}}]}), encoding="utf-8")
    config_path = tmp_path / "fixture-provider.json"
    config_path.write_text(json.dumps({"schema": "symbai.online_tygr.v1", "python": sys.executable,
        "tygr_root": str(root), "model": str(weights), "model_sha256": file_hash(weights),
        "mapping": str(mapping_path), "top_k": 2, "device": "cpu"}), encoding="utf-8")
    acquired = tmp_path / "fresh-provider-output"
    view, receipt = acquire_type_view(query, "D", config_path, acquired, time.monotonic() + 10,
                                      lambda *a, **k: None, profile_stages=True)
    assert receipt["stage_profile_sha256"] == file_hash(acquired / "stage-profile.json")
    assert len(view.labels) == 2


def test_profile_summary_retains_failures_and_makes_no_warm_claim():
    script = load_script("profile_neural_acquisition")
    failed = {"status": "failed", "reason": "controlled failure"}
    assert script.summarize([failed])["completed"] == 0
    completed = {"status": "completed", "wall_seconds": 2, "prediction_identity": "x",
                 "profile": {"stage_seconds": {"imports": 1, "model_forward": 0.1}}}
    report = script.summarize([failed, completed, completed])
    assert report["trials"] == 3 and report["failed"] == 1 and report["completed"] == 2
    assert report["median_acquisition_wall_seconds"] == 2
    assert "no warm-service" in report["interpretation"]
