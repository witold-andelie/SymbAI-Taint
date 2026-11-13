"""Native capture orchestration boundaries; no original framework or forward execution."""

import ast
import hashlib
from pathlib import Path
from types import SimpleNamespace
import uuid

import pytest

from scripts import capture_tygr_preprocessing as worker
from scripts import run_native_preprocessing as cli
from scripts import audit_native_preprocessing as audit
from src.selective_analysis.workspace import SCRATCH


@pytest.fixture
def folder():
    root = SCRATCH / "tests" / ("native-parent-" + uuid.uuid4().hex)
    root.mkdir(parents=True)
    return root


@pytest.fixture
def contract():
    return {"model_sha256": cli.MODEL_SHA256, "node_label_encoding_dim": 1,
            "all_ops": ["Extract"], "num_all_ops": 2, "num_edge_ops": 4,
            "flatten_vars": True, "use_arch": True, "arch_fields": ["x64"],
            "type_count": 1, "decoder_type": "independent", "node_aggregation": "mean",
            "layer_relation_capacities": [2], "edge_reduce_op_map": {}}


def identities():
    case = {"case_id": "direct_index", "binary_sha256": "1" * 64, "entry_rva": 0x1129}
    return case, {"schema": "unit request", **case}


@pytest.mark.parametrize("mode", ["missing", "invalid_json", "identity", "launch_error", "partial", "timeout"])
def test_failed_workers_remain_in_matrix_and_preserve_payload_bytes(folder, contract, monkeypatch, mode):
    case, request = identities()

    def execute(command, log, timeout, **kwargs):
        assert 0 < timeout <= 60
        assert command[1] == "-B" and "source_snapshot" in command[2]
        result = Path(command[-1])
        if mode == "launch_error":
            raise OSError("unit missing executable")
        if mode == "invalid_json":
            result.write_text("not JSON", encoding="utf-8")
        elif mode in ("identity", "partial"):
            value = cli.placeholder(request, "unit partial")
            value["status"] = "collecting"
            if mode == "identity":
                value["request_identity"]["entry_rva"] += 1
            cli.write(result, value)
        return cli.ProcessOutcome(-1 if mode == "timeout" else 0, mode == "timeout", 0.1)

    monkeypatch.setattr(cli, "run_bounded", execute)
    row = cli.run_case(case, request, contract, folder, Path("unit-python"))
    receipt = row["parent_receipt"]
    assert receipt["status"] == "failed"
    payload_path = folder / "workers/direct_index/trial-payload.json"
    assert receipt["payload_sha256"] == hashlib.sha256(payload_path.read_bytes()).hexdigest()
    assert cli.read(payload_path) == row["payload"]
    summary = cli.summarize_native_trials([row], contract)
    assert summary["planned_cases"] == summary["failed"] == 3 and summary["captured"] == 0
    if mode == "invalid_json":
        assert (folder / "workers/direct_index/capture.json").read_text() == "not JSON"
    if mode == "launch_error":
        assert cli.read(folder / "workers/direct_index/launch-error.json")["type"] == "OSError"


@pytest.mark.parametrize("late", [False, True])
def test_clock_includes_validation_and_complete_payload_persistence(folder, contract, monkeypatch, late):
    case, request = identities()
    clock = [0.0]
    original_write = cli.write

    def execute(command, log, timeout, **kwargs):
        clock[0] = 1.0
        value = cli.placeholder(request, "fabricated complete parent envelope")
        value["status"] = "captured"
        original_write(Path(command[-1]), value)
        return cli.ProcessOutcome(0, False, 1.0)

    def validate(*_):
        clock[0] += 1.0
        return {"captured": True}

    def persist(path, value):
        original_write(path, value)
        if path.name == "trial-payload.json":
            clock[0] += 59.0 if late else 1.0
        if path.name == "receipt.json":
            clock[0] += 100.0  # Explicitly outside the charged interval.

    monkeypatch.setattr(cli.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(cli, "run_bounded", execute)
    monkeypatch.setattr(cli, "validate_native_capture", validate)
    monkeypatch.setattr(cli, "write", persist)
    receipt = cli.run_case(case, request, contract, folder, Path("unit-python"))["parent_receipt"]
    assert receipt["charged_seconds"] == (61.0 if late else 3.0)
    assert receipt["late"] is late
    assert receipt["status"] == ("failed" if late else "captured")


def test_all_model_modules_are_guarded_without_calling_original_forward():
    calls, receipt = [], {"forward_attempts": 0}
    class Module:
        def forward(self):
            calls.append("must not run")
    modules = [Module(), Module(), Module()]
    model = SimpleNamespace(modules=lambda: iter(modules))
    assert worker.block_model_forwards(model, receipt) == 3
    for module in modules:
        with pytest.raises(RuntimeError, match="forbidden"):
            module.forward()
    assert receipt["forward_attempts"] == 3 and calls == []


def test_empty_model_module_inventory_is_rejected():
    with pytest.raises(ValueError):
        worker.block_model_forwards(SimpleNamespace(modules=lambda: iter([])), {"forward_attempts": 0})


@pytest.mark.parametrize("failed", [False, True])
def test_stage_cost_accumulates_even_when_preparation_fails(monkeypatch, failed):
    times = iter([1.0, 4.0, 6.0, 11.0])
    monkeypatch.setattr(worker.time, "monotonic", lambda: next(times))
    capture = {"timings_seconds": {}}
    with worker.timed_stage(capture, "preprocessing"):
        pass
    try:
        with worker.timed_stage(capture, "preprocessing"):
            if failed:
                raise RuntimeError("unit failed preparation")
    except RuntimeError:
        assert failed
    assert capture["timings_seconds"]["preprocessing"] == 8.0


@pytest.mark.parametrize("value,expected", [(True, {"kind": "bool", "value": True}),
    (2 ** 120, {"kind": "int", "value": str(2 ** 120)}),
    (-0.0, {"kind": "float", "value": "-0x0.0p+0"})])
def test_actual_scalar_kind_and_exact_value_are_preserved(value, expected):
    assert worker.scalar_value(value) == expected


def test_unsupported_ast_values_are_not_substituted():
    with pytest.raises(ValueError, match="Unsupported actual"):
        worker.scalar_value(object())


class Tensor:
    def __init__(self, shape, values, dtype="torch.int64", device="cpu"):
        self.shape, self.values, self.dtype, self.device = shape, values, dtype, device
    def detach(self):
        return self
    def cpu(self):
        return self
    def tolist(self):
        return self.values


@pytest.mark.parametrize("shape,device", [([1], "cuda:0"), ([2, 2, 2], "cpu"), ([2000001], "cpu")])
def test_tensor_capture_rejects_gpu_unbounded_or_high_rank_data(shape, device):
    with pytest.raises(ValueError, match="bounded CPU"):
        worker.tensor_snapshot(Tensor(shape, [], device=device))


def test_native_graph_iteration_groups_and_collated_rows_are_preserved():
    graph = SimpleNamespace(graph=SimpleNamespace(nodes=[1, 0], edges=[(1, 0)]),
        node_to_label={node: SimpleNamespace(bitsize=64, addr=None, ast_val=node) for node in (1, 0)},
        edge_to_labels={(1, 0): {"B", "A"}})
    variable = SimpleNamespace(nodes=[1, 0], name="original", locs=[(0x1129, None, SimpleNamespace(arg=-24))])
    glow = SimpleNamespace(ast_graph=graph, vars=[variable], low_high_pc=(0x1129, 0x1140), arch="arch")
    prepared = SimpleNamespace(var_nodes=[[1], [0]], node_labels=Tensor([2, 1], [[0.0], [0.0]], "torch.float32"),
        edge_labels=Tensor([2], [1, 3]), edges=Tensor([2, 2], [[1, 0], [0, 1]]))
    batch = ([2], prepared.node_labels, prepared.edge_labels, prepared.edges,
             Tensor([2], [1, 0]), Tensor([2], [0, 1]))
    seen = []
    def encode(labels, inverse, config):
        seen.append((labels, inverse))
        return 3 if inverse else 1
    native = worker.capture_native_function(glow, SimpleNamespace(flatten_vars=True), encode, 0x1129)
    assert native["prepared"] is None and native["batch"] is None
    assert native["capture_stage"] == "native_before_preprocessing"
    assert native["variables"][0]["original_value_nodes"] == [1, 0]
    seen.clear()
    value = worker.capture_function(glow, prepared, batch, SimpleNamespace(flatten_vars=True), encode, 0x1129)
    assert value["graph_node_order"] == [1, 0]
    assert [row["graph_node_id"] for row in value["node_labels"]] == [1, 0]
    assert value["variables"][0]["original_value_nodes"] == [1, 0]
    assert value["variables"][0]["flattened_output_rows"] == [0, 1]
    assert value["readout_contract"]["exporter_value_row_groups"] == [[0, 1]]
    assert value["graph_edges"][0]["labels"] == ["A", "B"]
    assert seen == [({"A", "B"}, False), ({"A", "B"}, True)]
    assert value["batch"]["var_gather"]["values"] == [1, 0]
    assert value["variables"][0]["locations"][0]["location_argument"] == -24


def test_worker_is_python38_compatible_and_imports_no_framework_at_module_scope():
    tree = ast.parse(Path(worker.__file__).read_text(encoding="utf-8"), feature_version=(3, 8))
    imports = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
    names = [alias.name.split(".")[0] for node in imports if isinstance(node, ast.Import) for alias in node.names]
    assert not set(names) & {"torch", "angr", "claripy", "pyvex", "numpy"}


def test_reduction_map_is_parsed_as_data_without_executing_source():
    metadata = {"model_sha256": "1" * 64, "preproc_config": {"node_label_encoding_dim": 1,
        "all_ops": ["Extract"], "num_all_ops": 2, "num_edge_ops": 4, "flatten_vars": True,
        "use_arch": True, "arch_fields": ["x64"]}, "model_config": {"decoder_type": "independent",
        "node_aggregation": "mean"}, "output_class_count": 1, "relation_layers": [{"num_relations": 2}]}
    result = cli.expected_model_contract(metadata, "raise RuntimeError('never run')\nREDUCE_OP_MAP = {'a': 'Extract'}")
    assert result["edge_reduce_op_map"] == {"a": "Extract"}


def test_prepare_only_integrity_checks_include_copies_and_inventory(folder):
    source, copied = folder / "src/example.py", folder / "source_snapshot/example.py"
    source.parent.mkdir()
    source.write_text("original", encoding="utf-8")
    copied.parent.mkdir()
    copied.write_bytes(source.read_bytes())
    digest = cli.file_hash(source)
    report = cli.integrity_report(folder, {}, {"example.py": source}, {}, {"example.py": digest}, folder, {"src/example.py": source})
    assert not cli.integrity_changed(report)
    copied.write_text("changed", encoding="utf-8")
    assert cli.integrity_changed(cli.integrity_report(folder, {}, {"example.py": source}, {}, {"example.py": digest}, folder, {"src/example.py": source}))


@pytest.fixture
def native_request(folder, monkeypatch):
    binary, model, source = folder / "query.elf", folder / "model", folder / "src/edge.py"
    binary.write_bytes(b"unit binary")
    model.write_bytes(b"unit checkpoint identity only")
    source.parent.mkdir()
    source.write_text("unit source", encoding="utf-8")
    monkeypatch.setattr(worker, "MODEL_SHA256", worker.file_hash(model))
    return {"schema": "symbai.native_preprocessing_request.v1", "binary": str(binary),
            "binary_sha256": worker.file_hash(binary), "entry_rva": 0x1129, "tygr_root": str(folder),
            "model": str(model), "model_sha256": worker.file_hash(model), "scratch_dir": str(folder / "cache"),
            "source_sha256": {"src/edge.py": worker.file_hash(source)}, "worker_sha256": worker.file_hash(worker.__file__)}


def test_strict_native_request_identity_and_source_inventory(native_request):
    worker.validate_request(native_request)


@pytest.mark.parametrize("field", ["property_bounds", "gold", "raw_predictions", "mapping_proof"])
def test_property_and_historical_prediction_channels_are_rejected(native_request, field):
    native_request[field] = {}
    with pytest.raises(ValueError, match="forbidden"):
        worker.validate_request(native_request)


@pytest.mark.parametrize("changed", ["binary", "model", "source", "worker", "inventory"])
def test_native_request_rechecks_every_executable_input(native_request, changed):
    if changed in ("binary", "model"):
        Path(native_request[changed]).write_bytes(b"changed")
    elif changed == "source":
        (Path(native_request["tygr_root"]) / "src/edge.py").write_text("changed", encoding="utf-8")
    elif changed == "worker":
        native_request["worker_sha256"] = "0" * 64
    else:
        (Path(native_request["tygr_root"]) / "src/new.py").write_text("new", encoding="utf-8")
    with pytest.raises(ValueError):
        worker.validate_request(native_request)


@pytest.mark.parametrize("path", ["/mnt/c/Users/x", "/mnt/d/other/query.elf",
                                 "/mnt/d/AI_Models/symbolic/../outside", "relative/path"])
def test_offline_wsl_path_mapping_cannot_leave_workspace(path):
    with pytest.raises(ValueError):
        audit.local_path(path)


def test_offline_encoder_control_flow_check_distinguishes_inside_and_after_loop_return():
    first = "def encode_edge_label(edge_label, inverse, config):\n for edge_op in sorted(list(edge_label)):\n  if edge_op:\n   idx = 1\n  return idx\n"
    last = "def encode_edge_label(edge_label, inverse, config):\n for edge_op in sorted(list(edge_label)):\n  if edge_op:\n   idx = 1\n return idx\n"
    assert audit.native_first_label_rule(first) == "first_sorted_label"
    with pytest.raises(ValueError):
        audit.native_first_label_rule(last)
