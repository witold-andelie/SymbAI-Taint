"""Passive pickle/checkpoint metadata checks; never import or load a framework."""

import builtins
import hashlib
import json
from pathlib import Path
import struct
import sys
import uuid
import zipfile

import pytest

from src.selective_analysis import checkpoint_metadata as metadata
from src.selective_analysis.checkpoint_metadata import GlobalRef, ObjectRef, PersistentRef


ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / "tygr_original/model/MODEL_base/x64.O0.base.model"


def text(value):
    raw = value.encode("utf-8")
    return b"X" + struct.pack("<I", len(raw)) + raw


def stream(body):
    return b"\x80\x02" + body + b"."


@pytest.fixture
def scratch():
    folder = ROOT.parent / ".scratch/selective_analysis/tests" / ("checkpoint-metadata-" + uuid.uuid4().hex)
    folder.mkdir(parents=True)
    return folder


def parameter(shape=(2, 3), stride=(3, 1), offset=0, numel=6, key="0"):
    storage = PersistentRef(("storage", GlobalRef("torch", "FloatStorage"), key, "cpu", numel))
    tensor = ObjectRef(GlobalRef("torch._utils", "_rebuild_tensor_v2"),
                       (storage, offset, shape, stride, False, ObjectRef(GlobalRef("collections", "OrderedDict"), (), "REDUCE")),
                       "REDUCE")
    return ObjectRef(GlobalRef("torch._utils", "_rebuild_parameter"),
                     (tensor, True, ObjectRef(GlobalRef("collections", "OrderedDict"), (), "REDUCE")), "REDUCE")


def module(name, parameters=None, children=None, **state):
    return ObjectRef(GlobalRef("fixture", name), (), "NEWOBJ",
                     {"_parameters": parameters or {}, "_modules": children or {}, **state})


def fake_root():
    encoder = module("Encoder", children={"first_layer": module("Sequential", children={
        "0": module("Linear", {"weight": parameter((2, 31), (31, 1), numel=62, key="1")})})})
    decoder = module("Decoder", children={"last_layer": module("Linear", {
        "weight": parameter((75, 2), (2, 1), numel=150, key="2")})})
    preproc = ObjectRef(GlobalRef("fixture", "PreprocConfig"), (), "NEWOBJ", {"node_label_encoding_dim": 31})
    config = ObjectRef(GlobalRef("fixture", "Config"), (), "NEWOBJ",
                       {"preproc_config": preproc, "node_encoder_in_dim": 31, "out_dim": 75})
    root = module("Model", children={"encoder": encoder, "decoder": decoder}, config=config)
    return root


def fake_archive(path, monkeypatch, root=None, storage_delta=0):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("archive/data.pkl", stream(b"N"))
        archive.writestr("archive/data/1", b"\0" * (62 * 4 + storage_delta))
        archive.writestr("archive/data/2", b"\0" * (150 * 4))
    monkeypatch.setattr(metadata, "FROZEN_SHA256", hashlib.sha256(path.read_bytes()).hexdigest())
    monkeypatch.setattr(metadata, "parse_symbolic_pickle", lambda _: fake_root() if root is None else root)


def test_memo_preserves_list_alias_and_in_place_mutation():
    # [] memo[0]; append that same list to itself, then return (memo[0], memo[0]).
    result = metadata.parse_symbolic_pickle(stream(b"]q\x00h\x00ah\x00\x86"))
    assert result[0] is result[1]
    assert result[0][0] is result[0]


def test_build_updates_memoized_object_without_instantiation():
    body = b"cnever_import_this_module\nNeverConstruct\n)\x81q\x00}" + text("saved") + b"K\x07sbh\x00\x86"
    first, second = metadata.parse_symbolic_pickle(stream(body))
    assert first is second and isinstance(first, ObjectRef)
    assert first.constructor == GlobalRef("never_import_this_module", "NeverConstruct")
    assert first.construction == "NEWOBJ" and first.args == () and first.state == {"saved": 7}


def test_reduce_global_never_imports_or_calls_referenced_function(monkeypatch):
    original_import = builtins.__import__
    forbidden = []

    def guarded_import(name, *args, **kwargs):
        if name.startswith(("never_import_this_module", "torch", "angr")):
            forbidden.append(name)
            raise AssertionError("external import attempted")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    result = metadata.parse_symbolic_pickle(stream(b"cnever_import_this_module\nexecute\n" + text("payload") + b"\x85R"))
    assert isinstance(result, ObjectRef) and result.construction == "REDUCE"
    assert result.constructor == GlobalRef("never_import_this_module", "execute")
    assert result.args == ("payload",) and forbidden == []


def test_ordered_dict_setitems_are_recorded_without_constructing_it():
    body = b"ccollections\nOrderedDict\n)Rq\x00(" + text("first") + b"K\x01" + text("second") + b"K\x02u"
    root = metadata.parse_symbolic_pickle(stream(body))
    assert isinstance(root, ObjectRef)
    assert root.items == [("first", 1), ("second", 2)]
    assert metadata._mapping(root) == {"first": 1, "second": 2}


def test_object_append_items_and_native_dictionary_mutations():
    root = metadata.parse_symbolic_pickle(stream(b"cfixture\nListSubclass\n)RK\x01a(K\x02K\x03e"))
    assert root.items == [1, 2, 3]
    root = metadata.parse_symbolic_pickle(stream(b"}" + text("one") + b"K\x01s(" + text("two") + b"K\x02u"))
    assert root == {"one": 1, "two": 2}


def test_long_memo_opcodes_and_persistent_reference_are_passive():
    body = text("storage") + b"r" + struct.pack("<I", 300) + b"j" + struct.pack("<I", 300) + b"\x86Q"
    root = metadata.parse_symbolic_pickle(stream(body))
    assert isinstance(root, PersistentRef) and root.key == ("storage", "storage")


@pytest.mark.parametrize("body", [
    b"0N",                         # POP is deliberately outside the whitelist.
    b"G" + b"\0" * 8,             # BINFLOAT is not required by this checkpoint.
    b"\x93",                       # STACK_GLOBAL.
    b"\x82\x01",                   # EXT1.
    b"Pexternal-id\n",              # Executable persistent-id loader protocol.
])
def test_unsupported_opcodes_are_rejected(body):
    with pytest.raises(ValueError, match="unsupported opcode"):
        metadata.parse_symbolic_pickle(stream(body))


@pytest.mark.parametrize("data", [
    b"", b"N.", b"\x80\x04N.", b"\x80\x02", b"\x80\x02N", b"\x80\x02N..",
    stream(b"h\x00"), stream(b"K\x01K\x02"), stream(b"("), stream(b"K\x01b"),
    stream(b"Na"), stream(b"}(K\x01u"), stream(b"K\x01q\x00q\x00"),
    stream(b"K\x01)R"), stream(b"cfixture\nClass\nN\x81"),
])
def test_malformed_streams_are_rejected(data):
    with pytest.raises(ValueError):
        metadata.parse_symbolic_pickle(data)


def test_every_truncated_prefix_of_passive_object_is_rejected():
    data = stream(b"cfixture\nClass\n)\x81}" + text("key") + b"K\x01sb")
    assert isinstance(metadata.parse_symbolic_pickle(data), ObjectRef)
    for end in range(len(data)):
        with pytest.raises(ValueError):
            metadata.parse_symbolic_pickle(data[:end])


@pytest.mark.parametrize("limit,value,data", [
    ("MAX_PICKLE_BYTES", 3, stream(b"N")),
    ("MAX_OPCODES", 2, stream(b"N")),
    ("MAX_MEMO", 1, stream(b"Nq\x01")),
    ("MAX_STACK", 2, stream(b"NNN\x87")),
    ("MAX_ITEMS", 1, stream(b"](K\x01K\x02e")),
])
def test_resource_caps_fail_closed(monkeypatch, limit, value, data):
    monkeypatch.setattr(metadata, limit, value)
    with pytest.raises(ValueError):
        metadata.parse_symbolic_pickle(data)


def test_tensor_parameter_shape_stride_and_storage_offset_are_metadata_only():
    value = metadata._tensor_metadata(parameter((2, 2), (3, 1), offset=1, numel=6))
    assert value == {"shape": [2, 2], "stride": [3, 1], "storage_offset": 1,
                     "storage_key": "0", "storage_type": "torch.FloatStorage", "storage_numel": 6,
                     "requires_grad": True}


@pytest.mark.parametrize("shape,stride,offset,numel", [
    ((2, 3), (3, 1), 1, 6), ((2, 3), (3,), 0, 6), ((-1, 3), (3, 1), 0, 6),
    ((2, 3), (-3, 1), 0, 6), ((2, 3), (3, 1), True, 6), ((2, 3), (3, 1), 0, 5),
])
def test_invalid_tensor_layout_metadata_is_rejected(shape, stride, offset, numel):
    with pytest.raises(ValueError):
        metadata._tensor_metadata(parameter(shape, stride, offset, numel))


def test_tensor_shape_and_storage_size_are_independently_checked(scratch, monkeypatch):
    path = scratch / "synthetic-metadata.zip"
    fake_archive(path, monkeypatch)
    result = metadata.inspect_frozen_checkpoint(path)
    assert result["output_class_count"] == 75
    assert result["parameter_shapes"]["encoder.first_layer.0.weight"] == [2, 31]
    assert result["storage_descriptors"][0]["zip_file_size"] == 248
    fake_archive(path, monkeypatch, storage_delta=1)
    with pytest.raises(ValueError, match="storage size"):
        metadata.inspect_frozen_checkpoint(path)


def test_saved_output_dimension_must_match_decoder_weight(scratch, monkeypatch):
    path = scratch / "bad-output.zip"
    root = fake_root()
    root.state["config"].state["out_dim"] = 74
    fake_archive(path, monkeypatch, root=root)
    with pytest.raises(ValueError, match="output classes"):
        metadata.inspect_frozen_checkpoint(path)


def test_saved_encoder_dimension_must_match_input_weight(scratch, monkeypatch):
    path = scratch / "bad-input.zip"
    root = fake_root()
    root.state["config"].state["node_encoder_in_dim"] = 32
    fake_archive(path, monkeypatch, root=root)
    with pytest.raises(ValueError, match="encoder input"):
        metadata.inspect_frozen_checkpoint(path)


def test_hash_gate_runs_before_zip_or_pickle_parsing(scratch, monkeypatch):
    path = scratch / "not-the-frozen-model"
    path.write_bytes(b"not a checkpoint")
    monkeypatch.setattr(metadata, "parse_symbolic_pickle", lambda _: pytest.fail("parser must not be reached"))
    with pytest.raises(ValueError, match="SHA-256"):
        metadata.inspect_frozen_checkpoint(path)


@pytest.mark.skipif(not MODEL.is_file(), reason="Frozen optional local model is absent")
def test_actual_checkpoint_saved_fields_parameter_shapes_and_no_framework_execution(monkeypatch):
    before = set(sys.modules)
    original_read = zipfile.ZipFile.read
    read_members = []

    def read_metadata_only(archive, name, *args, **kwargs):
        member = name.filename if hasattr(name, "filename") else name
        assert "/data/" not in member, "Tensor storage arrays must remain unread"
        read_members.append(member)
        return original_read(archive, name, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "read", read_metadata_only)
    result = metadata.inspect_frozen_checkpoint(MODEL)
    assert result["model_sha256"] == metadata.FROZEN_SHA256
    assert result["model_class"] == "GlowGNN"
    assert result["model_config"]["node_encoder_in_dim"] == 31
    assert result["model_config"]["edge_dim"] == 44
    assert result["model_config"]["decoder_type"] == "independent"
    assert result["model_config"]["node_aggregation"] == "mean"
    assert result["preproc_config"]["flatten_vars"] is True
    assert result["preproc_config"]["use_arch"] is True
    assert result["preproc_config"]["use_bitvector"] is False
    assert result["preproc_config"]["bitsize"] == 32
    assert result["preproc_config"]["feature_dim"] == 18
    assert result["preproc_config"]["bit_vector_encoding_dim"] == 8
    assert result["preproc_config"]["node_label_encoding_dim"] == 31
    assert result["preproc_config"]["arch_fields"] == ["x64", "x86", "arm32", "arm64", "mips"]
    assert result["preproc_config"]["bitsize_fields"] == [1, 8, 16, 32, 64, 128, 256]
    assert len(result["preproc_config"]["all_ops"]) == 29
    assert result["preproc_config"]["all_ops"][:4] == ["mem_data", "mem_loc", "reg_data", "reg_loc"]
    assert result["preproc_config"]["num_all_ops"] == 30
    assert result["preproc_config"]["num_edge_ops"] == 60
    assert result["parameter_shapes"]["encoder.first_layer.0.weight"] == [128, 31]
    assert result["parameter_shapes"]["decoder.last_layer.weight"] == [75, 128]
    assert result["parameter_shapes"]["decoder.last_layer.bias"] == [75]
    assert result["output_class_count"] == result["model_config"]["out_dim"] == 75
    assert len(result["relation_layers"]) == 8
    for index, layer in enumerate(result["relation_layers"]):
        assert layer["index"] == index and layer["module_path"] == f"rgcns.{index}"
        assert layer["num_relations"] == layer["parameter_relation_capacity"] == 44
        assert layer["parameter_shapes"]["weight"] == [10, 128, 128]
        assert layer["parameter_shapes"]["comp"] == [44, 10]
        assert layer["relation_capacity_verified"] is True
    assert len(result["storage_descriptors"]) == len(result["parameter_shapes"]) == 40
    assert all(value["expected_bytes"] == value["zip_file_size"] for value in result["storage_descriptors"])
    assert read_members == ["archive/data.pkl"]
    assert result["external_code_executed"] is result["inference_performed"] is result["tensor_arrays_loaded"] is False
    assert result["no_external_execution"] is True
    assert not {name for name in set(sys.modules) - before if name.split(".")[0] in ("torch", "angr", "claripy", "torch_geometric")}
    json.dumps(result)
