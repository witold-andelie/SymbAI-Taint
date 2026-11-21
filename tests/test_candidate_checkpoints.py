"""Candidate-only passive parsing must not relax the frozen model contract."""
from copy import deepcopy
import hashlib
from pathlib import Path
import sys
import zipfile

import pytest

from src.selective_analysis import candidate_checkpoint as candidate
from src.selective_analysis import checkpoint_metadata as frozen

MODEL = Path(__file__).resolve().parents[1] / "tygr_original/model/MODEL_base/x64.O0.base.model"
BLOB = "d3a44c657e672ffc6d08a6b45bb343c91355eb37"


def metadata(capacity=60):
    return {"model_class": "src.methods.glow.model.GlowGNN", "preproc_config": {"num_edge_ops": 60},
        "type_vocabulary_sha256": "same_ordered_vocabulary",
        "model_config": {"decoder_type": "independent", "num_msg_pass_layers": 8},
        "relation_layers": [{"parameter_relation_capacity": capacity} for _ in range(8)]}


def test_metadata_match_never_admits_inference_or_proves_training_mapping():
    result = candidate.assess_candidate(metadata(), metadata())
    assert result["status"] == "metadata_candidate" and not result["blockers"]
    assert result["inference_admitted"] is result["training_mapping_proven"] is False


@pytest.mark.parametrize("damage,reason", [("capacity", "relation_capacity_below_declared_domain"),
    ("one_layer", "relation_capacity_below_declared_domain"), ("types", "ordered_type_vocabulary_differs"),
    ("features", "preprocessing_configuration_differs"), ("decoder", "independent_decoder_required"),
    ("layers", "active_layer_count_differs_from_configuration")])
def test_candidate_semantic_or_capacity_mismatch_is_not_accepted(damage, reason):
    reference, changed = metadata(), metadata()
    if damage == "capacity":
        changed = metadata(44)
    elif damage == "one_layer":
        changed["relation_layers"][7]["parameter_relation_capacity"] = 44
    elif damage == "types":
        changed["type_vocabulary_sha256"] = "same_count_different_order"
    elif damage == "features":
        changed["preproc_config"]["different_feature_encoding"] = True
    elif damage == "decoder":
        changed["model_config"]["decoder_type"] = "autoreg"
    else:
        changed["relation_layers"].pop()
    assert reason in candidate.assess_candidate(changed, reference)["blockers"]


def test_blob_identity_gate_runs_before_archive_parsing(monkeypatch):
    monkeypatch.setattr(candidate.zipfile, "ZipFile", lambda *_: pytest.fail("Archive parser must not run"))
    with pytest.raises(ValueError, match="Git blob identity"):
        candidate.inspect_candidate_bytes(b"not the pinned blob", "0" * 40)
    assert candidate.git_blob_identity(b"example") == hashlib.sha1(b"blob 7\0example").hexdigest()


def test_symbolic_vocabulary_keeps_class_arguments_and_order_without_execution():
    dangerous = frozen.ObjectRef(frozen.GlobalRef("os", "system"), ("do not execute",), "REDUCE")
    encoded = candidate.symbolic_value(dangerous)
    assert encoded["constructor"] == {"global": "os.system"}
    assert encoded["args"] == ["do not execute"]
    first = frozen.ObjectRef(frozen.GlobalRef("types", "Integer"), (32,), "NEWOBJ")
    second = frozen.ObjectRef(frozen.GlobalRef("types", "Integer"), (64,), "NEWOBJ")
    assert candidate.symbolic_value([first, second]) != candidate.symbolic_value([second, first])
    first.state = {"cycle": first}
    with pytest.raises(ValueError, match="cycle"):
        candidate.symbolic_value(first)


@pytest.mark.skipif(not MODEL.is_file(), reason="Optional local frozen checkpoint absent")
def test_real_candidate_parser_agrees_with_frozen_reader_without_storage_reads(monkeypatch):
    before, original_read = set(sys.modules), zipfile.ZipFile.read

    def metadata_only(archive, name, *args, **kwargs):
        member = name.filename if hasattr(name, "filename") else name
        assert "/data/" not in member
        return original_read(archive, name, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "read", metadata_only)
    trusted = frozen.inspect_frozen_checkpoint(MODEL)
    inspected = candidate.inspect_candidate(MODEL, BLOB)
    assert inspected["sha256"] == frozen.FROZEN_SHA256
    assert inspected["model_config"] == trusted["model_config"]
    assert inspected["preproc_config"] == trusted["preproc_config"]
    assert inspected["parameter_shapes"] == trusted["parameter_shapes"]
    assert inspected["type_count"] == trusted["output_class_count"] == 75
    assert len(inspected["type_vocabulary"]["ordered_types"]) == 75
    assert inspected["tensor_arrays_loaded"] is inspected["external_code_executed"] is False
    result = candidate.assess_candidate(inspected, deepcopy(inspected))
    assert result["blockers"] == ["relation_capacity_below_declared_domain"]
    assert not {name for name in set(sys.modules) - before if name.split(".")[0] in ("torch", "torch_geometric", "angr", "claripy")}
