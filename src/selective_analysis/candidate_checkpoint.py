"""Passive candidate inspection with Git blob identity; never inference admission.

The frozen checkpoint reader and its hash gate are deliberately unchanged.
This audit reuses its bounded symbolic pickle parser and passive shape helpers.
"""
import hashlib
from io import BytesIO
import json
from pathlib import Path, PurePosixPath
import re
import zipfile

from . import checkpoint_metadata as passive


def git_blob_identity(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def symbolic_value(value, active=None, depth=0):
    """Canonical structural vocabulary data; never resolve a referenced class."""
    if depth > 64:
        raise ValueError("Candidate vocabulary nesting limit")
    if value is None or type(value) in (str, int, bool):
        return value
    if isinstance(value, passive.GlobalRef):
        return {"global": value.module + "." + value.name}
    active = set() if active is None else active
    if id(value) in active:
        raise ValueError("Candidate vocabulary cycle")
    active = active | {id(value)}
    encode = lambda item: symbolic_value(item, active, depth + 1)
    if isinstance(value, passive.ObjectRef):
        return {"constructor": encode(value.constructor), "args": encode(value.args),
                "state": encode(value.state), "items": encode(value.items)}
    if type(value) in (list, tuple):
        return [encode(item) for item in value]
    if type(value) is dict:
        pairs = [[encode(key), encode(item)] for key, item in value.items()]
        return {"mapping": sorted(pairs, key=lambda pair: json.dumps(pair[0], sort_keys=True))}
    raise ValueError("Unsupported passive vocabulary value")


def inspect_candidate_bytes(raw, expected_blob):
    if (not re.fullmatch(r"[0-9a-f]{40}", expected_blob)
            or not 0 < len(raw) <= passive.MAX_CHECKPOINT_BYTES
            or git_blob_identity(raw) != expected_blob):
        raise ValueError("Candidate Git blob identity or size differs")
    with zipfile.ZipFile(BytesIO(raw)) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if (not 0 < len(infos) <= 1024 or len(set(names)) != len(names)
                or any(PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts or "\\" in name for name in names)):
            raise ValueError("Candidate ZIP inventory differs")
        pickles = [info for info in infos if info.filename.endswith("/data.pkl")]
        if len(pickles) != 1 or not 0 < pickles[0].file_size <= passive.MAX_PICKLE_BYTES or pickles[0].flag_bits & 1:
            raise ValueError("Candidate pickle member differs")
        root = passive.parse_symbolic_pickle(archive.read(pickles[0]))
        prefix = pickles[0].filename[:-len("data.pkl")]
        members = {info.filename: info for info in infos}
        storages = {}
        for value in passive._walk(root):
            if isinstance(value, passive.PersistentRef):
                descriptor = passive._storage(value.key)
                key = descriptor["storage_key"]
                name = prefix + "data/" + key
                if (name not in members or members[name].flag_bits & 1
                        or members[name].file_size != descriptor["expected_bytes"]
                        or (key in storages and storages[key] != descriptor)):
                    raise ValueError("Candidate tensor storage descriptor differs")
                storages[key] = descriptor
        if {name for name in names if name.startswith(prefix + "data/")} != {prefix + "data/" + key for key in storages}:
            raise ValueError("Candidate has unreferenced tensor storage")
    config = passive._state(root)["config"]
    preproc = passive._state(config)["preproc_config"]
    model_config, _ = passive._saved_config(config, {"preproc_config"})
    preproc_config, _ = passive._saved_config(preproc, {"type_set", "archs"})
    type_set = passive._state(preproc)["type_set"]
    types = passive._state(type_set)["types"]
    if not isinstance(types, list) or not 0 < len(types) <= 4096:
        raise ValueError("Candidate type vocabulary is absent or unbounded")
    vocabulary = {"type_set_class": passive._global(type_set.constructor),
                  "ordered_types": [symbolic_value(value) for value in types]}
    vocabulary_hash = hashlib.sha256(json.dumps(vocabulary, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    shapes, layers = {}, []

    def visit(module, name, ancestors=()):
        if len(shapes) > 4096 or len(ancestors) >= 64 or id(module) in ancestors:
            raise ValueError("Candidate module traversal limit/cycle")
        state = passive._state(module)
        local = {}
        for key, value in passive._mapping(state["_parameters"]).items():
            if value is not None:
                if not isinstance(key, str):
                    raise ValueError("Invalid candidate parameter name")
                local[key] = passive._tensor_metadata(value)["shape"]
                shapes[(name + "." if name else "") + key] = local[key]
        if passive._global(module.constructor) == "torch_geometric.nn.conv.rgcn_conv.RGCNConv":
            weight, comp = local.get("weight"), local.get("comp")
            if (not isinstance(weight, list) or len(weight) != 3
                    or not isinstance(comp, list) or len(comp) != 2 or comp[1] != weight[0]
                    or state.get("num_relations") != comp[0] or state.get("num_bases") != weight[0]):
                raise ValueError("Candidate RGCN basis count/parameter capacity differs")
            layers.append({"module_path": name, "num_relations": state["num_relations"],
                "parameter_relation_capacity": comp[0], "num_bases": state["num_bases"],
                "aggregation": state.get("aggr"), "parameter_shapes": local})
        for key, child in passive._mapping(state["_modules"]).items():
            if not isinstance(key, str):
                raise ValueError("Invalid candidate module name")
            if child is not None:
                visit(child, (name + "." if name else "") + key, ancestors + (id(module),))

    visit(root, "")
    encoder, decoder = shapes.get("encoder.first_layer.0.weight"), shapes.get("decoder.last_layer.weight")
    if (not isinstance(encoder, list) or len(encoder) != 2
            or encoder[1] != model_config["node_encoder_in_dim"] or encoder[1] != preproc_config["node_label_encoding_dim"]
            or not isinstance(decoder, list) or len(decoder) != 2
            or decoder[0] != model_config["out_dim"] or decoder[0] != len(types)):
        raise ValueError("Candidate encoder/decoder/type dimensions disagree")
    return {"schema": "symbai.candidate_checkpoint_metadata.v1", "git_blob_sha1": expected_blob,
        "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
        "model_class": passive._global(root.constructor), "model_config": model_config,
        "preproc_config": preproc_config, "relation_layers": layers, "parameter_shapes": shapes,
        "type_count": len(types), "type_vocabulary": vocabulary, "type_vocabulary_sha256": vocabulary_hash,
        "external_code_executed": False, "tensor_arrays_loaded": False, "inference_admitted": False}


def inspect_candidate(path, expected_blob):
    path = Path(path)
    if not 0 < path.stat().st_size <= passive.MAX_CHECKPOINT_BYTES:
        raise ValueError("Candidate file size limit")
    return inspect_candidate_bytes(path.read_bytes(), expected_blob)


def assess_candidate(candidate, reference):
    """A metadata match is a candidate for review, never permission to run inference."""
    blockers = []
    if candidate["model_class"] != reference["model_class"]:
        blockers.append("model_class_differs")
    if candidate["preproc_config"] != reference["preproc_config"]:
        blockers.append("preprocessing_configuration_differs")
    if candidate["type_vocabulary_sha256"] != reference["type_vocabulary_sha256"]:
        blockers.append("ordered_type_vocabulary_differs")
    if candidate["model_config"]["decoder_type"] != "independent":
        blockers.append("independent_decoder_required")
    required = reference["preproc_config"]["num_edge_ops"]
    capacities = [layer["parameter_relation_capacity"] for layer in candidate["relation_layers"]]
    if not capacities or any(capacity < required for capacity in capacities):
        blockers.append("relation_capacity_below_declared_domain")
    if len(capacities) != candidate["model_config"]["num_msg_pass_layers"]:
        blockers.append("active_layer_count_differs_from_configuration")
    return {"status": "metadata_candidate" if not blockers else "blocked", "blockers": blockers,
        "required_relation_count": required, "layer_capacities": capacities,
        "ordered_type_vocabulary_matches": candidate["type_vocabulary_sha256"] == reference["type_vocabulary_sha256"],
        "inference_admitted": False, "training_mapping_proven": False}
