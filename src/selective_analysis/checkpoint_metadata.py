"""Passive, bounded parsing of the frozen checkpoint; no pickle objects are executed.

GLOBAL names, construction, reductions, persistent references and BUILD state remain
data. This is deliberately not a general unpickler. Unsupported opcodes and malformed
streams fail closed; tensor storage contents are never decompressed or interpreted.
"""

from dataclasses import dataclass, field
import hashlib
from io import BytesIO
from pathlib import Path, PurePosixPath
import pickletools
import zipfile


FROZEN_SHA256 = "f592caaa6c685f291f576b16fbf8b752a95e7cb757ea620751830563b77f67c8"
MAX_PICKLE_BYTES = 4 * 1024 * 1024
MAX_CHECKPOINT_BYTES = 64 * 1024 * 1024
MAX_OPCODES, MAX_MEMO, MAX_STACK, MAX_ITEMS = 200000, 50000, 8192, 200000
_MARK = object()
_ALLOWED = frozenset((
    "PROTO", "GLOBAL", "EMPTY_TUPLE", "EMPTY_DICT", "EMPTY_LIST", "BININT", "BININT1", "BININT2",
    "LONG1", "BINUNICODE", "NONE", "NEWTRUE", "NEWFALSE", "MARK", "APPEND", "APPENDS",
    "TUPLE", "TUPLE1", "TUPLE2", "TUPLE3", "SETITEM", "SETITEMS", "BINPUT", "BINGET",
    "LONG_BINPUT", "LONG_BINGET", "BINPERSID", "REDUCE", "NEWOBJ", "BUILD", "STOP",
))


@dataclass(frozen=True)
class GlobalRef:
    module: str
    name: str


@dataclass(eq=False)
class ObjectRef:
    constructor: object
    args: tuple
    construction: str
    state: object = None
    items: list = field(default_factory=list)


@dataclass(eq=False)
class PersistentRef:
    key: object


def _require(condition, message):
    if not condition:
        raise ValueError("Invalid checkpoint metadata: " + message)


def _int(value, minimum=0):
    return type(value) is int and value >= minimum


def _safe_key(value, depth=0):
    _require(depth < 64, "mapping key depth limit")
    if value is None or type(value) in (str, int, bool) or isinstance(value, (GlobalRef, ObjectRef, PersistentRef)):
        return
    _require(type(value) is tuple, "unsupported mapping key")
    for item in value:
        _safe_key(item, depth + 1)


def parse_symbolic_pickle(data):
    """Parse the supported protocol-2 stream into passive nodes, preserving memo aliases.

    ObjectRef.state records the last BUILD payload; ObjectRef.items records container
    mutations as values (APPEND) or key/value pairs (SETITEM). No referenced class,
    reducer, persistent loader or __setstate__ method is resolved or called.
    """
    _require(type(data) is bytes and 0 < len(data) <= MAX_PICKLE_BYTES, "pickle byte limit")
    stack, memo, items, marks = [], {}, 0, 0

    def pop():
        _require(bool(stack) and stack[-1] is not _MARK, "pickle stack underflow")
        return stack.pop()

    def marked():
        nonlocal marks
        _require(marks > 0, "missing MARK")
        index = len(stack) - 1
        while index >= 0 and stack[index] is not _MARK:
            index -= 1
        _require(index >= 0, "missing MARK")
        values = stack[index + 1:]
        del stack[index:]
        marks -= 1
        return values

    def charge(count):
        nonlocal items
        items += count
        _require(items <= MAX_ITEMS, "container item limit")

    def append(target, values):
        _require(type(target) is list or isinstance(target, ObjectRef), "APPEND target is not a passive container")
        charge(len(values))
        (target if type(target) is list else target.items).extend(values)

    def assign(target, values):
        _require((type(target) is dict or isinstance(target, ObjectRef)) and len(values) % 2 == 0,
                 "SETITEM target or pair count")
        charge(len(values))
        for index in range(0, len(values), 2):
            key, value = values[index:index + 2]
            _safe_key(key)
            if type(target) is dict:
                target[key] = value
            else:
                target.items.append((key, value))

    try:
        for count, (opcode, argument, position) in enumerate(pickletools.genops(data), 1):
            name = opcode.name
            _require(count <= MAX_OPCODES and name in _ALLOWED, "opcode limit or unsupported opcode " + name)
            _require(count != 1 or (name == "PROTO" and argument == 2), "protocol 2 header required")
            if name == "PROTO":
                _require(count == 1 and argument == 2, "duplicate or unsupported protocol")
            elif name == "GLOBAL":
                module, symbol = argument.split(" ", 1)
                _require(bool(module) and bool(symbol) and len(argument) <= 1024, "GLOBAL name")
                stack.append(GlobalRef(module, symbol))
            elif name in ("EMPTY_TUPLE", "EMPTY_DICT", "EMPTY_LIST"):
                stack.append({"EMPTY_TUPLE": tuple, "EMPTY_DICT": dict, "EMPTY_LIST": list}[name]())
            elif name in ("BININT", "BININT1", "BININT2", "LONG1", "BINUNICODE"):
                _require(type(argument) is str or (type(argument) is int and argument.bit_length() <= 4096),
                         "scalar resource limit")
                stack.append(argument)
            elif name in ("NONE", "NEWTRUE", "NEWFALSE"):
                stack.append({"NONE": None, "NEWTRUE": True, "NEWFALSE": False}[name])
            elif name == "MARK":
                marks += 1
                _require(marks <= 128, "MARK depth limit")
                stack.append(_MARK)
            elif name in ("BINPUT", "LONG_BINPUT"):
                _require(_int(argument) and argument < MAX_MEMO and argument not in memo and bool(stack)
                         and stack[-1] is not _MARK, "memo write")
                memo[argument] = stack[-1]
            elif name in ("BINGET", "LONG_BINGET"):
                _require(argument in memo, "undefined memo read")
                stack.append(memo[argument])
            elif name in ("TUPLE", "TUPLE1", "TUPLE2", "TUPLE3"):
                if name == "TUPLE":
                    values = marked()
                else:
                    values = [pop() for _ in range(int(name[-1]))][::-1]
                charge(len(values))
                stack.append(tuple(values))
            elif name in ("APPEND", "APPENDS"):
                values = [pop()] if name == "APPEND" else marked()
                _require(bool(stack) and stack[-1] is not _MARK, "APPEND missing target")
                append(stack[-1], values)
            elif name in ("SETITEM", "SETITEMS"):
                values = [pop(), pop()][::-1] if name == "SETITEM" else marked()
                _require(bool(stack) and stack[-1] is not _MARK, "SETITEM missing target")
                assign(stack[-1], values)
            elif name == "BINPERSID":
                stack.append(PersistentRef(pop()))
            elif name in ("REDUCE", "NEWOBJ"):
                args, constructor = pop(), pop()
                _require(type(args) is tuple and isinstance(constructor, (GlobalRef, ObjectRef)), "construction operands")
                stack.append(ObjectRef(constructor, args, name))
            elif name == "BUILD":
                state = pop()
                _require(bool(stack) and isinstance(stack[-1], ObjectRef), "BUILD target")
                stack[-1].state = state
            elif name == "STOP":
                _require(len(stack) == 1 and not marks and stack[0] is not _MARK and position + 1 == len(data),
                         "STOP stack or trailing data")
                return stack[0]
            _require(len(stack) <= MAX_STACK, "pickle stack limit")
    except (ValueError, TypeError, IndexError, KeyError, OverflowError, RecursionError, UnicodeError) as error:
        if isinstance(error, ValueError) and str(error).startswith("Invalid checkpoint metadata:"):
            raise
        raise ValueError("Invalid checkpoint metadata: malformed pickle stream") from error
    raise ValueError("Invalid checkpoint metadata: missing STOP")


def _global(value):
    _require(isinstance(value, GlobalRef), "expected symbolic GLOBAL")
    return value.module + "." + value.name


def _state(value):
    _require(isinstance(value, ObjectRef) and type(value.state) is dict, "expected object BUILD dictionary")
    return value.state


def _mapping(value):
    if type(value) is dict:
        return value
    _require(isinstance(value, ObjectRef) and value.constructor == GlobalRef("collections", "OrderedDict")
             and value.args == () and value.state is None, "expected passive OrderedDict")
    result = {}
    for pair in value.items:
        _require(type(pair) is tuple and len(pair) == 2, "OrderedDict item shape")
        _safe_key(pair[0])
        result[pair[0]] = pair[1]
    return result


def _primitive(value, depth=0):
    _require(depth < 64, "configuration depth limit")
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) in (tuple, list):
        return [_primitive(item, depth + 1) for item in value]
    if type(value) is dict and all(type(key) is str for key in value):
        return {key: _primitive(item, depth + 1) for key, item in value.items()}
    raise ValueError("Invalid checkpoint metadata: nonprimitive saved configuration field")


def _walk(root):
    pending, seen, count = [root], set(), 0
    while pending:
        value = pending.pop()
        count += 1
        _require(count <= MAX_ITEMS * 4, "passive traversal limit")
        if type(value) in (str, int, bool) or value is None:
            continue
        if id(value) in seen:
            continue
        seen.add(id(value))
        yield value
        if isinstance(value, ObjectRef):
            pending.extend((value.constructor, value.args, value.state, value.items))
        elif isinstance(value, PersistentRef):
            pending.append(value.key)
        elif type(value) in (list, tuple):
            pending.extend(value)
        elif type(value) is dict:
            pending.extend(value.keys())
            pending.extend(value.values())


def _storage(key):
    widths = {"FloatStorage": 4, "DoubleStorage": 8, "HalfStorage": 2, "BFloat16Storage": 2,
              "LongStorage": 8, "IntStorage": 4, "ShortStorage": 2, "CharStorage": 1,
              "ByteStorage": 1, "BoolStorage": 1}
    _require(type(key) is tuple and len(key) == 5 and key[0] == "storage"
             and isinstance(key[1], GlobalRef) and key[1].module == "torch" and key[1].name in widths
             and type(key[2]) is str and bool(key[2]) and all(c in "0123456789" for c in key[2])
             and type(key[3]) is str and _int(key[4]), "storage persistent descriptor")
    size = key[4] * widths[key[1].name]
    _require(size <= MAX_CHECKPOINT_BYTES, "storage size limit")
    return {"storage_key": key[2], "storage_type": _global(key[1]), "location": key[3],
            "numel": key[4], "element_bytes": widths[key[1].name], "expected_bytes": size}


def _tensor_metadata(parameter):
    _require(isinstance(parameter, ObjectRef)
             and parameter.constructor == GlobalRef("torch._utils", "_rebuild_parameter")
             and parameter.construction == "REDUCE" and len(parameter.args) == 3
             and type(parameter.args[1]) is bool, "parameter reconstruction metadata")
    tensor = parameter.args[0]
    _require(isinstance(tensor, ObjectRef) and tensor.constructor == GlobalRef("torch._utils", "_rebuild_tensor_v2")
             and tensor.construction == "REDUCE" and len(tensor.args) == 6, "tensor reconstruction metadata")
    storage, offset, shape, stride, requires_grad, _hooks = tensor.args
    _require(isinstance(storage, PersistentRef) and _int(offset) and type(shape) is tuple
             and type(stride) is tuple and len(shape) == len(stride) <= 8
             and all(_int(value) for value in shape + stride) and type(requires_grad) is bool,
             "tensor size, stride or offset")
    descriptor = _storage(storage.key)
    _require(offset <= descriptor["numel"], "tensor storage offset")
    if all(shape):
        last = offset + sum((size - 1) * step for size, step in zip(shape, stride))
        _require(last < descriptor["numel"], "tensor shape exceeds storage")
    return {"shape": list(shape), "stride": list(stride), "storage_offset": offset,
            "storage_key": descriptor["storage_key"], "storage_type": descriptor["storage_type"],
            "storage_numel": descriptor["numel"], "requires_grad": parameter.args[1]}


def _saved_config(value, excluded):
    state = _state(value)
    result, omitted = {}, []
    for key, item in state.items():
        _require(type(key) is str, "configuration field name")
        if key in excluded:
            omitted.append(key)
        else:
            result[key] = _primitive(item)
    return result, sorted(omitted)


def _inspect_frozen_checkpoint(path):
    """Read fixed-identity ZIP/pickle metadata without loading arrays or framework code."""
    path = Path(path)
    _require(0 < path.stat().st_size <= MAX_CHECKPOINT_BYTES, "checkpoint byte limit")
    with path.open("rb") as stream:
        raw = stream.read(MAX_CHECKPOINT_BYTES + 1)
    _require(len(raw) <= MAX_CHECKPOINT_BYTES, "checkpoint byte limit")
    digest = hashlib.sha256(raw).hexdigest()
    _require(digest == FROZEN_SHA256, "frozen checkpoint SHA-256 differs")
    try:
        archive = zipfile.ZipFile(BytesIO(raw))
        infos = archive.infolist()
        names = [info.filename for info in infos]
        _require(0 < len(infos) <= 1024 and len(set(names)) == len(names), "ZIP member count or duplicate name")
        _require(all(not PurePosixPath(name).is_absolute() and ".." not in PurePosixPath(name).parts
                     and "\\" not in name for name in names), "ZIP member path")
        pickles = [info for info in infos if info.filename.endswith("/data.pkl")]
        _require(len(pickles) == 1 and 0 < pickles[0].file_size <= MAX_PICKLE_BYTES
                 and not pickles[0].flag_bits & 1, "ZIP data.pkl descriptor")
        prefix = pickles[0].filename[:-len("data.pkl")]
        root = parse_symbolic_pickle(archive.read(pickles[0]))
        members = {info.filename: info for info in infos}
        storages, globals_seen = {}, set()
        for value in _walk(root):
            if isinstance(value, GlobalRef):
                globals_seen.add(_global(value))
            elif isinstance(value, PersistentRef):
                descriptor = _storage(value.key)
                key = descriptor["storage_key"]
                member = prefix + "data/" + key
                _require(member in members and not members[member].flag_bits & 1
                         and members[member].file_size == descriptor["expected_bytes"], "ZIP storage size differs")
                descriptor.update(zip_member=member, zip_file_size=members[member].file_size)
                _require(key not in storages or storages[key] == descriptor, "inconsistent shared storage descriptor")
                storages[key] = descriptor
        _require({name for name in names if name.startswith(prefix + "data/")}
                 == {value["zip_member"] for value in storages.values()}, "unreferenced ZIP storage")
    except (zipfile.BadZipFile, OSError, RuntimeError, EOFError) as error:
        raise ValueError("Invalid checkpoint metadata: malformed ZIP archive") from error
    finally:
        if "archive" in locals():
            archive.close()

    state = _state(root)
    config = state["config"]
    preproc = _state(config)["preproc_config"]
    model_config, model_omitted = _saved_config(config, {"preproc_config"})
    preproc_config, preproc_omitted = _saved_config(preproc, {"type_set", "archs"})
    parameter_shapes, tensor_metadata, relation_layers, module_classes = {}, {}, [], {}

    def visit(module, module_path, ancestors=()):
        _require(len(module_classes) < 4096 and len(ancestors) < 64 and id(module) not in ancestors, "module traversal limit or cycle")
        module_state = _state(module)
        module_class = _global(module.constructor)
        module_classes[module_path] = module_class
        local_shapes = {}
        for name, parameter in _mapping(module_state["_parameters"]).items():
            _require(type(name) is str and bool(name), "parameter name")
            if parameter is None:
                continue
            metadata = _tensor_metadata(parameter)
            full_name = (module_path + "." if module_path else "") + name
            tensor_metadata[full_name] = metadata
            parameter_shapes[full_name] = local_shapes[name] = metadata["shape"]
        if module_class == "torch_geometric.nn.conv.rgcn_conv.RGCNConv":
            saved_relations, bases = module_state.get("num_relations"), module_state.get("num_bases")
            weight, comp = local_shapes.get("weight"), local_shapes.get("comp")
            _require(isinstance(weight, list) and len(weight) == 3, "RGCN weight shape")
            if comp is not None:
                _require(len(comp) == 2 and comp[1] == weight[0], "RGCN basis decomposition shapes")
                capacity = comp[0]
            else:
                capacity = weight[0]
            _require(saved_relations is None or (_int(saved_relations, 1) and saved_relations == capacity),
                     "RGCN saved relation count disagrees with parameters")
            _require(bases is None or (_int(bases, 1) and bases == weight[0]), "RGCN saved basis count")
            relation_layers.append({"index": int(module_path.rsplit(".", 1)[-1]), "module_path": module_path,
                "module_class": module_class, "num_relations": saved_relations, "num_bases": bases,
                "parameter_shapes": local_shapes, "parameter_relation_capacity": capacity,
                "relation_capacity_verified": saved_relations == capacity,
                "notes": [] if saved_relations is not None else ["Saved num_relations absent; parameter capacity reported separately."]})
        for name, child in _mapping(module_state["_modules"]).items():
            _require(type(name) is str and bool(name), "module name")
            if child is not None:
                visit(child, (module_path + "." if module_path else "") + name, ancestors + (id(module),))

    visit(root, "")
    encoder = parameter_shapes.get("encoder.first_layer.0.weight")
    decoder = parameter_shapes.get("decoder.last_layer.weight")
    _require(isinstance(encoder, list) and len(encoder) == 2
             and encoder[1] == model_config["node_encoder_in_dim"] == preproc_config["node_label_encoding_dim"],
             "saved encoder input dimension disagrees with parameters")
    _require(isinstance(decoder, list) and len(decoder) == 2 and decoder[0] == model_config["out_dim"],
             "saved output classes disagree with decoder parameters")
    return {"schema": "symbai.frozen_checkpoint_metadata.v1", "model_sha256": digest,
            "model_class": root.constructor.name, "model_class_qualified": _global(root.constructor),
            "model_config": model_config, "preproc_config": preproc_config,
            "parameter_shapes": parameter_shapes, "tensor_metadata": tensor_metadata,
            "relation_layers": sorted(relation_layers, key=lambda value: value["index"]),
            "output_class_count": decoder[0], "storage_descriptors": sorted(storages.values(), key=lambda value: value["storage_key"]),
            "symbolic_globals": sorted(globals_seen), "module_classes": module_classes,
            "omitted_nonprimitive_config_fields": {"model_config": model_omitted, "preproc_config": preproc_omitted},
            "pickle_member": pickles[0].filename, "pickle_bytes": pickles[0].file_size,
            "external_code_executed": False, "no_external_execution": True, "inference_performed": False,
            "tensor_arrays_loaded": False, "scope": "passive_saved_metadata_and_storage_descriptors_only"}


def inspect_frozen_checkpoint(path):
    """Return JSON-compatible saved metadata for the exact frozen model identity.

    The hash gate is unconditional. Even on this trusted identity, all pickle
    constructors/reducers/state operations remain symbolic and arrays are unread.
    """
    try:
        return _inspect_frozen_checkpoint(path)
    except (KeyError, TypeError, AttributeError, IndexError, OverflowError, RecursionError) as error:
        raise ValueError("Invalid checkpoint metadata: malformed saved object or tensor structure") from error
