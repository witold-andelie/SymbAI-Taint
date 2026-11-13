"""Runtime inputs contain program assumptions, never gold labels or expected answers."""

from dataclasses import asdict, dataclass, fields
import hashlib
import json
from pathlib import Path


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def file_hash(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class InputRange:
    register: str
    minimum: int = 0
    maximum: int = (1 << 64) - 1

    def __post_init__(self):
        if self.register not in ("rdi", "rsi", "rdx", "rcx", "r8", "r9"):
            raise ValueError("Only explicit x86-64 integer argument registers are supported")
        if not 0 <= self.minimum <= self.maximum < (1 << 64):
            raise ValueError("Input bounds must be unsigned 64-bit ranges")


@dataclass(frozen=True)
class Query:
    query_id: str
    binary: str
    binary_sha256: str
    entry_rva: int
    write_rva: int
    object_rva: int
    capacity: int
    inputs: tuple[InputRange, ...]
    scope: str = "first_dynamic_visit"
    bounds_source: str = "explicit_query_contract"

    def __post_init__(self):
        if self.scope != "first_dynamic_visit":
            raise ValueError("The pilot scope is the first dynamic visit to one write site")
        if not self.query_id or not 0 < self.capacity < (1 << 64):
            raise ValueError("Queries need an ID and a positive object capacity")
        if any(x < 0 for x in (self.entry_rva, self.write_rva, self.object_rva)):
            raise ValueError("RVAs must be nonnegative")
        if len({i.register for i in self.inputs}) != len(self.inputs):
            raise ValueError("Duplicate input register")
        if len(self.binary_sha256) != 64:
            raise ValueError("Missing binary content hash")

    @property
    def use_site_id(self):
        return f"{self.binary_sha256}:{self.entry_rva:x}:{self.write_rva:x}:write_address"

    @property
    def contract_hash(self):
        value = asdict(self)
        value.pop("binary")
        return fingerprint(value)

    @classmethod
    def from_dict(cls, data, base=Path(".")):
        allowed = {f.name for f in fields(cls)}
        extra = set(data) - allowed
        if extra:
            raise ValueError(f"Unexpected runtime query fields: {sorted(extra)}")
        value = dict(data)
        value["inputs"] = tuple(InputRange(**r) for r in value["inputs"])
        value["binary"] = str((base / value["binary"]).resolve())
        query = cls(**value)
        if file_hash(query.binary) != query.binary_sha256:
            raise ValueError("Binary hash differs from query contract")
        return query


@dataclass(frozen=True)
class Operation:
    operation_id: str
    max_steps: int
    structural_utility: float
    estimated_seconds: float
    type_role: str
    implementation_revision: str = "exact_prefix_v2"


# One type-blind universe for A-D. These are initial developer estimates, not timings.
OPERATIONS = (
    Operation("definitions", 0, 0.20, 0.12, "pointer"),
    Operation("bounded_paths", 8, 1.0, 0.20, "integer"),
    Operation("expanded_paths", 128, 1.25, 0.60, "pointer"),
)


@dataclass(frozen=True)
class Checkpoint:
    query_hash: str
    attempted: tuple[str, ...] = ()
    facts: tuple[str, ...] = ()

    @property
    def checkpoint_id(self):
        return fingerprint(asdict(self))

    def advance(self, operation_id, facts=()):
        if operation_id in self.attempted:
            raise ValueError("An operation cannot be paid for twice at one fixed precision")
        return Checkpoint(self.query_hash, self.attempted + (operation_id,),
                          tuple(sorted(set(self.facts) | set(facts))))
