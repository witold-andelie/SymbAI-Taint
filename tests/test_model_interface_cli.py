"""Snapshot/query identity boundaries for the passive interface-audit entry."""

from pathlib import Path
import uuid

import pytest

from benchmarks.selective_analysis.indirection_mechanisms import make_indirection_mechanisms
from scripts import audit_tygr_interface as cli
from src.selective_analysis.instruction_provenance import build_syntax_provenance
from src.selective_analysis.workspace import SCRATCH

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture
def retained():
    root = SCRATCH / "tests" / ("interface-parent-" + uuid.uuid4().hex)
    root.mkdir(parents=True)
    manifest = make_indirection_mechanisms(root / "inputs")
    rows = []
    for contract in cli.read(manifest)["queries"]:
        name = contract["query_id"]
        request = {"schema": "symbai.syntax_request.v1", "binary": str(root / "inputs" / contract["binary"]),
                   "binary_sha256": contract["binary_sha256"], "entry_rva": contract["entry_rva"],
                   "target_store_rva": contract["write_rva"]}
        graph = build_syntax_provenance(request)
        assert graph["status"] == "available"
        identity = dict(contract)
        identity.pop("binary")
        payload = {"case_id": name, "worker_candidate": {"graph": graph, "forbidden_runtime_imports": []},
                   "source_query_hash": cli.fingerprint(identity), "request_fingerprint": cli.fingerprint(request),
                   "process": {"timed_out": False, "returncode": 0}}
        serialized = cli.json.dumps(payload, indent=2).encode("utf-8")
        receipt = {"status": "available", "late": False, "payload_fingerprint": cli.fingerprint(payload),
                   "payload_sha256": cli.hashlib.sha256(serialized).hexdigest()}
        rows.append({"case_id": name, "payload": payload, "parent_receipt": receipt})
        cli.write(root / "workers" / name / "request.json", request)
    cli.write(root / "records.json", rows)
    cli.write(root / "run-plan.json", {"input_sha256": {path.name: cli.file_hash(path)
              for path in (root / "inputs").iterdir() if path.name != "gold.json"}})
    return root


def test_original_retained_identity_and_complete_three_query_coverage(retained):
    cases = cli.syntax_cases(retained, REPO / "scripts/run_instruction_provenance.py")
    assert {case["case_id"] for case in cases} == set(cli.CASES)
    assert sum(len(case["graph"]["nodes"]) for case in cases) == 259


def test_changed_elf_cannot_pass_by_updating_only_its_local_plan(retained):
    binary = retained / "inputs/scalar_span.elf"
    binary.write_bytes(binary.read_bytes() + b"changed")
    plan = cli.read(retained / "run-plan.json")
    plan["input_sha256"][binary.name] = cli.file_hash(binary)
    cli.write(retained / "run-plan.json", plan)
    with pytest.raises(ValueError, match="pinned identity"):
        cli.syntax_cases(retained, REPO / "scripts/run_instruction_provenance.py")


def test_manifest_path_is_not_discarded_while_matching_identity(retained):
    manifest = retained / "inputs/queries.json"
    value = cli.read(manifest)
    value["queries"][0]["binary"] = "../scalar_span.elf"
    cli.write(manifest, value)
    plan = cli.read(retained / "run-plan.json")
    plan["input_sha256"][manifest.name] = cli.file_hash(manifest)
    cli.write(retained / "run-plan.json", plan)
    with pytest.raises(ValueError, match="pinned identity"):
        cli.syntax_cases(retained, REPO / "scripts/run_instruction_provenance.py")


def test_payload_fingerprint_cannot_replace_the_saved_serialized_payload_hash(retained):
    rows = cli.read(retained / "records.json")
    rows[0]["payload"]["extra_unobserved_metadata"] = "tampered"
    rows[0]["parent_receipt"]["payload_fingerprint"] = cli.fingerprint(rows[0]["payload"])
    cli.write(retained / "records.json", rows)
    with pytest.raises(ValueError, match="status or identity"):
        cli.syntax_cases(retained, REPO / "scripts/run_instruction_provenance.py")


def test_source_excerpts_follow_class_scope_without_executing_source():
    source = "raise RuntimeError('must never execute')\nclass A:\n def forward(self):\n  return 1\nclass B:\n def forward(self):\n  return 2\n"
    line, text = cli.excerpt(source, "B.forward", 20)
    assert line == 6 and text == [" def forward(self):", "  return 2"]


def test_metadata_audit_imports_no_new_framework_for_source_excerpts():
    before = set(cli.sys.modules)
    cli.excerpt("def f():\n return 'text'\n", "f", 4)
    assert not [name for name in set(cli.sys.modules) - before
                if name.split(".")[0] in ("torch", "angr", "claripy", "z3")]
