"""Torch- and angr-free checks of the consolidated Route B v4 backends and runner plumbing.

The behavioural regression (re-running the archived project-disjoint cohort) needs angr and runs in
WSL through scripts/regress_route_b_v4_backends.py.
"""
import ast
import json
from pathlib import Path

import pytest

from src.selective_analysis import finite_backends as fb
from src.selective_analysis import v4_runner as vr

ROOT = Path(__file__).resolve().parents[1]
SCRATCH = ROOT.parent / ".scratch/selective_analysis"
CENSUS = SCRATCH / "route-b-instruction-batch-census-20261118T212853877659Z/summary.json"
PRODUCER = SCRATCH / "route-b-instruction-batch-pilot-20261118T213329921957Z/batch_producer.py"
CONCRETE = SCRATCH / "route-b-concrete-enumeration-20261118T231121220578Z/concrete_core.py"


def test_constants_match_archive():
    assert fb.PROVEN == "excluded_within_scope" and fb.MAX_STEPS == 128 and fb.BATCH_LIMIT == 4
    if not CENSUS.is_file():
        pytest.skip("Archived census unavailable")
    assert fb.ELIGIBLE_MNEMONICS == frozenset(json.loads(CENSUS.read_bytes())["eligible_mnemonics"])


def _function_sources(path, names):
    text = path.read_text(encoding="utf-8")
    tree = ast.parse(text)
    return {n.name: ast.dump(n) for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in names}


@pytest.mark.parametrize("archive,names", [
    (PRODUCER, ("check_batched", "paths_from", "observation_record")),
    (CONCRETE, ("IncompleteExecution",)),
])
def test_copied_logic_is_ast_identical_to_archive(archive, names):
    """The consolidated functions must be copies, not re-derivations."""
    if not archive.is_file():
        pytest.skip("Archive unavailable")
    ours = _function_sources(ROOT / "src/selective_analysis/finite_backends.py", names)
    theirs = _function_sources(archive, names)
    assert set(theirs) == set(names)
    assert ours == theirs


def test_concrete_first_write_is_ast_identical_to_archive():
    if not CONCRETE.is_file():
        pytest.skip("Archive unavailable")
    ours = _function_sources(ROOT / "src/selective_analysis/finite_backends.py", ("ConcreteFirstWrite",))
    theirs = _function_sources(CONCRETE, ("ConcreteFirstWrite",))
    assert ours == theirs


def test_planner_differs_only_in_the_inlined_mnemonic_source():
    if not PRODUCER.is_file():
        pytest.skip("Archive unavailable")
    ours = _function_sources(ROOT / "src/selective_analysis/finite_backends.py", ("Planner",))["Planner"]
    theirs = _function_sources(PRODUCER, ("Planner",))["Planner"]
    archived_line = "frozenset(read(CENSUS / \"summary.json\")[\"eligible_mnemonics\"])"
    assert ast.dump(ast.parse(archived_line).body[0].value) in theirs
    assert theirs.replace(ast.dump(ast.parse(archived_line).body[0].value),
                          ast.dump(ast.parse("ELIGIBLE_MNEMONICS").body[0].value)) == ours


def test_orders():
    query = {"inputs": [{"register": "rdi", "minimum": 0, "maximum": 63}]}
    assert vr.fixed_cascade_order(query) == ("symbolic_certificate", "concrete_enumeration")
    assert vr.input_count_order(query)[0] == "concrete_enumeration"
    query["inputs"][0]["maximum"] = 255
    assert vr.input_count_order(query)[0] == "symbolic_certificate"
    assert set(vr.BACKENDS) == {"symbolic_certificate", "concrete_enumeration"}
