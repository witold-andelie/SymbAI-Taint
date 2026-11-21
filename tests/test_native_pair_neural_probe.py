"""Coverage selection and attribution of failures before any model forward."""
from copy import deepcopy

import pytest

from scripts import probe_native_pair_tygr as probe


def test_remaining_scope_preserves_manifest_order_and_excludes_initial_pair():
    names = ["case" + str(i) for i in range(10)]
    manifest = {"cases": [{"case_id": name} for name in (probe.CASES[0], *names, probe.CASES[1])]}
    assert probe.selected_cases(manifest) == probe.CASES
    assert probe.selected_cases(manifest, remaining=True) == tuple(names)
    manifest["cases"][-1] = manifest["cases"][0]
    with pytest.raises(ValueError, match="twelve unique frozen cases"):
        probe.selected_cases(manifest, remaining=True)


def failed_child():
    return {"status": "failed", "forward_calls_attempted": 0, "forward_calls_completed": 0,
        "error": {"type": "ValueError", "message":
            "Observed native relation outside declared/saved layer domains; forward refused"},
        "model_contract": {"layer_relation_capacities": [44] * 8},
        "functions": [{"function_address": 0x401000, "native_input": {
            "batch": {"edge_labels": {"values": [2, 32, 18, 48]}},
            "graph_edges": [{"labels": ["__lshift__"], "forward_id": 18, "inverse_id": 48}]}}]}


def test_child_error_survives_parent_review_without_becoming_identity_failure():
    with pytest.raises(ValueError, match="outside declared/saved layer domains; forward refused"):
        probe.review(failed_child(), {}, None, None)


def test_failure_attribution_retains_actual_unsupported_edge_and_never_mutates_input():
    payload = failed_child()
    before = deepcopy(payload)
    detail = probe.failure_details(payload)
    assert detail["failure_stage"] == "pre_forward_relation_domain"
    assert detail["relation_domain_findings"][0]["out_of_saved_domain_ids"] == [48]
    assert detail["relation_domain_findings"][0]["edges"][0]["labels"] == ["__lshift__"]
    assert payload == before


@pytest.mark.parametrize("change", ["forward_attempted", "other_error", "no_contract"])
def test_failure_stage_is_not_inferred_from_an_unsupported_edge_alone(change):
    payload = failed_child()
    if change == "forward_attempted":
        payload["forward_calls_attempted"] = 1
    elif change == "other_error":
        payload["error"] = {"type": "OSError", "message": "another cause"}
    else:
        payload.pop("model_contract")
    assert probe.failure_details(payload)["failure_stage"] == "acquisition_or_review"
