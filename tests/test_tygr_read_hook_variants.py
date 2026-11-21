"""External hook routing, timing isolation, stale-value handling and restoration."""
from types import SimpleNamespace
from pathlib import Path

import pytest

from scripts.tygr_read_hook_variants import install


def subject():
    class Strategy:
        def register_read_before_hook(self, state):
            state.calls.append("reg")
            if state.raise_read:
                raise ValueError("subject failure")
            if not state.ignore_read:
                state.inspect.register_read_expr = object()
            return state

        def memory_read_before_hook(self, state):
            state.calls.append("mem")
            state.inspect.memory_read_expr = object()
            return state

        def write_hook(self, state):
            pass

        def init_symbolic_state(self):
            state = SimpleNamespace(inspect=SimpleNamespace(), calls=[], ignore_read=False, raise_read=False)
            state.inspect._breakpoints = {
                "reg_read": [SimpleNamespace(action=self.register_read_before_hook, when="before")],
                "mem_read": [SimpleNamespace(action=self.memory_read_before_hook, when="before")],
                "reg_write": [SimpleNamespace(action=self.write_hook, when="before")],
                "mem_write": [SimpleNamespace(action=self.write_hook, when="before")]}
            return state
    return Strategy


def test_original_leaves_callbacks_and_fields_unchanged():
    cls = subject()
    original = cls.register_read_before_hook
    with install(cls, "original", "before", "after") as report:
        assert cls.register_read_before_hook is original
        strategy = cls()
        state = strategy.init_symbolic_state()
        assert strategy.register_read_before_hook(state) is state
        assert not hasattr(state.inspect, "reg_read_expr")
        assert not report["field_routes"] and not report["timing_moves"]


@pytest.mark.parametrize("variant", ["field_names_before", "field_names_after"])
def test_fresh_values_routed_once_stale_ignored_read_not_reused(variant):
    cls = subject()
    with install(cls, variant, "before", "after") as report:
        strategy = cls()
        state = strategy.init_symbolic_state()
        assert strategy.register_read_before_hook(state) is state
        assert state.inspect.reg_read_expr is state.inspect.register_read_expr
        expected = object()
        state.inspect.reg_read_expr = expected
        state.ignore_read = True
        strategy.register_read_before_hook(state)
        assert state.inspect.reg_read_expr is expected
        assert strategy.memory_read_before_hook(state) is state
        assert state.inspect.mem_read_expr is state.inspect.memory_read_expr
        assert state.calls == ["reg", "reg", "mem"]
        assert report["field_routes"] == {"reg_read_expr": 1, "mem_read_expr": 1}
        assert report["original_hook_calls"] == {"register_read_before_hook": 2, "memory_read_before_hook": 1}


@pytest.mark.parametrize("variant", ["original", "field_names_before", "field_names_after"])
def test_timing_changes_only_matching_read_breakpoints_and_restores(variant):
    cls = subject()
    originals = cls.register_read_before_hook, cls.memory_read_before_hook, cls.init_symbolic_state
    with pytest.raises(RuntimeError, match="caller failure"):
        with install(cls, variant, "before", "after") as report:
            strategy = cls()
            state = strategy.init_symbolic_state()
            expected = "after" if variant == "field_names_after" else "before"
            assert all(state.inspect._breakpoints[event][0].when == expected for event in ("reg_read", "mem_read"))
            assert all(state.inspect._breakpoints[event][0].when == "before" for event in ("reg_write", "mem_write"))
            assert len(report["timing_moves"]) == (2 if variant == "field_names_after" else 0)
            raise RuntimeError("caller failure")
    assert originals == (cls.register_read_before_hook, cls.memory_read_before_hook, cls.init_symbolic_state)


def test_subject_failure_is_propagated_without_routing_stale_value():
    cls = subject()
    with install(cls, "field_names_before", "before", "after") as report:
        strategy = cls()
        state = strategy.init_symbolic_state()
        state.raise_read = True
        with pytest.raises(ValueError, match="subject failure"):
            strategy.register_read_before_hook(state)
        assert state.calls == ["reg"] and not report["field_routes"]


def test_unexpected_original_timing_is_refused():
    cls = subject()
    original = cls.init_symbolic_state

    def changed(strategy):
        state = original(strategy)
        state.inspect._breakpoints["reg_read"][0].when = "after"
        return state

    cls.init_symbolic_state = changed
    with install(cls, "field_names_after", "before", "after"):
        with pytest.raises(ValueError, match="binding/timing differs"):
            cls().init_symbolic_state()
    assert cls.init_symbolic_state is changed


@pytest.mark.parametrize("variant", ["original", "field_names_before", "field_names_after"])
def test_real_inspection_engine_preserves_values_and_after_expression(variant):
    """Host-runtime integration; not evidence about the frozen old runtime."""
    angr = pytest.importorskip("angr")
    claripy = pytest.importorskip("claripy")

    class Strategy:
        def register_read_before_hook(self, state):
            value = claripy.BVS("routed_register", 64)
            state.solver.add(value == 7)
            state.inspect.register_read_expr = value

        def memory_read_before_hook(self, state):
            value = claripy.BVS("routed_memory", 8)
            state.solver.add(value == 3)
            state.inspect.memory_read_expr = value

        def init_symbolic_state(self):
            state = angr.SimState(arch="AMD64", mode="symbolic")
            state.registers.store("rdi", claripy.BVV(7, 64), inspect=False)
            state.memory.store(0x2000, claripy.BVV(3, 8), inspect=False)
            state.inspect.b("reg_read", when=angr.BP_BEFORE, action=self.register_read_before_hook)
            state.inspect.b("mem_read", when=angr.BP_BEFORE, action=self.memory_read_before_hook)
            return state

    with install(Strategy, variant, angr.BP_BEFORE, angr.BP_AFTER):
        state = Strategy().init_symbolic_state()
        register = state.registers.load("rdi", size=8)
        memory = state.memory.load(0x2000, size=1)
        assert state.solver.eval_upto(register, 2) == [7]
        assert state.solver.eval_upto(memory, 2) == [3]
        if variant == "original":
            assert not register.symbolic and not memory.symbolic
        elif variant == "field_names_after":
            assert register.symbolic and memory.symbolic


@pytest.mark.parametrize("unsupported", [False, True])
def test_review_replays_original_guard_including_diagnostic_rejection(monkeypatch, unsupported):
    from scripts import compare_tygr_read_hooks as driver
    from scripts import export_typed_complementarity as guard

    def tensor(values, shape, dtype="torch.int64"):
        return {"values": values, "shape": shape, "device": "cpu", "dtype": dtype}

    batch = {"num_vars": [1], "node_labels": tensor([[0] * 31] * 2, [2, 31], "torch.float32"),
        "edge_labels": tensor([50 if unsupported else 2], [1]), "edges": tensor([[0], [1]], [2, 1]),
        "var_gather": tensor([0], [1]), "var_scatter": tensor([0], [1]), "labels_supplied_to_model": False}
    native = {"batch": batch, "prepared": {**batch, "var_nodes": [[0]]}}
    contract = {"feature_width": 31, "type_count": 75, "declared_relation_count": 60,
                "layer_relation_capacities": [44] * 8}
    try:
        receipt = guard.guard_native_input(native, contract)
    except ValueError as error:
        receipt = {"status": "rejected", "reason": str(error)}
    graph = {"node_count": 2, "nodes": [{"id": 0, "annotation_address": None},
        {"id": 1, "annotation_address": 4096}],
        "edges": [{"source": 0, "target": 1, "labels": ["mem_loc"]}]}
    function = {"function_address": 4080, "native_input": native, "saved_model_input_guard": receipt,
        "blocks": [{"actions": [{"type": "mem", "action": "write", "instruction_address": 4096}]}],
        "step_exceptions": [], "splices": [{"before": graph, "after": graph, "seed_nodes": [0]}]}
    payload = {"status": "captured", "variant": "field_names_before", "forward_attempts": 0,
        "model_forward_performed": False, "original_identities_rechecked": True,
        "observer_errors": [], "location_errors": [], "location_records": [{"location": 1}],
        "binary_sha256": "binary", "model_sha256": "model", "model_contract": contract,
        "intervention": {"variant": "field_names_before", "routing_installed": True,
            "timing_override_installed": False, "field_routes": {"reg_read_expr": 1}, "timing_moves": []},
        "functions": [function]}
    directory = Path("in_memory_review")
    job = {"case_id": "modeled", "variant": "field_names_before", "directory": directory,
           "job_directory": directory, "address": 4080}
    guard_path = driver.ROOT / "scripts" / "export_typed_complementarity.py"
    files = {directory / "request.json": {"native_request": {"binary_sha256": "binary", "model_sha256": "model"},
        "implementation": {"guard": {"path": str(guard_path), "sha256": driver.base.digest(guard_path)}}},
        directory / "offline-location-trace.json": [{"location": 1}],
        directory / "static-instructions.json": {"write_address": 4096}}
    monkeypatch.setattr(driver.base, "read", files.__getitem__)
    result = driver.review(job, payload)
    assert result["saved_model_guard_replayed"]
    assert result["saved_model_guard"]["status"] == ("rejected" if unsupported else "passed")
    assert result["out_of_saved_relation_domain_ids"] == ([50] if unsupported else [])
    function["saved_model_input_guard"] = {"status": "passed", "forged": True}
    with pytest.raises(ValueError, match="guard receipt differs"):
        driver.review(job, payload)
