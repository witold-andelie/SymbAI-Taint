"""Observer delegation/restoration and rooted batch correspondence."""
from copy import deepcopy
from types import SimpleNamespace

import networkx as nx
import pytest

from scripts.capture_tygr_graph_stages import StageObserver
from scripts.audit_native_graph_stages import equal_inputs


def test_observers_delegate_once_preserve_returns_and_restore_after_failure():
    calls = []
    state = SimpleNamespace(history=SimpleNamespace(actions=SimpleNamespace(hardcopy=[])),
        scratch=SimpleNamespace(ins_addr=0x1000), inspect=SimpleNamespace())

    class Graph:
        def __init__(self):
            self.graph = nx.DiGraph([(0, 1)])
            self.node_to_label = {i: SimpleNamespace(bitsize=64, addr=None, ast_val=0) for i in (0, 1)}
            self.edge_to_labels = {(0, 1): {"reg_data"}}

        def directed_splice_and_normalize(self, nodes):
            calls.append("splice")
            return self, {0: 0, 1: 1}

    class Strategy:
        def sim_exec_block(self, current, block):
            calls.append("block")
            return current

        def register_read_before_hook(self, current):
            calls.append("register")
            current.inspect.register_read_expr = "original-value"

        def memory_read_before_hook(self, current):
            calls.append("memory")

    class State:
        scratch = state.scratch

        def step(self, **kwargs):
            calls.append("step")
            raise ValueError("original step failure")

    graph, strategy, returned = Graph(), Strategy(), object()

    def subject(task):
        strategy.register_read_before_hook(state)
        strategy.memory_read_before_hook(state)
        assert strategy.sim_exec_block(state, SimpleNamespace(instruction_addrs=[0x1000])) is state
        assert graph.directed_splice_and_normalize({1})[0] is graph
        with pytest.raises(ValueError, match="original step failure"):
            State().step(num_inst=1)
        return returned

    datagen = SimpleNamespace(sym_exec_one=subject)
    originals = (Strategy.sim_exec_block, Graph.directed_splice_and_normalize, State.step)
    observer = StageObserver()
    with pytest.raises(RuntimeError, match="caller failure"):
        with observer.install(datagen, SimpleNamespace(SimExecStrategy=Strategy), Graph, State):
            assert datagen.sym_exec_one((0x1000,)) is returned
            raise RuntimeError("caller failure")
    assert datagen.sym_exec_one is subject
    assert originals == (Strategy.sim_exec_block, Graph.directed_splice_and_normalize, State.step)
    assert calls == ["register", "memory", "block", "splice", "step"]
    record, = observer.functions
    assert record["step_exceptions"][0]["message"] == "original step failure"
    fields = record["read_hook_events"][0]["fields_after_original_hook"]
    assert fields["register_read_expr"] == "original-value" and fields["reg_read_expr"] is None
    assert observer.current is None and not observer.errors


def test_batch_correspondence_preserves_relations_and_variable_readout():
    def tensor(values, shape):
        return {"values": values, "shape": shape}
    left = {"num_vars": [1], "node_labels": tensor([[1, 0], [0, 1], [2, 0]], [3, 2]),
        "edge_labels": tensor([3, 33, 2, 32], [4]), "edges": tensor([[1, 0, 2, 0], [0, 1, 0, 2]], [2, 4]),
        "var_gather": tensor([0], [1]), "var_scatter": tensor([0], [1])}
    right = deepcopy(left)
    right["node_labels"]["values"] = [[2, 0], [1, 0], [0, 1]]
    right["edges"]["values"] = [[2, 1, 0, 1], [1, 2, 1, 0]]
    right["var_gather"]["values"] = [1]
    assert equal_inputs(left, right)
    wrong = deepcopy(right)
    wrong["var_gather"]["values"] = [0]
    assert not equal_inputs(left, wrong)
    wrong = deepcopy(right)
    wrong["edge_labels"]["values"][0] = 7
    assert not equal_inputs(left, wrong)
