"""Readiness, late admission and startup failure at the parent transport boundary."""
from types import SimpleNamespace

from scripts import measure_native_local_actions as local


class MemoryPath:
    def __init__(self, name="memory"):
        self.name = name

    def __truediv__(self, name):
        return MemoryPath(self.name + "/" + name)

    def __str__(self):
        return self.name

    def mkdir(self):
        pass

    def with_suffix(self, suffix):
        return MemoryPath(self.name + suffix)

    def exists(self):
        return False


def simulated_transport(monkeypatch, *, action_seconds=1.0, startup_failure=False):
    state = SimpleNamespace(now=100.0, request=None, returncode=None)
    process = SimpleNamespace(pid=123, poll=lambda: state.returncode)
    child = (process, None, MemoryPath("ready"), MemoryPath("log"))
    monkeypatch.setattr(local.time, "monotonic", lambda: state.now)

    def launch(*args):
        state.now += 0.2
        return child

    def ready(*args):
        state.now += 20.0 if startup_failure else 2.0
        return None if startup_failure else state.now

    def send(child, request):
        state.request = request

    def receive(*args):
        state.now += action_seconds
        identity = state.request["identity"]
        return {"kind": "backend", "nonce": identity["nonce"], "query_hash": identity["query_hash"],
            "time": state.now, "result": {**identity, "status": "excluded_within_scope", "route": "exact"}}, state.now

    def finish(*args):
        state.now += 0.1
        state.returncode = 0
        process.returncode = 0
        return True

    transport = SimpleNamespace(iso=SimpleNamespace(launch=launch, finish=finish, log_events=lambda path: []),
        wait_ready=ready, send=send, receive=receive,
        matching=lambda reply, received, deadline, identity, kind: received <= deadline)
    return transport, state


def execute(transport):
    return local.execute_action(transport, MemoryPath(), 1,
        {"case": "case", "repetition": 0, "arm": "concrete_only"},
        SimpleNamespace(contract_hash="q" * 64))


def test_slow_startup_does_not_consume_the_three_second_action_window(monkeypatch):
    transport, state = simulated_transport(monkeypatch)
    row = execute(transport)
    assert row["admitted"] and row["status"] == "excluded_within_scope"
    assert state.request["deadline"] == row["ready_observed"] + 3.0
    assert abs(row["startup_seconds"] - 2.2) < 1e-10
    assert abs(row["action_wall_seconds"] - 1.0) < 1e-10
    assert abs(row["recovery_seconds"] - 0.1) < 1e-10
    assert abs(row["diagnostic_parent_seconds"] - 3.3) < 1e-10


def test_late_reply_is_retained_but_never_admitted(monkeypatch):
    transport, _ = simulated_transport(monkeypatch, action_seconds=3.1)
    row = execute(transport)
    assert not row["admitted"] and row["status"] == "unknown"
    assert row["reply"]["result"]["status"] == "excluded_within_scope"
    assert row["process"]["worker_reaped"]


def test_startup_failure_remains_an_unknown_infrastructure_failure(monkeypatch):
    transport, state = simulated_transport(monkeypatch, startup_failure=True)
    row = execute(transport)
    assert not row["admitted"] and row["status"] == "unknown"
    assert row["action_wall_seconds"] is None and row["deadline"] is None
    assert row["failure"]["type"] == "TimeoutError"
    assert state.request is None and row["process"]["worker_reaped"]
    assert abs(row["diagnostic_parent_seconds"] - 20.3) < 1e-10
