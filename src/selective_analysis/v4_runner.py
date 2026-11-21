"""Parent-enforced, isolated execution of finite-domain backend orders for Route B v4.

An arm is an order over the two backends of ``finite_backends``. The first backend runs under the
request deadline; if its result is not decisive and time remains, the next backend starts fresh
under the same deadline, as in the archived fixed symbolic-to-concrete cascade. A persistent,
warm worker process executes requests; the parent clock charges each request from dispatch to
admitted reply, and a reply after the deadline (plus a grace interval for reaping) is discarded and
recorded as unknown. The worker is then replaced, and the replacement time is recorded separately.
Runtime code reads query contracts only, never references or labels.
"""
import multiprocessing
import time

DECISIVE = ("excluded_within_scope", "violation")
BACKENDS = ("symbolic_certificate", "concrete_enumeration")
REAP_GRACE_SECONDS = 0.5


def _worker(connection):
    import logging
    logging.getLogger("angr").setLevel(logging.CRITICAL)
    from .contracts import Query
    from . import finite_backends
    import angr  # noqa: F401  (load once while warming up)
    connection.send({"event": "ready"})
    while True:
        request = connection.recv()
        if request is None:
            return
        query = Query.from_dict(request["query"])
        deadline = time.monotonic() + request["budget_seconds"]
        attempts, final = [], {"status": "unknown", "route": "not_started"}
        for name in request["order"]:
            if time.monotonic() >= deadline:
                break
            started = time.monotonic()
            result = getattr(finite_backends, name)(query, deadline)
            attempts.append({"backend": name, "status": result["status"], "route": result["route"],
                             "seconds": time.monotonic() - started})
            final = dict(result, backend=name)
            if result["status"] in DECISIVE:
                break
        connection.send({"event": "reply", "request_id": request["request_id"], "final": final,
                         "attempts": attempts, "worker_finished_before_deadline": time.monotonic() < deadline})


class WarmWorker:
    def __init__(self):
        self.context = multiprocessing.get_context("spawn")
        self.process, self.connection, self.replacements = None, None, []
        self.start()

    def start(self):
        started = time.monotonic()
        parent, child = self.context.Pipe()
        self.process = self.context.Process(target=_worker, args=(child,), daemon=True)
        self.process.start()
        self.connection = parent
        if not parent.poll(300) or parent.recv().get("event") != "ready":
            raise RuntimeError("Worker did not become ready")
        return time.monotonic() - started

    def stop(self):
        if self.process is not None and self.process.is_alive():
            try:
                self.connection.send(None)
            except (BrokenPipeError, OSError):
                pass
            self.process.join(5)
            if self.process.is_alive():
                self.process.kill()
                self.process.join(5)

    def run(self, request_id, query_dict, order, budget_seconds):
        if any(name not in BACKENDS for name in order) or not order:
            raise ValueError("Unknown backend order")
        dispatched = time.monotonic()
        self.connection.send({"request_id": request_id, "query": query_dict, "order": list(order),
                              "budget_seconds": budget_seconds})
        if self.connection.poll(budget_seconds + REAP_GRACE_SECONDS):
            reply = self.connection.recv()
            charged = time.monotonic() - dispatched
            admitted = charged <= budget_seconds and reply["request_id"] == request_id
            final = reply["final"] if admitted else {"status": "unknown", "route": "late_reply"}
            return {"request_id": request_id, "order": list(order), "charged_seconds": charged,
                    "admitted": admitted, "status": final["status"], "final": final,
                    "attempts": reply["attempts"], "worker_replaced": False}
        charged = time.monotonic() - dispatched
        self.process.kill()
        self.process.join(5)
        replacement = self.start()
        self.replacements.append(replacement)
        return {"request_id": request_id, "order": list(order), "charged_seconds": charged,
                "admitted": False, "status": "unknown", "final": {"status": "unknown", "route": "reaped"},
                "attempts": [], "worker_replaced": True, "replacement_seconds": replacement}


def fixed_cascade_order(query_dict):
    return ("symbolic_certificate", "concrete_enumeration")


def input_count_order(query_dict, threshold=64):
    (bounds,) = query_dict["inputs"]
    size = bounds["maximum"] - bounds["minimum"] + 1
    return (("concrete_enumeration", "symbolic_certificate") if size <= threshold
            else ("symbolic_certificate", "concrete_enumeration"))
