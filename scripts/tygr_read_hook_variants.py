"""External read-expression routing and read-event timing interventions, Python 3.8."""
from contextlib import contextmanager
from functools import wraps

VARIANTS = ("original", "field_names_before", "field_names_after")
FIELDS = (("register_read_before_hook", "register_read_expr", "reg_read_expr", "reg_read"),
          ("memory_read_before_hook", "memory_read_expr", "mem_read_expr", "mem_read"))


@contextmanager
def install(strategy_class, variant, before, after):
    """Call original hooks once; route only an expression freshly created by that call."""
    if variant not in VARIANTS:
        raise ValueError("Unknown hook intervention")
    originals = {name: getattr(strategy_class, name) for name, _, _, _ in FIELDS}
    original_init = strategy_class.init_symbolic_state
    report = {"variant": variant, "routing_installed": variant != "original",
        "timing_override_installed": variant == "field_names_after",
        "original_hook_calls": {}, "field_routes": {}, "timing_moves": []}
    sentinel = object()

    def routed(original, method, old, new):
        @wraps(original)
        def hook(strategy, state):
            previous = getattr(state.inspect, old, sentinel)
            result = original(strategy, state)
            report["original_hook_calls"][method] = report["original_hook_calls"].get(method, 0) + 1
            current = getattr(state.inspect, old, sentinel)
            # Ignored-register callbacks leave a stale alias; never route that value.
            if current is not sentinel and current is not previous:
                setattr(state.inspect, new, current)
                report["field_routes"][new] = report["field_routes"].get(new, 0) + 1
            return result
        return hook

    @wraps(original_init)
    def init_after(strategy, *args, **kwargs):
        state = original_init(strategy, *args, **kwargs)
        for method, _, _, event in FIELDS:
            target = getattr(strategy, method)
            matches = [bp for bp in state.inspect._breakpoints[event] if bp.action == target]
            if len(matches) != 1 or matches[0].when != before:
                raise ValueError("Original read breakpoint binding/timing differs: " + event)
            matches[0].when = after
            report["timing_moves"].append({"event": event, "from": str(before), "to": str(after)})
        return state

    try:
        if variant != "original":
            for method, old, new, _ in FIELDS:
                setattr(strategy_class, method, routed(originals[method], method, old, new))
        if variant == "field_names_after":
            strategy_class.init_symbolic_state = init_after
        yield report
    finally:
        for name, original in originals.items():
            setattr(strategy_class, name, original)
        strategy_class.init_symbolic_state = original_init
