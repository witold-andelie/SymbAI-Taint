"""Finite-domain write-bound backends consolidated from the Route B execution-strategy archive.

Two backends decide whether the first dynamic visit to a query's write site stays inside the
declared object for every input of a finite domain:

- ``symbolic_certificate``: batched symbolic exploration (archive ``batch_producer.py`` from
  ``route-b-instruction-batch-pilot-20261118T213329921957Z``), then an independent path
  certificate check (``PathChecker``) with a fresh-replay fallback (worker body of
  ``route-b-cold-warm-certificate-20261118T214546898406Z/run.py`` with the later
  ``DiagnosticChecker -> PathChecker`` substitution used by the cascade baselines).
- ``concrete_enumeration``: concrete first-write execution of every input (archive
  ``route-b-concrete-enumeration-20261118T231121220578Z/concrete_core.py`` and its
  ``concrete_worker`` body).

The logic is copied, not re-derived. Only process plumbing changed: results are returned and
events go to an optional callback. No reference, label or expected answer is read here.
"""
from collections import Counter, defaultdict
from dataclasses import dataclass
from functools import lru_cache
import json
import time

from .contracts import fingerprint
from .local_bounds import LocalBoundsChecker, UnsupportedBounds
from .operations import BinaryChecker, BudgetExpired

PROVEN = "excluded_within_scope"
MAX_STEPS = 128
BATCH_LIMIT = 4
TRACE = "_route_b_batched_instruction_prefix"
TERMINAL_BRANCH = frozenset(("je", "jne", "jle"))
# Copied from route-b-instruction-batch-census-20261118T212853877659Z/summary.json.
ELIGIBLE_MNEMONICS = frozenset(("add", "and", "cmp", "endbr64", "mov", "movabs", "movsxd", "nop", "or",
                                "rol", "ror", "sar", "shl", "shr", "sub", "test", "xor"))


class IncompleteExecution(ValueError):
    pass


def _noop(event, **fields):
    return None


# ----------------------------------------------------------------------------- symbolic producer

@dataclass(frozen=True)
class Batch:
    pcs: tuple
    successors: frozenset
    irsb: object


class Planner:
    def __init__(self, checker):
        self.checker = checker
        self.decoder = LocalBoundsChecker(checker.query)
        if self.decoder.base != checker.base or self.decoder.target != checker.write:
            raise ValueError("Batch decoder and symbolic loader disagree on mapping")
        self.eligible = ELIGIBLE_MNEMONICS

    @lru_cache(maxsize=256)
    def choose(self, pc, remaining):
        """Admit straight register operations and one optional terminal direct branch."""
        addresses = []
        allowed_successors = set()
        next_pc = pc
        x86 = self.decoder.x86
        while len(addresses) < min(remaining, BATCH_LIMIT):
            if next_pc == self.checker.write or self.checker.project.is_hooked(next_pc):
                break
            try:
                insn = self.decoder.decode(next_pc)
            except UnsupportedBounds:
                break
            following = next_pc + insn.size
            if insn.mnemonic in TERMINAL_BRANCH:
                if len(insn.operands) == 1 and insn.operands[0].type == x86.X86_OP_IMM:
                    addresses.append(next_pc)
                    allowed_successors.update((following, insn.operands[0].imm))
                break
            if insn.mnemonic not in self.eligible or any(
                operand.type not in (x86.X86_OP_REG, x86.X86_OP_IMM)
                for operand in insn.operands
            ):
                break
            addresses.append(next_pc)
            next_pc = following
        if len(addresses) < 2:
            return None
        # VEX must agree about the exact decoded prefix. Unsupported lifts fall back before execution.
        block = self.checker.project.factory.block(pc, num_inst=len(addresses))
        if tuple(block.instruction_addrs) != tuple(addresses) or block.vex.jumpkind != "Ijk_Boring":
            return None
        exits = [(statement, index) for index, statement in enumerate(block.vex.statements)
                 if statement.tag == "Ist_Exit"]
        marks = [index for index, statement in enumerate(block.vex.statements)
                 if statement.tag == "Ist_IMark"]
        if (not allowed_successors and exits) or any(index < marks[-1] for _, index in exits):
            return None
        return Batch(tuple(addresses), frozenset(allowed_successors or {next_pc}), block.vex)


def observation_record(checker, state, snapshot, address, length, trace):
    return {"path": trace, "constraints": tuple(snapshot.solver.constraints),
            "address": address, "length": length}


def check_batched(checker, deadline, retain_observations=False, max_steps=MAX_STEPS):
    if max_steps < 0:
        raise ValueError("Instruction depth must be nonnegative")
    planner = Planner(checker)
    state, _ = checker.new_state()
    state.globals[TRACE] = ()
    scheduled = defaultdict(list, {0: [state]})
    skipped = Counter()
    lengths = Counter()
    unsupported = set()
    records = []
    instructions = 0

    def finish(status, remaining):
        return ({
            "status": status, "complete": status == PROVEN,
            "steps": instructions, "paths_checked": len(records),
            "remaining_states": remaining, "unsupported": sorted(unsupported),
            "basis": "all_first_visit_obligations_discharged" if status == PROVEN
            else "incomplete_exploration",
        }, records, {"calls": sum(lengths.values()),
                     "batches": {str(key): value for key, value in sorted(lengths.items())}})

    for depth in range(max_steps + 1):
        active = scheduled.pop(depth, [])
        frontier = len(active) + skipped.pop(depth, 0)
        if frontier > 64:
            unsupported.add("state_limit")
            return finish("unknown", frontier)
        if depth == max_steps:
            return finish(PROVEN if not frontier and not unsupported else "unknown", frontier)
        if not active and not scheduled:
            return finish(PROVEN if not unsupported else "unknown", 0)
        for current in active:
            if time.monotonic() >= deadline:
                raise BudgetExpired("Producer deadline reached")
            current.solver._solver.timeout = max(1, int((deadline - time.monotonic()) * 1000))
            unsupported.update(current.globals.get("precision_loss", ()))
            pc = current.addr
            if pc == checker.return_address:
                continue
            if pc == checker.write:
                snapshot, address, length, bad = checker._write_observation(current, deadline)
                trace = (*current.globals[TRACE], pc)
                records.append(observation_record(checker, current, snapshot, address, length, trace)
                               if retain_observations else trace)
                if snapshot.solver.satisfiable(extra_constraints=(bad,)):
                    return finish("violation", frontier)
                continue
            if current.history.jumpkind.startswith("Ijk_Sys") or checker.project.is_hooked(pc):
                unsupported.add("unmodeled_external_behavior")
                continue
            batch = planner.choose(pc, max_steps - depth)
            addresses = batch.pcs if batch else (pc,)
            span = len(addresses)
            try:
                result = (checker.project.factory.successors(current, irsb=batch.irsb)
                          if batch else checker.project.factory.successors(current, num_inst=1))
            except (RuntimeError, ValueError, checker.angr.errors.AngrError) as error:
                unsupported.add(type(error).__name__)
                continue
            if result.unconstrained_successors:
                unsupported.add("symbolic_control_flow")
            if result.artifacts.get("irsb") is None:
                unsupported.add("missing_ir_block")
            children = result.flat_successors
            if batch and (
                tuple(result.artifacts.get("insn_addrs", ())) != addresses
                or any(child.addr not in batch.successors for child in children)
            ):
                unsupported.add("batch_successor_or_lift_mismatch")
                return finish("unknown", frontier)
            trace = current.globals[TRACE] + addresses
            for child in children:
                child.globals[TRACE] = trace
            for intermediate in range(1, span):
                skipped[depth + intermediate] += 1
            scheduled[depth + span].extend(children)
            lengths[span] += 1
            instructions += span
    raise AssertionError("Depth loop did not terminate")


def paths_from(records):
    return [list(record["path"]) if isinstance(record, dict) else list(record) for record in records]


def symbolic_certificate(query, deadline, emit=_noop):
    """Batched symbolic producer, then certificate validation with a fresh-replay fallback."""
    import z3
    from .path_certificate import PathChecker, SCHEMA
    route, status = "producer_unresolved", "unknown"
    try:
        checker = BinaryChecker(query)
        started = time.monotonic()
        emit("producer_started")
        result, observations, progress = check_batched(checker, deadline)
        paths = paths_from(observations)
        emit("producer_finished", status=result["status"], complete=result["complete"],
             paths_checked=result["paths_checked"], steps=result["steps"], calls=progress["calls"],
             trace_hash=fingerprint(sorted(paths)), producer_seconds=time.monotonic() - started)
        status = result["status"]
        if status == PROVEN and result["complete"]:
            route = "certificate"
            emit("certificate_started")
            try:
                if len(paths) != result["paths_checked"]:
                    raise ValueError("Certificate path accounting differs")
                proof = {"schema": SCHEMA, "query_hash": query.contract_hash,
                         "binary_sha256": query.binary_sha256, "paths": paths}
                wire = json.dumps(proof, separators=(",", ":")).encode("utf-8")
                verdict = PathChecker(query).validate(json.loads(wire), deadline)
                status = verdict["status"]
            except (ValueError, TimeoutError, z3.Z3Exception) as error:
                emit("certificate_rejected", reason=str(error))
                route = "certificate_rejected_then_replay"
                status = "unknown"
                if time.monotonic() < deadline:
                    emit("fresh_replay_started")
                    status = checker.validate(result, MAX_STEPS, deadline)["status"]
            else:
                emit("certificate_finished", checked_nodes=verdict["checked_nodes"],
                     solver_checks=verdict["solver_checks"], serialized_bytes=len(wire))
    except BudgetExpired:
        status = "unknown"
    return {"status": status, "route": route, "in_time": time.monotonic() < deadline}


# ----------------------------------------------------------------------------- concrete enumeration

class ConcreteFirstWrite:
    def __init__(self, checker):
        self.checker = checker
        self.loader = LocalBoundsChecker(checker.query)
        if (self.loader.base, self.loader.target) != (checker.base, checker.write):
            raise ValueError("Concrete and checksum-checked loader layout differ")
        self.target = checker.write
        insn = self.loader.decode(self.target)
        if insn.mnemonic != "mov" or insn.operands[0].size != 1:
            raise ValueError("Expected the frozen ordinary byte marker write")
        self.initial = checker.project.factory.call_state(checker.entry, ret_addr=checker.return_address)

        def mark_concretization(state):
            state.globals["used_symbolic_address"] = True

        self.initial.inspect.b("address_concretization", when=checker.angr.BP_BEFORE,
                               action=mark_concretization)

    @lru_cache(maxsize=256)
    def block(self, pc, remaining, use_blocks):
        if not any(start <= pc < start + len(data) for start, data in self.loader.segments):
            raise IncompleteExecution("execution_outside_initialized_code")
        limit = min(remaining, 32) if use_blocks else 1
        block = self.checker.project.factory.block(pc, num_inst=limit)
        addresses = tuple(block.instruction_addrs)
        if self.target in addresses:
            # The first-write callback observes the exact instruction separately.
            limit = addresses.index(self.target)
            if not limit:
                raise IncompleteExecution("target_should_have_been_observed")
            block = self.checker.project.factory.block(pc, num_inst=limit)
            addresses = tuple(block.instruction_addrs)
        if not addresses or len(addresses) > remaining or self.target in addresses:
            raise IncompleteExecution("unsupported_lifted_block_shape")
        if any(not any(start <= address < start + len(data) for start, data in self.loader.segments)
               for address in addresses):
            raise IncompleteExecution("instruction_outside_initialized_code")
        return block.vex, len(addresses)

    def observe(self, value, deadline, max_steps=128, use_blocks=True):
        checker = self.checker
        state = self.initial.copy()
        state.regs.rdi = checker.claripy.BVV(value, 64)
        steps, successor_calls = 0, 0
        while steps < max_steps:
            if time.monotonic() >= deadline:
                raise BudgetExpired("Concrete execution deadline reached")
            if state.regs.ip.symbolic:
                raise IncompleteExecution("symbolic_instruction_address")
            pc = state.addr
            if state.globals.get("used_symbolic_address"):
                raise IncompleteExecution("symbolic_memory_address")
            if pc == self.target:
                _, address, length, bad = checker._write_observation(state, deadline)
                if address.symbolic or length.symbolic or bad.symbolic:
                    raise IncompleteExecution("symbolic_first_write_observation")
                return {"input": value, "address": address.concrete_value, "size": length.concrete_value,
                        "within_object": bad.is_false(), "steps": steps, "successor_calls": successor_calls}
            if pc == checker.return_address or checker.project.is_hooked(pc):
                raise IncompleteExecution("return_or_hook_before_target")
            if state.history.jumpkind.startswith("Ijk_Sys"):
                raise IncompleteExecution("system_path_outside_fixture_scope")
            block, span = self.block(pc, max_steps - steps, use_blocks)
            try:
                successors = checker.project.factory.successors(state, irsb=block)
            except checker.angr.errors.AngrError as error:
                raise IncompleteExecution(type(error).__name__) from error
            if len(successors.flat_successors) != 1 or successors.unconstrained_successors:
                raise IncompleteExecution("nonunique_concrete_successor")
            state = successors.flat_successors[0]
            guard = state.history.jump_guard
            if guard is None or guard.symbolic or not guard.is_true():
                raise IncompleteExecution("symbolic_or_unsupported_branch_condition")
            successor_calls += 1
            steps += span
        raise IncompleteExecution("instruction_depth")


def concrete_enumeration(query, deadline, emit=_noop):
    """Execute every domain input concretely; exact only if every input reaches the write site."""
    checker = ConcreteFirstWrite(BinaryChecker(query))
    (bounds,) = query.inputs
    input_domain = range(bounds.minimum, bounds.maximum + 1)
    records = []
    unknown = 0
    started = time.monotonic()
    emit("producer_started")
    try:
        for value in input_domain:
            try:
                observation = checker.observe(value, deadline, MAX_STEPS)
            except IncompleteExecution as error:
                emit("input_unresolved", input=value, reason=str(error))
                unknown += 1
                continue
            records.append(observation)
            emit("first_write_observed", **observation)
    except BudgetExpired:
        return {"status": "unknown", "route": "budget_expired", "in_time": False}
    exact = len(records) == len(input_domain) and unknown == 0
    status = PROVEN if exact and all(row["within_object"] for row in records) else "unknown"
    if exact and status != PROVEN:
        status = "violation"
    emit("producer_finished", status=status, complete=exact, paths_checked=len(records),
         steps=sum(row["steps"] for row in records), calls=sum(row["successor_calls"] for row in records),
         trace_hash=fingerprint(records), producer_seconds=time.monotonic() - started)
    return {"status": status, "route": "exact_enumeration" if status == PROVEN else "concrete_incomplete",
            "in_time": time.monotonic() < deadline,
            "witness": min((r["input"] for r in records if not r["within_object"]), default=None)}
