"""Real byte-address checks over a declared first-visit query; neural data is not an input."""

import time

from .contracts import fingerprint

class BudgetExpired(TimeoutError):
    pass


class WriteCaptured(Exception):
    """Stop at the query write before any address concretization or memory mutation."""


class BinaryChecker:
    def __init__(self, query):
        import angr
        import claripy
        self.angr, self.claripy = angr, claripy
        self.query = query
        self.project = angr.Project(query.binary, auto_load_libs=False)
        if self.project.arch.name != "AMD64" or self.project.loader.main_object.__class__.__name__ != "ELF":
            raise ValueError("The pilot requires x86-64 ELF")
        self.base = self.project.loader.main_object.mapped_base
        self.entry, self.write = self.base + query.entry_rva, self.base + query.write_rva
        self.object_base = self.base + query.object_rva
        self.return_address = 0xF000000000000000
        self._prepared_prefix = None
        if self.object_base + query.capacity > (1 << 64):
            raise ValueError("Object bounds wrap the address space")
        writes = [s for s in self.project.factory.block(self.write, num_inst=1).vex.statements
                  if type(s).__name__ in ("Store", "StoreG", "CAS", "LLSC")]
        if len(writes) != 1 or type(writes[0]).__name__ != "Store":
            raise ValueError("Query target must decode to one ordinary VEX Store")

    def structural_features(self):
        """Cheap, type-blind query features; these are heuristics, never exclusion proofs."""
        block = self.project.factory.block(self.entry)
        addresses = block.instruction_addrs
        conditional = any(i.mnemonic.startswith("j") and i.mnemonic != "jmp"
                          for i in block.capstone.insns)
        return {"entry_instruction_count": len(addresses),
                "entry_has_conditional_branch": conditional,
                "write_index_in_entry_block": addresses.index(self.write) if self.write in addresses else None}

    def new_state(self, concrete=None):
        state = self.project.factory.call_state(self.entry, ret_addr=self.return_address)
        def mark_concretization(current):
            current.globals["precision_loss"] = tuple(current.globals.get("precision_loss", ())) + ("address_concretization",)
        state.inspect.b("address_concretization", when=self.angr.BP_BEFORE, action=mark_concretization)
        symbols = {}
        for bounds in self.query.inputs:
            symbol = self.claripy.BVS(f"input_{bounds.register}", 64, explicit_name=True)
            symbols[bounds.register] = symbol
            setattr(state.regs, bounds.register, symbol)
            state.solver.add(self.claripy.UGE(symbol, bounds.minimum), self.claripy.ULE(symbol, bounds.maximum))
            if concrete is not None:
                state.solver.add(symbol == concrete[bounds.register])
        return state, symbols

    def prepare_dependencies(self, deadline):
        """Pay for RDA and exact prefix execution; cache only states actually reached."""
        self._prepared_prefix = None
        from .dependencies import inspect_dependencies
        dependencies = inspect_dependencies(self.project, self.query, deadline)
        plan = dependencies["prefix_plan"]
        if plan["query_hash"] != self.query.contract_hash or plan["target_rva"] != self.query.write_rva:
            raise ValueError("Dependency plan belongs to another query")
        summary = {"status": "not_prepared", "reason": plan["basis"], "build_steps": 0,
                   "plan_id": plan["plan_id"]}
        if not plan["eligible"]:
            return {"dependencies": dependencies, "prepared_prefix": summary}
        if len(plan["instruction_rvas"]) > 64:
            summary["reason"] = "prefix_snapshot_limit"
            return {"dependencies": dependencies, "prepared_prefix": summary}
        state, symbols = self.new_state()
        snapshots = [state.copy()]
        for rva in plan["instruction_rvas"]:
            if time.monotonic() >= deadline:
                raise BudgetExpired("Exact prefix preparation exhausted the budget")
            if state.addr != self.base + rva or self.project.is_hooked(state.addr):
                summary["reason"] = "prefix_instruction_mismatch_or_hook"
                return {"dependencies": dependencies, "prepared_prefix": summary}
            state.solver._solver.timeout = max(1, int((deadline - time.monotonic()) * 1000))
            successors = self.project.factory.successors(state, num_inst=1)
            summary["build_steps"] += 1
            if len(successors.flat_successors) != 1 or successors.unconstrained_successors:
                summary["reason"] = "prefix_not_single_successor"
                return {"dependencies": dependencies, "prepared_prefix": summary}
            state = successors.flat_successors[0]
            if (state.globals.get("precision_loss") or state.history.jumpkind.startswith("Ijk_Sys")
                    or successors.artifacts.get("irsb") is None):
                summary["reason"] = "prefix_precision_loss_or_unsupported_behavior"
                return {"dependencies": dependencies, "prepared_prefix": summary}
            snapshots.append(state.copy())
        if state.addr != self.write:
            summary["reason"] = "prefix_did_not_reach_target"
            return {"dependencies": dependencies, "prepared_prefix": summary}
        if time.monotonic() >= deadline:
            raise BudgetExpired("Exact prefix preparation exhausted the budget")
        cache_id = fingerprint({"query_hash": self.query.contract_hash, "plan_id": plan["plan_id"],
                                "depth": len(snapshots) - 1})
        self._prepared_prefix = {"query_hash": self.query.contract_hash, "snapshots": snapshots,
                                 "symbols": symbols, "cache_id": cache_id}
        summary.update(status="ready", reason="exact_single_successor_prefix",
                       cache_id=cache_id, deepest_depth=len(snapshots) - 1)
        return {"dependencies": dependencies, "prepared_prefix": summary}

    def _write_observation(self, state, deadline):
        observed = []
        def observe(current):
            attrs = getattr(current.inspect, "attrs", current.inspect)
            address, length = attrs.mem_write_address, attrs.mem_write_length
            if isinstance(length, int):
                length = self.claripy.BVV(length, 64)
            elif length.size() < 64:
                length = self.claripy.ZeroExt(64 - length.size(), length)
            elif length.size() > 64:
                raise ValueError("Unsupported write length width")
            if address.size() != 64:
                raise ValueError("Unsupported destination address width")
            condition = attrs.mem_write_condition
            if condition is None:
                condition = self.claripy.true()
            capacity = self.claripy.BVV(self.query.capacity, 64)
            offset = address - self.object_base
            bad = self.claripy.And(condition, length != 0,
                     self.claripy.Or(self.claripy.ULT(address, self.object_base),
                                     self.claripy.UGT(length, capacity),
                                     self.claripy.UGT(offset, capacity - length)))
            copy = current.copy()
            copy.solver._solver.timeout = max(1, int((deadline - time.monotonic()) * 1000))
            observed.append((copy, address, length, bad))
            # The scope ends here. Never concretize a symbolic destination to execute the store.
            raise WriteCaptured()
        probe = state.copy()
        probe.inspect.b("mem_write", when=self.angr.BP_BEFORE, action=observe)
        try:
            probe.step(num_inst=1)
        except WriteCaptured:
            pass
        if len(observed) != 1:
            raise ValueError("Target must be an instruction with exactly one modeled write")
        return observed[0]

    def check(self, max_steps, deadline, concrete=None, use_prepared=True):
        if not isinstance(max_steps, int) or max_steps < 0:
            raise ValueError("A nonnegative integer instruction-depth cap is required")
        if time.monotonic() >= deadline:
            raise BudgetExpired("Operation deadline reached")
        reused_depth = 0
        cache_id = None
        if use_prepared and concrete is None and self._prepared_prefix is not None:
            prepared = self._prepared_prefix
            if prepared["query_hash"] != self.query.contract_hash:
                raise ValueError("Prepared prefix belongs to another query")
            reused_depth = min(max_steps, len(prepared["snapshots"]) - 1)
            state = prepared["snapshots"][reused_depth].copy()
            symbols = prepared["symbols"]
            cache_id = prepared["cache_id"]
        else:
            state, symbols = self.new_state(concrete)
        active = [state]
        visited, checked = reused_depth, 0
        unsupported = []
        for _ in range(reused_depth, max_steps):
            next_states = []
            for current in active:
                if time.monotonic() >= deadline:
                    raise BudgetExpired("Operation deadline reached")
                current.solver._solver.timeout = max(1, int((deadline - time.monotonic()) * 1000))
                unsupported.extend(current.globals.get("precision_loss", ()))
                if current.addr == self.return_address:
                    continue
                if current.addr == self.write:
                    snapshot, address, length, bad = self._write_observation(current, deadline)
                    checked += 1
                    if snapshot.solver.satisfiable(extra_constraints=(bad,)):
                        snapshot.solver.add(bad)
                        witness = {name: snapshot.solver.eval(symbol) for name, symbol in symbols.items()}
                        return {"status": "violation", "witness": witness,
                                "address": snapshot.solver.eval(address), "length": snapshot.solver.eval(length),
                                "paths_checked": checked, "steps": visited, "complete": False,
                                "executed_prefix_steps": visited - reused_depth,
                                "reused_prefix_steps": reused_depth, "prefix_cache_id": cache_id,
                                "basis": "SAT(path_condition AND bad_write)"}
                    continue
                # Unmodeled calls/syscalls and symbolic IPs cannot justify exclusion.
                if current.history.jumpkind.startswith("Ijk_Sys") or self.project.is_hooked(current.addr):
                    unsupported.append("unmodeled_external_behavior")
                    continue
                try:
                    successors = self.project.factory.successors(current, num_inst=1)
                    next_states.extend(successors.flat_successors)
                    if successors.unconstrained_successors:
                        unsupported.append("symbolic_control_flow")
                    if successors.artifacts.get("irsb") is None:
                        unsupported.append("missing_ir_block")
                except Exception as error:
                    unsupported.append(type(error).__name__)
                visited += 1
            active = next_states
            if not active:
                break
            if len(active) > 64:
                unsupported.append("state_limit")
                break
        complete = not active and not unsupported
        return {"status": "excluded_within_scope" if complete else "unknown",
                "complete": complete, "paths_checked": checked, "steps": visited,
                "remaining_states": len(active), "unsupported": sorted(set(unsupported)),
                "executed_prefix_steps": visited - reused_depth,
                "reused_prefix_steps": reused_depth, "prefix_cache_id": cache_id,
                "basis": "all_first_visit_obligations_discharged" if complete else "incomplete_exploration"}

    def validate(self, result, max_steps, deadline):
        """Recheck from a fresh entry state; this is modeled replay, not native execution."""
        if result["status"] == "violation":
            replay = self.check(max_steps, deadline, concrete=result["witness"], use_prepared=False)
            if replay["status"] != "violation" or replay["witness"] != result["witness"]:
                raise ValueError("Witness failed independent concrete-input modeled replay")
            return dict(result, validation="concrete_input_modeled_reexecution", native_replay="not_attempted",
                        validation_reused_prefix_steps=replay["reused_prefix_steps"],
                        validation_executed_prefix_steps=replay["executed_prefix_steps"])
        if result["status"] == "excluded_within_scope":
            replay = self.check(max_steps, deadline, use_prepared=False)
            if replay["status"] != "excluded_within_scope" or not replay["complete"]:
                raise ValueError("Exclusion failed independent recheck")
            return dict(result, validation="fresh_state_complete_scope_recheck",
                        validation_reused_prefix_steps=replay["reused_prefix_steps"],
                        validation_executed_prefix_steps=replay["executed_prefix_steps"])
        return dict(result, validation="no_decisive_evidence")
