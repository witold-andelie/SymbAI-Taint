"""
OPM Pipeline: Main orchestration module

Implements the complete workflow from infra.txt:
SourceCode → Compilation → Binary → CodeLifting → VEX IR
                                    → CFGRecovery → CFG
            VEX IR + CFG → DFGConstruction → DFG
            CFG + DFG → GNNSemanticInference → TypeRecoveryOutput
            VEX IR + CFG + DFG + TypeRecoveryOutput → TypeMetadataInjection → TypedIR
            TypedIR + TypeRecoveryOutput → PathPrioritization → TypeGuidedSymbolicExecution
            TypeGuidedSymbolicExecution → SymbolicState + ExecutionPaths
            ExecutionPaths + TaintSpec + TypedIR → TaintPropagation → TaintState
            TaintState + ExecutionPaths + TaintSpec → SourceSinkChecking → TaintTrace
            TaintTrace + GroundTruth → Evaluation → EvaluationMetrics
            TaintTrace + EvaluationMetrics → ReportGeneration → Report
"""

import os
import logging
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass, field
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('OPM')


@dataclass
class OPMConfig:
    """Configuration for the OPM pipeline."""
    # Compilation
    compiler: str = "gcc"
    compile_flags: list = field(default_factory=lambda: ["-g", "-O0"])
    strip_binary: bool = True

    # Analysis
    max_symbolic_steps: int = 1000
    solver_timeout: int = 1000  # milliseconds
    max_states: int = 100

    # GNN Type Recovery
    gnn_model_path: Optional[str] = None
    confidence_threshold: float = 0.7

    # Taint Analysis
    taint_spec_path: Optional[str] = None

    # Output
    output_dir: str = "./output"
    verbose: bool = True


@dataclass
class OPMState:
    """State container for the OPM pipeline."""
    # Objects (data)
    source_code: Optional[str] = None
    binary: Optional[str] = None
    binary_debug: Optional[str] = None  # unstripped (DWARF) binary, for GNN type recovery
    ground_truth: Optional[Dict[str, Any]] = None
    vex_ir: Optional[Any] = None
    cfg: Optional[Any] = None
    dfg: Optional[Any] = None
    call_graph: Optional[Any] = None  # Call graph for taint analysis
    type_recovery_output: Optional[Dict[str, Any]] = None
    typed_ir: Optional[Any] = None
    symbolic_state: Optional[Any] = None
    execution_paths: Optional[list] = None
    taint_state: Optional[Dict[str, Any]] = None
    taint_trace: Optional[list] = None
    evaluation_metrics: Optional[Dict[str, float]] = None
    report: Optional[Dict[str, Any]] = None

    # Metadata
    current_stage: str = "init"
    errors: list = field(default_factory=list)


class OPMPipeline:
    """
    Main OPM Pipeline orchestrating the complete analysis workflow.

    Follows the OPM model from infra.txt strictly.
    """

    def __init__(self, config: Optional[OPMConfig] = None):
        self.config = config or OPMConfig()
        self.state = OPMState()

        # Lazy-loaded modules
        self._compilation = None
        self._ground_truth = None
        self._binary_analysis = None
        self._type_recovery = None
        self._typed_ir = None
        self._symbolic_exec = None
        self._taint_analysis = None
        self._evaluation = None
        self._orchestrator = None

        # Ensure output directory exists
        os.makedirs(self.config.output_dir, exist_ok=True)

    @property
    def compilation(self):
        if self._compilation is None:
            from .compilation import compiler, stripper
            # Use a simple namespace class
            class Compilation:
                compile_source = staticmethod(compiler.compile_source)
                strip_binary = staticmethod(stripper.strip_binary)
            self._compilation = Compilation()
        return self._compilation

    @property
    def ground_truth(self):
        if self._ground_truth is None:
            from .ground_truth import extractor, validator
            class GroundTruth:
                extract = staticmethod(extractor.extract_ground_truth)
                validate = staticmethod(validator.validate_ground_truth)
            self._ground_truth = GroundTruth()
        return self._ground_truth

    @property
    def binary_analysis(self):
        if self._binary_analysis is None:
            from .binary_analysis import cfg_recovery, dfg_construction, vex_lift, call_analysis
            class BinaryAnalysis:
                lift_to_vex = staticmethod(vex_lift.lift_binary)
                recover_cfg = staticmethod(cfg_recovery.recover_cfg)
                construct_dfg = staticmethod(dfg_construction.construct_dfg)
                analyze_calls = staticmethod(call_analysis.analyze_calls)
            self._binary_analysis = BinaryAnalysis()
        return self._binary_analysis

    @property
    def type_recovery(self):
        if self._type_recovery is None:
            from .type_recovery import inference, gat_model
            class TypeRecovery:
                recover_types = staticmethod(inference.recover_types)
                # Use GAT model if available
                create_gat = staticmethod(gat_model.create_gat_model)
            self._type_recovery = TypeRecovery()
        return self._type_recovery

    @property
    def typed_ir(self):
        if self._typed_ir is None:
            from .typed_ir import type_injector
            class TypedIRModule:
                inject_types = staticmethod(type_injector.inject_type_metadata)
            self._typed_ir = TypedIRModule()
        return self._typed_ir

    @property
    def symbolic_exec(self):
        if self._symbolic_exec is None:
            from .symbolic_exec import guided_executor, path_prioritizer, heuristic_pruning
            class SymbolicExec:
                prioritize_paths = staticmethod(path_prioritizer.prioritize_paths)
                execute = staticmethod(guided_executor.execute_guided)
                # Heuristic pruning
                create_pruner = staticmethod(heuristic_pruning.create_pruner)
            self._symbolic_exec = SymbolicExec()
        return self._symbolic_exec

    @property
    def taint_analysis(self):
        if self._taint_analysis is None:
            from .taint_analysis import taint_engine, taint_engine_v2, source_sink, learned_propagation
            class TaintAnalysis:
                propagate = staticmethod(taint_engine.propagate_taint)
                check_source_sink = staticmethod(source_sink.check_source_sink)
                run_analysis = staticmethod(taint_engine_v2.run_taint_analysis)
                # Learned propagation
                create_learned = staticmethod(learned_propagation.create_learned_propagation)
            self._taint_analysis = TaintAnalysis()
        return self._taint_analysis

    @property
    def evaluation(self):
        if self._evaluation is None:
            from .evaluation import metrics, reporter
            class Evaluation:
                compute_metrics = staticmethod(metrics.compute_metrics)
                generate_report = staticmethod(reporter.generate_report)
            self._evaluation = Evaluation()
        return self._evaluation

    @property
    def orchestrator(self):
        if self._orchestrator is None:
            from .orchestrator import AIOrchestrator, OrchestratorConfig
            config = OrchestratorConfig(
                use_llm=True,
                llm_provider='openai',
                # Optional per-process override via env (lets concurrent runs use
                # different keys to avoid 451 contention); hardcoded value is the fallback.
                # Configure via environment variables — never hardcode credentials.
                #   export MIMO_API_BASE=https://<your-openai-compatible-endpoint>/v1
                #   export MIMO_API_KEY=<your-api-key>
                llm_api_base=os.environ.get('MIMO_API_BASE', 'https://api.openai.com/v1'),
                llm_api_key=os.environ.get('MIMO_API_KEY', ''),
                llm_model=os.environ.get('MIMO_MODEL', 'mimo-v2.5-pro'),
                output_dir=self.config.output_dir,
                verbose=self.config.verbose,
            )
            self._orchestrator = AIOrchestrator(config)
        return self._orchestrator

    def run(self, source_code: str, taint_spec: Optional[str] = None) -> Dict[str, Any]:
        """
        Run the complete OPM pipeline.

        Args:
            source_code: Path to the C source file
            taint_spec: Optional path to taint specification file

        Returns:
            Dictionary containing analysis results
        """
        logger.info(f"Starting OPM pipeline for: {source_code}")
        self.state.source_code = source_code

        try:
            # Stage 0: AI Orchestration (guides the entire pipeline)
            self._stage_orchestration()

            # Stage 1: Compilation and Stripping
            self._stage_compilation()

            # Stage 2: Ground Truth Extraction
            self._stage_ground_truth()

            # Stage 3: Code Lifting (VEX IR)
            self._stage_code_lifting()

            # Stage 4: CFG Recovery
            self._stage_cfg_recovery()

            # Stage 5: DFG Construction
            self._stage_dfg_construction()

            # Stage 6: GNN-Based Type Recovery
            self._stage_type_recovery()

            # Stage 7: Type Metadata Injection
            self._stage_type_injection()

            # Stage 8: Path Prioritization (guided by orchestrator)
            self._stage_path_prioritization()

            # Stage 9: Type-Guided Symbolic Execution
            self._stage_symbolic_execution()

            # Stage 10: Taint Propagation (guided by orchestrator)
            self._stage_taint_propagation()

            # Stage 11: Source-Sink Checking
            self._stage_source_sink_checking()

            # Stage 12: Evaluation
            self._stage_evaluation()

            # Stage 13: Report Generation
            self._stage_report_generation()

            logger.info("OPM pipeline completed successfully")
            return self.state.report

        except Exception as e:
            logger.error(f"Pipeline failed at stage {self.state.current_stage}: {e}")
            self.state.errors.append({
                'stage': self.state.current_stage,
                'error': str(e)
            })
            raise

    def _stage_orchestration(self):
        """Stage 0: AI Orchestration - Guides the entire pipeline"""
        self.state.current_stage = "orchestration"
        logger.info("Stage 0: AI Orchestration")

        # Initialize orchestrator with binary info
        # This will be updated after CFG recovery
        self.orchestrator.analyze_binary(
            binary_path=self.state.source_code,  # Will be updated
            cfg=None
        )

        # Get taint specification from orchestrator
        taint_spec = self.orchestrator.get_taint_spec()
        logger.info(f"  Orchestrator generated {len(taint_spec.get('sources', []))} sources, "
                   f"{len(taint_spec.get('sinks', []))} sinks")

        # Get execution strategy
        strategy = self.orchestrator.get_execution_strategy()
        logger.info(f"  Execution strategy: max_steps={strategy.get('max_steps', 1000)}")

    def _stage_compilation(self):
        """Stage 1: SourceCode → Compilation → Binary"""
        self.state.current_stage = "compilation"
        logger.info("Stage 1: Compilation and Stripping")

        # Compile source to binary
        binary_path = self.compilation.compile_source(
            source_path=self.state.source_code,
            compiler=self.config.compiler,
            flags=self.config.compile_flags,
            output_dir=self.config.output_dir
        )

        # Keep the unstripped (DWARF-carrying) binary for GNN type recovery:
        # TYGR locates variables via DWARF, then the GNN predicts their types.
        self.state.binary_debug = binary_path

        # Strip binary if configured
        if self.config.strip_binary:
            binary_path = self.compilation.strip_binary(binary_path)

        self.state.binary = binary_path
        logger.info(f"  Binary created: {binary_path}")

    def _stage_ground_truth(self):
        """Stage 2: SourceCode → GroundTruthExtraction → GroundTruth"""
        self.state.current_stage = "ground_truth"
        logger.info("Stage 2: Ground Truth Extraction")

        self.state.ground_truth = self.ground_truth.extract(
            source_path=self.state.source_code
        )
        logger.info(f"  Ground truth extracted: {len(self.state.ground_truth)} items")

    def _stage_code_lifting(self):
        """Stage 3: Binary → CodeLifting → VEX IR"""
        self.state.current_stage = "code_lifting"
        logger.info("Stage 3: Code Lifting (angr/VEX)")

        self.state.vex_ir = self.binary_analysis.lift_to_vex(
            binary_path=self.state.binary
        )
        logger.info("  VEX IR generated")

    def _stage_cfg_recovery(self):
        """Stage 4: Binary → CFGRecovery → CFG"""
        self.state.current_stage = "cfg_recovery"
        logger.info("Stage 4: CFG Recovery (angr CFGFast)")

        self.state.cfg = self.binary_analysis.recover_cfg(
            binary_path=self.state.binary
        )
        logger.info(f"  CFG recovered: {len(self.state.cfg.blocks)} blocks, {len(self.state.cfg.functions)} functions")

    def _stage_dfg_construction(self):
        """Stage 5: VEX IR + CFG → DFGConstruction → DFG"""
        self.state.current_stage = "dfg_construction"
        logger.info("Stage 5: DFG Construction")

        self.state.dfg = self.binary_analysis.construct_dfg(
            vex_ir=self.state.vex_ir,
            cfg=self.state.cfg
        )
        logger.info(f"  DFG constructed: {len(self.state.dfg.nodes)} nodes, {len(self.state.dfg.edges)} edges")

        # Also analyze function calls
        logger.info("Stage 5b: Call Graph Analysis")
        self.state.call_graph = self.binary_analysis.analyze_calls(
            binary_path=self.state.binary,
            cfg=self.state.cfg
        )
        logger.info(f"  Call graph: {len(self.state.call_graph.call_sites)} call sites")

    def _stage_type_recovery(self):
        """Stage 6: CFG + DFG → GNNSemanticInference → TypeRecoveryOutput"""
        self.state.current_stage = "type_recovery"
        logger.info("Stage 6: GNN-Based Type Recovery (TYGR)")

        self.state.type_recovery_output = self.type_recovery.recover_types(
            binary_path=getattr(self.state, 'binary_debug', None) or self.state.binary,
            cfg=self.state.cfg,
            dfg=self.state.dfg,
            model_path=self.config.gnn_model_path,
            confidence_threshold=self.config.confidence_threshold
        )
        logger.info(f"  Type recovery complete: {len(self.state.type_recovery_output)} variables")

    def _stage_type_injection(self):
        """Stage 7: VEX IR + CFG + DFG + TypeRecoveryOutput → TypeMetadataInjection → TypedIR"""
        self.state.current_stage = "type_injection"
        logger.info("Stage 7: Type Metadata Injection")

        self.state.typed_ir = self.typed_ir.inject_types(
            vex_ir=self.state.vex_ir,
            cfg=self.state.cfg,
            dfg=self.state.dfg,
            type_recovery_output=self.state.type_recovery_output
        )
        logger.info("  Typed IR created")

    def _stage_path_prioritization(self):
        """Stage 8: TypedIR + TypeRecoveryOutput → PathPrioritization"""
        self.state.current_stage = "path_prioritization"
        logger.info("Stage 8: Type-Aware Path Prioritization + Heuristic Pruning")

        # Get initial paths
        initial_paths = self.symbolic_exec.prioritize_paths(
            typed_ir=self.state.typed_ir,
            type_recovery_output=self.state.type_recovery_output
        )

        # Apply heuristic pruning
        pruner = self.symbolic_exec.create_pruner(adaptive=True)
        context = {
            'type_info': {},
            'taint_info': {},
            'block_info': {},
        }

        # Convert paths to dict format for pruner
        path_dicts = []
        for path in initial_paths:
            path_dict = {
                'blocks': path.blocks if hasattr(path, 'blocks') else [],
                'num_branches': 0,
                'num_edges': 0,
            }
            path_dicts.append(path_dict)

        # Prune paths
        pruned_paths = pruner.prune_paths(path_dicts, context)

        # Convert back to original format
        self.state.execution_paths = initial_paths[:len(pruned_paths)]

        # Get pruning statistics
        stats = pruner.get_statistics()
        logger.info(f"  {len(initial_paths)} -> {len(pruned_paths)} paths after pruning")
        logger.info(f"  Pruning rate: {stats['pruning_rate']:.2%}")

    def _stage_symbolic_execution(self):
        """Stage 9: Type-Guided Symbolic Execution"""
        self.state.current_stage = "symbolic_execution"
        logger.info("Stage 9: Type-Guided Symbolic Execution")

        result = self.symbolic_exec.execute(
            typed_ir=self.state.typed_ir,
            paths=self.state.execution_paths,
            max_steps=self.config.max_symbolic_steps,
            solver_timeout=self.config.solver_timeout
        )
        self.state.symbolic_state = result.get('state')
        self.state.execution_paths = result.get('paths', [])

        # Store symbolic execution results for taint analysis.
        # 'constraint_evidence' carries formatted angr path constraints / parameter
        # ranges (hard evidence) captured while the solver was still alive.
        self.state.symbolic_results = {
            'feasible_paths': result.get('paths', []),
            'states': result.get('states', []),
            'constraint_evidence': result.get('constraint_evidence', []),
        }

        logger.info(f"  Symbolic execution complete: {len(self.state.execution_paths)} feasible paths")

    def _stage_taint_propagation(self):
        """Stage 10: ExecutionPaths + TaintSpec + TypedIR → TaintPropagation → TaintState"""
        self.state.current_stage = "taint_propagation"
        logger.info("Stage 10: Automated Taint Propagation (V2 + LLM + Symbolic)")

        # Get taint specification from AI Orchestrator
        taint_spec = self.orchestrator.get_taint_spec()
        logger.info(f"  LLM taint spec: {len(taint_spec.get('sources', []))} sources, {len(taint_spec.get('sinks', []))} sinks")

        # Get feasible paths from symbolic execution
        feasible_paths = self.state.symbolic_results.get('feasible_paths', [])
        logger.info(f"  Symbolic execution: {len(feasible_paths)} feasible paths")

        # Use the new taint analysis engine with call graph and symbolic results
        if self.state.call_graph:
            taint_results = self.taint_analysis.run_analysis(
                binary_path=self.state.binary,
                cfg=self.state.cfg,
                call_graph=self.state.call_graph,
                taint_spec=taint_spec,
                symbolic_results=self.state.symbolic_results,  # Pass symbolic results
                type_recovery_output=self.state.type_recovery_output  # GNN types (Stage 6)
            )
            self.state.taint_state = taint_results
            logger.info(f"  Sources found: {taint_results['summary']['total_sources']}")
            logger.info(f"  Sinks found: {taint_results['summary']['total_sinks']}")
            logger.info(f"  Taint paths: {taint_results['summary']['total_paths']}")
        else:
            # Fallback to old method
            self.state.taint_state = self.taint_analysis.propagate(
                execution_paths=self.state.execution_paths,
                typed_ir=self.state.typed_ir,
                taint_spec=taint_spec
            )
            logger.info(f"  Taint propagation complete: {len(self.state.taint_state)} tainted items")

    def _stage_source_sink_checking(self):
        """Stage 11: TaintState + ExecutionPaths + TaintSpec → SourceSinkChecking → TaintTrace"""
        self.state.current_stage = "source_sink_checking"
        logger.info("Stage 11: Source-Sink Checking (with CoT + symbolic evidence)")

        # Use V2 results if available
        if self.state.taint_state and 'taint_paths' in self.state.taint_state:
            taint_paths = self.state.taint_state['taint_paths']

            # Get lifecycle analysis from taint state
            lifecycle_analysis = self.state.taint_state.get('lifecycle_analysis', '')

            # Build global symbolic evidence (GNN + dangerous calls + types + angr constraints)
            global_evidence = self._build_symbolic_evidence()

            # Use LLM with Chain-of-Thought reasoning
            validated_paths = []
            confidence_threshold = 0.3

            for path in taint_paths:
                # Per-path "hard proof" that breaks function-name safety bias
                # (e.g. unconstrained strncpy size, tainted free pointer)
                path_evidence = self._build_path_constraint_evidence(path)
                if path_evidence:
                    combined_evidence = (
                        f"{global_evidence}\n\n{path_evidence}" if global_evidence else path_evidence
                    )
                else:
                    combined_evidence = global_evidence

                # Ask LLM with CoT reasoning
                llm_result = self.orchestrator.llm_client.analyze_taint_path_cot(
                    path,
                    symbolic_evidence=combined_evidence,
                    lifecycle_analysis=lifecycle_analysis
                )

                is_real = llm_result.get('is_real_taint', True)
                confidence = llm_result.get('confidence', 0.5)
                reasoning = llm_result.get('reasoning', '')

                # Soft threshold: use confidence score
                if confidence >= confidence_threshold:
                    path['llm_confidence'] = confidence
                    path['llm_reasoning'] = reasoning
                    validated_paths.append(path)
                    logger.debug(f"  LLM accepted: {path.get('source')} -> {path.get('sink')} "
                               f"(conf={confidence:.2f})")
                else:
                    logger.debug(f"  LLM rejected: {path.get('source')} -> {path.get('sink')} "
                               f"(conf={confidence:.2f} < {confidence_threshold})")

            self.state.taint_trace = validated_paths
            logger.info(f"  Source-Sink checking complete: {len(taint_paths)} -> {len(validated_paths)} traces "
                       f"(threshold={confidence_threshold})")
        else:
            # Fallback to old method
            taint_spec = self._load_taint_spec()
            self.state.taint_trace = self.taint_analysis.check_source_sink(
                taint_state=self.state.taint_state,
                execution_paths=self.state.execution_paths,
                taint_spec=taint_spec
            )
            logger.info(f"  Source-Sink checking complete: {len(self.state.taint_trace)} traces found")

    def _build_symbolic_evidence(self) -> str:
        """Build symbolic evidence from angr and GNN for LLM."""
        evidence_parts = []

        # 1. GNN Attention Report
        try:
            from .type_recovery.attention_report import create_attention_report_generator
            report_gen = create_attention_report_generator()
            gnn_report = report_gen.format_for_llm(
                self.state.cfg,
                self.state.dfg,
                self.state.type_recovery_output
            )
            if gnn_report:
                evidence_parts.append("### GNN Graph Analysis")
                evidence_parts.append(gnn_report)
        except Exception as e:
            logger.debug(f"GNN report generation failed: {e}")

        # 2. Call graph evidence (dangerous functions)
        if self.state.call_graph:
            evidence_parts.append("\n### Dangerous Function Calls")
            for addr, cs in self.state.call_graph.call_sites.items():
                if cs.callee in {'gets', 'strcpy', 'free', 'malloc', 'system', 'sprintf'}:
                    evidence_parts.append(f"- {cs.caller} -> {cs.callee} at {hex(addr)}")

        # 3. Type information
        if self.state.type_recovery_output:
            evidence_parts.append("\n### Type Information")
            for func_name, output in self.state.type_recovery_output.items():
                if hasattr(output, 'predictions'):
                    for pred in output.predictions[:5]:  # Limit to 5
                        evidence_parts.append(
                            f"- {pred.variable_name}: {pred.predicted_type} (conf={pred.confidence:.2f})"
                        )

        # 4. Angr path constraints / parameter ranges (real symbolic hard evidence)
        symbolic_results = getattr(self.state, 'symbolic_results', None)
        constraint_blocks = (symbolic_results or {}).get('constraint_evidence', []) if symbolic_results else []
        if constraint_blocks:
            evidence_parts.append("\n### Angr Path Constraints / Parameter Ranges")
            seen = set()
            for block in constraint_blocks[:5]:  # cap to keep the prompt compact
                if block and block not in seen:
                    seen.add(block)
                    evidence_parts.append(block)

        return "\n".join(evidence_parts[:80])  # raised cap so constraint proof survives

    def _build_path_constraint_evidence(self, path: Dict[str, Any]) -> str:
        """Build per-path symbolic 'hard evidence' for a single taint path.

        Delegates to ConstraintExtractor.build_semantic_evidence, which turns the
        established taint facts (taint-derived dangerous argument, no recovered bound)
        into an explicit statement the LLM cannot dismiss via function-name bias
        (e.g. "strncpy size is UNCONSTRAINED -> overflow SAT").
        """
        try:
            from .symbolic_exec.constraint_extractor import create_constraint_extractor
            return create_constraint_extractor().build_semantic_evidence(path)
        except Exception as e:
            logger.debug(f"Path constraint evidence failed: {e}")
            return ""

    def _stage_evaluation(self):
        """Stage 12: TaintTrace + GroundTruth → Evaluation → EvaluationMetrics"""
        self.state.current_stage = "evaluation"
        logger.info("Stage 12: Evaluation and Comparison")

        self.state.evaluation_metrics = self.evaluation.compute_metrics(
            taint_trace=self.state.taint_trace,
            ground_truth=self.state.ground_truth
        )
        logger.info(f"  Evaluation metrics: {self.state.evaluation_metrics}")

    def _stage_report_generation(self):
        """Stage 13: TaintTrace + EvaluationMetrics → ReportGeneration → Report"""
        self.state.current_stage = "report_generation"
        logger.info("Stage 13: Report Generation")

        self.state.report = self.evaluation.generate_report(
            taint_trace=self.state.taint_trace,
            metrics=self.state.evaluation_metrics,
            output_dir=self.config.output_dir
        )
        logger.info(f"  Report generated: {self.state.report.get('path', 'N/A')}")

    def _load_taint_spec(self) -> Dict[str, Any]:
        """Load taint specification from file or use defaults."""
        if self.config.taint_spec_path and os.path.exists(self.config.taint_spec_path):
            import json
            with open(self.config.taint_spec_path, 'r') as f:
                return json.load(f)

        # Default taint specification
        return {
            'sources': [
                {'name': 'getchar', 'type': 'input'},
                {'name': 'gets', 'type': 'input'},
                {'name': 'scanf', 'type': 'input'},
                {'name': 'fgets', 'type': 'input'},
                {'name': 'read', 'type': 'input'},
                {'name': 'recv', 'type': 'network'},
                {'name': 'getenv', 'type': 'environment'},
            ],
            'sinks': [
                {'name': 'strcpy', 'type': 'buffer_overflow'},
                {'name': 'strcat', 'type': 'buffer_overflow'},
                {'name': 'sprintf', 'type': 'format_string'},
                {'name': 'printf', 'type': 'format_string'},
                {'name': 'system', 'type': 'command_injection'},
                {'name': 'exec', 'type': 'command_injection'},
                {'name': 'malloc', 'type': 'memory'},
                {'name': 'free', 'type': 'use_after_free'},
            ],
            'propagation_rules': [
                {'op': 'assign', 'propagates': True},
                {'op': 'add', 'propagates': True},
                {'op': 'sub', 'propagates': True},
                {'op': 'mul', 'propagates': True},
                {'op': 'div', 'propagates': False},
            ]
        }


def run_pipeline(source_code: str, config: Optional[OPMConfig] = None) -> Dict[str, Any]:
    """
    Convenience function to run the OPM pipeline.

    Args:
        source_code: Path to the C source file
        config: Optional pipeline configuration

    Returns:
        Analysis results dictionary
    """
    pipeline = OPMPipeline(config)
    return pipeline.run(source_code)
