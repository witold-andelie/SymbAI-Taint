"""
AI Orchestrator Module

Main orchestrator that coordinates the analysis pipeline.
"""

import logging
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger('OPM.orchestrator')


@dataclass
class OrchestratorConfig:
    """Configuration for the AI Orchestrator."""
    # LLM settings
    llm_provider: str = 'mock'  # 'mock', 'ollama', 'openai'
    llm_model: str = 'llama2'
    llm_api_base: str = 'http://localhost:11434'
    llm_api_key: Optional[str] = None

    # Decision settings
    use_llm: bool = False  # Whether to use LLM for decisions
    confidence_threshold: float = 0.7

    # Output settings
    output_dir: str = './output'
    verbose: bool = True


class AIOrchestrator:
    """
    AI Orchestrator for guiding binary analysis.

    Coordinates:
    - Symbolic execution strategy
    - Taint specification generation
    - Path prioritization
    - Taint propagation guidance
    """

    def __init__(self, config: Optional[OrchestratorConfig] = None):
        self.config = config or OrchestratorConfig()

        # Initialize components
        self._init_components()

        # State
        self.binary_info = {}
        self.taint_spec = None
        self.execution_strategy = None
        self.propagation_guidance = None

    def _init_components(self):
        """Initialize orchestrator components."""
        from .llm_client import LLMClient, LLMConfig
        from .decision_engine import DecisionEngine

        # Create LLM client
        if self.config.use_llm:
            llm_config = LLMConfig(
                provider=self.config.llm_provider,
                model=self.config.llm_model,
                api_base=self.config.llm_api_base,
                api_key=self.config.llm_api_key,
            )
            self.llm_client = LLMClient(llm_config)
        else:
            self.llm_client = LLMClient(LLMConfig(provider='mock'))

        # Create decision engine
        self.decision_engine = DecisionEngine(self.llm_client)

        logger.info(f"Initialized orchestrator (use_llm={self.config.use_llm})")

    def analyze_binary(self, binary_path: str, cfg: Any = None) -> Dict[str, Any]:
        """
        Analyze a binary and prepare for taint analysis.

        Args:
            binary_path: Path to the binary
            cfg: Control flow graph (optional)

        Returns:
            Analysis results
        """
        logger.info(f"Analyzing binary: {binary_path}")

        # Extract binary information
        self.binary_info = self._extract_binary_info(binary_path, cfg)

        # Decide analysis strategy
        self.execution_strategy = self.decision_engine.decide_strategy(self.binary_info)

        # Generate taint specification
        self.taint_spec = self.decision_engine.generate_taint_spec(self.binary_info)

        # Get propagation guidance
        self.propagation_guidance = self.decision_engine.guide_propagation({})

        results = {
            'binary_info': self.binary_info,
            'execution_strategy': self.execution_strategy.__dict__,
            'taint_spec': self.taint_spec,
            'propagation_guidance': self.propagation_guidance,
        }

        logger.info(f"Analysis complete: {len(self.taint_spec.get('sources', []))} sources, "
                   f"{len(self.taint_spec.get('sinks', []))} sinks")

        return results

    def _extract_binary_info(self, binary_path: str, cfg: Any = None) -> Dict[str, Any]:
        """Extract information from binary."""
        info = {
            'path': binary_path,
            'arch': 'unknown',
            'num_functions': 0,
            'has_loops': False,
            'has_recursion': False,
            'detected_sources': [],
            'detected_sinks': [],
        }

        if cfg:
            info['num_functions'] = len(cfg.functions) if hasattr(cfg, 'functions') else 0

            # Detect sources and sinks
            source_funcs = {'getchar', 'gets', 'scanf', 'fgets', 'read', 'recv'}
            sink_funcs = {'strcpy', 'strcat', 'sprintf', 'printf', 'system', 'exec', 'malloc', 'free'}

            for func_name in cfg.functions if hasattr(cfg, 'functions') else []:
                if func_name in source_funcs:
                    info['detected_sources'].append(func_name)
                if func_name in sink_funcs:
                    info['detected_sinks'].append(func_name)

        return info

    def get_taint_spec(self) -> Dict[str, Any]:
        """Get the generated taint specification."""
        if self.taint_spec is None:
            return {
                'sources': list(self.decision_engine.default_sources),
                'sinks': list(self.decision_engine.default_sinks),
            }
        return self.taint_spec

    def get_execution_strategy(self) -> Dict[str, Any]:
        """Get the execution strategy."""
        if self.execution_strategy is None:
            return {
                'max_steps': 1000,
                'timeout': 1000,
                'prioritize_paths': True,
            }
        return self.execution_strategy.__dict__

    def get_propagation_guidance(self) -> Dict[str, Any]:
        """Get propagation guidance."""
        if self.propagation_guidance is None:
            return {
                'strategy': 'type_guided',
                'confidence_threshold': 0.7,
            }
        return self.propagation_guidance

    def guide_symbolic_execution(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Guide symbolic execution based on context.

        Args:
            context: Current execution context

        Returns:
            Execution guidance
        """
        logger.info("Guiding symbolic execution")

        # Get strategy
        strategy = self.get_execution_strategy()

        # Adjust based on context
        if context.get('has_loops', False):
            strategy['max_steps'] = min(strategy['max_steps'], 500)

        if context.get('has_recursion', False):
            strategy['max_steps'] = min(strategy['max_steps'], 300)

        return strategy

    def guide_taint_propagation(self, current_state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Guide taint propagation.

        Args:
            current_state: Current taint state

        Returns:
            Propagation guidance
        """
        logger.info("Guiding taint propagation")

        # Get base guidance
        guidance = self.get_propagation_guidance()

        # Adjust based on current state
        num_tainted = len(current_state.get('tainted_vars', {}))
        if num_tainted > 100:
            # Too many tainted vars, be more selective
            guidance['confidence_threshold'] = 0.8

        return guidance

    def decide_path_priority(self, paths: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Decide path priority.

        Args:
            paths: List of paths

        Returns:
            Prioritized paths
        """
        logger.info(f"Deciding priority for {len(paths)} paths")

        context = {
            'binary_info': self.binary_info,
            'taint_spec': self.taint_spec,
        }

        return self.decision_engine.prioritize_paths(paths, context)

    def save_state(self, output_path: str):
        """Save orchestrator state to file."""
        state = {
            'binary_info': self.binary_info,
            'taint_spec': self.taint_spec,
            'execution_strategy': self.execution_strategy.__dict__ if self.execution_strategy else None,
            'propagation_guidance': self.propagation_guidance,
        }

        import os
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)

        with open(output_path, 'w') as f:
            json.dump(state, f, indent=2)

        logger.info(f"State saved to {output_path}")

    def load_state(self, input_path: str):
        """Load orchestrator state from file."""
        with open(input_path, 'r') as f:
            state = json.load(f)

        self.binary_info = state.get('binary_info', {})
        self.taint_spec = state.get('taint_spec')
        self.propagation_guidance = state.get('propagation_guidance')

        if state.get('execution_strategy'):
            from .decision_engine import AnalysisDecision
            self.execution_strategy = AnalysisDecision(**state['execution_strategy'])

        logger.info(f"State loaded from {input_path}")


def create_orchestrator(config: Optional[OrchestratorConfig] = None) -> AIOrchestrator:
    """Create an AI orchestrator."""
    return AIOrchestrator(config)
