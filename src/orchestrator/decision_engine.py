"""
Decision Engine Module

Makes intelligent decisions about analysis strategy.
"""

import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger('OPM.orchestrator')


@dataclass
class AnalysisDecision:
    """Decision about analysis strategy."""
    # Symbolic execution
    max_steps: int = 1000
    timeout: int = 1000
    prioritize_paths: bool = True
    use_type_guided: bool = True
    prune_unlikely_paths: bool = True

    # Taint analysis
    sources: List[str] = field(default_factory=list)
    sinks: List[str] = field(default_factory=list)
    propagation_strategy: str = 'type_guided'
    confidence_threshold: float = 0.7

    # Path prioritization
    priority_factors: Dict[str, float] = field(default_factory=dict)
    prune_threshold: float = 0.3

    # Reasoning
    reasoning: str = ''


class DecisionEngine:
    """
    Engine for making analysis decisions.

    Combines rule-based and LLM-based decision making.
    """

    def __init__(self, llm_client=None):
        self.llm_client = llm_client

        # Default rules
        self.default_sources = {
            'getchar', 'gets', 'scanf', 'fscanf', 'sscanf',
            'fgets', 'read', 'recv', 'recvfrom', 'getenv',
        }

        self.default_sinks = {
            'strcpy', 'strncpy', 'strcat', 'strncat',
            'sprintf', 'snprintf', 'printf', 'fprintf',
            'system', 'popen', 'exec', 'execl', 'execlp',
            'malloc', 'calloc', 'realloc', 'free',
        }

        # Priority weights
        self.default_priority_weights = {
            'has_source': 10.0,
            'has_sink': 10.0,
            'type_mismatch': 5.0,
            'buffer_operation': 8.0,
            'pointer_operation': 6.0,
            'user_input': 9.0,
        }

    def decide_strategy(self, binary_info: Dict[str, Any]) -> AnalysisDecision:
        """
        Decide analysis strategy based on binary information.

        Args:
            binary_info: Information about the binary

        Returns:
            Analysis decision
        """
        logger.info("Deciding analysis strategy")

        # Rule-based decisions
        decision = self._rule_based_decision(binary_info)

        # LLM-based refinement (if available)
        if self.llm_client:
            decision = self._llm_refined_decision(binary_info, decision)

        logger.info(f"Decision: max_steps={decision.max_steps}, "
                   f"sources={len(decision.sources)}, sinks={len(decision.sinks)}")

        return decision

    def _rule_based_decision(self, binary_info: Dict[str, Any]) -> AnalysisDecision:
        """Make rule-based decisions."""
        decision = AnalysisDecision()

        # Set sources and sinks
        decision.sources = list(self.default_sources)
        decision.sinks = list(self.default_sinks)

        # Set priority weights
        decision.priority_factors = dict(self.default_priority_weights)

        # Adjust based on binary complexity
        num_functions = binary_info.get('num_functions', 0)
        if num_functions > 100:
            decision.max_steps = 500  # Reduce for complex binaries
            decision.prune_unlikely_paths = True
        elif num_functions < 10:
            decision.max_steps = 2000  # More steps for simple binaries

        # Adjust based on detected features
        if binary_info.get('has_loops', False):
            decision.timeout = 2000  # More time for loops

        if binary_info.get('has_recursion', False):
            decision.max_steps = 500  # Limit recursion depth

        # Set reasoning
        decision.reasoning = f"Rule-based decision: {num_functions} functions detected"

        return decision

    def _llm_refined_decision(self, binary_info: Dict[str, Any],
                               base_decision: AnalysisDecision) -> AnalysisDecision:
        """Refine decision using LLM."""
        try:
            # Get LLM recommendations
            llm_strategy = self.llm_client.decide_execution_strategy(binary_info)

            # Merge with base decision
            if 'max_steps' in llm_strategy:
                base_decision.max_steps = llm_strategy['max_steps']
            if 'timeout' in llm_strategy:
                base_decision.timeout = llm_strategy['timeout']
            if 'prioritize_paths' in llm_strategy:
                base_decision.prioritize_paths = llm_strategy['prioritize_paths']

            # Update reasoning
            base_decision.reasoning += f" + LLM refinement"

            logger.info("Applied LLM refinement to decision")

        except Exception as e:
            logger.warning(f"LLM refinement failed: {e}")

        return base_decision

    def generate_taint_spec(self, binary_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate taint specification.

        Args:
            binary_info: Binary information

        Returns:
            Taint specification
        """
        logger.info("Generating taint specification")

        # Start with defaults
        spec = {
            'sources': list(self.default_sources),
            'sinks': list(self.default_sinks),
            'propagation_rules': [
                {'op': 'assign', 'propagates': True},
                {'op': 'add', 'propagates': True},
                {'op': 'sub', 'propagates': True},
                {'op': 'mul', 'propagates': True},
                {'op': 'call', 'propagates': True},
                {'op': 'return', 'propagates': True},
            ]
        }

        # Add detected functions
        detected_sources = binary_info.get('detected_sources', [])
        detected_sinks = binary_info.get('detected_sinks', [])

        spec['sources'].extend(detected_sources)
        spec['sinks'].extend(detected_sinks)

        # Remove duplicates
        spec['sources'] = list(set(spec['sources']))
        spec['sinks'] = list(set(spec['sinks']))

        # LLM refinement (if available)
        if self.llm_client:
            try:
                llm_spec = self.llm_client.generate_taint_spec(binary_info)
                if 'sources' in llm_spec:
                    spec['sources'].extend(llm_spec['sources'])
                if 'sinks' in llm_spec:
                    spec['sinks'].extend(llm_spec['sinks'])
                spec['sources'] = list(set(spec['sources']))
                spec['sinks'] = list(set(spec['sinks']))
            except Exception as e:
                logger.warning(f"LLM taint spec generation failed: {e}")

        logger.info(f"Generated spec: {len(spec['sources'])} sources, {len(spec['sinks'])} sinks")
        return spec

    def prioritize_paths(self, paths: List[Dict[str, Any]],
                         context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Prioritize execution paths.

        Args:
            paths: List of paths
            context: Analysis context

        Returns:
            Prioritized paths
        """
        logger.info(f"Prioritizing {len(paths)} paths")

        # Score each path
        scored_paths = []
        for path in paths:
            score = self._score_path(path, context)
            scored_paths.append((path, score))

        # Sort by score (higher is better)
        scored_paths.sort(key=lambda x: x[1], reverse=True)

        # Return prioritized paths
        prioritized = [p for p, s in scored_paths]

        logger.info(f"Prioritized {len(prioritized)} paths")
        return prioritized

    def _score_path(self, path: Dict[str, Any], context: Dict[str, Any]) -> float:
        """Score a path for prioritization."""
        score = 0.0

        # Check for sources and sinks
        if path.get('has_source', False):
            score += self.default_priority_weights.get('has_source', 10.0)

        if path.get('has_sink', False):
            score += self.default_priority_weights.get('has_sink', 10.0)

        # Check for type mismatches
        if path.get('has_type_mismatch', False):
            score += self.default_priority_weights.get('type_mismatch', 5.0)

        # Check for buffer operations
        if path.get('has_buffer_op', False):
            score += self.default_priority_weights.get('buffer_operation', 8.0)

        # Check for pointer operations
        if path.get('has_pointer_op', False):
            score += self.default_priority_weights.get('pointer_operation', 6.0)

        # Check for user input
        if path.get('has_user_input', False):
            score += self.default_priority_weights.get('user_input', 9.0)

        # Penalize long paths
        path_length = path.get('length', 0)
        if path_length > 100:
            score -= (path_length - 100) * 0.1

        return score

    def guide_propagation(self, current_state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Guide taint propagation.

        Args:
            current_state: Current taint state

        Returns:
            Propagation guidance
        """
        logger.info("Guiding taint propagation")

        guidance = {
            'strategy': 'type_guided',
            'confidence_threshold': 0.7,
            'track_memory': True,
            'track_registers': True,
            'propagate_through_calls': True,
        }

        # LLM refinement (if available)
        if self.llm_client:
            try:
                llm_guidance = self.llm_client.guide_propagation(current_state)
                guidance.update(llm_guidance)
            except Exception as e:
                logger.warning(f"LLM propagation guidance failed: {e}")

        return guidance


def create_decision_engine(llm_client=None) -> DecisionEngine:
    """Create a decision engine."""
    return DecisionEngine(llm_client)
