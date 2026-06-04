"""
Heuristic Path Pruning

Implements intelligent path pruning strategies for symbolic execution.
"""

import logging
import math
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger('OPM.symbolic_exec')


@dataclass
class PathScore:
    """Score for an execution path."""
    # Basic metrics
    length: int = 0
    num_branches: int = 0

    # Type-related metrics
    has_type_mismatch: bool = False
    type_confidence: float = 0.0

    # Taint-related metrics
    has_source: bool = False
    has_sink: bool = False
    taint_relevance: float = 0.0

    # Complexity metrics
    cyclomatic_complexity: int = 0
    loop_depth: int = 0

    # Vulnerability likelihood
    vuln_score: float = 0.0

    def total_score(self) -> float:
        """Calculate total score."""
        score = 0.0

        # Taint relevance is most important
        if self.has_source and self.has_sink:
            score += 100.0
        elif self.has_source or self.has_sink:
            score += 50.0

        # Type mismatch indicates potential vulnerability
        if self.has_type_mismatch:
            score += 30.0

        # Higher confidence is better
        score += self.type_confidence * 20.0

        # Taint relevance
        score += self.taint_relevance * 40.0

        # Vulnerability score
        score += self.vuln_score * 60.0

        # Penalize very long paths (less likely to be vulnerable)
        if self.length > 100:
            score -= (self.length - 100) * 0.1

        # Penalize high complexity (harder to analyze)
        score -= self.cyclomatic_complexity * 2.0

        return score


@dataclass
class PruningStrategy:
    """Strategy for path pruning."""
    # Thresholds
    max_path_length: int = 1000
    max_states: int = 100
    min_score_threshold: float = 0.0

    # Weights for scoring
    taint_weight: float = 1.0
    type_weight: float = 0.5
    complexity_weight: float = 0.3

    # Heuristic flags
    use_type_heuristic: bool = True
    use_taint_heuristic: bool = True
    use_complexity_heuristic: bool = True
    use_loop_heuristic: bool = True


class HeuristicPathPruner:
    """
    Heuristic-based path pruner for symbolic execution.

    Uses multiple heuristics to prioritize and prune paths.
    """

    def __init__(self, strategy: Optional[PruningStrategy] = None):
        self.strategy = strategy or PruningStrategy()

        # Statistics
        self.total_paths = 0
        self.pruned_paths = 0
        self.prioritized_paths = 0

    def score_path(self, path: Dict[str, Any], context: Dict[str, Any]) -> PathScore:
        """
        Score a path based on multiple heuristics.

        Args:
            path: Path information
            context: Analysis context (types, taint, etc.)

        Returns:
            PathScore
        """
        score = PathScore()

        # Basic metrics
        score.length = len(path.get('blocks', []))
        score.num_branches = path.get('num_branches', 0)

        # Type-related heuristics
        if self.strategy.use_type_heuristic:
            score = self._apply_type_heuristic(score, path, context)

        # Taint-related heuristics
        if self.strategy.use_taint_heuristic:
            score = self._apply_taint_heuristic(score, path, context)

        # Complexity heuristics
        if self.strategy.use_complexity_heuristic:
            score = self._apply_complexity_heuristic(score, path, context)

        # Loop heuristics
        if self.strategy.use_loop_heuristic:
            score = self._apply_loop_heuristic(score, path, context)

        # Vulnerability likelihood
        score.vuln_score = self._calculate_vulnerability_score(path, context)

        return score

    def _apply_type_heuristic(self, score: PathScore, path: Dict[str, Any],
                               context: Dict[str, Any]) -> PathScore:
        """Apply type-related heuristics."""
        type_info = context.get('type_info', {})

        # Check for type mismatches
        for block in path.get('blocks', []):
            block_types = type_info.get(block, {})
            if block_types.get('has_mismatch', False):
                score.has_type_mismatch = True
                break

        # Calculate type confidence
        confidences = []
        for block in path.get('blocks', []):
            block_types = type_info.get(block, {})
            if 'confidence' in block_types:
                confidences.append(block_types['confidence'])

        if confidences:
            score.type_confidence = sum(confidences) / len(confidences)

        return score

    def _apply_taint_heuristic(self, score: PathScore, path: Dict[str, Any],
                                context: Dict[str, Any]) -> PathScore:
        """Apply taint-related heuristics."""
        taint_info = context.get('taint_info', {})

        # Check for sources and sinks
        for block in path.get('blocks', []):
            block_taint = taint_info.get(block, {})
            if block_taint.get('is_source', False):
                score.has_source = True
            if block_taint.get('is_sink', False):
                score.has_sink = True

        # Calculate taint relevance
        tainted_blocks = sum(
            1 for block in path.get('blocks', [])
            if taint_info.get(block, {}).get('is_tainted', False)
        )
        total_blocks = len(path.get('blocks', []))
        if total_blocks > 0:
            score.taint_relevance = tainted_blocks / total_blocks

        return score

    def _apply_complexity_heuristic(self, score: PathScore, path: Dict[str, Any],
                                     context: Dict[str, Any]) -> PathScore:
        """Apply complexity heuristics."""
        # Calculate cyclomatic complexity
        num_edges = path.get('num_edges', 0)
        num_nodes = len(path.get('blocks', []))
        num_components = 1  # Assume single connected component

        if num_nodes > 0:
            score.cyclomatic_complexity = num_edges - num_nodes + 2 * num_components

        return score

    def _apply_loop_heuristic(self, score: PathScore, path: Dict[str, Any],
                               context: Dict[str, Any]) -> PathScore:
        """Apply loop-related heuristics."""
        # Estimate loop depth
        blocks = path.get('blocks', [])
        visited = set()
        max_depth = 0
        current_depth = 0

        for block in blocks:
            if block in visited:
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            else:
                visited.add(block)
                current_depth = 0

        score.loop_depth = max_depth
        return score

    def _calculate_vulnerability_score(self, path: Dict[str, Any],
                                        context: Dict[str, Any]) -> float:
        """Calculate vulnerability likelihood score."""
        score = 0.0

        # Check for dangerous patterns
        dangerous_funcs = {
            'strcpy', 'strcat', 'sprintf', 'gets',
            'system', 'exec', 'printf'
        }

        for block in path.get('blocks', []):
            block_info = context.get('block_info', {}).get(block, {})
            calls = block_info.get('calls', [])

            for call in calls:
                if call in dangerous_funcs:
                    score += 20.0

        # Check for buffer operations
        for block in path.get('blocks', []):
            block_info = context.get('block_info', {}).get(block, {})
            if block_info.get('has_buffer_op', False):
                score += 10.0

        # Check for user input
        for block in path.get('blocks', []):
            block_info = context.get('block_info', {}).get(block, {})
            if block_info.get('has_user_input', False):
                score += 15.0

        return min(score, 100.0)  # Cap at 100

    def prune_paths(self, paths: List[Dict[str, Any]],
                    context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Prune and prioritize paths.

        Args:
            paths: List of paths
            context: Analysis context

        Returns:
            Pruned and prioritized paths
        """
        self.total_paths += len(paths)

        # Score all paths
        scored_paths = []
        for path in paths:
            score = self.score_path(path, context)
            scored_paths.append((path, score))

        # Sort by score (higher is better)
        scored_paths.sort(key=lambda x: x[1].total_score(), reverse=True)

        # Apply pruning
        pruned_paths = []
        for path, score in scored_paths:
            # Check path length
            if score.length > self.strategy.max_path_length:
                self.pruned_paths += 1
                continue

            # Check score threshold
            if score.total_score() < self.strategy.min_score_threshold:
                self.pruned_paths += 1
                continue

            pruned_paths.append(path)

            # Limit number of states
            if len(pruned_paths) >= self.strategy.max_states:
                break

        self.prioritized_paths += len(pruned_paths)

        logger.info(f"Pruned {len(paths)} -> {len(pruned_paths)} paths")
        return pruned_paths

    def get_statistics(self) -> Dict[str, Any]:
        """Get pruning statistics."""
        return {
            'total_paths': self.total_paths,
            'pruned_paths': self.pruned_paths,
            'prioritized_paths': self.prioritized_paths,
            'pruning_rate': self.pruned_paths / self.total_paths if self.total_paths > 0 else 0,
        }


class AdaptivePathPruner(HeuristicPathPruner):
    """
    Adaptive path pruner that adjusts strategy based on results.
    """

    def __init__(self, initial_strategy: Optional[PruningStrategy] = None):
        super().__init__(initial_strategy)
        self.success_history = []
        self.failure_history = []

    def update_strategy(self, found_vulnerability: bool, path_score: float):
        """
        Update pruning strategy based on results.

        Args:
            found_vulnerability: Whether a vulnerability was found
            path_score: Score of the path that was analyzed
        """
        if found_vulnerability:
            self.success_history.append(path_score)
            # Lower threshold to explore more similar paths
            self.strategy.min_score_threshold *= 0.9
        else:
            self.failure_history.append(path_score)
            # Raise threshold to skip low-quality paths
            self.strategy.min_score_threshold *= 1.1

        # Keep threshold in reasonable range
        self.strategy.min_score_threshold = max(0.0, min(100.0, self.strategy.min_score_threshold))

        logger.info(f"Updated threshold: {self.strategy.min_score_threshold:.2f}")


def create_pruner(strategy: Optional[PruningStrategy] = None,
                  adaptive: bool = False) -> HeuristicPathPruner:
    """Create a path pruner."""
    if adaptive:
        return AdaptivePathPruner(strategy)
    return HeuristicPathPruner(strategy)
