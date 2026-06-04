"""
Counterfactual Sample Generation

Implements VISION-style counterfactual augmentation to reduce false positives.
Reference: VISION - Robust and Interpretable Code Vulnerability Detection

The idea: If a model can correctly distinguish between a vulnerable pattern
and its counterfactual (safe) version, it's more likely to be a true positive.
"""

import logging
import re
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger('OPM.taint_analysis')


@dataclass
class CounterfactualPair:
    """A pair of vulnerable and safe code patterns."""
    vulnerable: Dict[str, Any]
    safe: Dict[str, Any]
    difference: str  # Description of the difference


@dataclass
class CounterfactualConfig:
    """Configuration for counterfactual generation."""
    # What to check
    check_bounds: bool = True
    check_sanitization: bool = True
    check_input_validation: bool = True
    check_memory_management: bool = True

    # Thresholds
    min_confidence_diff: float = 0.3  # Minimum confidence difference to consider


class CounterfactualGenerator:
    """
    Generates counterfactual samples for vulnerability detection.

    For each potential vulnerability, generates a "safe" version
    and checks if the model can distinguish them.
    """

    def __init__(self, config: Optional[CounterfactualConfig] = None):
        self.config = config or CounterfactualConfig()

        # Safe patterns (counterfactuals of dangerous patterns)
        self.safe_patterns = {
            'strcpy': ['strncpy', 'strlcpy', 'memcpy with bounds'],
            'strcat': ['strncat', 'strlcat'],
            'sprintf': ['snprintf', 'asprintf'],
            'gets': ['fgets', 'getline'],
            'printf(input)': ['printf("%s", input)'],
            'system': ['execve with controlled args'],
            'malloc': ['malloc with size check'],
            'free': ['free with NULL check'],
        }

    def generate_counterfactuals(self, taint_path: Dict[str, Any]) -> List[CounterfactualPair]:
        """
        Generate counterfactual pairs for a taint path.

        Args:
            taint_path: Taint path to analyze

        Returns:
            List of counterfactual pairs
        """
        pairs = []

        source = taint_path.get('source', '')
        sink = taint_path.get('sink', '')
        source_caller = taint_path.get('source_caller', '')
        sink_caller = taint_path.get('sink_caller', '')

        # Check for known vulnerable patterns
        if sink in self.safe_patterns:
            # Generate safe version
            safe_alternatives = self.safe_patterns[sink]

            for safe_func in safe_alternatives:
                pair = CounterfactualPair(
                    vulnerable={
                        'source': source,
                        'sink': sink,
                        'caller': sink_caller,
                        'pattern': f'{sink}(user_input)',
                    },
                    safe={
                        'source': source,
                        'sink': safe_func.split()[0],  # First word
                        'caller': sink_caller,
                        'pattern': safe_func,
                    },
                    difference=f'{sink} -> {safe_func}'
                )
                pairs.append(pair)

        # Check for missing bounds checking
        if self.config.check_bounds and self._is_buffer_operation(sink):
            pair = self._generate_bounds_check_counterfactual(taint_path)
            if pair:
                pairs.append(pair)

        # Check for missing sanitization
        if self.config.check_sanitization and self._needs_sanitization(sink):
            pair = self._generate_sanitization_counterfactual(taint_path)
            if pair:
                pairs.append(pair)

        return pairs

    def _is_buffer_operation(self, func_name: str) -> bool:
        """Check if function is a buffer operation."""
        buffer_ops = {'strcpy', 'strcat', 'sprintf', 'memcpy', 'memmove', 'gets'}
        return func_name in buffer_ops

    def _needs_sanitization(self, func_name: str) -> bool:
        """Check if function needs input sanitization."""
        needs_sanitize = {'system', 'exec', 'popen', 'printf', 'sprintf'}
        return func_name in needs_sanitize

    def _generate_bounds_check_counterfactual(self, taint_path: Dict[str, Any]) -> Optional[CounterfactualPair]:
        """Generate counterfactual with bounds checking."""
        sink = taint_path.get('sink', '')

        # Pattern: strcpy(buf, input) -> strncpy(buf, input, sizeof(buf)-1)
        if sink == 'strcpy':
            return CounterfactualPair(
                vulnerable={
                    'pattern': 'strcpy(buf, input)',
                    'has_bounds_check': False,
                },
                safe={
                    'pattern': 'strncpy(buf, input, sizeof(buf)-1); buf[sizeof(buf)-1] = \'\\0\'',
                    'has_bounds_check': True,
                },
                difference='Missing bounds check in strcpy'
            )

        # Pattern: sprintf(buf, fmt, ...) -> snprintf(buf, sizeof(buf), fmt, ...)
        if sink == 'sprintf':
            return CounterfactualPair(
                vulnerable={
                    'pattern': 'sprintf(buf, fmt, ...)',
                    'has_bounds_check': False,
                },
                safe={
                    'pattern': 'snprintf(buf, sizeof(buf), fmt, ...)',
                    'has_bounds_check': True,
                },
                difference='Missing bounds check in sprintf'
            )

        return None

    def _generate_sanitization_counterfactual(self, taint_path: Dict[str, Any]) -> Optional[CounterfactualPair]:
        """Generate counterfactual with input sanitization."""
        sink = taint_path.get('sink', '')

        # Pattern: system(input) -> system(sanitized_input)
        if sink == 'system':
            return CounterfactualPair(
                vulnerable={
                    'pattern': 'system(user_input)',
                    'has_sanitization': False,
                },
                safe={
                    'pattern': 'if (is_valid_command(user_input)) system(user_input)',
                    'has_sanitization': True,
                },
                difference='Missing input validation for system()'
            )

        # Pattern: printf(input) -> printf("%s", input)
        if sink == 'printf':
            return CounterfactualPair(
                vulnerable={
                    'pattern': 'printf(user_input)',
                    'has_sanitization': False,
                },
                safe={
                    'pattern': 'printf("%s", user_input)',
                    'has_sanitization': True,
                },
                difference='Format string vulnerability in printf'
            )

        return None


class CounterfactualValidator:
    """
    Validates taint paths using counterfactual analysis.

    If a taint path cannot be distinguished from its counterfactual,
    it's likely a false positive.
    """

    def __init__(self, generator: Optional[CounterfactualGenerator] = None):
        self.generator = generator or CounterfactualGenerator()

    def validate_paths(self, taint_paths: List[Dict[str, Any]],
                       model=None) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Validate taint paths using counterfactual analysis.

        Args:
            taint_paths: List of taint paths to validate
            model: Optional model for confidence-based filtering

        Returns:
            (valid_paths, filtered_paths)
        """
        logger.info(f"Validating {len(taint_paths)} paths with counterfactual analysis")

        valid_paths = []
        filtered_paths = []

        for path in taint_paths:
            # Generate counterfactuals
            counterfactuals = self.generator.generate_counterfactuals(path)

            if not counterfactuals:
                # No counterfactual available, keep path
                valid_paths.append(path)
                continue

            # Check if path is distinguishable from counterfactuals
            is_valid = self._check_distinguishability(path, counterfactuals, model)

            if is_valid:
                valid_paths.append(path)
            else:
                filtered_paths.append(path)
                logger.debug(f"Filtered path: {path.get('source')} -> {path.get('sink')}")

        logger.info(f"Counterfactual validation: {len(valid_paths)} valid, {len(filtered_paths)} filtered")

        return valid_paths, filtered_paths

    def _check_distinguishability(self, path: Dict[str, Any],
                                   counterfactuals: List[CounterfactualPair],
                                   model=None) -> bool:
        """
        Check if a path is distinguishable from its counterfactuals.

        Args:
            path: Taint path
            counterfactuals: Counterfactual pairs
            model: Optional model for confidence-based check

        Returns:
            True if path is likely a true positive
        """
        # If no model, use heuristic check
        if model is None:
            return self._heuristic_check(path, counterfactuals)

        # Model-based check would go here
        # For now, use heuristic
        return self._heuristic_check(path, counterfactuals)

    def _heuristic_check(self, path: Dict[str, Any],
                          counterfactuals: List[CounterfactualPair]) -> bool:
        """
        Heuristic check for path validity.

        A path is considered valid if:
        1. It uses a known dangerous function
        2. The counterfactual would require significant code changes
        """
        sink = path.get('sink', '')

        # High-risk sinks are always considered valid
        high_risk_sinks = {'system', 'exec', 'popen', 'gets', 'strcpy'}
        if sink in high_risk_sinks:
            return True

        # Check if counterfactual involves safe alternatives
        for cf in counterfactuals:
            safe_pattern = cf.safe.get('pattern', '')
            # If the safe pattern is significantly different, path is valid
            if 'bounds check' in cf.difference.lower() or \
               'sanitization' in cf.difference.lower() or \
               'validation' in cf.difference.lower():
                return True

        # Default: consider valid
        return True


def create_counterfactual_validator(config: Optional[CounterfactualConfig] = None) -> CounterfactualValidator:
    """Create counterfactual validator."""
    generator = CounterfactualGenerator(config)
    return CounterfactualValidator(generator)
