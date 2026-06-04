"""
LLM Client Module

Provides a unified interface for interacting with LLMs.
Supports both local and remote LLM endpoints.
"""

import logging
import json
import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger('OPM.orchestrator')


@dataclass
class LLMConfig:
    """Configuration for LLM client."""
    # Provider: 'openai', 'ollama', 'local', 'mock'
    provider: str = 'mock'

    # API settings
    api_base: str = 'http://localhost:11434'  # Default Ollama endpoint
    api_key: Optional[str] = None
    model: str = 'llama2'  # Default model

    # Generation settings
    temperature: float = 0.7
    # mimo-v2.5-pro is a REASONING model: hidden reasoning_tokens count against
    # max_tokens. With 1024, reasoning consumed the entire budget (reasoning_tokens
    # ~1023) and the visible JSON answer came back empty/truncated -> parse failed ->
    # every verdict silently defaulted to 0.5. Give the visible answer real headroom.
    max_tokens: int = 4096
    top_p: float = 0.9

    # Timeout
    timeout: int = 60


class LLMClient:
    """
    Client for interacting with LLMs.

    Supports multiple providers:
    - openai: OpenAI API
    - ollama: Ollama local server
    - local: Local model
    - mock: Mock responses for testing
    """

    def __init__(self, config: Optional[LLMConfig] = None):
        self.config = config or LLMConfig()
        self.provider = self.config.provider

        # Initialize provider - only support openai-compatible (mimo)
        if self.provider in ('openai', 'mimo'):
            self._init_openai()
        else:
            logger.warning(f"Unsupported provider: {self.provider}, using openai")
            self.provider = 'openai'
            self._init_openai()

    def _init_openai(self):
        """Initialize OpenAI client."""
        try:
            import openai
            self.client = openai.OpenAI(
                base_url=self.config.api_base,
                api_key=self.config.api_key or 'dummy'
            )
            logger.info(f"Initialized OpenAI client: {self.config.api_base}")
        except ImportError:
            logger.warning("openai not available, falling back to mock")
            self.provider = 'mock'
            self._init_mock()

    def _init_freemodel(self):
        """Initialize FreeModel client (uses responses API)."""
        try:
            import httpx
            self.client = httpx.Client(
                base_url=self.config.api_base,
                timeout=self.config.timeout,
                headers={
                    'Authorization': f'Bearer {self.config.api_key}',
                    'Content-Type': 'application/json'
                }
            )
            logger.info(f"Initialized FreeModel client: {self.config.api_base}")
        except ImportError:
            logger.warning("httpx not available, falling back to mock")
            self.provider = 'mock'
            self._init_mock()

    def _init_mock(self):
        """Initialize mock client for testing."""
        self.client = None
        logger.info("Using mock LLM client")

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """
        Generate a response from the LLM (mimo API only).

        Args:
            prompt: User prompt
            system_prompt: Optional system prompt

        Returns:
            Generated text
        """
        import time

        max_retries = 3
        for attempt in range(max_retries):
            try:
                return self._generate_openai(prompt, system_prompt)
            except Exception as e:
                wait_time = 3 * (attempt + 1)
                logger.warning(f"API error (attempt {attempt+1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(wait_time)

        # All retries failed - return mock
        logger.warning("All API retries failed, using mock response")
        return self._generate_mock(prompt, system_prompt)

    def _generate_openai(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate using OpenAI API."""
        try:
            messages = []
            if system_prompt:
                messages.append({'role': 'system', 'content': system_prompt})
            messages.append({'role': 'user', 'content': prompt})

            response = self.client.chat.completions.create(
                model=self.config.model,
                messages=messages,
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
            )

            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"OpenAI generation failed: {e}")
            return self._generate_mock(prompt, system_prompt)

    def _generate_mock(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate mock response for testing."""
        # Analyze the prompt and return a reasonable mock response
        prompt_lower = prompt.lower()

        # Taint specification generation
        if 'source' in prompt_lower and 'sink' in prompt_lower:
            return json.dumps({
                'sources': ['getchar', 'gets', 'scanf', 'fgets', 'read', 'recv'],
                'sinks': ['strcpy', 'strcat', 'sprintf', 'printf', 'system', 'exec', 'malloc', 'free'],
                'propagation_rules': [
                    {'op': 'assign', 'propagates': True},
                    {'op': 'add', 'propagates': True},
                    {'op': 'call', 'propagates': True},
                ]
            })

        # Symbolic execution strategy
        if 'strategy' in prompt_lower or 'execution' in prompt_lower:
            return json.dumps({
                'max_steps': 1000,
                'timeout': 1000,
                'prioritize_paths': True,
                'use_type_guided': True,
                'prune_unlikely_paths': True,
            })

        # Path prioritization
        if 'priorit' in prompt_lower or 'path' in prompt_lower:
            return json.dumps({
                'priority_factors': [
                    {'factor': 'has_source', 'weight': 10.0},
                    {'factor': 'has_sink', 'weight': 10.0},
                    {'factor': 'type_mismatch', 'weight': 5.0},
                    {'factor': 'buffer_operation', 'weight': 8.0},
                ],
                'prune_threshold': 0.3,
            })

        # Taint propagation guidance
        if 'taint' in prompt_lower or 'propagat' in prompt_lower:
            return json.dumps({
                'propagation_strategy': 'type_guided',
                'use_confidence': True,
                'confidence_threshold': 0.7,
                'track_memory': True,
                'track_registers': True,
            })

        # Default response
        return json.dumps({
            'status': 'ok',
            'message': 'Analysis complete',
            'recommendations': [],
        })

    def analyze_binary(self, binary_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze binary information and provide recommendations.

        Args:
            binary_info: Information about the binary

        Returns:
            Analysis results and recommendations
        """
        prompt = f"""Analyze this binary and provide recommendations for taint analysis:

Binary Info:
- Architecture: {binary_info.get('arch', 'unknown')}
- Functions: {binary_info.get('num_functions', 0)}
- Has source calls: {binary_info.get('has_sources', False)}
- Has sink calls: {binary_info.get('has_sinks', False)}

Provide:
1. Recommended taint sources
2. Recommended taint sinks
3. Symbolic execution strategy
4. Path prioritization rules"""

        response = self.generate(prompt, "You are a binary analysis expert.")
        return self._parse_json_response(response)

    def decide_execution_strategy(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Decide symbolic execution strategy.

        Args:
            context: Analysis context

        Returns:
            Execution strategy
        """
        prompt = f"""Based on this analysis context, decide the symbolic execution strategy:

Context:
- Binary complexity: {context.get('complexity', 'medium')}
- Number of functions: {context.get('num_functions', 0)}
- Has loops: {context.get('has_loops', False)}
- Has recursion: {context.get('has_recursion', False)}

Provide strategy in JSON format."""

        response = self.generate(prompt, "You are a symbolic execution expert.")
        return self._parse_json_response(response)

    def generate_taint_spec(self, binary_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate taint specification.

        Args:
            binary_info: Binary information

        Returns:
            Taint specification
        """
        prompt = f"""Analyze this binary and generate a taint specification.

Binary Info:
- Path: {binary_info.get('path', 'unknown')}
- Functions: {binary_info.get('functions', [])}
- External calls: {binary_info.get('external_calls', [])}
- Detected sources: {binary_info.get('detected_sources', [])}
- Detected sinks: {binary_info.get('detected_sinks', [])}

Based on the function names and call patterns, identify:
1. Which functions are likely taint SOURCES (receive user input)
2. Which functions are likely taint SINKS (dangerous operations)
3. What specific arguments are tainted/vulnerable

Return JSON format:
{{
  "sources": ["func1", "func2"],
  "sinks": ["func3", "func4"],
  "source_details": {{"func1": {{"tainted_args": [0]}}}},
  "sink_details": {{"func3": {{"vulnerable_args": [0, 1]}}}}
}}"""

        response = self.generate(prompt, "You are a binary security analysis expert. Analyze the function names and identify potential security-relevant functions.")
        return self._parse_json_response(response)

    def guide_propagation(self, current_state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Guide taint propagation.

        Args:
            current_state: Current taint analysis state

        Returns:
            Propagation guidance
        """
        prompt = f"""Guide the taint propagation based on current state:

Current State:
- Tainted variables: {current_state.get('tainted_vars', [])}
- Tainted memory: {current_state.get('tainted_memory', [])}
- Source calls: {current_state.get('sources', [])}
- Sink calls: {current_state.get('sinks', [])}

Provide propagation guidance in JSON format."""

        response = self.generate(prompt, "You are a taint propagation expert.")
        return self._parse_json_response(response)

    def analyze_taint_path(self, path_info: Dict[str, Any],
                           symbolic_evidence: str = "",
                           lifecycle_analysis: str = "") -> Dict[str, Any]:
        """
        Analyze a taint path with enriched context.
        Uses shorter prompts to avoid API limits.
        """
        source = path_info.get('source', '')
        sink = path_info.get('sink', '')
        source_caller = path_info.get('source_caller', '')
        sink_caller = path_info.get('sink_caller', '')
        call_chain = path_info.get('call_chain', '')[:200]  # Limit length
        vuln_type = path_info.get('vulnerability_type', 'unknown')

        # Shorter system prompt
        system_prompt = "You are a binary security expert. Cross-function taint flows via parameters are REAL. Reply JSON only."

        # Build concise prompt
        prompt = f"Taint: {source}({source_caller}) -> {sink}({sink_caller})\n"
        prompt += f"Chain: {call_chain}\n"
        prompt += f"Type: {vuln_type}\n"

        # Add symbolic evidence (shortened)
        if symbolic_evidence:
            # Extract key constraints only
            lines = symbolic_evidence.split('\n')[:5]
            prompt += f"Evidence: {' '.join(lines)}\n"

        prompt += 'Is this real? JSON: {"is_feasible":bool,"confidence_score":0.0-1.0,"reason":"..."}'

        response = self.generate(prompt, system_prompt)

        # Parse response
        result = self._parse_json_response(response)

        # Normalize result
        confidence = result.get('confidence_score', 0.5)
        is_feasible = result.get('is_feasible', True)

        return {
            'is_real_taint': is_feasible,
            'confidence': confidence,
            'reasoning': result.get('reason', result.get('reasoning', '')),
            'raw_confidence': confidence,
        }

    def analyze_taint_path_cot(self, path_info: Dict[str, Any],
                                symbolic_evidence: str = "",
                                lifecycle_analysis: str = "") -> Dict[str, Any]:
        """
        Analyze taint path using Chain-of-Thought (CoT) reasoning.

        Forces LLM to think step-by-step:
        1. Syntactic feasibility (call stack alignment)
        2. Semantic realism (common in binary?)
        3. Constraint satisfiability (sanitization?)
        4. Final score
        """
        source = path_info.get('source', '')
        sink = path_info.get('sink', '')
        source_caller = path_info.get('source_caller', '')
        sink_caller = path_info.get('sink_caller', '')
        call_chain = path_info.get('call_chain', '')[:200]
        vuln_type = path_info.get('vulnerability_type', 'unknown')
        is_same_function = path_info.get('is_same_function', False)

        system_prompt = """You are a binary security expert performing taint-analysis triage. \
Think step-by-step and weigh SYMBOLIC and LIFECYCLE evidence ABOVE surface-level function names.

CORE RULES:
- Cross-function taint via parameters (RDI, RSI, RDX, stack) is COMMON and REAL.
- gets->strcpy, gets->strncpy, gets->free, argv->system are TYPICAL vulnerability patterns.
- NEVER reject just because the functions differ - only reject if data flow is LOGICALLY severed
  (value overwritten, sanitized, or replaced by a constant).
- Do NOT trust a function name to imply safety. strncpy / snprintf / memcpy are SAFE ONLY IF the
  size argument is PROVABLY bounded by the destination size. If the symbolic evidence says the size
  is UNCONSTRAINED (or taint-derived with no recovered upper bound), the bounded-copy guarantee is
  VOID -> treat it as a REAL buffer overflow.

OBJECT-LIFECYCLE STATE MACHINE (track the POINTER's lifetime, not just the data flow):
  Allocation (malloc/calloc/realloc)
    -> Taint Input (gets/scanf/read/recv)
    -> Deallocation (free)
    -> Use-After-Free / Double-Free
If taint data controls the address passed to free(), or a freed pointer is used or freed again,
this is a REAL vulnerability EVEN IF the sequence is rare in normal business logic. Rarity is NOT
evidence of safety.

Reply with JSON ONLY. Put the DECISION FIELDS FIRST so they are never lost, then brief
(<= 1 short sentence each) justification fields:
{"is_feasible": bool, "score": 0.0-1.0, "step1_syntactic":"...", "step2_symbolic":"...", "step3_lifecycle":"...", "step4_semantic":"..."}"""

        # Keep generous caps so the hard evidence is NOT truncated away
        evidence_text = symbolic_evidence[:1800] if symbolic_evidence else "(none recovered)"
        lifecycle_text = lifecycle_analysis[:1200] if lifecycle_analysis else "(no lifecycle events recorded)"

        prompt = f"""Analyze taint path: {source}({source_caller}) -> {sink}({sink_caller})
Vulnerability type: {vuln_type}
Call chain: {call_chain}
Same function: {is_same_function}

=== SYMBOLIC / CONSTRAINT EVIDENCE (hard proof) ===
{evidence_text}

=== MEMORY LIFECYCLE STATE MACHINE ===
{lifecycle_text}

Reason step-by-step, but keep each step to ONE short sentence:
Step 1 (Syntactic): Can the call-stack pointers align so taint reaches the sink argument?
Step 2 (Symbolic): Do the constraints/ranges show the size/length/command argument is bounded or
  UNCONSTRAINED? Treat an unconstrained size as proof of overflow.
Step 3 (Lifecycle): Per the state machine, is there Use-After-Free, Double-Free, or tainted-free?
  A rare-but-valid free/use ordering still counts.
Step 4 (Semantic): Combine the above - is this a real, exploitable flow?

Output `is_feasible` and `score` FIRST (score = final confidence 0.0-1.0, >=0.3 means report)."""

        response = self.generate(prompt, system_prompt)
        result = self._parse_json_response(response)

        # Extract confidence (new 'score' key, with back-compat fallbacks)
        confidence = result.get('score', result.get('step4', result.get('confidence_score', 0.5)))
        if isinstance(confidence, str):
            try:
                confidence = float(confidence)
            except:
                confidence = 0.5

        is_feasible = result.get('is_feasible', True)

        # Build reasoning from steps (new keys, with back-compat fallbacks)
        reasoning = (
            f"Syntactic: {result.get('step1_syntactic', result.get('step1', 'N/A'))} | "
            f"Symbolic: {result.get('step2_symbolic', result.get('step2', 'N/A'))} | "
            f"Lifecycle: {result.get('step3_lifecycle', result.get('step3', 'N/A'))} | "
            f"Semantic: {result.get('step4_semantic', 'N/A')}"
        )

        return {
            'is_real_taint': is_feasible,
            'confidence': confidence,
            'reasoning': reasoning,
            'raw_confidence': confidence,
        }

    def _parse_json_response(self, response: str) -> Dict[str, Any]:
        """Parse JSON from an LLM response, tolerant to reasoning-model quirks.

        Reasoning models (mimo-v2.5-pro) often (a) wrap JSON in ```json fences,
        (b) emit reasoning that pushes the answer past max_tokens so the JSON is
        truncated before its closing brace, or (c) return empty content. The old
        naive find('{')..rfind('}') + json.loads failed on all three and the caller
        then silently defaulted every verdict to 0.5. We now degrade gracefully:
        strip fences -> strict parse -> regex-extract the scalar fields we need.
        """
        if not response or not isinstance(response, str):
            return {}

        text = response.strip()

        # (a) strip markdown code fences if present
        if '```' in text:
            m = re.search(r'```(?:json)?\s*(.*?)```', text, re.DOTALL)
            if m:
                text = m.group(1).strip()

        # (b) strict parse of the first balanced-looking object
        start = text.find('{')
        end = text.rfind('}') + 1
        if start >= 0 and end > start:
            try:
                return json.loads(text[start:end])
            except json.JSONDecodeError:
                pass

        # (c) tolerant fallback: regex-extract the fields callers actually read,
        # so a truncated-but-informative response is NOT thrown away.
        loose = self._extract_fields_loose(text)
        return loose if loose else {'raw_response': response}

    def _extract_fields_loose(self, text: str) -> Dict[str, Any]:
        """Best-effort field extraction from invalid / truncated JSON text."""
        out: Dict[str, Any] = {}

        # numeric decision fields
        for key in ('score', 'step4', 'confidence_score', 'confidence'):
            m = re.search(r'"?%s"?\s*:\s*([0-9]*\.?[0-9]+)' % re.escape(key), text)
            if m:
                try:
                    out[key] = float(m.group(1))
                except ValueError:
                    pass

        # boolean decision field
        m = re.search(r'"?is_feasible"?\s*:\s*(true|false)', text, re.IGNORECASE)
        if m:
            out['is_feasible'] = (m.group(1).lower() == 'true')

        # string reasoning fields (may be truncated mid-value -> capture what exists)
        for key in ('step1_syntactic', 'step2_symbolic', 'step3_lifecycle',
                    'step4_semantic', 'step1', 'step2', 'step3', 'reason', 'reasoning'):
            m = re.search(r'"%s"\s*:\s*"([^"]*)' % re.escape(key), text)
            if m and m.group(1):
                out[key] = m.group(1)

        return out


def create_llm_client(config: Optional[LLMConfig] = None) -> LLMClient:
    """Create an LLM client."""
    return LLMClient(config)
