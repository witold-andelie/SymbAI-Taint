"""
AI Orchestrator Module

Implements the AI Orchestrator component from the OPM architecture.
Uses LLM to guide binary analysis, symbolic execution, and taint propagation.

Features:
- Analyzes program structure
- Decides symbolic execution strategy
- Generates taint specifications
- Guides taint propagation

Note: RAG functionality is not included to keep the system lightweight.
"""

from .orchestrator import AIOrchestrator, OrchestratorConfig
from .llm_client import LLMClient, LLMConfig
from .decision_engine import DecisionEngine
