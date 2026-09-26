"""
Defense framework for prompt injection research.

Provides input sanitization, prompt engineering, output validation,
and tool guardrails, orchestrated by DefenseManager.
"""

from .defense_base import DefenseBase
from .input_sanitization import InputSanitizer
from .prompt_engineering import PromptEngineeringDefense
from .output_validation import OutputValidator
from .tool_guardrails import ToolGuardrails
from .defense_manager import DefenseManager, create_defense_manager

__all__ = [
    "DefenseBase",
    "InputSanitizer",
    "PromptEngineeringDefense",
    "OutputValidator",
    "ToolGuardrails",
    "DefenseManager",
    "create_defense_manager",
]
