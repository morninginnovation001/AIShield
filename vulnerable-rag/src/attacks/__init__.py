"""
Attack framework for prompt injection research.

This package provides comprehensive attack implementations for testing
prompt injection vulnerabilities in agentic RAG systems.
"""

from .attack_base import AttackBase
from .corpus_poisoning import CorpusPoisoningAttack
from .context_injection import ContextInjectionAttack
from .system_bypass import SystemBypassAttack
from .tool_injection import ToolInjectionAttack
from .multi_step_attacks import MultiStepAttack
from .attack_generator import AttackGenerator

__all__ = [
    'AttackBase',
    'CorpusPoisoningAttack',
    'ContextInjectionAttack',
    'SystemBypassAttack',
    'ToolInjectionAttack',
    'MultiStepAttack',
    'AttackGenerator',
]

__version__ = '0.1.0'