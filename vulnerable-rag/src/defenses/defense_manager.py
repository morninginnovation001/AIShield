"""
Defense manager: orchestrates multiple defenses for input and output stages.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except Exception:
    yaml = None

from .defense_base import DefenseBase
from .input_sanitization import InputSanitizer
from .prompt_engineering import PromptEngineeringDefense
from .output_validation import OutputValidator
from .tool_guardrails import ToolGuardrails

try:
    from ..agent.tool_registry import ToolRegistry
    from ..agent.tool_parser import ToolCall
except Exception:  # for static analysis
    ToolRegistry = Any  # type: ignore
    ToolCall = Any  # type: ignore


class DefenseManager:
    """Manages and orchestrates multiple defense mechanisms."""

    def __init__(self):
        self.defenses: Dict[str, DefenseBase] = {}
        self.enabled_order: List[str] = []
        self.logger = logging.getLogger(__name__)

    def register_defense(self, defense: DefenseBase) -> None:
        self.defenses[defense.name] = defense
        if defense.enabled:
            self.enabled_order.append(defense.name)

    def enable_defenses(self, names: List[str]) -> None:
        for n in names:
            if n in self.defenses:
                self.defenses[n].enable()
                if n not in self.enabled_order:
                    self.enabled_order.append(n)

    def disable_defenses(self, names: List[str]) -> None:
        for n in names:
            if n in self.defenses:
                self.defenses[n].disable()
                if n in self.enabled_order:
                    self.enabled_order.remove(n)

    def apply_input_defenses(
        self,
        query: str,
        contexts: List[str],
        system_prompt: Optional[str] = None,
    ) -> Tuple[bool, Dict[str, Any], Optional[str]]:
        # Start with pass-through
        current_query = query
        current_contexts = contexts[:]
        current_system = system_prompt
        reason: Optional[str] = None

        # Input Sanitization first
        sanitizer = self.defenses.get("Input Sanitization")
        if sanitizer and sanitizer.is_enabled():
            ok, current_query, r = getattr(sanitizer, "apply")(current_query)
            if r:
                reason = r if not reason else f"{reason};{r}"

        # Prompt Engineering next
        prompt_def = self.defenses.get("Prompt Engineering Defense")
        if prompt_def and prompt_def.is_enabled():
            ok, components, r = getattr(prompt_def, "apply")(current_query, current_contexts, current_system)
            current_query = components.get("query", current_query)
            current_contexts = components.get("contexts", current_contexts)
            current_system = components.get("system_prompt", current_system)
            if r:
                reason = r if not reason else f"{reason};{r}"

        return True, {
            "query": current_query,
            "contexts": current_contexts,
            "system_prompt": current_system,
        }, reason

    def apply_output_defenses(
        self,
        llm_output: str,
        tool_calls: List[ToolCall],
    ) -> Tuple[bool, List[ToolCall], Optional[str]]:
        current_calls = list(tool_calls)
        reason: Optional[str] = None

        # Output Validation
        validator = self.defenses.get("Output Validation")
        if validator and validator.is_enabled():
            ok, current_calls, r = getattr(validator, "apply")(llm_output, current_calls)
            if r:
                reason = r if not reason else f"{reason};{r}"

        # Tool Guardrails
        guardrails = self.defenses.get("Tool Guardrails")
        if guardrails and guardrails.is_enabled():
            ok, current_calls, r = getattr(guardrails, "apply")(current_calls)
            if r:
                reason = r if not reason else f"{reason};{r}"

        return True, current_calls, reason

    def get_stats(self) -> Dict[str, Any]:
        return {name: defense.get_stats() for name, defense in self.defenses.items()}


def create_defense_manager(
    tool_registry: Optional[ToolRegistry] = None,
    config_path: Optional[str] = None,
) -> DefenseManager:
    """Factory to create a DefenseManager configured from YAML."""
    cfg: Dict[str, Any] = {}
    if not config_path:
        default = Path("config") / "defense_config.yaml"
        if default.exists():
            config_path = str(default)
    if config_path and yaml is not None and Path(config_path).exists():
        try:
            with open(config_path, "r") as f:
                cfg = yaml.safe_load(f) or {}
        except Exception:
            cfg = {}

    dm = DefenseManager()

    # Input Sanitization
    input_cfg = cfg.get("input_sanitization", {})
    input_enabled = bool((cfg.get("defense_types", {}).get("input_sanitization", {}) or {}).get("enabled", False))
    dm.register_defense(InputSanitizer(config=input_cfg, enabled=input_enabled))

    # Prompt Engineering
    pe_cfg = cfg.get("prompt_engineering", {})
    pe_enabled = bool((cfg.get("defense_types", {}).get("prompt_engineering", {}) or {}).get("enabled", False))
    dm.register_defense(PromptEngineeringDefense(config=pe_cfg, enabled=pe_enabled))

    # Output Validation
    ov_cfg = cfg.get("output_validation", {})
    ov_enabled = bool((cfg.get("defense_types", {}).get("output_validation", {}) or {}).get("enabled", False))
    dm.register_defense(OutputValidator(tool_registry=tool_registry, config=ov_cfg, enabled=ov_enabled))

    # Tool Guardrails
    tg_cfg = cfg.get("tool_guardrails", {})
    tg_enabled = bool((cfg.get("defense_types", {}).get("tool_guardrails", {}) or {}).get("enabled", False))
    dm.register_defense(ToolGuardrails(tool_registry=tool_registry, config=tg_cfg, enabled=tg_enabled))

    return dm

