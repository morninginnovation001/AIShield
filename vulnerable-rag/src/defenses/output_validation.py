"""
Output validation defenses.

Validates LLM outputs and parsed tool calls before execution.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .defense_base import DefenseBase

try:
    from ..agent.tool_registry import ToolRegistry
    from ..agent.tool_parser import ToolCall
except Exception:  # for static analysis
    ToolRegistry = Any  # type: ignore
    ToolCall = Any  # type: ignore


class OutputValidator(DefenseBase):
    """Validate that tool calls are well-formed and authorized."""

    def __init__(self, tool_registry: Optional[ToolRegistry] = None,
                 config: Optional[Dict[str, Any]] = None,
                 enabled: bool = False):
        super().__init__(
            name="Output Validation",
            description="Validates LLM outputs and tool calls",
            defense_type="output_validation",
            enabled=enabled,
        )
        self.tool_registry = tool_registry
        cfg = (config or {}).get("tool_call_validation", {})
        self.verify_tool_exists = bool(cfg.get("verify_tool_exists", True))
        self.verify_parameters = bool(cfg.get("verify_parameters", True))
        self.check_authorization = bool(cfg.get("check_authorization", True))

    def apply(self, llm_output: str, tool_calls: List[ToolCall]) -> Tuple[bool, List[ToolCall], Optional[str]]:
        if not self.enabled:
            return True, tool_calls, None

        self.applied_count += 1
        valid_calls: List[ToolCall] = []
        reason: Optional[str] = None

        for call in tool_calls:
            # Tool existence
            if self.verify_tool_exists and self.tool_registry is not None:
                tool = self.tool_registry.get_tool(call.tool_name)
                if tool is None:
                    reason = f"tool_not_found:{call.tool_name}"
                    self.blocked_count += 1
                    continue

            # Parameter validation via registry schema
            if self.verify_parameters and self.tool_registry is not None:
                ok, err = self.tool_registry.validate_tool_call(call.tool_name, call.parameters)
                if not ok:
                    reason = f"param_invalid:{err}"
                    self.blocked_count += 1
                    continue

            valid_calls.append(call)

        return True, valid_calls, reason

