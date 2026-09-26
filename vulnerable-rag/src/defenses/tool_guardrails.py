"""
Tool guardrails defense.

Enforces tool whitelisting and parameter validation policies.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .defense_base import DefenseBase

try:
    from ..agent.tool_registry import ToolRegistry
    from ..agent.tool_parser import ToolCall
except Exception:  # for static analysis
    ToolRegistry = Any  # type: ignore
    ToolCall = Any  # type: ignore


class ToolGuardrails(DefenseBase):
    """Whitelist and parameter checks for tool calls."""

    def __init__(self, tool_registry: Optional[ToolRegistry] = None,
                 config: Optional[Dict[str, Any]] = None,
                 enabled: bool = False):
        super().__init__(
            name="Tool Guardrails",
            description="Whitelisting and parameter validation",
            defense_type="tool_guardrails",
            enabled=enabled,
        )
        self.tool_registry = tool_registry
        cfg = config or {}

        wl_cfg = ((cfg.get("whitelist") or {}))
        self.whitelist_enabled = bool(wl_cfg.get("enabled", False))
        self.allowed_tools = set(wl_cfg.get("allowed_tools", []) or [])

        pv_cfg = (cfg.get("parameter_validation") or {})
        self.fr_cfg = pv_cfg.get("file_reader", {})
        self.db_cfg = pv_cfg.get("database_query", {})

        appr_cfg = (cfg.get("approval_workflow") or {})
        self.require_approval_for = set(appr_cfg.get("require_approval_for", []) or [])
        # Note: actual human approval workflow not implemented here (research-only)

    def _validate_file_reader(self, path_value: str) -> bool:
        # Block traversal attempts
        if self.fr_cfg.get("block_path_traversal", True):
            if ".." in path_value:
                return False

        # Allowed extensions
        exts = self.fr_cfg.get("allowed_extensions")
        if exts:
            if not any(str(path_value).lower().endswith(ext.lower()) for ext in exts):
                return False

        # Max file size can't be checked without reading; rely on tool internals.
        return True

    def _validate_database_query(self, query: str) -> bool:
        q = (query or "").upper()
        if self.db_cfg.get("read_only", True):
            blocked_keywords = set(self.db_cfg.get("block_keywords", []) or ["DROP", "DELETE", "UPDATE", "INSERT", "ALTER"]).union({";"})
            if any(kw in q for kw in blocked_keywords):
                return False
        return True

    def apply(self, tool_calls: List[ToolCall]) -> Tuple[bool, List[ToolCall], Optional[str]]:
        if not self.enabled:
            return True, tool_calls, None

        self.applied_count += 1
        allowed: List[ToolCall] = []
        reason: Optional[str] = None

        for call in tool_calls:
            # Whitelist enforcement
            if self.whitelist_enabled and call.tool_name not in self.allowed_tools:
                reason = f"tool_not_whitelisted:{call.tool_name}"
                self.blocked_count += 1
                continue

            # Tool-specific parameter validation
            if call.tool_name == "file_reader":
                path = str(call.parameters.get("path", ""))
                if not self._validate_file_reader(path):
                    reason = "file_reader_param_blocked"
                    self.blocked_count += 1
                    continue

            if call.tool_name == "database_query":
                query = str(call.parameters.get("query", ""))
                if not self._validate_database_query(query):
                    reason = "database_query_blocked"
                    self.blocked_count += 1
                    continue

            allowed.append(call)

        return True, allowed, reason

