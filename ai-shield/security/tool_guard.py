"""
Tool Guard: Agent Tool Invocation and Parameter Safety Guardrail.
Validates tool permissions, blocks path traversal, SQL injection, and command injection in tool calls.
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .risk_engine import Finding, GuardResult, RiskEngine, Severity, ThreatCategory


class ToolGuard:
    """Enforces least privilege, tool whitelisting, and parameter validation for agentic tools."""

    # Explicit list of allowed tools
    DEFAULT_ALLOWED_TOOLS = {
        "calculator",
        "file_reader",
        "database_query",
        "web_search",
    }

    # Forbidden tool names often requested in injection attacks
    BLOCKED_TOOLS = {
        "shell_exec",
        "system_command",
        "bash",
        "sh",
        "cmd",
        "powershell",
        "python_exec",
        "eval",
        "exec",
        "write_file",
        "delete_file",
    }

    # Sensitive files that should never be read by file_reader
    SENSITIVE_FILES_PATTERN = re.compile(
        r"(?:/etc/(?:passwd|shadow|hosts)|(?:~|\.ssh)/id_rsa|\.env|secrets\.json|credentials\.yaml|\bconfig\.ya?ml\b|web\.config|\.git/config)",
        re.I,
    )

    # Path traversal detection pattern
    PATH_TRAVERSAL_PATTERN = re.compile(r"(?:\.\.[\\/]|[\\/]\.\.)")

    # SQL injection patterns
    SQLI_PATTERNS = [
        (
            "sql_drop_or_truncate",
            re.compile(r"\b(drop|truncate|alter)\s+(table|database|schema)\b", re.I),
            Severity.CRITICAL,
            "Destructive SQL command attempted",
        ),
        (
            "sql_union_injection",
            re.compile(r"\bunion\s+(all\s+)?select\b", re.I),
            Severity.HIGH,
            "SQL UNION-based exfiltration query",
        ),
        (
            "sql_tautology_or_comment",
            re.compile(r"(?:'|\")\s*or\s+['\"]?1['\"]?\s*=\s*['\"]?1|--|\bshutdown\b", re.I),
            Severity.HIGH,
            "SQL tautology bypass or inline comment",
        ),
    ]

    # Command injection patterns
    COMMAND_INJECTION_PATTERN = re.compile(
        r"(?:[;&|`$]|\b(?:rm\s+-rf|del\s+/f|format|chmod\s+777|curl\s+http|wget\s+http)\b)",
        re.I,
    )

    # SSRF / Internal network targets in URLs
    SSRF_PATTERN = re.compile(
        r"(?:https?://(?:127\.0\.0\.1|localhost|169\.254\.169\.254|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})|file://)",
        re.I,
    )

    def __init__(self, risk_engine: Optional[RiskEngine] = None,
                 allowed_tools: Optional[Set[str]] = None,
                 allowed_directories: Optional[List[str]] = None,
                 block_path_traversal: bool = True,
                 block_dangerous_sql: bool = True):
        self.risk_engine = risk_engine or RiskEngine()
        self.allowed_tools = allowed_tools or self.DEFAULT_ALLOWED_TOOLS.copy()
        self.allowed_directories = allowed_directories or ["data", "docs", "public", "reports"]
        self.block_path_traversal = block_path_traversal
        self.block_dangerous_sql = block_dangerous_sql

    def validate_tool_call(self, tool_name: str, parameters: Dict[str, Any]) -> GuardResult:
        """Validate whether a tool invocation and its arguments are authorized and safe."""
        start_time = time.perf_counter()
        findings: List[Finding] = []
        clean_params = dict(parameters or {})
        normalized_tool = (tool_name or "").strip().lower()

        # 1. Authorization check
        if normalized_tool in self.BLOCKED_TOOLS:
            findings.append(
                Finding(
                    rule="unauthorized_forbidden_tool",
                    severity=Severity.CRITICAL,
                    snippet=f"Tool: {tool_name}",
                    category=ThreatCategory.TOOL_ABUSE,
                    description=f"Invocation of strictly prohibited system tool '{tool_name}'",
                )
            )
        elif normalized_tool not in self.allowed_tools:
            findings.append(
                Finding(
                    rule="unregistered_tool_access",
                    severity=Severity.HIGH,
                    snippet=f"Tool: {tool_name}",
                    category=ThreatCategory.TOOL_ABUSE,
                    description=f"Attempt to call unapproved tool '{tool_name}'",
                )
            )

        # 2. Parameter validation for specific tools
        if normalized_tool == "file_reader":
            path_val = str(clean_params.get("path") or clean_params.get("filename") or "")
            self._validate_file_path(path_val, findings)

        elif normalized_tool == "database_query":
            query_val = str(clean_params.get("query") or clean_params.get("sql") or "")
            self._validate_sql_query(query_val, findings)

        elif normalized_tool == "web_search":
            url_or_query = str(clean_params.get("query") or clean_params.get("url") or "")
            self._validate_web_search(url_or_query, findings)

        # General command injection check across all parameters
        for param_key, param_val in clean_params.items():
            if isinstance(param_val, str) and self.COMMAND_INJECTION_PATTERN.search(param_val):
                findings.append(
                    Finding(
                        rule="command_injection_symbol",
                        severity=Severity.CRITICAL,
                        snippet=f"Param '{param_key}': {param_val[:40]}",
                        category=ThreatCategory.TOOL_ABUSE,
                        description="Potential shell command injection character or utility found",
                    )
                )

        blocked = any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)

        return self.risk_engine.evaluate_stage(
            stage_name="tool_guard",
            findings=findings,
            sanitized_text=f"Tool: {tool_name} (blocked: {blocked})",
            start_time=start_time,
            block_condition=blocked,
            metadata={"tool_name": tool_name, "parameters": clean_params},
        )

    def _validate_file_path(self, path_str: str, findings: List[Finding]) -> None:
        """Inspect file paths for traversal and sensitive file access."""
        if not path_str:
            return

        # Check path traversal
        if self.block_path_traversal and self.PATH_TRAVERSAL_PATTERN.search(path_str):
            findings.append(
                Finding(
                    rule="path_traversal_detected",
                    severity=Severity.CRITICAL,
                    snippet=path_str[:60],
                    category=ThreatCategory.TOOL_ABUSE,
                    description="Path traversal syntax ('..') detected in file parameter",
                )
            )

        # Check sensitive file targets
        if self.SENSITIVE_FILES_PATTERN.search(path_str):
            findings.append(
                Finding(
                    rule="sensitive_file_read_attempt",
                    severity=Severity.CRITICAL,
                    snippet=path_str[:60],
                    category=ThreatCategory.DATA_EXFILTRATION,
                    description="Attempt to read sensitive operating system or configuration file",
                )
            )

        # Check directory confinement
        try:
            p = Path(path_str).as_posix().lower()
            if p.startswith("/") or re.match(r"^[a-z]:", p):
                # Absolute path attempt
                findings.append(
                    Finding(
                        rule="absolute_path_escape",
                        severity=Severity.HIGH,
                        snippet=path_str[:60],
                        category=ThreatCategory.TOOL_ABUSE,
                        description="Absolute file path supplied; must be confined to allowed directories",
                    )
                )
        except Exception:
            pass

    def _validate_sql_query(self, query_str: str, findings: List[Finding]) -> None:
        """Inspect SQL queries for destructive operations and injection constructs."""
        if not query_str or not self.block_dangerous_sql:
            return

        for rule, pattern, severity, desc in self.SQLI_PATTERNS:
            match = pattern.search(query_str)
            if match:
                findings.append(
                    Finding(
                        rule=rule,
                        severity=severity,
                        snippet=match.group(0)[:50],
                        category=ThreatCategory.TOOL_ABUSE,
                        description=desc,
                    )
                )

    def _validate_web_search(self, query_str: str, findings: List[Finding]) -> None:
        """Inspect web queries for SSRF attempts against internal addresses."""
        if self.SSRF_PATTERN.search(query_str):
            findings.append(
                Finding(
                    rule="ssrf_internal_target",
                    severity=Severity.CRITICAL,
                    snippet=query_str[:60],
                    category=ThreatCategory.DATA_EXFILTRATION,
                    description="Target query points to internal loopback, metadata, or private IP address",
                )
            )


_DEFAULT_TOOL_GUARD = ToolGuard()


def validate_tool_call(tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """Inspect tool execution request and validate parameters."""
    res = _DEFAULT_TOOL_GUARD.validate_tool_call(tool_name, parameters)
    return {
        "blocked": res.blocked,
        "risk_score": res.risk_score,
        "risk_level": res.risk_level.value,
        "findings": [f.to_dict() for f in res.findings],
        "latency_ms": res.latency_ms,
    }