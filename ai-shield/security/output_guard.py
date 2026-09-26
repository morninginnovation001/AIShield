"""
Output Guard: Sensitive Information and Secret Leakage Guardrail.
Detects, redacts, or blocks PII and confidential secrets in LLM-generated responses.
"""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Pattern, Tuple

from .risk_engine import Finding, GuardResult, RiskEngine, Severity, ThreatCategory


class OutputGuard:
    """Scans and redacts sensitive data (PII, credentials, API keys) from model responses."""

    _PATTERNS: List[Tuple[str, Severity, Pattern, ThreatCategory, str]] = [
        # Secrets and Credentials
        (
            "aws_access_key",
            Severity.CRITICAL,
            re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
            ThreatCategory.SENSITIVE_LEAKAGE,
            "AWS Access Key ID disclosure",
        ),
        (
            "generic_api_key",
            Severity.CRITICAL,
            re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b|\b(?:sk|pk|ghp|gho|ghu|glpat|xox[bap]|npm_[A-Za-z0-9])[-_][A-Za-z0-9]{16,}\b"),
            ThreatCategory.SENSITIVE_LEAKAGE,
            "Developer API key disclosure (OpenAI/GitHub/Slack)",
        ),
        (
            "bearer_token",
            Severity.HIGH,
            re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]{20,}=*\b", re.I),
            ThreatCategory.SENSITIVE_LEAKAGE,
            "HTTP Bearer authorization token disclosure",
        ),
        (
            "private_key_block",
            Severity.CRITICAL,
            re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
            ThreatCategory.SENSITIVE_LEAKAGE,
            "Cryptographic private key block disclosure",
        ),
        (
            "database_connection_uri",
            Severity.HIGH,
            re.compile(r"\b(?:postgres|mysql|mongodb|redis|mssql):\/\/[A-Za-z0-9_\-\.]+:[^@\s]+@[A-Za-z0-9_\-\.]+(?::\d+)?\/[A-Za-z0-9_\-\.]*\b", re.I),
            ThreatCategory.SENSITIVE_LEAKAGE,
            "Database connection string with credentials",
        ),
        (
            "env_credential_assignment",
            Severity.HIGH,
            re.compile(r"\b(?:PASSWORD|SECRET_KEY|DB_PASS|AUTH_TOKEN)\s*=\s*['\"][^'\"]{6,}['\"]", re.I),
            ThreatCategory.SENSITIVE_LEAKAGE,
            "Environment configuration secret disclosure",
        ),

        # Personally Identifiable Information (PII)
        (
            "ssn",
            Severity.CRITICAL,
            re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
            ThreatCategory.SENSITIVE_LEAKAGE,
            "US Social Security Number disclosure",
        ),
        (
            "credit_card",
            Severity.CRITICAL,
            re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b|\b3[47]\d{13}\b"),
            ThreatCategory.SENSITIVE_LEAKAGE,
            "Credit card number disclosure",
        ),
        (
            "email",
            Severity.MEDIUM,
            re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
            ThreatCategory.SENSITIVE_LEAKAGE,
            "Email address disclosure",
        ),
        (
            "phone_number",
            Severity.LOW,
            re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
            ThreatCategory.SENSITIVE_LEAKAGE,
            "Phone number disclosure",
        ),
    ]

    def __init__(self, risk_engine: Optional[RiskEngine] = None,
                 redact: bool = True,
                 block_on_critical: bool = True,
                 mask_template: str = "[REDACTED:{label}]"):
        self.risk_engine = risk_engine or RiskEngine()
        self.redact = redact
        self.block_on_critical = block_on_critical
        self.mask_template = mask_template

    def scan(self, text: str) -> GuardResult:
        """Scan generated output for secrets and PII, masking detected matches."""
        start_time = time.perf_counter()
        findings: List[Finding] = []
        cleaned = text or ""

        for label, severity, pattern, category, desc in self._PATTERNS:
            def _mask_handler(match: re.Match) -> str:
                snippet = match.group(0)
                snippet_preview = snippet[:8] + "..." if len(snippet) > 8 else snippet
                findings.append(
                    Finding(
                        rule=label,
                        severity=severity,
                        snippet=snippet_preview,
                        category=category,
                        description=desc,
                    )
                )
                return self.mask_template.format(label=label.upper())

            if self.redact:
                cleaned = pattern.sub(_mask_handler, cleaned)
            else:
                for match in pattern.finditer(cleaned):
                    snippet = match.group(0)
                    findings.append(
                        Finding(
                            rule=label,
                            severity=severity,
                            snippet=snippet[:8] + "...",
                            category=category,
                            description=desc,
                        )
                    )

        # Determine if output must be hard-blocked
        has_critical = any(f.severity == Severity.CRITICAL for f in findings)
        block_decision = self.block_on_critical and has_critical

        result = self.risk_engine.evaluate_stage(
            stage_name="output_guard",
            findings=findings,
            sanitized_text="[Security Alert: Response blocked due to sensitive secret leakage]" if block_decision else cleaned,
            start_time=start_time,
            block_condition=block_decision,
            metadata={"original_length": len(text or ""), "redacted_count": len(findings)},
        )
        return result


_DEFAULT_OUTPUT_GUARD = OutputGuard()


def scan_output(text: str, redact: bool = True) -> Dict[str, Any]:
    """Inspect model output for sensitive data leaks."""
    res = _DEFAULT_OUTPUT_GUARD.scan(text)
    return {
        "blocked": res.blocked,
        "risk_score": res.risk_score,
        "risk_level": res.risk_level.value,
        "sanitized_output": res.sanitized_text,
        "findings": [f.to_dict() for f in res.findings],
        "latency_ms": res.latency_ms,
    }