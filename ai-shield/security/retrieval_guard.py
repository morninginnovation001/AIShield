"""
Retrieval Guard: Indirect Prompt Injection and Context Poisoning Guardrail.
Scans and sanitizes documents retrieved from the vector database/search before prompt assembly.
"""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from .risk_engine import Finding, GuardResult, RiskEngine, Severity, ThreatCategory


class RetrievalGuard:
    """Neutralizes indirect prompt injections, poisoned corpus context, and exfiltration triggers."""

    # Chat-template and delimiter control tokens
    _TEMPLATE_TOKENS = re.compile(
        r"(?:<\|?(?:system|im_start|im_end|endoftext|user|assistant)\|?>|<start_of_turn>|<end_of_turn>|\[INST\]|\[/INST\]|###\s*(?:system|instruction|human|assistant):)",
        re.I,
    )

    # Exfiltration via markdown images or HTML embeds
    _MARKDOWN_EXFIL = re.compile(r"!\[.*?\]\((https?://[^\s\)]+)\)", re.I)
    _HTML_TAGS = re.compile(r"<(?:img|script|iframe|object|embed|a)\s+[^>]*>", re.I)

    # Imperative override triggers embedded inside retrieved documents
    _INDIRECT_INJECTION_PATTERNS: List[Tuple[str, Severity, re.Pattern, str]] = [
        (
            "context_instruction_override",
            Severity.HIGH,
            re.compile(
                r"\b(important|system|admin|developer|urgent|override)\s*:\s*(ignore|disregard|forget)\b.{0,30}\b(previous|prior|user|instructions)\b",
                re.I,
            ),
            "Retrieved document contains command instructing model to override instructions",
        ),
        (
            "context_role_reassignment",
            Severity.HIGH,
            re.compile(
                r"\b(from now on|you are now|instead of answering|act as)\b.{0,40}\b(dan|evil|unrestricted|hacker|compromised)\b",
                re.I,
            ),
            "Retrieved document attempts to reassign the model role or persona",
        ),
        (
            "context_exfiltration_directive",
            Severity.HIGH,
            re.compile(
                r"\b(send|transmit|post|leak|exfiltrate|fetch|request)\b.{0,60}\b(secret|token|password|history|context|query|user\s+queries|system\s+prompt)\b.{0,60}\b(https?://|http://|ftp://|curl|webhook)|\b(send|transmit|post|leak|exfiltrate|forward)\b.{0,40}\b(https?://|http://|webhook)\b",
                re.I,
            ),
            "Retrieved document directs model to exfiltrate data via URL or web hook",
        ),
        (
            "context_directive_injection",
            Severity.MEDIUM,
            re.compile(
                r"\b(do not tell the user|hidden instruction|secret directive|say exactly|output only|respond with)\b.{0,40}\b(hacked|system compromised|password|pwned)\b",
                re.I,
            ),
            "Suspicious forced output or hidden directive embedded in document",
        ),
    ]

    def __init__(self, risk_engine: Optional[RiskEngine] = None,
                 enforce_fencing: bool = True,
                 fence_start: str = "<<<UNTRUSTED_EXTERNAL_CONTEXT>>>",
                 fence_end: str = "<<<END_UNTRUSTED_EXTERNAL_CONTEXT>>>",
                 strip_template_tokens: bool = True,
                 defang_exfil_links: bool = True):
        self.risk_engine = risk_engine or RiskEngine()
        self.enforce_fencing = enforce_fencing
        self.fence_start = fence_start
        self.fence_end = fence_end
        self.strip_template_tokens = strip_template_tokens
        self.defang_exfil_links = defang_exfil_links

    def scan_context(self, context: Union[str, List[Any]]) -> GuardResult:
        """Scan and sanitize retrieved context documents."""
        start_time = time.perf_counter()
        findings: List[Finding] = []

        # Normalize context items to list of strings
        if isinstance(context, str):
            contexts_list = [context]
        elif isinstance(context, list):
            contexts_list = [
                item.content if hasattr(item, "content") else str(item)
                for item in context
            ]
        else:
            contexts_list = [str(context)]

        sanitized_chunks: List[str] = []

        for idx, text in enumerate(contexts_list):
            chunk = text or ""
            cleaned = chunk

            # 1. Check for control and template tokens
            if self._TEMPLATE_TOKENS.search(cleaned):
                findings.append(
                    Finding(
                        rule="embedded_template_token",
                        severity=Severity.HIGH,
                        snippet="Control delimiters found in retrieved context",
                        category=ThreatCategory.CONTEXT_POISONING,
                        description=f"Context chunk {idx + 1} contains LLM control delimiters",
                    )
                )
                if self.strip_template_tokens:
                    cleaned = self._TEMPLATE_TOKENS.sub(" [STRIPPED_TOKEN] ", cleaned)

            # 2. Check for exfiltration links
            if self._MARKDOWN_EXFIL.search(cleaned) or self._HTML_TAGS.search(cleaned):
                findings.append(
                    Finding(
                        rule="exfiltration_markdown_link",
                        severity=Severity.HIGH,
                        snippet="Markdown/HTML image or link capable of exfiltration",
                        category=ThreatCategory.DATA_EXFILTRATION,
                        description=f"Context chunk {idx + 1} contains potential exfiltration links",
                    )
                )
                if self.defang_exfil_links:
                    cleaned = self._MARKDOWN_EXFIL.sub("[DEFANGED_IMAGE_LINK]", cleaned)
                    cleaned = self._HTML_TAGS.sub("[DEFANGED_HTML_TAG]", cleaned)

            # 3. Check for indirect injection patterns
            for rule, severity, pattern, desc in self._INDIRECT_INJECTION_PATTERNS:
                match = pattern.search(cleaned)
                if match:
                    snippet = match.group(0).strip()[:100]
                    findings.append(
                        Finding(
                            rule=rule,
                            severity=severity,
                            snippet=snippet,
                            category=ThreatCategory.CONTEXT_POISONING,
                            description=f"{desc} (chunk {idx + 1})",
                        )
                    )

            sanitized_chunks.append(cleaned)

        # 4. Enforce strict data fencing
        combined_cleaned = "\n\n".join(sanitized_chunks).strip()
        if self.enforce_fencing and combined_cleaned:
            final_sanitized = f"{self.fence_start}\n{combined_cleaned}\n{self.fence_end}"
        else:
            final_sanitized = combined_cleaned

        # Deduplicate findings
        seen = set()
        deduped: List[Finding] = []
        for f in findings:
            key = (f.rule, f.snippet)
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        return self.risk_engine.evaluate_stage(
            stage_name="retrieval_guard",
            findings=deduped,
            sanitized_text=final_sanitized,
            start_time=start_time,
            metadata={
                "original_chunks_count": len(contexts_list),
                "sanitized_chunks": sanitized_chunks,
            },
        )


# Functional convenience wrappers
_DEFAULT_RETRIEVAL_GUARD = RetrievalGuard()


def check_retrieval(context: Union[str, List[Any]]) -> Dict[str, Any]:
    """Inspect and sanitize retrieved contexts."""
    res = _DEFAULT_RETRIEVAL_GUARD.scan_context(context)
    return {
        "blocked": res.blocked,
        "risk_score": res.risk_score,
        "risk_level": res.risk_level.value,
        "sanitized_text": res.sanitized_text,
        "sanitized_chunks": res.metadata.get("sanitized_chunks", []),
        "findings": [f.to_dict() for f in res.findings],
        "latency_ms": res.latency_ms,
    }