"""
Input Guard: Direct Prompt Injection and Jailbreak Guardrail.
Inspects incoming user queries before they reach the RAG retriever or model.
"""

from __future__ import annotations

import base64
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .risk_engine import Finding, GuardResult, RiskEngine, Severity, ThreatCategory


class InputGuard:
    """Detects direct prompt injection, jailbreak attempts, and system prompt exfiltration."""

    # Heuristic detection patterns: (rule_name, severity, pattern, category, description)
    _PATTERNS: List[Tuple[str, Severity, re.Pattern, ThreatCategory, str]] = [
        (
            "ignore_instructions",
            Severity.HIGH,
            re.compile(
                r"\b(ignore|disregard|forget|bypass|override|drop|cancel)\b.{0,40}\b(previous|prior|earlier|all|above|system|developer)\b.{0,30}\b(instruction|prompt|rule|constraint|directive|guide)",
                re.I | re.S,
            ),
            ThreatCategory.PROMPT_INJECTION,
            "Attempt to override or disregard prior instructions",
        ),
        (
            "reveal_system_prompt",
            Severity.HIGH,
            re.compile(
                r"\b(reveal|show|print|repeat|output|leak|display|echo|disclose)\b.{0,35}\b(system|developer|hidden|initial|base|confidential)\b.{0,25}\b(prompt|instruction|message|directive|rule|text)",
                re.I | re.S,
            ),
            ThreatCategory.PROMPT_INJECTION,
            "Attempt to extract hidden system instructions or prompt",
        ),
        (
            "roleplay_jailbreak",
            Severity.HIGH,
            re.compile(
                r"\b(you are now|act as|pretend to be|roleplay as|from now on you are|simulate)\b.{0,45}\b(dan|jailbreak|unfiltered|unrestricted|god mode|developer mode|chaos|evil|anarchist|do anything now)",
                re.I,
            ),
            ThreatCategory.PROMPT_INJECTION,
            "Jailbreak persona or unrestricted roleplay attempt",
        ),
        (
            "exfiltrate_secrets_probe",
            Severity.HIGH,
            re.compile(
                r"\b(print|reveal|show|leak|give me|tell me|extract)\b.{0,30}\b(api[_\s-]?key|secret|password|token|credential|env|environment variable|private key|database password)",
                re.I,
            ),
            ThreatCategory.DATA_EXFILTRATION,
            "Direct query seeking credential or secret exfiltration",
        ),
        (
            "chat_template_delimiter",
            Severity.HIGH,
            re.compile(
                r"(?:<\|?(?:system|im_start|im_end|endoftext|user|assistant)\|?>|<start_of_turn>|<end_of_turn>|\[INST\]|\[/INST\]|###\s*(?:system|instruction|human|assistant):)",
                re.I,
            ),
            ThreatCategory.SYSTEM_BYPASS,
            "Attempt to inject raw chat template control delimiters",
        ),
        (
            "jailbreak_keyword_marker",
            Severity.MEDIUM,
            re.compile(
                r"\b(jailbreak|bypass filters|disable safety|unrestricted mode|no moral constraints|do anything now|aim mode|anti-gpt)\b",
                re.I,
            ),
            ThreatCategory.PROMPT_INJECTION,
            "Common jailbreak signature keywords detected",
        ),
        (
            "hypothetical_override",
            Severity.MEDIUM,
            re.compile(
                r"\b(in a hypothetical world|hypothetically speaking|purely fictionally|for educational purposes only).{0,50}\b(ignore rules|no laws|bypass restrictions|no morals|unfiltered)\b",
                re.I,
            ),
            ThreatCategory.PROMPT_INJECTION,
            "Hypothetical framing used to circumvent safety policies",
        ),
        (
            "instruction_boundary_smuggle",
            Severity.MEDIUM,
            re.compile(
                r"\b(new system directive|admin override:|system update:|new instructions follow:|real prompt:)\b",
                re.I,
            ),
            ThreatCategory.SYSTEM_BYPASS,
            "Faux system header or delimiter to smuggle new directives",
        ),
        (
            "repeat_above_context",
            Severity.MEDIUM,
            re.compile(
                r"\b(repeat|echo|verbatim)\b.{0,30}\b(everything|all text|words)\b.{0,20}\b(above|before this|starting with)\b",
                re.I,
            ),
            ThreatCategory.DATA_EXFILTRATION,
            "Prompt leakage attempt via verbatim repetition request",
        ),
    ]

    # Regex for detecting potential Base64 encoded payload blocks
    _BASE64_PATTERN = re.compile(r"(?:[A-Za-z0-9+/]{28,}={0,2})")

    def __init__(self, risk_engine: Optional[RiskEngine] = None,
                 scan_base64: bool = True,
                 max_input_length: int = 4096):
        self.risk_engine = risk_engine or RiskEngine()
        self.scan_base64 = scan_base64
        self.max_input_length = max_input_length

    def scan(self, text: str) -> GuardResult:
        """Scan input query for prompt injections, delimiters, and obfuscated payloads."""
        start_time = time.perf_counter()
        findings: List[Finding] = []
        raw_text = text or ""

        # Check for length anomaly (buffer overflow / context stuffing attempt)
        if len(raw_text) > self.max_input_length:
            findings.append(
                Finding(
                    rule="input_length_anomaly",
                    severity=Severity.MEDIUM,
                    snippet=f"Length {len(raw_text)} chars > {self.max_input_length}",
                    category=ThreatCategory.SYSTEM_BYPASS,
                    description=f"Input exceeds maximum allowed length ({self.max_input_length} chars)",
                )
            )

        # 1. Primary Regex Pattern Matching
        for rule, severity, pattern, category, description in self._PATTERNS:
            match = pattern.search(raw_text)
            if match:
                snippet = match.group(0).strip()[:100]
                findings.append(
                    Finding(
                        rule=rule,
                        severity=severity,
                        snippet=snippet,
                        category=category,
                        description=description,
                    )
                )

        # 2. Obfuscation & Base64 Decoding Check
        if self.scan_base64:
            b64_findings = self._check_base64_payloads(raw_text)
            findings.extend(b64_findings)

        # 3. Leetspeak / Spaced text normalization check
        normalized_findings = self._check_normalized_injections(raw_text)
        findings.extend(normalized_findings)

        # Deduplicate findings by rule
        seen_rules = set()
        deduped_findings: List[Finding] = []
        for f in findings:
            if f.rule not in seen_rules:
                seen_rules.add(f.rule)
                deduped_findings.append(f)

        return self.risk_engine.evaluate_stage(
            stage_name="input_guard",
            findings=deduped_findings,
            sanitized_text=raw_text,
            start_time=start_time,
            metadata={"original_text": raw_text, "char_count": len(raw_text)},
        )

    def _check_base64_payloads(self, text: str) -> List[Finding]:
        """Detect and decode Base64 strings to check for hidden injection commands."""
        findings: List[Finding] = []
        for match in self._BASE64_PATTERN.finditer(text):
            candidate = match.group(0)
            try:
                decoded_bytes = base64.b64decode(candidate, validate=True)
                decoded_str = decoded_bytes.decode("utf-8", errors="ignore").strip()
                if len(decoded_str) >= 10:
                    for rule, severity, pattern, category, description in self._PATTERNS:
                        if pattern.search(decoded_str):
                            findings.append(
                                Finding(
                                    rule=f"base64_{rule}",
                                    severity=Severity.HIGH,
                                    snippet=f"Decoded: '{decoded_str[:60]}...'",
                                    category=ThreatCategory.PROMPT_INJECTION,
                                    description=f"Base64 encoded injection payload: {description}",
                                )
                            )
                            break
            except Exception:
                continue
        return findings

    def _check_normalized_injections(self, text: str) -> List[Finding]:
        """Detect injections disguised by extra spacing or leetspeak."""
        findings: List[Finding] = []
        raw_lower = text.lower()
        
        # 1. Handle double-spaced word separation (e.g., 'i g n o r e  a l l')
        temp = re.sub(r"\s{2,}", " <WSEP> ", raw_lower)
        collapsed_words = re.sub(r"(?<=\b[a-z])\s+(?=[a-z]\b)", "", temp).replace(" <WSEP> ", " ")
        
        # 2. Fully stripped whitespace
        no_spaces = re.sub(r"\s+", "", raw_lower)

        for candidate in [collapsed_words, no_spaces]:
            if candidate != raw_lower:
                for rule, severity, pattern, category, description in self._PATTERNS:
                    if pattern.search(candidate):
                        findings.append(
                            Finding(
                                rule=f"obfuscated_{rule}",
                                severity=Severity.HIGH,
                                snippet=f"Normalized: '{candidate[:60]}...'",
                                category=category,
                                description=f"Evasion attempt with character spacing/obfuscation: {description}",
                            )
                        )
                        return findings
                        
                # Also check direct concatenated keyword match (e.g. ignoreallprevious)
                if re.search(r"(?:ignore|disregard|forget).{0,25}(?:previous|prior|all).{0,25}(?:instruction|prompt|rule)", candidate):
                    findings.append(
                        Finding(
                            rule="obfuscated_ignore_instructions",
                            severity=Severity.HIGH,
                            snippet=f"Normalized: '{candidate[:60]}...'",
                            category=ThreatCategory.PROMPT_INJECTION,
                            description="Evasion attempt with character spacing to override instructions",
                        )
                    )
                    return findings

        return findings


# Backwards compatibility helper function
_DEFAULT_GUARD = InputGuard()


def check_input(text: str) -> Dict[str, Any]:
    """Inspect user input query and return security assessment."""
    res = _DEFAULT_GUARD.scan(text)
    return {
        "blocked": res.blocked,
        "risk_score": res.risk_score,
        "risk_level": res.risk_level.value,
        "findings": [f.snippet for f in res.findings],
        "finding_objects": [f.to_dict() for f in res.findings],
        "latency_ms": res.latency_ms,
    }