"""
Risk Engine for AIShield
Calculates multi-dimensional risk scores, threat categories, and policy enforcement decisions.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskLevel(str, Enum):
    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    CONTEXT_POISONING = "context_poisoning"
    DATA_EXFILTRATION = "data_exfiltration"
    TOOL_ABUSE = "tool_abuse"
    SENSITIVE_LEAKAGE = "sensitive_leakage"
    SYSTEM_BYPASS = "system_bypass"
    BENIGN = "benign"


@dataclass(frozen=True)
class Finding:
    """A single security finding identified by a guardrail."""
    rule: str
    severity: Severity
    snippet: str
    category: ThreatCategory = ThreatCategory.PROMPT_INJECTION
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity.value,
            "snippet": self.snippet,
            "category": self.category.value,
            "description": self.description or self.rule.replace("_", " ").title(),
        }

    def __str__(self) -> str:
        return f"[{self.severity.value.upper()}] ({self.category.value}) {self.rule}: {self.snippet!r}"


@dataclass
class GuardResult:
    """The result of executing a guardrail stage."""
    blocked: bool = False
    risk_score: int = 0
    risk_level: RiskLevel = RiskLevel.CLEAN
    findings: List[Finding] = field(default_factory=list)
    sanitized_text: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "blocked": self.blocked,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "findings": [f.to_dict() for f in self.findings],
            "sanitized_text": self.sanitized_text,
            "metadata": self.metadata,
            "latency_ms": round(self.latency_ms, 2),
        }


@dataclass
class PipelineRiskReport:
    """Composite risk report across all AIShield guardrail stages."""
    overall_risk_score: int = 0
    overall_risk_level: RiskLevel = RiskLevel.CLEAN
    blocked: bool = False
    blocking_stage: Optional[str] = None
    action_taken: str = "ALLOWED"  # ALLOWED, BLOCKED, SANITIZED
    reasons: List[str] = field(default_factory=list)
    stage_results: Dict[str, GuardResult] = field(default_factory=dict)
    total_latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_risk_score": self.overall_risk_score,
            "overall_risk_level": self.overall_risk_level.value,
            "blocked": self.blocked,
            "blocking_stage": self.blocking_stage,
            "action_taken": self.action_taken,
            "reasons": self.reasons,
            "stage_results": {k: v.to_dict() for k, v in self.stage_results.items()},
            "total_latency_ms": round(self.total_latency_ms, 2),
        }


class RiskEngine:
    """Calculates risk levels, enforces security thresholds, and aggregates findings."""

    DEFAULT_WEIGHTS = {
        Severity.LOW: 10,
        Severity.MEDIUM: 25,
        Severity.HIGH: 50,
        Severity.CRITICAL: 90,
    }

    def __init__(self, block_threshold: int = 50, warn_threshold: int = 25,
                 weights: Optional[Dict[Severity, int]] = None):
        self.block_threshold = block_threshold
        self.warn_threshold = warn_threshold
        self.weights = weights or self.DEFAULT_WEIGHTS.copy()

    def score_findings(self, findings: List[Finding]) -> Tuple[int, RiskLevel]:
        """Compute aggregate risk score and corresponding risk level from findings."""
        if not findings:
            return 0, RiskLevel.CLEAN

        total_weight = sum(self.weights.get(f.severity, 20) for f in findings)
        score = min(100, total_weight)

        if any(f.severity == Severity.CRITICAL for f in findings) or score >= 80:
            level = RiskLevel.CRITICAL
        elif any(f.severity == Severity.HIGH for f in findings) or score >= 50:
            level = RiskLevel.HIGH
        elif score >= self.warn_threshold:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW

        return score, level

    def evaluate_stage(self, stage_name: str, findings: List[Finding],
                       sanitized_text: str = "", start_time: Optional[float] = None,
                       block_condition: Optional[bool] = None,
                       metadata: Optional[Dict[str, Any]] = None) -> GuardResult:
        """Create a GuardResult for a stage, computing risk score and blocking decision."""
        latency_ms = (time.perf_counter() - start_time) * 1000 if start_time else 0.0
        risk_score, risk_level = self.score_findings(findings)

        # Block if explicitly conditioned, or if risk score reaches threshold, or if critical
        if block_condition is not None:
            blocked = block_condition
        else:
            blocked = (
                risk_score >= self.block_threshold or
                any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)
            )

        return GuardResult(
            blocked=blocked,
            risk_score=risk_score,
            risk_level=risk_level,
            findings=findings,
            sanitized_text=sanitized_text,
            metadata=metadata or {},
            latency_ms=latency_ms,
        )

    def aggregate_pipeline(self, stage_results: Dict[str, GuardResult],
                           total_latency_ms: float = 0.0) -> PipelineRiskReport:
        """Combine all stages into a single comprehensive PipelineRiskReport."""
        all_findings: List[Finding] = []
        blocking_stage: Optional[str] = None
        blocked = False
        reasons: List[str] = []

        for stage, res in stage_results.items():
            all_findings.extend(res.findings)
            if res.blocked and not blocked:
                blocked = True
                blocking_stage = stage
                for f in res.findings:
                    if f.severity in (Severity.HIGH, Severity.CRITICAL):
                        reasons.append(f"[{stage.upper()}] {f.rule}: {f.description or f.snippet}")

        overall_score, overall_level = self.score_findings(all_findings)

        if blocked:
            action_taken = "BLOCKED"
        elif any(res.sanitized_text != res.metadata.get("original_text", res.sanitized_text)
                 for res in stage_results.values() if "original_text" in res.metadata):
            action_taken = "SANITIZED"
        elif overall_score >= self.warn_threshold:
            action_taken = "SANITIZED"
        else:
            action_taken = "ALLOWED"

        return PipelineRiskReport(
            overall_risk_score=overall_score,
            overall_risk_level=overall_level,
            blocked=blocked,
            blocking_stage=blocking_stage,
            action_taken=action_taken,
            reasons=reasons,
            stage_results=stage_results,
            total_latency_ms=total_latency_ms,
        )
