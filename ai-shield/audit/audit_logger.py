"""
Audit Logger for AIShield
Provides thread-safe structured JSONL security event logging, querying, and metrics aggregation.
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

try:
    from security.risk_engine import GuardResult, PipelineRiskReport
except (ImportError, ValueError):
    try:
        from ..security.risk_engine import GuardResult, PipelineRiskReport
    except (ImportError, ValueError):
        # Fallback when running from root as module
        from ai_shield.security.risk_engine import GuardResult, PipelineRiskReport


class AuditLogger:
    """Thread-safe event logger for AIShield security audits."""

    def __init__(self, log_file: Optional[Union[str, Path]] = None, max_snippet_len: int = 200):
        if log_file is None:
            # Default to ai-shield/audit/events.jsonl relative to this file
            current_dir = Path(__file__).resolve().parent
            self.log_file = current_dir / "events.jsonl"
        else:
            self.log_file = Path(log_file)

        self.max_snippet_len = max_snippet_len
        self._lock = threading.Lock()

        # Ensure parent directory exists
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        # Touch file if it doesn't exist
        if not self.log_file.exists():
            self.log_file.touch()

    def log_event(self, stage: str, action: str, risk_score: int,
                  risk_level: str, findings: List[Dict[str, Any]],
                  query: str = "", sanitized_text: str = "",
                  session_id: Optional[str] = None,
                  latency_ms: float = 0.0,
                  metadata: Optional[Dict[str, Any]] = None,
                  request_id: Optional[str] = None,
                  attack_type: Optional[str] = None,
                  reason: Optional[str] = None,
                  source: Optional[str] = None) -> Dict[str, Any]:
        """Record an individual security decision event into events.jsonl."""
        event_id = f"EVT-{uuid.uuid4().hex[:8].upper()}"
        req_id = request_id or f"REQ-{uuid.uuid4().hex[:6].upper()}"
        now = datetime.now().astimezone()
        now_iso = now.isoformat()
        local_time_str = now.strftime("%H:%M:%S")

        snippet = (query or "").strip()
        if len(snippet) > self.max_snippet_len:
            snippet = snippet[:self.max_snippet_len] + "..."

        # Determine readable attack type
        if not attack_type:
            if findings:
                cat = findings[0].get("category", "")
                rule = findings[0].get("rule", "")
                if "indirect" in cat or "context" in cat or "template" in rule:
                    attack_type = "Indirect Prompt Injection"
                elif "tool" in cat or "path" in rule or "sql" in rule:
                    attack_type = "Tool Injection"
                elif "sensitive" in cat or "key" in rule or "secret" in rule or "ssn" in rule:
                    attack_type = "Secret Leakage"
                elif "bypass" in cat:
                    attack_type = "System Bypass"
                else:
                    attack_type = "Direct Prompt Injection"
            else:
                attack_type = "Normal Request"

        # Determine evidence
        evidence = findings[0].get("snippet", "") if findings else "Clean input; no rules triggered"

        # Determine default reason
        if not reason:
            if findings:
                reason = findings[0].get("description") or f"Violated rule {findings[0].get('rule')}"
            else:
                reason = "Request verified safe against all active guardrails."

        # Determine default source
        if not source:
            stage_l = stage.lower()
            if "retriev" in stage_l:
                source = "retrieved_document"
            elif "output" in stage_l:
                source = "llm_output"
            elif "tool" in stage_l:
                source = "agent_tool"
            else:
                source = "user"

        event_record = {
            "event_id": event_id,
            "timestamp": now_iso,
            "local_time": local_time_str,
            "request_id": req_id,
            "attack_type": attack_type,
            "stage": stage.upper(),
            "severity": risk_level.upper(),
            "risk_score": risk_score,
            "risk_level": risk_level.lower(),
            "action": action.upper(),
            "reason": reason,
            "evidence": evidence,
            "source": source,
            "query_snippet": snippet,
            "findings_count": len(findings),
            "findings": findings,
            "sanitized_snippet": (sanitized_text[:self.max_snippet_len] + "...") if len(sanitized_text) > self.max_snippet_len else sanitized_text,
            "session_id": session_id or "default_session",
            "latency_ms": round(latency_ms, 2),
            "metadata": metadata or {},
        }

        with self._lock:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(event_record) + "\n")

        return event_record

    def log_pipeline_report(self, query: str, report: PipelineRiskReport,
                            final_output: str = "", session_id: Optional[str] = None) -> Dict[str, Any]:
        """Record the complete lifecycle risk report for a request."""
        all_findings = []
        for stage_name, res in report.stage_results.items():
            for f in res.findings:
                finding_dict = f.to_dict()
                finding_dict["stage"] = stage_name
                all_findings.append(finding_dict)

        # Primary stage where action occurred
        primary_stage = report.blocking_stage.upper() if report.blocking_stage else "PIPELINE_ORCHESTRATION"
        
        # Primary reason
        primary_reason = report.reasons[0] if report.reasons else (
            "Request validated safe by all active guardrails" if not report.blocked else "Security violation detected"
        )

        return self.log_event(
            stage=primary_stage,
            action=report.action_taken,
            risk_score=report.overall_risk_score,
            risk_level=report.overall_risk_level.value,
            findings=all_findings,
            query=query,
            sanitized_text=final_output,
            session_id=session_id,
            latency_ms=report.total_latency_ms,
            reason=primary_reason,
            metadata={
                "blocking_stage": report.blocking_stage,
                "reasons": report.reasons,
                "stages_evaluated": list(report.stage_results.keys()),
            },
        )

    def get_recent_events(self, limit: int = 50, stage: Optional[str] = None,
                          action: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve recent security audit events with optional filtering."""
        if not self.log_file.exists():
            return []

        events: List[Dict[str, Any]] = []
        with self._lock:
            with open(self.log_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        if stage and record.get("stage") != stage.upper():
                            continue
                        if action and record.get("action") != action.upper():
                            continue
                        events.append(record)
                    except Exception:
                        continue

        # Return latest first
        return events[::-1][:limit]

    def get_statistics(self) -> Dict[str, Any]:
        """Compute aggregate metrics and summary counts from logged events."""
        default_stats = {
            "total_events": 0,
            "threats_detected": 0,
            "requests_blocked": 0,
            "content_sanitized": 0,
            "secrets_redacted": 0,
            "allowed_count": 0,
            "block_rate_percent": 0.0,
            "bypass_rate_percent": 0.0,
            "avg_risk_score": 0.0,
            "top_triggered_rules": {},
            "risk_distribution": {"clean": 0, "low": 0, "medium": 0, "high": 0, "critical": 0},
            "threat_distribution": {
                "Prompt Injection": 0,
                "Indirect RAG Injection": 0,
                "Corpus Poisoning": 0,
                "Secret Leakage": 0,
                "Tool Injection": 0,
                "System Bypass": 0,
            },
            "pipeline_stages": {
                "INPUT GUARD": {"total": 0, "blocked": 0, "status": "ACTIVE"},
                "RAG RETRIEVAL": {"total": 0, "status": "ACTIVE"},
                "RETRIEVAL GUARD": {"total": 0, "sanitized": 0, "blocked": 0, "status": "ACTIVE"},
                "TOOL GUARD": {"total": 0, "blocked": 0, "status": "ACTIVE"},
                "OUTPUT GUARD": {"total": 0, "redacted": 0, "blocked": 0, "status": "ACTIVE"},
            }
        }

        if not self.log_file.exists():
            return default_stats

        total_events = 0
        threats_detected = 0
        blocked_count = 0
        sanitized_count = 0
        secrets_redacted = 0
        allowed_count = 0
        total_risk = 0
        rule_counts: Dict[str, int] = {}
        risk_dist = {"clean": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
        threat_dist = default_stats["threat_distribution"].copy()
        stages = default_stats["pipeline_stages"]

        with self._lock:
            with open(self.log_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                        total_events += 1
                        action = ev.get("action", "ALLOWED").upper()
                        risk_score = ev.get("risk_score", 0)
                        total_risk += risk_score

                        level = ev.get("risk_level", "clean").lower()
                        if level in risk_dist:
                            risk_dist[level] += 1

                        if action == "BLOCKED":
                            blocked_count += 1
                            threats_detected += 1
                        elif action in ("SANITIZED", "REDACTED"):
                            sanitized_count += 1
                            threats_detected += 1
                        elif risk_score >= 25 or ev.get("findings_count", 0) > 0:
                            threats_detected += 1
                        else:
                            allowed_count += 1

                        # Track threat categories
                        att_type = ev.get("attack_type", "")
                        for threat_key in threat_dist.keys():
                            if threat_key.lower() in att_type.lower():
                                threat_dist[threat_key] += 1

                        # Stage-specific counting
                        stage_name = ev.get("stage", "").upper()
                        if "INPUT" in stage_name:
                            stages["INPUT GUARD"]["total"] += 1
                            if action == "BLOCKED":
                                stages["INPUT GUARD"]["blocked"] += 1
                        elif "RETRIEV" in stage_name:
                            stages["RETRIEVAL GUARD"]["total"] += 1
                            if action == "BLOCKED":
                                stages["RETRIEVAL GUARD"]["blocked"] += 1
                            elif action == "SANITIZED":
                                stages["RETRIEVAL GUARD"]["sanitized"] += 1
                        elif "TOOL" in stage_name:
                            stages["TOOL GUARD"]["total"] += 1
                            if action == "BLOCKED":
                                stages["TOOL GUARD"]["blocked"] += 1
                        elif "OUTPUT" in stage_name:
                            stages["OUTPUT GUARD"]["total"] += 1
                            if "redact" in action.lower() or action == "BLOCKED":
                                secrets_redacted += 1
                                stages["OUTPUT GUARD"]["redacted"] += 1

                        for f in ev.get("findings", []):
                            rule = f.get("rule", "unknown")
                            rule_counts[rule] = rule_counts.get(rule, 0) + 1
                            if "key" in rule or "secret" in rule or "token" in rule or "ssn" in rule:
                                secrets_redacted += 1
                    except Exception:
                        continue

        avg_risk = round(total_risk / total_events, 1) if total_events > 0 else 0.0
        block_rate = round((blocked_count / total_events) * 100, 1) if total_events > 0 else 0.0
        top_rules = dict(sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:5])

        return {
            "total_events": total_events,
            "threats_detected": threats_detected,
            "requests_blocked": blocked_count,
            "content_sanitized": sanitized_count,
            "secrets_redacted": secrets_redacted,
            "allowed_count": allowed_count,
            "block_rate_percent": block_rate,
            "bypass_rate_percent": round(100.0 - block_rate, 1) if total_events > 0 else 0.0,
            "avg_risk_score": avg_risk,
            "top_triggered_rules": top_rules,
            "risk_distribution": risk_dist,
            "threat_distribution": threat_dist,
            "pipeline_stages": stages,
        }

    def clear_logs(self) -> None:
        """Clear all audit logs."""
        with self._lock:
            with open(self.log_file, "w", encoding="utf-8") as f:
                f.write("")
