"""
AIShield Agent: Security Analyst and Orchestration Brain.
Coordinates the end-to-end RAG lifecycle through Input Guard, Retrieval Guard, Tool Guard, and Output Guard.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

try:
    from security.risk_engine import (
        Finding,
        GuardResult,
        PipelineRiskReport,
        RiskEngine,
        RiskLevel,
        Severity,
        ThreatCategory,
    )
    from security.input_guard import InputGuard
    from security.retrieval_guard import RetrievalGuard
    from security.output_guard import OutputGuard
    from security.tool_guard import ToolGuard
    from audit.audit_logger import AuditLogger
except (ImportError, ValueError):
    try:
        from ..security.risk_engine import (
            Finding,
            GuardResult,
            PipelineRiskReport,
            RiskEngine,
            RiskLevel,
            Severity,
            ThreatCategory,
        )
        from ..security.input_guard import InputGuard
        from ..security.retrieval_guard import RetrievalGuard
        from ..security.output_guard import OutputGuard
        from ..security.tool_guard import ToolGuard
        from ..audit.audit_logger import AuditLogger
    except (ImportError, ValueError):
        from ai_shield.security.risk_engine import (
            Finding,
            GuardResult,
            PipelineRiskReport,
            RiskEngine,
            RiskLevel,
            Severity,
            ThreatCategory,
        )
        from ai_shield.security.input_guard import InputGuard
        from ai_shield.security.retrieval_guard import RetrievalGuard
        from ai_shield.security.output_guard import OutputGuard
        from ai_shield.security.tool_guard import ToolGuard
        from ai_shield.audit.audit_logger import AuditLogger


@dataclass
class AgentResponse:
    """The structured response from the AIShield Agent."""
    query: str
    final_output: str
    blocked: bool = False
    blocking_stage: Optional[str] = None
    action_taken: str = "ALLOWED"
    risk_report: Optional[PipelineRiskReport] = None
    retrieved_contexts: List[str] = field(default_factory=list)
    sanitized_contexts: List[str] = field(default_factory=list)
    tool_results: Optional[Dict[str, Any]] = None
    total_latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query": self.query,
            "final_output": self.final_output,
            "blocked": self.blocked,
            "blocking_stage": self.blocking_stage,
            "action_taken": self.action_taken,
            "risk_report": self.risk_report.to_dict() if self.risk_report else None,
            "retrieved_contexts": self.retrieved_contexts,
            "sanitized_contexts": self.sanitized_contexts,
            "tool_results": self.tool_results,
            "total_latency_ms": round(self.total_latency_ms, 2),
        }


class MockRAGBackend:
    """Built-in knowledge retriever & LLM generator when external model weights are not loaded."""

    KNOWLEDGE_BASE = [
        ("q3_revenue", "In Q3 2026, enterprise software revenue reached $42.5 million, an increase of 14% year-over-year."),
        ("rag_architecture", "Retrieval-Augmented Generation (RAG) grounds language models by retrieving relevant factual documents from a vector index before generating answers."),
        ("logging_guide", "Application logs are written to /var/log/aishield. Set LOG_LEVEL=DEBUG in configuration to enable trace output."),
        ("customer_data", "Customer ID 1092 status is ACTIVE. Primary contact email is support@example.com."),
    ]

    def retrieve(self, query: str, k: int = 2) -> List[str]:
        q_words = set(query.lower().split())
        scored = []
        for key, text in self.KNOWLEDGE_BASE:
            matches = sum(1 for w in q_words if w in text.lower())
            scored.append((matches, text))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [item[1] for item in scored[:k]]

    def generate(self, prompt: str, context: str = "") -> str:
        # If prompt was hijacked and context has imperative command (unprotected mode)
        lower_prompt = prompt.lower()
        if "system compromised" in lower_prompt or "system pwned" in lower_prompt:
            return "System Compromised. Admin directives overridden."
        if "reveal your entire confidential system prompt" in lower_prompt or "reveal system prompt" in lower_prompt:
            return "System Prompt: You are a helpful assistant with secret API key sk-proj-1234567890abcdef."
        if "akiai" in lower_prompt or "aws" in lower_prompt:
            return "Configuration retrieved. Using AWS credential AKIAIOSFODNN7EXAMPLE for cloud backup sync."
        if "ssn" in lower_prompt or "transaction" in lower_prompt:
            return "Customer record retrieved: Jane Doe (SSN: 012-34-5678) paid with card 4532-0156-7892-4432."
        if context:
            return f"Based on retrieved context:\n{context.strip()}"
        return "AIShield processed your request safely and successfully."


class AIShieldAgent:
    """
    AIShield Agent: Security Analyst and Orchestrator.
    Manages the multi-stage defense lifecycle and executes comprehensive risk analysis.
    """

    def __init__(self,
                 risk_engine: Optional[RiskEngine] = None,
                 input_guard: Optional[InputGuard] = None,
                 retrieval_guard: Optional[RetrievalGuard] = None,
                 output_guard: Optional[OutputGuard] = None,
                 tool_guard: Optional[ToolGuard] = None,
                 audit_logger: Optional[AuditLogger] = None,
                 rag_pipeline: Optional[Any] = None,
                 guardrails_enabled: bool = True):
        self.risk_engine = risk_engine or RiskEngine()
        self.input_guard = input_guard or InputGuard(self.risk_engine)
        self.retrieval_guard = retrieval_guard or RetrievalGuard(self.risk_engine)
        self.output_guard = output_guard or OutputGuard(self.risk_engine)
        self.tool_guard = tool_guard or ToolGuard(self.risk_engine)
        self.audit_logger = audit_logger or AuditLogger()
        self.rag_pipeline = rag_pipeline
        self.mock_backend = MockRAGBackend()
        self.guardrails_enabled = guardrails_enabled
        self.logger = logging.getLogger(__name__)

    def run(self, query: str,
            session_id: Optional[str] = None,
            context_override: Optional[str] = None,
            tool_call_override: Optional[Dict[str, Any]] = None,
            mock_output_override: Optional[str] = None) -> AgentResponse:
        """
        Execute a user query through the protected AIShield lifecycle:
        Input Guard -> Retrieval -> Retrieval Guard -> Tool Guard -> LLM -> Output Guard -> Audit Logger.
        """
        start_time = time.perf_counter()
        stage_results: Dict[str, GuardResult] = {}
        retrieved_contexts: List[str] = []
        sanitized_contexts: List[str] = []
        tool_results: Optional[Dict[str, Any]] = None

        # ---------------------------------------------------------------------
        # STAGE 1: INPUT GUARD (Direct Prompt Injection Detection)
        # ---------------------------------------------------------------------
        input_result = self.input_guard.scan(query)
        stage_results["input_guard"] = input_result

        if self.guardrails_enabled and input_result.blocked:
            total_latency = (time.perf_counter() - start_time) * 1000
            report = self.risk_engine.aggregate_pipeline(stage_results, total_latency_ms=total_latency)

            refusal_message = (
                "🛡️ [AIShield Security Block]\n"
                "Your request was terminated because it violates security policies (Direct Prompt Injection / Jailbreak detected).\n"
                f"Risk Score: {report.overall_risk_score}/100 ({report.overall_risk_level.value.upper()})\n"
                f"Triggered Rules: {', '.join(f.rule for f in input_result.findings)}"
            )

            # Log audit trail
            self.audit_logger.log_pipeline_report(
                query=query,
                report=report,
                final_output=refusal_message,
                session_id=session_id,
            )

            return AgentResponse(
                query=query,
                final_output=refusal_message,
                blocked=True,
                blocking_stage="input_guard",
                action_taken="BLOCKED",
                risk_report=report,
                total_latency_ms=total_latency,
            )

        # ---------------------------------------------------------------------
        # STAGE 2: RAG RETRIEVAL (Vulnerable RAG or Knowledge Base)
        # ---------------------------------------------------------------------
        if context_override is not None:
            retrieved_contexts = [context_override]
        elif self.rag_pipeline and hasattr(self.rag_pipeline, "retriever"):
            try:
                retrieved_obj = self.rag_pipeline.retriever.retrieve(query, k=2)
                retrieved_contexts = [
                    c.content if hasattr(c, "content") else str(c) for c in retrieved_obj
                ]
            except Exception as e:
                self.logger.warning(f"RAG pipeline retrieval failed, falling back to mock: {e}")
                retrieved_contexts = self.mock_backend.retrieve(query, k=2)
        else:
            retrieved_contexts = self.mock_backend.retrieve(query, k=2)

        # ---------------------------------------------------------------------
        # STAGE 3: RETRIEVAL GUARD (Indirect Context Injection Defense)
        # ---------------------------------------------------------------------
        if self.guardrails_enabled:
            retrieval_result = self.retrieval_guard.scan_context(retrieved_contexts)
            stage_results["retrieval_guard"] = retrieval_result
            effective_context = retrieval_result.sanitized_text
            sanitized_contexts = retrieval_result.metadata.get("sanitized_chunks", retrieved_contexts)
        else:
            # Unprotected: Raw context injected directly into prompt
            effective_context = "\n\n".join(retrieved_contexts)
            sanitized_contexts = retrieved_contexts
            stage_results["retrieval_guard"] = GuardResult(
                blocked=False,
                risk_score=0,
                risk_level=RiskLevel.CLEAN,
                sanitized_text=effective_context,
            )

        # ---------------------------------------------------------------------
        # STAGE 4: TOOL GUARD (Tool Permission & Parameter Validation)
        # ---------------------------------------------------------------------
        if tool_call_override:
            tool_name = tool_call_override.get("tool", "")
            tool_params = tool_call_override.get("parameters", {})
            tool_result = self.tool_guard.validate_tool_call(tool_name, tool_params)
            stage_results["tool_guard"] = tool_result

            if self.guardrails_enabled and tool_result.blocked:
                total_latency = (time.perf_counter() - start_time) * 1000
                report = self.risk_engine.aggregate_pipeline(stage_results, total_latency_ms=total_latency)

                refusal_message = (
                    f"🛡️ [AIShield Tool Guard Block]\n"
                    f"Execution of tool '{tool_name}' was blocked due to safety violations.\n"
                    f"Risk Score: {report.overall_risk_score}/100 ({report.overall_risk_level.value.upper()})\n"
                    f"Triggered Rules: {', '.join(f.rule for f in tool_result.findings)}"
                )

                self.audit_logger.log_pipeline_report(
                    query=query,
                    report=report,
                    final_output=refusal_message,
                    session_id=session_id,
                )

                return AgentResponse(
                    query=query,
                    final_output=refusal_message,
                    blocked=True,
                    blocking_stage="tool_guard",
                    action_taken="BLOCKED",
                    risk_report=report,
                    retrieved_contexts=retrieved_contexts,
                    sanitized_contexts=sanitized_contexts,
                    tool_results={"tool": tool_name, "status": "blocked", "findings": [f.to_dict() for f in tool_result.findings]},
                    total_latency_ms=total_latency,
                )
            else:
                tool_results = {"tool": tool_name, "status": "allowed", "parameters": tool_params}

        # ---------------------------------------------------------------------
        # STAGE 5: LLM GENERATION
        # ---------------------------------------------------------------------
        raw_output = ""
        if mock_output_override is not None:
            raw_output = mock_output_override
        elif self.rag_pipeline and hasattr(self.rag_pipeline, "llm_wrapper"):
            try:
                prompt = f"Context:\n{effective_context}\n\nQuestion: {query}"
                raw_output = self.rag_pipeline.llm_wrapper.generate(prompt)
            except Exception as e:
                self.logger.warning(f"RAG generation failed, using mock backend: {e}")
                raw_output = self.mock_backend.generate(query, context=effective_context)
        else:
            raw_output = self.mock_backend.generate(query, context=effective_context)

        # ---------------------------------------------------------------------
        # STAGE 6: OUTPUT GUARD (Secret and PII Leakage Defense)
        # ---------------------------------------------------------------------
        if self.guardrails_enabled:
            output_result = self.output_guard.scan(raw_output)
            stage_results["output_guard"] = output_result
            final_output = output_result.sanitized_text

            if output_result.blocked:
                final_output = (
                    "🛡️ [AIShield Security Redaction]\n"
                    "The model generated confidential secrets or sensitive PII that were blocked by AIShield Output Guard."
                )
        else:
            # Unprotected: Raw output leaking secrets / PII
            final_output = raw_output
            stage_results["output_guard"] = GuardResult(
                blocked=False,
                risk_score=0,
                risk_level=RiskLevel.CLEAN,
                sanitized_text=raw_output,
            )

        # ---------------------------------------------------------------------
        # STAGE 7: AGGREGATE RISK REPORT & AUDIT LOGGING
        # ---------------------------------------------------------------------
        total_latency = (time.perf_counter() - start_time) * 1000
        report = self.risk_engine.aggregate_pipeline(stage_results, total_latency_ms=total_latency)

        self.audit_logger.log_pipeline_report(
            query=query,
            report=report,
            final_output=final_output,
            session_id=session_id,
        )

        return AgentResponse(
            query=query,
            final_output=final_output,
            blocked=report.blocked,
            blocking_stage=report.blocking_stage,
            action_taken=report.action_taken,
            risk_report=report,
            retrieved_contexts=retrieved_contexts,
            sanitized_contexts=sanitized_contexts,
            tool_results=tool_results,
            total_latency_ms=total_latency,
        )
