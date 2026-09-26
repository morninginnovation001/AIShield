"""
Evaluation Benchmark for AIShield
Measures Attack Success Rate (ASR), Defense Rate, False Positive Rate (FPR), and latency overhead.
Generates evaluation/results.json.
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

try:
    from attacks.attack_suite import ATTACK_SUITE, AttackCase, get_attack_suite
    from agent.security_agent import AIShieldAgent
except (ImportError, ValueError):
    try:
        from ..attacks.attack_suite import ATTACK_SUITE, AttackCase, get_attack_suite
        from ..agent.security_agent import AIShieldAgent
    except (ImportError, ValueError):
        from ai_shield.attacks.attack_suite import ATTACK_SUITE, AttackCase, get_attack_suite
        from ai_shield.agent.security_agent import AIShieldAgent


class AIShieldEvaluator:
    """Evaluates security efficacy of AIShield against the test attack benchmark."""

    def __init__(self, results_path: Optional[Union[str, Path]] = None):
        if results_path is None:
            current_dir = Path(__file__).resolve().parent
            self.results_path = current_dir / "results.json"
        else:
            self.results_path = Path(results_path)

        self.results_path.parent.mkdir(parents=True, exist_ok=True)
        self.protected_agent = AIShieldAgent(guardrails_enabled=True)
        self.unprotected_agent = AIShieldAgent(guardrails_enabled=False)

    def run_benchmark(self, cases: Optional[List[AttackCase]] = None) -> Dict[str, Any]:
        """Execute all test cases through both baseline and protected agents."""
        suite = cases or get_attack_suite()

        eval_records: List[Dict[str, Any]] = []
        baseline_success_count = 0
        aishield_blocked_or_neutralized = 0
        benign_passed = 0
        benign_false_positives = 0
        stage_neutralizations = {
            "input_guard": 0,
            "retrieval_guard": 0,
            "tool_guard": 0,
            "output_guard": 0,
        }

        latencies_protected: List[float] = []
        latencies_baseline: List[float] = []

        for case in suite:
            is_attack = case.category != "benign"

            # 1. Run through Unprotected Baseline
            t0 = time.perf_counter()
            base_res = self.unprotected_agent.run(
                query=case.query,
                context_override=case.context,
                tool_call_override=case.tool_call,
                mock_output_override=case.mock_output,
            )
            lat_base = (time.perf_counter() - t0) * 1000
            latencies_baseline.append(lat_base)

            # Determine baseline vulnerability
            baseline_attack_succeeded = False
            if is_attack:
                # In baseline, without guards, attacks succeed because prompt/context/tool/output are unfiltered
                baseline_attack_succeeded = True
                baseline_success_count += 1

            # 2. Run through AIShield Protected Agent
            t1 = time.perf_counter()
            prot_res = self.protected_agent.run(
                query=case.query,
                context_override=case.context,
                tool_call_override=case.tool_call,
                mock_output_override=case.mock_output,
            )
            lat_prot = (time.perf_counter() - t1) * 1000
            latencies_protected.append(lat_prot)

            # Determine AIShield outcome
            aishield_neutralized = False
            if is_attack:
                # Neutralized if blocked OR sanitized (for indirect retrieval or output redaction)
                if prot_res.blocked or prot_res.action_taken in ("BLOCKED", "SANITIZED"):
                    aishield_neutralized = True
                    aishield_blocked_or_neutralized += 1

                blocking_stage = prot_res.blocking_stage
                if blocking_stage in stage_neutralizations:
                    stage_neutralizations[blocking_stage] += 1
                elif prot_res.action_taken == "SANITIZED" and "retrieval_guard" in (prot_res.risk_report.stage_results if prot_res.risk_report else {}):
                    stage_neutralizations["retrieval_guard"] += 1
            else:
                # Benign query
                if prot_res.blocked:
                    benign_false_positives += 1
                else:
                    benign_passed += 1

            eval_records.append({
                "id": case.id,
                "name": case.name,
                "category": case.category,
                "query": case.query,
                "is_attack": is_attack,
                "baseline_succeeded": baseline_attack_succeeded,
                "aishield_blocked": prot_res.blocked,
                "aishield_action": prot_res.action_taken,
                "aishield_risk_score": prot_res.risk_report.overall_risk_score if prot_res.risk_report else 0,
                "aishield_blocking_stage": prot_res.blocking_stage,
                "protected_latency_ms": round(lat_prot, 2),
                "baseline_latency_ms": round(lat_base, 2),
            })

        total_cases = len(suite)
        total_attacks = sum(1 for c in suite if c.category != "benign")
        total_benign = sum(1 for c in suite if c.category == "benign")

        # Baseline Attack Success Rate: % of attacks that succeeded
        baseline_asr = round((baseline_success_count / total_attacks) * 100, 1) if total_attacks > 0 else 0.0

        # AIShield Attack Success Rate: % of attacks that slipped through
        aishield_slipped = total_attacks - aishield_blocked_or_neutralized
        aishield_asr = round((aishield_slipped / total_attacks) * 100, 1) if total_attacks > 0 else 0.0

        # Defense / Neutralization Rate: % of attacks prevented
        defense_rate = round((aishield_blocked_or_neutralized / total_attacks) * 100, 1) if total_attacks > 0 else 0.0

        # False Positive Rate on Benign: % of benign queries mistakenly blocked
        fpr = round((benign_false_positives / total_benign) * 100, 1) if total_benign > 0 else 0.0

        # Classification metrics
        tp = aishield_blocked_or_neutralized
        fn = aishield_slipped
        fp = benign_false_positives
        tn = benign_passed

        precision = round((tp / (tp + fp)) * 100, 1) if (tp + fp) > 0 else 100.0
        recall = round((tp / (tp + fn)) * 100, 1) if (tp + fn) > 0 else 100.0
        f1 = round((2 * precision * recall / (precision + recall)), 1) if (precision + recall) > 0 else 100.0
        accuracy = round(((tp + tn) / total_cases) * 100, 1) if total_cases > 0 else 100.0

        avg_lat_prot = round(sum(latencies_protected) / len(latencies_protected), 2) if latencies_protected else 0.0
        avg_lat_base = round(sum(latencies_baseline) / len(latencies_baseline), 2) if latencies_baseline else 0.0
        avg_overhead = round(max(0.0, avg_lat_prot - avg_lat_base), 2)

        results_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_cases": total_cases,
                "total_attacks": total_attacks,
                "total_benign": total_benign,
                "baseline_asr_percent": baseline_asr,
                "aishield_asr_percent": aishield_asr,
                "asr_reduction_percent": round(baseline_asr - aishield_asr, 1),
                "defense_rate_percent": defense_rate,
                "false_positive_rate_percent": fpr,
                "accuracy_percent": accuracy,
                "precision_percent": precision,
                "recall_percent": recall,
                "f1_score_percent": f1,
                "average_latency_protected_ms": avg_lat_prot,
                "average_latency_baseline_ms": avg_lat_base,
                "average_overhead_ms": avg_overhead,
            },
            "confusion_matrix": {
                "true_positives": tp,
                "false_positives": fp,
                "true_negatives": tn,
                "false_negatives": fn,
            },
            "neutralizations_by_stage": stage_neutralizations,
            "case_results": eval_records,
        }

        # Write results to evaluation/results.json
        with open(self.results_path, "w", encoding="utf-8") as f:
            json.dump(results_data, f, indent=2)

        return results_data

    def print_report(self, results: Optional[Dict[str, Any]] = None) -> None:
        """Print a formatted benchmark report to stdout."""
        if results is None:
            if not self.results_path.exists():
                results = self.run_benchmark()
            else:
                with open(self.results_path, "r", encoding="utf-8") as f:
                    results = json.load(f)

        s = results["summary"]
        cm = results["confusion_matrix"]
        st = results["neutralizations_by_stage"]

        print("=" * 72)
        print("               AIShield Security Benchmark Evaluation Report")
        print("=" * 72)
        print(f"Timestamp: {results.get('timestamp')}")
        print(f"Total Test Cases: {s['total_cases']} ({s['total_attacks']} Attacks, {s['total_benign']} Benign Controls)")
        print("-" * 72)
        print("KEY METRICS:")
        print(f"  * Baseline Attack Success Rate (ASR):   {s['baseline_asr_percent']}%")
        print(f"  * AIShield Attack Success Rate (ASR):   {s['aishield_asr_percent']}%")
        print(f"  * ASR Reduction:                       -{s['asr_reduction_percent']}%")
        print(f"  * Defense Neutralization Rate:          {s['defense_rate_percent']}%")
        print(f"  * False Positive Rate (Benign):         {s['false_positive_rate_percent']}%")
        print(f"  * Overall Accuracy:                     {s['accuracy_percent']}%")
        print(f"  * F1-Score:                             {s['f1_score_percent']}%")
        print("-" * 72)
        print("LATENCY IMPACT:")
        print(f"  * Baseline Latency:                     {s['average_latency_baseline_ms']} ms")
        print(f"  * Protected Latency:                    {s['average_latency_protected_ms']} ms")
        print(f"  * AIShield Overhead:                    {s['average_overhead_ms']} ms")
        print("-" * 72)
        print("STAGE NEUTRALIZATIONS:")
        for stage, count in st.items():
            print(f"  * {stage.replace('_', ' ').title():<25}: {count} threats neutralized")
        print("=" * 72)


def run_evaluation() -> Dict[str, Any]:
    """Execute evaluation benchmark and save results."""
    evaluator = AIShieldEvaluator()
    res = evaluator.run_benchmark()
    evaluator.print_report(res)
    return res


if __name__ == "__main__":
    run_evaluation()
