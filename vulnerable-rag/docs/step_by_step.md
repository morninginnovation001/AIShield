#+ Step‑By‑Step Plan: Prompt Injection Research

Use this checklist to implement the research plan end‑to‑end. We will update and tick items as we progress.

## Phase 0 — Environment & Data
- [x] Install dependencies (`pip install -r requirements.txt`); verify Python/pytest
- [x] Verify model file present at `models/gemma-3-4b-it-q4_0.gguf`
- [x] Prepare/curate clean documents under `data/corpus`
- [x] Ingest clean corpus with `create_document_ingester(...).ingest_directory()` to `collection_id="clean"`
- [x] Commit baseline corpus ingestion metadata (db path noted)

## Phase 1 — Baseline & Scaffolding
- [x] Ensure BM25/hybrid retrieval functional (tests already pass)
- [x] Configure pipeline (no defenses); verify heavy model path
- [x] Fetch standardized datasets (deepset, injecagent, pint-example) into `data/attack_payloads/`
- [x] Run E1 baseline (pilot, pipeline, deepset subset): compute ASR and latencies
- [x] Switch to existing vector DB (use `data/rag_vectors__e2_fp16.db`, pick collection as needed; probe schema/dim = 384)
- [x] Run E1 baseline (pilot, agent, InjecAgent subset): compute ASR and latencies
- [ ] Configure and run full E1 baseline across all datasets and agent mode
- [ ] Save full baseline results to `experiments/baseline/` (JSON/CSV)

## Phase 2 — Individual Defenses (E2)
- [ ] Toggle `input_sanitization` only in `config/defense_config.yaml`; rebuild `DefenseManager`
- [ ] Re‑run E1; save results to `experiments/defense_evaluation/input_sanitization`
- [ ] Toggle `prompt_engineering` only; re‑run and save
- [ ] Toggle `output_validation` only; re‑run and save
- [ ] Toggle `tool_guardrails` only; re‑run and save

## Phase 3 — Defense Combinations (E3)
- [ ] Enable PromptEngineering + OutputValidation; re‑run and save
- [ ] Enable OutputValidation + ToolGuardrails; re‑run and save
- [ ] Enable all four defenses; re‑run and save

## Phase 4 — Retrieval Sensitivity (E4)
- [ ] For baseline (no defenses), sweep `retrieval_method` in {vector, keyword, hybrid}
- [ ] For hybrid, sweep `alpha` (e.g., 0.3, 0.5, 0.7)
- [ ] Record ASR per method and retrieved context diagnostics

## Phase 5 — Agentic vs Non‑Agentic (E5)
- [ ] Run identical attacks via pipeline `.query()` and agent `.run()`
- [ ] Compare ASR and tool misuse rate (from `trace`) between modes

## Phase 6 — Tool Injection & Guardrails (E6)
- [ ] Focus dataset on `tool_injection` variants
- [ ] Toggle guardrails whitelist and parameter validation
- [ ] Measure blocked vs allowed calls and false blocks on benign tool usage

## Phase 7 — Poison Severity & Placement (E7)
- [ ] Use `CorpusPoisoningAttack.poison_corpus` with varied `poison_ratio`
- [ ] Vary `poison_placement` ∈ {start, middle, end}
- [ ] Ingest to `collection_id="poisoned"` and compute ASR curves

## Phase 8 — Prompt Engineering Effectiveness (E8)
- [ ] Enable `PromptEngineeringDefense` in defense config
- [ ] Run `context_injection` (boundary breaking, stuffing) and `system_bypass` (delimiter escape)
- [ ] Check for leaked injected tokens and compliance acknowledgments

## Phase 9 — Approval Workflow (E9)
- [ ] Set `require_approval: true` for the agent; simulate approvals/rejections
- [ ] Measure reduction in tool misuse rate and throughput penalty

## Phase 10 — Stuffing Thresholds (E10)
- [ ] Vary stuffing payload repetition/size
- [ ] Measure ASR vs. length and prompt token counts

## Phase 11 — False Positives & Utility (E11)
- [ ] Construct benign query set on clean corpus
- [ ] Evaluate correctness/consistency without defenses (baseline)
- [ ] Re‑evaluate with each defense bundle; compute FPR and utility deltas

## Phase 12 — Performance Overhead (E12)
- [ ] Time defense application and end‑to‑end latency vs. baseline
- [ ] Record prompt token counts and overhead distributions

## Phase 13 — Analysis & Reporting
- [ ] Aggregate results; compute ASR/FPR/utility CIs (bootstrap) and paired comparisons
- [ ] Summarize interaction effects between defenses and attack types
- [ ] Draft figures/tables for thesis/report (ASR heatmaps, overhead boxplots)
- [ ] Write findings and recommendations; discuss limitations and future work

## Optional — Automation
- [ ] Add a `scripts/benchmark.py` harness to reproduce runs
- [ ] Add plotting notebook under `experiments/results/` for visualization

## Artifacts & Reproducibility
- [ ] Save raw outputs (JSON/CSV) per run under `experiments/`
- [ ] Log config snapshots (agent/defense YAML, tool sets, retrieval settings)
- [ ] Record environment (Python, packages, model hash, seed)

