# AIShield: Autonomous RAG Guardrail Defense Engine

AIShield is an enterprise-grade AI safety and guardrail system designed to protect Retrieval-Augmented Generation (RAG) and Agentic LLM pipelines against prompt injections, context poisoning, tool abuse, and data exfiltration.

```
                         USER
                           │
                           ▼
                 ┌──────────────────┐
                 │  AIShield Agent  │ 🧠 Risk Analysis
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │   INPUT GUARD    │ 🛡️ Direct Injection & Jailbreak Defense
                 └────────┬─────────┘
                          │
                     SAFE / BLOCK
                          │
                          ▼
                 ┌──────────────────┐
                 │  VULNERABLE RAG  │
                 │    Retriever     │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │ RETRIEVAL GUARD  │ 🛡️ Indirect Poisoning & Fencing
                 └────────┬─────────┘
                          │
                          ▼
                         LLM
                          │
                          ▼
                 ┌──────────────────┐
                 │   OUTPUT GUARD   │ 🛡️ PII & Secret Redaction
                 └────────┬─────────┘
                          │
                          ▼
                        USER

                          +
                          │
                          ▼
                  ┌──────────────┐
                  │ AUDIT LOGGER │ 📜 events.jsonl
                  └──────┬───────┘
                         │
                         ▼
              ┌─────────────────────┐
              │ Security Dashboard  │ 📊 Web Operations Console
              └─────────────────────┘
```

---

## 📁 Repository Layout

```
AIShield/
│
├── vulnerable-rag/                    # REPO 1: Intentionally vulnerable RAG target
│   ├── src/core/                      # RAG pipeline, prompt builder, retriever
│   ├── src/agent/                     # ReACT agent, tool executor, registry
│   ├── src/attacks/                   # Attack generators
│   └── tools/                         # Calculator, file reader, database query
│
├── guardrail-reference/              # REPO 2: Lightweight reference implementation
│   └── guardrails.py
│
└── ai-shield/                        # OUR SYSTEM: Production Defense Suite
    │
    ├── security/
    │   ├── input_guard.py            # Direct prompt injection & jailbreak detection
    │   ├── retrieval_guard.py        # Indirect RAG context poisoning & untrusted fencing
    │   ├── output_guard.py           # Sensitive secret & PII leakage protection
    │   ├── tool_guard.py             # Agent tool permission & parameter validation
    │   └── risk_engine.py            # Multi-dimensional risk calculation & scoring
    │
    ├── agent/
    │   └── security_agent.py         # AIShield Agent (🧠 orchestrator & analyst)
    │
    ├── audit/
    │   ├── audit_logger.py           # Thread-safe JSONL security event logging
    │   └── events.jsonl              # Security audit log records
    │
    ├── attacks/
    │   └── attack_suite.py           # 25 curated attack benchmarks & benign controls
    │
    ├── evaluation/
    │   ├── evaluator.py              # ASR, Defense Rate, and latency benchmark
    │   └── results.json              # Benchmark evaluation output
    │
    ├── dashboard/
    │   └── app.py                    # Real-time Flask Security Operations Dashboard
    │
    ├── config/
    │   └── security_config.yaml      # Security policies, weights & thresholds
    │
    └── app.py                         # Unified AIShield application entry point
```

---

## 🛡️ Multi-Layer Defense Architecture

| Layer | Guard | Threats Mitigated | Action Taken |
|---|---|---|---|
| **Layer 1** | **Input Guard** | Direct prompt injections, DAN jailbreaks, system prompt extraction, delimiter smuggling, Base64/spacing obfuscations | Immediate `BLOCKED` with detailed security alert |
| **Layer 2** | **Retrieval Guard** | Poisoned RAG documents, chat template hijack tokens, hidden markdown image exfiltration (`![exfil](...)`), imperative overrides | `SANITIZED`, control tokens stripped, wrapped in `<<<UNTRUSTED_EXTERNAL_CONTEXT>>>` fences |
| **Layer 3** | **Tool Guard** | Prohibited tool execution (`shell_exec`, `cmd`), path traversal (`../../etc/passwd`), SQL injection (`DROP TABLE`), SSRF | Execution intercepted and `BLOCKED` before tool dispatch |
| **Layer 4** | **Output Guard** | AWS keys, OpenAI API keys (`sk-proj-...`), private keys, passwords, database URIs, SSNs, credit cards, emails | Redacted to `[REDACTED:{TYPE}]` or `BLOCKED` on critical leaks |
| **Cross-Cutting**| **Risk Engine & Audit Logger** | Multi-vector attacks across the entire lifecycle | Composite score (0-100), risk levels (`CLEAN`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), structured JSONL event logging |

---

## 🚀 Getting Started & Usage

### 1. Automated Attack Demonstration
Runs 5 key attack scenarios through all defense layers (Direct Injection, Poisoned Context, Tool Traversal, Secret Leakage, and Benign Query):
```powershell
python ai-shield/app.py --demo
```

### 2. Interactive Terminal Shell
Launch real-time interactive pair-programming CLI with AIShield protection:
```powershell
python ai-shield/app.py
```
*In interactive mode, type `toggle` to switch between Protected Mode and Vulnerable Mode, `stats` to view telemetry, or `exit` to quit.*

### 3. Run Security Benchmark Evaluation
Executes the test suite against unprotected baseline vs protected AIShield, generating `ai-shield/evaluation/results.json`:
```powershell
python ai-shield/app.py --eval
```

### 4. Launch Security Operations Web Dashboard
Starts the interactive dark-mode dashboard at `http://127.0.0.1:5000`:
```powershell
python ai-shield/app.py --dashboard
```

---

## 📊 Security Benchmark Results

Tested against 25 curated test cases (20 attacks across all OWASP LLM categories + 5 benign controls):

| Metric | Vulnerable Baseline | AIShield Protected | Delta |
|---|---|---|---|
| **Attack Success Rate (ASR)** | **100.0%** | **0.0%** | **-100.0%** |
| **Defense Neutralization Rate** | 0.0% | **100.0%** | **+100.0%** |
| **False Positive Rate (Benign)** | 0.0% | **0.0%** | **0.0%** |
| **Overall Accuracy** | 20.0% | **100.0%** | **+80.0%** |
| **F1-Score** | 0.0% | **100.0%** | **+100.0%** |
| **Inspection Latency Overhead** | - | **~0.25 ms** | Sub-millisecond |

Stage Neutralization Breakdown:
- **Input Guard:** 7 direct injection threats blocked
- **Retrieval Guard:** 4 context poisoning threats neutralized & fenced
- **Tool Guard:** 5 tool traversal & command injection threats blocked
- **Output Guard:** 4 sensitive credential & PII leaks blocked / redacted