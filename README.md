# AIShield

AIShield is a small research workspace for studying prompt injection defenses in
RAG and agentic LLM systems. It contains three related but separately runnable
implementations:

1. `ai-shield`: a guardrail orchestration prototype with a CLI, Streamlit
   dashboard, audit logging, and a synthetic benchmark.
2. `vulnerable-rag`: an intentionally unsafe RAG and ReAct agent used as a
   research target for attacks and defense experiments.
3. `guardrail-reference`: a dependency-free reference implementation of input,
   retrieval-context, and output guardrails.

These projects are not wired into one executable deployment. By default,
`ai-shield` uses its own deterministic mock retriever and generator; it does
not automatically start or use `vulnerable-rag`.

## Architecture

The `ai-shield` request lifecycle is:

```text
user query
    |
    v
InputGuard ---- block direct injection and jailbreak patterns
    |
    v
retrieval ---- injected RAG pipeline, context override, or mock backend
    |
    v
RetrievalGuard - sanitize, defang, and fence untrusted context
    |
    v
ToolGuard ----- validate an optional tool-call dictionary
    |
    v
mock/LLM output
    |
    v
OutputGuard --- redact secrets and PII; block critical leaks
    |
    v
response + RiskEngine report + AuditLogger JSONL event
```

The four guards report findings to the shared risk engine. The audit logger
writes pipeline reports to `ai-shield/audit/events.jsonl`. The dashboard reads
that local event stream for operational views.

## Repository map

```text
AIShield/
├── ai-shield/
│   ├── agent/security_agent.py   # Guardrail orchestrator and mock RAG backend
│   ├── security/                 # Input, retrieval, tool, output, and risk logic
│   ├── audit/                    # JSONL audit logger and sample event log
│   ├── attacks/                  # Synthetic attack and benign scenarios
│   ├── evaluation/               # Benchmark runner and recorded result
│   ├── dashboard/app.py          # Streamlit security dashboard
│   ├── config/security_config.yaml
│   └── app.py                    # CLI, demo, evaluation, and dashboard entry point
├── vulnerable-rag/
│   ├── src/core/                 # Ingestion, embeddings, vector DB, retrieval, RAG
│   ├── src/agent/                # ReAct loop, tool registry, parsing, execution
│   ├── src/attacks/              # Corpus, context, system, tool, and multi-step attacks
│   ├── src/defenses/             # Experimental defense components
│   ├── tools/                    # Calculator, file, database, and web-search tools
│   ├── scripts/                  # Ingestion, querying, datasets, and baselines
│   └── config/                   # Agent, attack, and defense configuration
└── guardrail-reference/
    ├── guardrails.py             # Standard-library guardrail facade
    ├── test_guardrails.py        # Unit tests
    └── demo.py                   # Small end-to-end demonstration
```

## Quick start: AIShield

Run these commands from the repository root. A virtual environment is
recommended.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r ai-shield\requirements.txt
python ai-shield\app.py --demo
```

Other modes:

```powershell
# Interactive CLI. Use toggle, stats, clear, or exit at the prompt.
python ai-shield\app.py

# Run the 25-case synthetic evaluation and update the result JSON.
python ai-shield\app.py --eval

# Start the Streamlit dashboard at http://127.0.0.1:5000.
python ai-shield\app.py --dashboard

# Use a different dashboard bind address or port.
python ai-shield\app.py --dashboard --host 127.0.0.1 --port 8501
```

The demo covers direct prompt injection, poisoned retrieval context, a tool
path-traversal attempt, sensitive-output scanning, and a benign request.

## Guardrail reference

`guardrail-reference` is the smallest component and has no runtime
dependencies. It exposes a `Guardrails` facade with three operations:

```python
from guardrails import Guardrails

guards = Guardrails()

input_result = guards.check_input(user_query)
context_result = guards.sanitize_context(retrieved_documents)
output_result = guards.filter_output(model_answer)
```

Run its demo and tests from that directory:

```powershell
Set-Location guardrail-reference
python -m pip install -r requirements-dev.txt
python demo.py
python -m pytest -q
Set-Location ..
```

The reference implementation is deliberately heuristic. It fences retrieved
text as untrusted data and redacts common secrets and PII, but it is not a
classifier or a complete production security boundary.

## Vulnerable RAG research target

The `vulnerable-rag` project requires substantially more setup than the other
two components:

- Python packages from `vulnerable-rag/requirements.txt`.
- A local GGUF model at `models/gemma-3-4b-it-q4_0.gguf`.
- A downloaded SentenceTransformers embedding model.
- A corpus and writable data directories for the vector database.
- Extra network-dependent setup for the dataset-fetching script.

Install its dependencies and inspect the available script help first:

```powershell
Set-Location vulnerable-rag
python -m pip install -r requirements.txt
python scripts\ingest_corpus.py --help
python scripts\query_rag.py --help
python scripts\run_baseline.py --help
Set-Location ..
```

With a corpus, model, and database available, a keyword-retrieval query looks
like this in PowerShell:

```powershell
Set-Location vulnerable-rag
$env:PYTHONPATH = "."
python scripts\ingest_corpus.py `
  --db data\rag_vectors.db `
  --corpus data\corpus `
  --collection clean `
  --embedding-model sentence-transformers/all-MiniLM-L6-v2 `
  --seed-if-empty
python scripts\query_rag.py `
  --db data\rag_vectors.db `
  --collection clean `
  --embedding-model sentence-transformers/all-MiniLM-L6-v2 `
  --model-path models\gemma-3-4b-it-q4_0.gguf `
  --retrieval-method keyword `
  --k 3 `
  --question "What is machine learning?"
Set-Location ..
```

This system is intentionally vulnerable. Its prompt builder places user input
and retrieved documents directly into prompts, and some tools are deliberately
unsafe for research purposes. Do not expose it to real data, credentials, or
untrusted users. The checked-in workspace does not include the model, corpus,
vector database, or a complete lightweight test suite, so the heavyweight
`vulnerable-rag\test_system.py` smoke test cannot run until those assets exist.

## Evaluation results

`ai-shield/evaluation/results.json` contains a recorded run over 25 synthetic
cases: 20 attack cases and 5 benign controls. The recorded run reports 100%
neutralization and 0% false positives for that fixture.

Treat those numbers as a demonstration of the rule set, not as a claim about
real-world attack resistance. The evaluator assumes attack outcomes for the
baseline and uses the built-in mock backend; it does not measure a live Gemma
pipeline or prove that novel, paraphrased, multilingual, encoded, or
multi-turn attacks are blocked.

## Security limitations

- The guards are pattern-based and can be bypassed by novel wording, encoding,
  obfuscation, language changes, or attacks outside the rule set.
- `ai-shield` validates tool-call overrides but does not execute tools itself.
- The built-in backend is a deterministic mock, not a production LLM or vector
  database.
- `ai-shield/config/security_config.yaml` is present as policy documentation,
  but the current runtime does not load all of its settings.
- Retrieval findings may be reported as high risk while processing continues
  with sanitized and fenced context.
- Audit events include query snippets and findings in a local JSONL file; apply
  appropriate access controls before using real data.
- `vulnerable-rag` has no production authentication, authorization, sandbox,
  rate limiting, or isolation boundary. Its calculator and file-reader tools
  are especially unsuitable for deployment.

## Further reading

- [AIShield implementation plan](vulnerable-rag/docs/IMPLEMENTATION_PLAN.md)
- [Core usage notes](vulnerable-rag/docs/core_usage.md)
- [Research plan](vulnerable-rag/docs/research_plan.md)
- [Vulnerable RAG README](vulnerable-rag/README.md)
- [Reference guardrails README](guardrail-reference/README.md)