#+ Core Usage: Answer Queries with RAG

This guide shows the minimal, end‑to‑end flow to have an LLM answer queries using the vector database.

## Prerequisites

- Python venv activated: `source venv/bin/activate`
- Model file present: `models/gemma-3-4b-it-q4_0.gguf`
- Vector DB available (no ingestion required): `data/rag_vectors__e2_fp16.db`
  - Suggested collection: `e2_fiqa_bge_fp16`
  - Embedding dimension: 384 → use `BAAI/bge-small-en-v1.5`

## Quick Query via Script

```bash
PYTHONPATH=. python scripts/query_rag.py \
  --db data/rag_vectors__e2_fp16.db \
  --collection e2_fiqa_bge_fp16 \
  --embedding-model BAAI/bge-small-en-v1.5 \
  --model-path models/gemma-3-4b-it-q4_0.gguf \
  --retrieval-method keyword --k 3 \
  --question "What is machine learning?"
```

- Output includes the model’s answer and a brief summary of retrieved contexts.
- For very large DBs, start with `--retrieval-method keyword` (BM25) for speed; try `hybrid` as needed.

## Minimal Python Example

```python
from src.core.rag_pipeline import create_rag_pipeline

pipeline = create_rag_pipeline(
    db_path="data/rag_vectors__e2_fp16.db",
    embedding_model_path="BAAI/bge-small-en-v1.5",
    llm_model_path="models/gemma-3-4b-it-q4_0.gguf",
)

resp = pipeline.query(
    "What is machine learning?",
    k=3,
    retrieval_method="keyword",
    collection_id="e2_fiqa_bge_fp16",
)

print("Answer:\n", resp["answer"])  # core LLM answer
print("Contexts:", resp["num_contexts"]) # number of retrieved chunks
```

## Tips

- DB/model alignment:
  - 384‑dim: `BAAI/bge-small-en-v1.5` or `sentence-transformers/all-MiniLM-L6-v2`
  - 768‑dim: `intfloat/e5-base-v2` or `sentence-transformers/all-mpnet-base-v2`
- Large DBs: prefer `keyword` first; `hybrid` offers better relevance at higher cost.
- You can enable defenses by passing `--defense-config config/defense_config.yaml` to `scripts/query_rag.py`.

