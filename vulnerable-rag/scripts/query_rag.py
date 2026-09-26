#!/usr/bin/env python3
"""
Query the RAG pipeline and print the answer using an existing vector database.

Example:
  source venv/bin/activate
  PYTHONPATH=. python scripts/query_rag.py \
    --db data/rag_vectors__e2_fp16.db \
    --collection e2_fiqa_bge_fp16 \
    --embedding-model BAAI/bge-small-en-v1.5 \
    --model-path models/gemma-3-4b-it-q4_0.gguf \
    --retrieval-method keyword --k 3 \
    --question "What is machine learning?"
"""

from __future__ import annotations

import argparse
from typing import Any, Dict

from src.core.rag_pipeline import create_rag_pipeline
from src.defenses.defense_manager import create_defense_manager


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--db', required=True, help='Path to SQLite vector DB (e.g., data/rag_vectors__e2_fp16.db)')
    ap.add_argument('--collection', default='default', help='Collection ID to search')
    ap.add_argument('--embedding-model', required=True, help='Embedding model path or identifier (e.g., BAAI/bge-small-en-v1.5)')
    ap.add_argument('--model-path', required=True, help='Path to Gemma 3 4B GGUF (e.g., models/gemma-3-4b-it-q4_0.gguf)')
    ap.add_argument('--retrieval-method', choices=['vector', 'keyword', 'hybrid'], default='hybrid')
    ap.add_argument('--k', type=int, default=3)
    ap.add_argument('--question', required=True, help='User question')
    ap.add_argument('--defense-config', default='none', help='Path to defense_config.yaml or "none"')
    args = ap.parse_args()

    defense_mgr = None if args.defense_config == 'none' else create_defense_manager(config_path=args.defense_config)

    pipeline = create_rag_pipeline(
        db_path=args.db,
        embedding_model_path=args.embedding_model,
        llm_model_path=args.model_path,
        defense_manager=defense_mgr,
    )

    resp: Dict[str, Any] = pipeline.query(
        user_query=args.question,
        k=args.k,
        retrieval_method=args.retrieval_method,
        collection_id=args.collection,
    )

    print("\n=== Answer ===")
    print(resp.get('answer', ''))

    print("\n=== Retrieval ===")
    print(f"contexts: {resp.get('num_contexts', 0)} | method: {resp.get('retrieval_method')} | prompt_tokens: {resp.get('prompt_tokens')}")
    for i, ctx in enumerate(resp.get('contexts', [])[:args.k], 1):
        # ctx may be a dict from RetrievalResult.to_dict()
        if isinstance(ctx, dict):
            meta = ctx.get('metadata', {})
            source = meta.get('source', 'unknown')
            print(f"[{i}] score={ctx.get('score'):.3f} source={source}")
        else:
            print(f"[{i}] {str(ctx)[:80]}...")


if __name__ == '__main__':
    main()

