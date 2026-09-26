#!/usr/bin/env python3
"""
Ingest a clean corpus (and optionally create a small synthetic seed corpus).

Usage:
  source venv/bin/activate
  python scripts/ingest_corpus.py --db data/rag_vectors.db --corpus data/corpus --collection clean \
         --embedding-model sentence-transformers/all-MiniLM-L6-v2 --seed-if-empty

This script intentionally avoids any network fetch for documents; it only
creates small synthetic texts if the corpus directory is empty.
"""

import argparse
import json
import os
from pathlib import Path
from typing import List

from src.utils.document_ingestion import create_document_ingester
from src.core.vector_database import VectorDatabase


SEED_DOCS = {
    "ai_ml.txt": """
Artificial Intelligence (AI) studies intelligent systems. Machine learning (ML)
is a subset of AI that learns patterns from data to make predictions.
Supervised learning uses labeled datasets; unsupervised learning finds structure
in unlabeled data. Common applications include classification, regression, and
recommendation systems.
""".strip(),
    "cybersecurity.txt": """
Cybersecurity protects systems, networks, and data from digital attacks. Common
domains include network security, application security, and incident response.
Best practices emphasize least privilege, defense in depth, and strong key
management.
""".strip(),
    "databases.txt": """
Databases store and retrieve structured information. SQL databases use tables
and ACID transactions; NoSQL systems offer flexible schemas and horizontal
scaling. Indexing and query optimization are critical for performance.
""".strip(),
    "biology.txt": """
Biology examines living organisms. Genetics explores inheritance and DNA as a
blueprint. Cellular biology studies organelles and biochemical processes
underlying life.
""".strip(),
    "physics.txt": """
Physics explains matter, energy, and their interactions. Classical mechanics
describes motion, while quantum mechanics governs behavior at atomic scales.
Electromagnetism unifies electric and magnetic phenomena.
""".strip(),
    "mathematics.txt": """
Mathematics provides formal languages for reasoning about quantity and structure.
Key branches include algebra, calculus, probability, and geometry. Proofs
establish theorems from axioms with logical rigor.
""".strip(),
    "climate.txt": """
Climate science analyzes long-term weather patterns. Greenhouse gases trap heat
in the atmosphere. Mitigation and adaptation strategies address climate risks.
""".strip(),
    "economics.txt": """
Economics studies production, consumption, and distribution of goods. Microeconomics
focuses on firms and consumers; macroeconomics studies inflation, growth, and
employment.
""".strip(),
    "networks.txt": """
Computer networks interconnect devices to share data. Protocols like TCP/IP
govern reliable data transfer; routers and switches direct traffic across links.
""".strip(),
    "literature.txt": """
Literature encompasses written works of artistic value. Analysis explores themes,
narrative structure, and stylistic devices that shape meaning.
""".strip(),
}


def maybe_seed_corpus(corpus_dir: Path) -> int:
    corpus_dir.mkdir(parents=True, exist_ok=True)
    files = list(corpus_dir.glob("*.txt"))
    if files:
        return 0
    for name, content in SEED_DOCS.items():
        (corpus_dir / name).write_text(content.strip() + "\n", encoding="utf-8")
    return len(SEED_DOCS)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="data/rag_vectors.db")
    ap.add_argument("--corpus", default="data/corpus")
    ap.add_argument("--collection", default="clean")
    ap.add_argument("--embedding-model", default="sentence-transformers/all-MiniLM-L6-v2")
    ap.add_argument("--seed-if-empty", action="store_true")
    args = ap.parse_args()

    corpus_dir = Path(args.corpus)
    if args.seed_if_empty:
        created = maybe_seed_corpus(corpus_dir)
        if created:
            print(f"Seeded {created} documents in {corpus_dir}")

    ingester = create_document_ingester(
        db_path=args.db,
        embedding_model_path=args.embedding_model,
    )
    total_chunks = ingester.ingest_directory(
        dir_path=corpus_dir,
        pattern="*.txt",
        collection_id=args.collection,
    )
    print(f"Ingested {total_chunks} chunks from {corpus_dir} into {args.db} [{args.collection}]")

    # Persist a small run config
    outdir = Path("experiments/baseline")
    outdir.mkdir(parents=True, exist_ok=True)
    cfg = {
        "db": args.db,
        "collection": args.collection,
        "embedding_model": args.embedding_model,
        "corpus_dir": str(corpus_dir),
    }
    (outdir / "config.json").write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    print(f"Wrote baseline config to {outdir / 'config.json'}")


if __name__ == "__main__":
    main()

