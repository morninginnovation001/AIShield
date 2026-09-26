"""
Simplified Vector Database for Prompt Injection RAG
SQLite-based with basic vector similarity search.
"""

import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Optional, Dict, Any
import uuid

import numpy as np


class VectorDatabase:
    """Simplified SQLite-based vector database."""

    def __init__(self, db_path: str, embedding_dimension: int = 384):
        """
        Initialize the vector database.

        Args:
            db_path: Path to SQLite database file
            embedding_dimension: Dimension of embedding vectors
        """
        self.db_path = Path(db_path)
        self.embedding_dimension = embedding_dimension
        self.logger = logging.getLogger(__name__)

        # Ensure directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Initialize database
        self.init_database()

    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def init_database(self):
        """Initialize database schema."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Documents table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS documents (
                    doc_id TEXT PRIMARY KEY,
                    source_path TEXT NOT NULL,
                    ingested_at TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    collection_id TEXT NOT NULL DEFAULT 'default'
                )
            """)

            # Chunks table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS chunks (
                    chunk_id TEXT PRIMARY KEY,
                    doc_id TEXT NOT NULL,
                    chunk_index INTEGER NOT NULL,
                    content TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    collection_id TEXT NOT NULL DEFAULT 'default',
                    FOREIGN KEY (doc_id) REFERENCES documents (doc_id) ON DELETE CASCADE
                )
            """)

            # Embeddings table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS embeddings (
                    chunk_id TEXT PRIMARY KEY,
                    embedding_vector BLOB NOT NULL,
                    FOREIGN KEY (chunk_id) REFERENCES chunks (chunk_id) ON DELETE CASCADE
                )
            """)

            # FTS5 table for keyword search
            cursor.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts
                USING fts5(chunk_id, content, tokenize='porter unicode61')
            """)

            # Create indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_chunks_collection ON chunks(collection_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_docs_collection ON documents(collection_id)")

            conn.commit()
            self.logger.info(f"Database initialized: {self.db_path}")

    def add_document(self, doc_id: str, source_path: str, metadata: Dict[str, Any],
                    collection_id: str = 'default'):
        """Add a document to the database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO documents (doc_id, source_path, ingested_at, metadata_json, collection_id)
                VALUES (?, ?, ?, ?, ?)
            """, (doc_id, source_path, datetime.now().isoformat(), json.dumps(metadata), collection_id))
            conn.commit()

    def add_chunk(self, chunk_id: str, doc_id: str, chunk_index: int, content: str,
                 embedding: np.ndarray, metadata: Dict[str, Any], collection_id: str = 'default'):
        """Add a chunk with its embedding to the database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Add chunk
            cursor.execute("""
                INSERT OR REPLACE INTO chunks (chunk_id, doc_id, chunk_index, content, metadata_json, collection_id)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (chunk_id, doc_id, chunk_index, content, json.dumps(metadata), collection_id))

            # Add embedding
            embedding_blob = embedding.astype(np.float32).tobytes()
            cursor.execute("""
                INSERT OR REPLACE INTO embeddings (chunk_id, embedding_vector)
                VALUES (?, ?)
            """, (chunk_id, embedding_blob))

            # Add to FTS index for keyword search
            cursor.execute("""
                INSERT OR REPLACE INTO chunks_fts (chunk_id, content)
                VALUES (?, ?)
            """, (chunk_id, content))

            conn.commit()

    def vector_search(self, query_embedding: np.ndarray, k: int = 5,
                     collection_id: Optional[str] = None) -> List[Tuple[str, str, float, Dict]]:
        """
        Perform vector similarity search.

        Args:
            query_embedding: Query vector
            k: Number of results to return
            collection_id: Optional collection filter

        Returns:
            List of (chunk_id, content, similarity_score, metadata) tuples
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Fetch all embeddings (with optional collection filter)
            if collection_id:
                cursor.execute("""
                    SELECT e.chunk_id, e.embedding_vector, c.content, c.metadata_json
                    FROM embeddings e
                    JOIN chunks c ON e.chunk_id = c.chunk_id
                    WHERE c.collection_id = ?
                """, (collection_id,))
            else:
                cursor.execute("""
                    SELECT e.chunk_id, e.embedding_vector, c.content, c.metadata_json
                    FROM embeddings e
                    JOIN chunks c ON e.chunk_id = c.chunk_id
                """)

            rows = cursor.fetchall()

            if not rows:
                return []

            # Calculate similarities
            results = []
            for row in rows:
                chunk_id = row['chunk_id']
                embedding_blob = row['embedding_vector']
                content = row['content']
                metadata_json = row['metadata_json']

                # Deserialize embedding
                embedding = np.frombuffer(embedding_blob, dtype=np.float32)

                # Calculate cosine similarity (embeddings are normalized)
                similarity = float(np.dot(query_embedding, embedding))

                metadata = json.loads(metadata_json)
                results.append((chunk_id, content, similarity, metadata))

            # Sort by similarity (highest first) and return top k
            results.sort(key=lambda x: x[2], reverse=True)
            return results[:k]

    def keyword_search(self, query: str, k: int = 5,
                      collection_id: Optional[str] = None) -> List[Tuple[str, str, float, Dict]]:
        """
        Perform keyword/BM25 search using FTS5.

        Args:
            query: Search query string
            k: Number of results to return
            collection_id: Optional collection filter

        Returns:
            List of (chunk_id, content, bm25_score, metadata) tuples
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Use FTS5 bm25() ranking (lower is better). We will convert to a
            # higher-is-better score for consistency with vector similarity.
            # Use quoted phrase to reduce FTS5 syntax errors from arbitrary inputs
            fts_query = '"' + query.replace('"', ' ') + '"'
            if collection_id:
                try:
                    cursor.execute(
                    """
                    SELECT f.chunk_id,
                           bm25(chunks_fts) AS bm25_score,
                           c.content,
                           c.metadata_json
                    FROM chunks_fts f
                    JOIN chunks c ON f.chunk_id = c.chunk_id
                    WHERE f.content MATCH ? AND c.collection_id = ?
                    ORDER BY bm25_score ASC
                    LIMIT ?
                    """,
                    (fts_query, collection_id, k),
                )
                except Exception:
                    return []
            else:
                try:
                    cursor.execute(
                    """
                    SELECT f.chunk_id,
                           bm25(chunks_fts) AS bm25_score,
                           c.content,
                           c.metadata_json
                    FROM chunks_fts f
                    JOIN chunks c ON f.chunk_id = c.chunk_id
                    WHERE f.content MATCH ?
                    ORDER BY bm25_score ASC
                    LIMIT ?
                    """,
                    (fts_query, k),
                )
                except Exception:
                    return []

            rows = cursor.fetchall()
            results = []
            for row in rows:
                chunk_id = row["chunk_id"]
                # Convert bm25 (lower is better) to a normalized [0,1] score
                bm25_val = float(row["bm25_score"]) if row["bm25_score"] is not None else 0.0
                score = 1.0 / (1.0 + bm25_val)
                content = row["content"]
                metadata = json.loads(row["metadata_json"])
                results.append((chunk_id, content, score, metadata))

            return results

    def hybrid_search(self, query: str, query_embedding: np.ndarray, k: int = 5,
                     alpha: float = 0.7, collection_id: Optional[str] = None) -> List[Tuple[str, str, float, Dict]]:
        """
        Perform hybrid search combining vector and keyword search.

        Args:
            query: Search query string
            query_embedding: Query vector
            k: Number of results to return
            alpha: Weight for vector search (1-alpha for keyword)
            collection_id: Optional collection filter

        Returns:
            List of (chunk_id, content, hybrid_score, metadata) tuples
        """
        # Get vector results
        vector_results = self.vector_search(query_embedding, k=k*2, collection_id=collection_id)

        # Get keyword results
        keyword_results = self.keyword_search(query, k=k*2, collection_id=collection_id)

        # Normalize scores to [0, 1]
        def normalize_scores(results):
            if not results:
                return {}
            scores = [r[2] for r in results]
            min_score, max_score = min(scores), max(scores)
            if max_score == min_score:
                return {r[0]: 1.0 for r in results}
            return {r[0]: (r[2] - min_score) / (max_score - min_score) for r in results}

        vector_scores = normalize_scores(vector_results)
        keyword_scores = normalize_scores(keyword_results)

        # Combine scores
        all_chunk_ids = set(vector_scores.keys()) | set(keyword_scores.keys())
        hybrid_results = {}

        for chunk_id in all_chunk_ids:
            vector_score = vector_scores.get(chunk_id, 0.0)
            keyword_score = keyword_scores.get(chunk_id, 0.0)
            hybrid_score = alpha * vector_score + (1 - alpha) * keyword_score
            hybrid_results[chunk_id] = hybrid_score

        # Get content and metadata for top results
        sorted_chunk_ids = sorted(hybrid_results.items(), key=lambda x: x[1], reverse=True)[:k]

        final_results = []
        with self._get_connection() as conn:
            cursor = conn.cursor()
            for chunk_id, score in sorted_chunk_ids:
                cursor.execute("""
                    SELECT content, metadata_json FROM chunks WHERE chunk_id = ?
                """, (chunk_id,))
                row = cursor.fetchone()
                if row:
                    content = row['content']
                    metadata = json.loads(row['metadata_json'])
                    final_results.append((chunk_id, content, score, metadata))

        return final_results

    def get_collection_stats(self, collection_id: str = 'default') -> Dict[str, Any]:
        """Get statistics for a collection."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM documents WHERE collection_id = ?", (collection_id,))
            doc_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM chunks WHERE collection_id = ?", (collection_id,))
            chunk_count = cursor.fetchone()[0]

            return {
                'collection_id': collection_id,
                'document_count': doc_count,
                'chunk_count': chunk_count
            }


def create_vector_database(db_path: str, embedding_dimension: int = 384) -> VectorDatabase:
    """Factory function to create a VectorDatabase instance."""
    return VectorDatabase(db_path, embedding_dimension)
