"""
Simplified Retriever for Prompt Injection RAG
Retrieves relevant chunks from vector database.
"""

import logging
from typing import List, Optional, Dict, Any

from .embedding_service import EmbeddingService
from .vector_database import VectorDatabase
from .prompt_builder import RetrievalResult


class Retriever:
    """Retrieves relevant chunks for RAG queries."""

    def __init__(self, vector_db: VectorDatabase, embedding_service: EmbeddingService):
        """
        Initialize the retriever.

        Args:
            vector_db: Vector database instance
            embedding_service: Embedding service instance
        """
        self.vector_db = vector_db
        self.embedding_service = embedding_service
        self.logger = logging.getLogger(__name__)

    def retrieve(self, query: str, k: int = 5, method: str = "vector",
                collection_id: Optional[str] = None, alpha: float = 0.7) -> List[RetrievalResult]:
        """
        Retrieve relevant chunks for a query.

        Args:
            query: Search query string
            k: Number of results to return
            method: Retrieval method ("vector", "keyword", "hybrid")
            collection_id: Optional collection filter
            alpha: Hybrid fusion weight (only for hybrid method)

        Returns:
            List of RetrievalResult objects
        """
        self.logger.debug(f"Retrieving with method={method}, k={k}, collection={collection_id}")

        if method == "vector":
            return self._vector_retrieve(query, k, collection_id)
        elif method == "keyword":
            return self._keyword_retrieve(query, k, collection_id)
        elif method == "hybrid":
            return self._hybrid_retrieve(query, k, collection_id, alpha)
        else:
            raise ValueError(f"Unknown retrieval method: {method}")

    def _vector_retrieve(self, query: str, k: int,
                        collection_id: Optional[str]) -> List[RetrievalResult]:
        """Perform vector similarity search."""
        # Embed query
        query_embedding = self.embedding_service.embed_text(query)

        # Search
        results = self.vector_db.vector_search(query_embedding, k=k, collection_id=collection_id)

        # Convert to RetrievalResult objects
        return self._format_results(results)

    def _keyword_retrieve(self, query: str, k: int,
                         collection_id: Optional[str]) -> List[RetrievalResult]:
        """Perform keyword search."""
        results = self.vector_db.keyword_search(query, k=k, collection_id=collection_id)
        return self._format_results(results)

    def _hybrid_retrieve(self, query: str, k: int, collection_id: Optional[str],
                        alpha: float) -> List[RetrievalResult]:
        """Perform hybrid search."""
        # Embed query
        query_embedding = self.embedding_service.embed_text(query)

        # Search
        results = self.vector_db.hybrid_search(
            query, query_embedding, k=k, alpha=alpha, collection_id=collection_id
        )

        return self._format_results(results)

    def _format_results(self, results: List[tuple]) -> List[RetrievalResult]:
        """Convert database results to RetrievalResult objects."""
        formatted = []
        for i, (chunk_id, content, score, metadata) in enumerate(results):
            result = RetrievalResult(
                chunk_id=chunk_id,
                content=content,
                score=score,
                metadata=metadata,
                doc_id=metadata.get('doc_id', 'unknown'),
                chunk_index=metadata.get('chunk_index', i)
            )
            formatted.append(result)
        return formatted


def create_retriever(db_path: str, embedding_model_path: str,
                    embedding_dimension: int = 384) -> Retriever:
    """
    Factory function to create a Retriever instance.

    Args:
        db_path: Path to vector database
        embedding_model_path: Path to embedding model
        embedding_dimension: Embedding vector dimension

    Returns:
        Configured Retriever instance
    """
    vector_db = VectorDatabase(db_path, embedding_dimension)
    embedding_service = EmbeddingService(embedding_model_path)
    return Retriever(vector_db, embedding_service)