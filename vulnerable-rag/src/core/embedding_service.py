"""
Simplified Embedding Service for Prompt Injection RAG
Handles embedding generation using SentenceTransformers.
"""

import logging
from pathlib import Path
from typing import List, Optional

import numpy as np


class EmbeddingService:
    """Simplified service for generating embeddings from text."""

    def __init__(self, model_path: str, device: Optional[str] = None):
        """
        Initialize the embedding service.

        Args:
            model_path: Path to the SentenceTransformers model
            device: Device to use ('cpu', 'mps', 'cuda'). If None, auto-detect.
        """
        self.model_path = Path(model_path)
        self.device = device or self._get_optimal_device()
        self.model = None
        self.logger = logging.getLogger(__name__)
        self._load_model()

    def _get_optimal_device(self) -> str:
        """Determine the best device for embedding generation."""
        try:
            import torch
            if hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
                return "mps"
            if torch.cuda.is_available():
                return "cuda"
        except Exception:
            pass
        return "cpu"

    def _load_model(self):
        """Load the SentenceTransformers model."""
        try:
            from sentence_transformers import SentenceTransformer
            self.logger.info(f"Loading embedding model: {self.model_path} on {self.device}")
            self.model = SentenceTransformer(str(self.model_path), device=self.device)

            embedding_dim = self.model.get_sentence_embedding_dimension()
            max_seq_len = getattr(self.model, 'max_seq_length', 256)

            self.logger.info(f"Model loaded - Dim: {embedding_dim}, Max seq: {max_seq_len}")
        except Exception as e:
            self.logger.error(f"Failed to load embedding model: {e}")
            raise RuntimeError(f"Cannot initialize embedding model from '{self.model_path}'") from e

    def get_embedding_dimension(self) -> int:
        """Get the dimension of embeddings produced by this model."""
        return self.model.get_sentence_embedding_dimension()

    def embed_text(self, text: str) -> np.ndarray:
        """Generate embedding for a single text."""
        return self.embed_texts([text])[0]

    def embed_texts(self, texts: List[str]) -> List[np.ndarray]:
        """
        Generate embeddings for a list of texts.

        Args:
            texts: List of texts to embed

        Returns:
            List of normalized embedding vectors as numpy arrays
        """
        if not texts:
            return []

        embeddings = self.model.encode(
            texts,
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=False
        )

        return list(embeddings)

    def similarity(self, embedding1: np.ndarray, embedding2: np.ndarray) -> float:
        """Calculate cosine similarity between two embeddings."""
        return float(np.dot(embedding1, embedding2))

    def batch_similarity(self, query_embedding: np.ndarray,
                        embeddings: List[np.ndarray]) -> np.ndarray:
        """Calculate cosine similarity between query embedding and a batch of embeddings."""
        embeddings_matrix = np.vstack(embeddings)
        return np.dot(embeddings_matrix, query_embedding)


def create_embedding_service(model_path: str, **kwargs) -> EmbeddingService:
    """Factory function to create an EmbeddingService instance."""
    return EmbeddingService(model_path, **kwargs)