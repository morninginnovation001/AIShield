"""
Simple Document Ingestion for Prompt Injection RAG
Handles document loading, chunking, and ingestion into vector database.
"""

import hashlib
import logging
import uuid
from pathlib import Path
from typing import List, Dict, Any, Optional

from ..core.embedding_service import EmbeddingService
from ..core.vector_database import VectorDatabase


class DocumentChunk:
    """Represents a chunk of text from a document."""

    def __init__(self, content: str, chunk_index: int, metadata: Dict[str, Any]):
        self.content = content
        self.chunk_index = chunk_index
        self.metadata = metadata
        self.chunk_id = str(uuid.uuid4())


class DocumentIngester:
    """Simple document ingester for RAG system."""

    def __init__(self, vector_db: VectorDatabase, embedding_service: EmbeddingService):
        """
        Initialize document ingester.

        Args:
            vector_db: Vector database instance
            embedding_service: Embedding service instance
        """
        self.vector_db = vector_db
        self.embedding_service = embedding_service
        self.logger = logging.getLogger(__name__)

    def ingest_text(self, text: str, source: str, chunk_size: int = 512,
                   chunk_overlap: int = 128, metadata: Optional[Dict] = None,
                   collection_id: str = 'default') -> int:
        """
        Ingest a text document.

        Args:
            text: Document text content
            source: Source identifier (filename, URL, etc.)
            chunk_size: Number of characters per chunk
            chunk_overlap: Overlap between chunks
            metadata: Additional metadata
            collection_id: Collection to add document to

        Returns:
            Number of chunks created
        """
        self.logger.info(f"Ingesting document: {source}")

        # Create document ID
        doc_id = hashlib.md5(source.encode()).hexdigest()

        # Add document to database
        doc_metadata = metadata.copy() if metadata else {}
        doc_metadata.update({'source': source, 'length': len(text)})
        self.vector_db.add_document(doc_id, source, doc_metadata, collection_id)

        # Chunk the text
        chunks = self._chunk_text(text, chunk_size, chunk_overlap)

        # Create chunk objects with metadata
        chunk_objects = []
        for i, chunk_text in enumerate(chunks):
            chunk_metadata = {
                'doc_id': doc_id,
                'source': source,
                'chunk_index': i,
                'total_chunks': len(chunks)
            }
            chunk_objects.append(DocumentChunk(chunk_text, i, chunk_metadata))

        # Generate embeddings
        self.logger.info(f"Generating embeddings for {len(chunk_objects)} chunks...")
        embeddings = self.embedding_service.embed_texts([c.content for c in chunk_objects])

        # Add chunks to database
        for chunk, embedding in zip(chunk_objects, embeddings):
            self.vector_db.add_chunk(
                chunk.chunk_id,
                doc_id,
                chunk.chunk_index,
                chunk.content,
                embedding,
                chunk.metadata,
                collection_id
            )

        self.logger.info(f"Ingested {len(chunk_objects)} chunks from {source}")
        return len(chunk_objects)

    def ingest_file(self, file_path: Path, chunk_size: int = 512,
                   chunk_overlap: int = 128, metadata: Optional[Dict] = None,
                   collection_id: str = 'default') -> int:
        """
        Ingest a text file.

        Args:
            file_path: Path to text file
            chunk_size: Number of characters per chunk
            chunk_overlap: Overlap between chunks
            metadata: Additional metadata
            collection_id: Collection to add document to

        Returns:
            Number of chunks created
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                text = f.read()

            return self.ingest_text(
                text,
                str(file_path),
                chunk_size,
                chunk_overlap,
                metadata,
                collection_id
            )
        except Exception as e:
            self.logger.error(f"Failed to ingest file {file_path}: {e}")
            raise

    def ingest_directory(self, dir_path: Path, pattern: str = "*.txt",
                        chunk_size: int = 512, chunk_overlap: int = 128,
                        collection_id: str = 'default') -> int:
        """
        Ingest all files matching pattern in a directory.

        Args:
            dir_path: Directory path
            pattern: File pattern to match
            chunk_size: Number of characters per chunk
            chunk_overlap: Overlap between chunks
            collection_id: Collection to add documents to

        Returns:
            Total number of chunks created
        """
        total_chunks = 0
        files = list(dir_path.glob(pattern))

        self.logger.info(f"Ingesting {len(files)} files from {dir_path}")

        for file_path in files:
            try:
                chunks = self.ingest_file(
                    file_path,
                    chunk_size,
                    chunk_overlap,
                    collection_id=collection_id
                )
                total_chunks += chunks
            except Exception as e:
                self.logger.error(f"Skipping {file_path}: {e}")

        self.logger.info(f"Ingested {len(files)} files, {total_chunks} total chunks")
        return total_chunks

    def _chunk_text(self, text: str, chunk_size: int, chunk_overlap: int) -> List[str]:
        """
        Split text into overlapping chunks.

        Args:
            text: Text to chunk
            chunk_size: Characters per chunk
            chunk_overlap: Overlap between chunks

        Returns:
            List of text chunks
        """
        if len(text) <= chunk_size:
            return [text]

        chunks = []
        start = 0

        while start < len(text):
            end = start + chunk_size
            chunk = text[start:end]
            chunks.append(chunk)

            # Move forward by (chunk_size - overlap)
            start += (chunk_size - chunk_overlap)

        return chunks


def create_document_ingester(db_path: str, embedding_model_path: str,
                            embedding_dimension: int = 384) -> DocumentIngester:
    """Factory function to create a DocumentIngester instance."""
    vector_db = VectorDatabase(db_path, embedding_dimension)
    embedding_service = EmbeddingService(embedding_model_path)
    return DocumentIngester(vector_db, embedding_service)