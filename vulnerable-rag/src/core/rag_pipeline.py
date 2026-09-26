"""
Simplified RAG Pipeline for Prompt Injection RAG
Integrates retrieval, prompt building, and generation.
"""

import logging
from typing import Dict, Any, List, Optional

from .retriever import Retriever, create_retriever
from .prompt_builder import PromptBuilder, create_prompt_builder
from .llm_wrapper import LLMWrapper, create_llm_wrapper

try:
    from ..defenses.defense_manager import DefenseManager
except Exception:
    DefenseManager = None  # type: ignore


class RAGPipeline:
    """Simplified RAG pipeline for prompt injection research."""

    def __init__(self, db_path: str, embedding_model_path: str, llm_model_path: str,
                 config: Optional[Dict[str, Any]] = None,
                 defense_manager: Optional["DefenseManager"] = None):
        """
        Initialize the RAG pipeline.

        Args:
            db_path: Path to vector database
            embedding_model_path: Path to embedding model
            llm_model_path: Path to LLM model (Gemma 3 4B)
            config: Optional configuration dictionary
        """
        self.db_path = db_path
        self.embedding_model_path = embedding_model_path
        self.llm_model_path = llm_model_path
        self.config = config or {}

        self.logger = logging.getLogger(__name__)
        self.defense_manager = defense_manager

        # Initialize components
        self.logger.info("Initializing RAG pipeline...")

        self.retriever = create_retriever(
            db_path,
            embedding_model_path,
            embedding_dimension=self.config.get('embedding_dimension', 384)
        )

        self.prompt_builder = create_prompt_builder(
            self.config.get('chat_template')
        )

        llm_params = self.config.get('llm_params', {})
        self.llm_wrapper = create_llm_wrapper(llm_model_path, llm_params)

        self.logger.info("RAG pipeline initialized successfully")

    def query(self, user_query: str, k: int = 5, retrieval_method: str = "vector",
             system_prompt: Optional[str] = None, collection_id: Optional[str] = None,
             **generation_kwargs) -> Dict[str, Any]:
        """
        Execute a RAG query.

        Args:
            user_query: User question
            k: Number of contexts to retrieve
            retrieval_method: Retrieval method ('vector', 'keyword', 'hybrid')
            system_prompt: Optional system instruction
            collection_id: Optional collection to search
            **generation_kwargs: Additional generation parameters

        Returns:
            Dictionary with answer, retrieved contexts, and metadata
        """
        self.logger.info(f"Processing query: {user_query[:100]}...")

        # Step 1: Retrieve relevant contexts
        retrieved_contexts = self.retriever.retrieve(
            user_query,
            k=k,
            method=retrieval_method,
            collection_id=collection_id
        )

        self.logger.info(f"Retrieved {len(retrieved_contexts)} contexts")

        # Optional: Apply input-stage defenses (sanitization, prompt engineering)
        effective_query = user_query
        effective_system_prompt = system_prompt
        if self.defense_manager is not None:
            contexts_text = [ctx.content for ctx in retrieved_contexts]
            ok, components, _ = self.defense_manager.apply_input_defenses(
                user_query, contexts_text, system_prompt
            )
            effective_query = components.get("query", user_query)
            new_contexts = components.get("contexts", contexts_text)
            effective_system_prompt = components.get("system_prompt", system_prompt)
            # Replace contents on the RetrievalResult objects
            for i, ctx in enumerate(retrieved_contexts):
                if i < len(new_contexts):
                    ctx.content = new_contexts[i]

        # Step 2: Build prompt (⚠️ VULNERABLE BY DESIGN ⚠️)
        prompt = self.prompt_builder.build_rag_prompt(
            effective_query,
            retrieved_contexts,
            system_prompt=effective_system_prompt
        )

        # Step 3: Generate answer
        answer = self.llm_wrapper.generate(prompt, **generation_kwargs)

        # Return results
        return {
            'query': user_query,
            'answer': answer,
            'contexts': [ctx.to_dict() if hasattr(ctx, 'to_dict') else ctx for ctx in retrieved_contexts],
            'retrieval_method': retrieval_method,
            'num_contexts': len(retrieved_contexts),
            'prompt_tokens': self.llm_wrapper.count_tokens(prompt),
            'collection_id': collection_id
        }

    def query_without_rag(self, user_query: str, system_prompt: Optional[str] = None,
                         **generation_kwargs) -> Dict[str, Any]:
        """
        Execute a query without RAG (direct LLM generation).

        Args:
            user_query: User question
            system_prompt: Optional system instruction
            **generation_kwargs: Additional generation parameters

        Returns:
            Dictionary with answer and metadata
        """
        # Optional: apply input-stage defenses even for no-RAG prompt
        effective_query = user_query
        effective_system_prompt = system_prompt
        if self.defense_manager is not None:
            ok, components, _ = self.defense_manager.apply_input_defenses(user_query, [], system_prompt)
            effective_query = components.get("query", user_query)
            effective_system_prompt = components.get("system_prompt", system_prompt)

        prompt = self.prompt_builder.build_simple_prompt(effective_query, effective_system_prompt)
        answer = self.llm_wrapper.generate(prompt, **generation_kwargs)

        return {
            'query': user_query,
            'answer': answer,
            'contexts': [],
            'retrieval_method': 'none',
            'num_contexts': 0,
            'prompt_tokens': self.llm_wrapper.count_tokens(prompt)
        }


def create_rag_pipeline(db_path: str, embedding_model_path: str,
                       llm_model_path: str, config: Optional[Dict[str, Any]] = None,
                       defense_manager: Optional["DefenseManager"] = None) -> RAGPipeline:
    """Factory function to create a RAGPipeline instance."""
    return RAGPipeline(db_path, embedding_model_path, llm_model_path, config, defense_manager)
