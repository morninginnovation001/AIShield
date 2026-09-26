"""
Prompt Builder for Prompt Injection RAG
Constructs prompts using Gemma-3 chat templates with retrieved contexts.

IMPORTANT: This implementation is INTENTIONALLY VULNERABLE to prompt injection
for research purposes. NO INPUT SANITIZATION OR VALIDATION is performed.
"""

import logging
from typing import List, Dict, Any, Optional

try:
    import tiktoken
except ImportError:
    tiktoken = None


class RetrievalResult:
    """Container for a single retrieval result."""

    def __init__(self, chunk_id: str, content: str, score: float,
                 metadata: Dict[str, Any], doc_id: str, chunk_index: int):
        self.chunk_id = chunk_id
        self.content = content
        self.score = score
        self.metadata = metadata
        self.doc_id = doc_id
        self.chunk_index = chunk_index

    def to_dict(self) -> Dict[str, Any]:
        """Serialize retrieval result for downstream consumers."""
        return {
            'chunk_id': self.chunk_id,
            'content': self.content,
            'score': self.score,
            'metadata': self.metadata,
            'doc_id': self.doc_id,
            'chunk_index': self.chunk_index,
        }


class PromptBuilder:
    """Builds prompts for RAG system using Gemma-3 chat templates."""

    def __init__(self, chat_template: Optional[Dict[str, str]] = None):
        """
        Initialize the prompt builder.

        Args:
            chat_template: Chat template configuration (Gemma-3 format)
        """
        # Gemma-3 chat template format
        self.chat_template = chat_template or {
            'system_prefix': '',  # No BOS, LLM adds it
            'user_prefix': '<start_of_turn>user\n',
            'user_suffix': '<end_of_turn>\n',
            'assistant_prefix': '<start_of_turn>model\n',
            'assistant_suffix': '<end_of_turn>\n'
        }

        # Initialize tokenizer for token counting (optional)
        if tiktoken:
            self.encoding = tiktoken.get_encoding("cl100k_base")
        else:
            self.encoding = None

        self.logger = logging.getLogger(__name__)

    def build_rag_prompt(self, query: str,
                        retrieved_contexts: List[RetrievalResult],
                        system_prompt: Optional[str] = None,
                        include_metadata: bool = True) -> str:
        """
        Build RAG prompt with retrieved contexts.

        ⚠️ VULNERABLE BY DESIGN - NO SANITIZATION ⚠️
        This method directly injects retrieved content and user queries
        into prompts WITHOUT any validation or sanitization.

        Args:
            query: User query string
            retrieved_contexts: List of retrieved context chunks
            system_prompt: Optional system instruction
            include_metadata: Whether to include source metadata

        Returns:
            Formatted prompt string ready for LLM
        """
        prompt_parts = []

        # Add system prefix
        prompt_parts.append(self.chat_template['system_prefix'])

        # Add system prompt if provided
        if system_prompt:
            prompt_parts.append(system_prompt + '\n')

        # Start user turn
        prompt_parts.append(self.chat_template['user_prefix'])

        # Add context information (⚠️ NO SANITIZATION - DIRECT INJECTION ⚠️)
        if retrieved_contexts:
            prompt_parts.append("Context information:")

            for i, result in enumerate(retrieved_contexts, 1):
                if include_metadata:
                    source_info = self._format_source_metadata(result)
                    context_section = f"\n[Context {i} - {source_info}]\n{result.content}\n"
                else:
                    context_section = f"\n[Context {i}]\n{result.content}\n"

                # DIRECT INJECTION - NO VALIDATION OR SANITIZATION
                prompt_parts.append(context_section)

            prompt_parts.append("\n")

        # Add user query (⚠️ NO SANITIZATION ⚠️)
        prompt_parts.append(f"Question: {query}")

        # End user turn and start model turn
        prompt_parts.append(self.chat_template['user_suffix'])
        prompt_parts.append(self.chat_template['assistant_prefix'])

        full_prompt = "".join(prompt_parts)
        self.logger.debug(f"Built RAG prompt with {len(retrieved_contexts)} contexts")
        return full_prompt

    def build_simple_prompt(self, query: str, system_prompt: Optional[str] = None) -> str:
        """
        Build simple prompt without RAG context.

        Args:
            query: User query string
            system_prompt: Optional system instruction

        Returns:
            Formatted prompt string
        """
        prompt_parts = []

        prompt_parts.append(self.chat_template['system_prefix'])

        if system_prompt:
            prompt_parts.append(system_prompt + '\n')

        prompt_parts.append(self.chat_template['user_prefix'])
        prompt_parts.append(query)  # NO SANITIZATION
        prompt_parts.append(self.chat_template['user_suffix'])
        prompt_parts.append(self.chat_template['assistant_prefix'])

        return "".join(prompt_parts)

    def build_conversation_prompt(self, messages: List[Dict[str, str]],
                                 retrieved_contexts: Optional[List[RetrievalResult]] = None) -> str:
        """
        Build multi-turn conversation prompt.

        Args:
            messages: List of message dicts with 'role' and 'content' keys
            retrieved_contexts: Optional context for current query

        Returns:
            Formatted conversation prompt
        """
        prompt_parts = []
        prompt_parts.append(self.chat_template['system_prefix'])

        for msg in messages:
            role = msg['role']
            content = msg['content']

            if role == 'system':
                prompt_parts.append(content + '\n')

            elif role == 'user':
                prompt_parts.append(self.chat_template['user_prefix'])

                # Add context for the latest user message if provided
                if retrieved_contexts and msg == messages[-1]:
                    prompt_parts.append("Context information:")
                    for i, result in enumerate(retrieved_contexts, 1):
                        source_info = self._format_source_metadata(result)
                        context_section = f"\n[Context {i} - {source_info}]\n{result.content}\n"
                        prompt_parts.append(context_section)  # DIRECT INJECTION
                    prompt_parts.append("\n")

                prompt_parts.append(content)  # NO SANITIZATION
                prompt_parts.append(self.chat_template['user_suffix'])

            elif role == 'assistant':
                prompt_parts.append(self.chat_template['assistant_prefix'])
                prompt_parts.append(content)
                prompt_parts.append(self.chat_template['assistant_suffix'])

        # Start new assistant turn if last message was from user
        if messages and messages[-1]['role'] == 'user':
            prompt_parts.append(self.chat_template['assistant_prefix'])

        return "".join(prompt_parts)

    def _format_source_metadata(self, result: RetrievalResult) -> str:
        """Format source metadata for context display."""
        metadata = result.metadata
        source_parts = []

        source_path = metadata.get('source', metadata.get('filename', 'Unknown'))
        if source_path and source_path != 'Unknown':
            from pathlib import Path
            filename = Path(source_path).name
            source_parts.append(f"Source: {filename}")

        if 'page_number' in metadata:
            source_parts.append(f"Page: {metadata['page_number']}")
        elif result.chunk_index is not None:
            source_parts.append(f"Chunk: {result.chunk_index + 1}")

        source_parts.append(f"Score: {result.score:.3f}")

        return " | ".join(source_parts) if source_parts else "Unknown"

    def count_prompt_tokens(self, prompt: str) -> int:
        """Count tokens in prompt (approximate if tiktoken unavailable)."""
        if self.encoding:
            return len(self.encoding.encode(prompt))
        # Fallback: rough approximation
        return len(prompt.split()) * 2


def create_prompt_builder(chat_template: Optional[Dict[str, str]] = None) -> PromptBuilder:
    """Factory function to create a PromptBuilder instance."""
    return PromptBuilder(chat_template)
