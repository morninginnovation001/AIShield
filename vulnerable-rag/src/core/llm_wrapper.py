"""
Simplified LLM Wrapper for Prompt Injection RAG
Handles language model inference using llama-cpp-python with Gemma 3 4B.
"""

import logging
import time
from pathlib import Path
from typing import Dict, Any, Optional, Generator


class LLMWrapper:
    """Wrapper for llama-cpp language model with Metal acceleration."""

    def __init__(self, model_path: str, **kwargs):
        """
        Initialize the LLM wrapper.

        Args:
            model_path: Path to the GGUF model file (Gemma 3 4B)
            **kwargs: Configuration parameters (n_ctx, temperature, etc.)
        """
        self.model_path = Path(model_path).expanduser().resolve()
        if not self.model_path.exists():
            raise FileNotFoundError(f"Model file not found: {model_path}")

        # Configuration parameters
        self.n_ctx = kwargs.get('n_ctx', 8192)
        self.n_batch = kwargs.get('n_batch', 512)
        self.n_threads = kwargs.get('n_threads', 8)
        self.n_gpu_layers = kwargs.get('n_gpu_layers', -1)  # -1 = all layers on GPU
        self.temperature = kwargs.get('temperature', 0.7)
        self.top_p = kwargs.get('top_p', 0.95)
        self.max_tokens = kwargs.get('max_tokens', 2048)

        self.model = None
        self.logger = logging.getLogger(__name__)
        self._load_model()

    def _load_model(self):
        """Load the language model."""
        self.logger.info(f"Loading LLM model: {self.model_path}")
        start_time = time.time()

        try:
            from llama_cpp import Llama

            self.model = Llama(
                model_path=str(self.model_path),
                n_ctx=self.n_ctx,
                n_batch=self.n_batch,
                n_threads=self.n_threads,
                n_gpu_layers=self.n_gpu_layers,
                verbose=False
            )

            load_time = time.time() - start_time
            self.logger.info(f"Model loaded in {load_time:.2f}s")
            self.logger.info(f"  Context window: {self.n_ctx}")
            self.logger.info(f"  GPU layers: {self.n_gpu_layers}")

        except Exception as e:
            self.logger.error(f"Failed to load model: {e}")
            raise

    def generate(self, prompt: str, max_tokens: Optional[int] = None,
                temperature: Optional[float] = None,
                stop_sequences: Optional[list] = None) -> str:
        """
        Generate text completion for a prompt.

        Args:
            prompt: Input text prompt
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            stop_sequences: List of stop sequences

        Returns:
            Generated text completion
        """
        max_tokens = max_tokens or self.max_tokens
        temperature = temperature if temperature is not None else self.temperature

        response = self.model(
            prompt,
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=self.top_p,
            stop=stop_sequences or [],
            echo=False
        )

        return response['choices'][0]['text']

    def generate_stream(self, prompt: str, max_tokens: Optional[int] = None,
                       temperature: Optional[float] = None,
                       stop_sequences: Optional[list] = None) -> Generator[str, None, None]:
        """
        Generate streaming text completion.

        Args:
            prompt: Input text prompt
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            stop_sequences: List of stop sequences

        Yields:
            Generated text tokens
        """
        max_tokens = max_tokens or self.max_tokens
        temperature = temperature if temperature is not None else self.temperature

        stream = self.model(
            prompt,
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=self.top_p,
            stop=stop_sequences or [],
            stream=True,
            echo=False
        )

        for chunk in stream:
            token = chunk['choices'][0]['text']
            yield token

    def count_tokens(self, text: str) -> int:
        """Count tokens in text using the model's tokenizer."""
        tokens = self.model.tokenize(text.encode('utf-8'))
        return len(tokens)

    def get_context_remaining(self, current_prompt: str) -> int:
        """Calculate remaining context window space."""
        used_tokens = self.count_tokens(current_prompt)
        return max(0, self.n_ctx - used_tokens)


def create_llm_wrapper(model_path: str, config_params: Dict[str, Any]) -> LLMWrapper:
    """Factory function to create an LLMWrapper instance."""
    return LLMWrapper(model_path, **config_params)