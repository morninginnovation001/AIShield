"""
Mock Web Search Tool for Agentic RAG
Simulates web search for testing attack vectors.
"""

import logging
from typing import Dict, Any, List


class WebSearchTool:
    """
    Mock web search tool for research.

    Simulates search results - useful for testing attacks
    where malicious content is injected via search results.
    """

    def __init__(self, mock_mode: bool = True, max_results: int = 5):
        """
        Initialize web search tool.

        Args:
            mock_mode: Use mock search results (True for research)
            max_results: Maximum number of results to return
        """
        self.name = "web_search"
        self.description = "Searches the web and returns relevant results."
        self.parameters = {
            "query": {
                "type": "string",
                "description": "Search query",
                "required": True
            },
            "num_results": {
                "type": "integer",
                "description": "Number of results to return (default: 3)",
                "required": False
            }
        }

        self.mock_mode = mock_mode
        self.max_results = max_results
        self.logger = logging.getLogger(__name__)

        # Mock search results database
        self.mock_results = {
            "machine learning": [
                {
                    "title": "Machine Learning - Wikipedia",
                    "url": "https://en.wikipedia.org/wiki/Machine_learning",
                    "snippet": "Machine learning is a subset of artificial intelligence that enables systems to learn and improve from experience."
                },
                {
                    "title": "What is Machine Learning? | IBM",
                    "url": "https://www.ibm.com/topics/machine-learning",
                    "snippet": "Machine learning is a branch of AI focused on building systems that learn from data."
                }
            ],
            "default": [
                {
                    "title": "Search Result",
                    "url": "https://example.com/result",
                    "snippet": "This is a mock search result for testing purposes."
                }
            ]
        }

    def execute(self, query: str, num_results: int = 3) -> Dict[str, Any]:
        """
        Execute web search (mock mode).

        Args:
            query: Search query
            num_results: Number of results to return

        Returns:
            Dictionary with search results
        """
        try:
            num_results = min(num_results, self.max_results)

            if self.mock_mode:
                # Return mock results
                results = self._mock_search(query, num_results)
            else:
                # Real search would go here (not implemented for security)
                return {
                    'success': False,
                    'error': "Real web search not implemented",
                    'results': []
                }

            self.logger.info(f"WebSearch: '{query}' returned {len(results)} results")

            return {
                'success': True,
                'query': query,
                'results': results,
                'num_results': len(results),
                'error': None
            }

        except Exception as e:
            self.logger.error(f"WebSearch error: {e}")
            return {
                'success': False,
                'error': str(e),
                'results': []
            }

    def _mock_search(self, query: str, num_results: int) -> List[Dict[str, str]]:
        """Return mock search results."""
        query_lower = query.lower()

        # Find matching mock results
        for key in self.mock_results:
            if key in query_lower:
                return self.mock_results[key][:num_results]

        # Return default results
        return self.mock_results["default"][:num_results]

    def get_schema(self) -> Dict[str, Any]:
        """Get tool schema for function calling."""
        return {
            'name': self.name,
            'description': self.description,
            'parameters': self.parameters
        }