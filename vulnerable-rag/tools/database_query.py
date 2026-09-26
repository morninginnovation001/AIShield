"""
Mock Database Query Tool for Agentic RAG
Simulates database queries for testing SQL injection-style attacks.
"""

import logging
from typing import Dict, Any, List


class DatabaseQueryTool:
    """
    Mock database query tool for research.

    Simulates a database - useful for testing SQL injection-style
    attacks in tool parameters.
    """

    def __init__(self, mock_mode: bool = True, max_results: int = 100):
        """
        Initialize database query tool.

        Args:
            mock_mode: Use mock database (True for research)
            max_results: Maximum results to return
        """
        self.name = "database_query"
        self.description = "Queries a database and returns matching records."
        self.parameters = {
            "query": {
                "type": "string",
                "description": "Database query (SQL-like syntax)",
                "required": True
            }
        }

        self.mock_mode = mock_mode
        self.max_results = max_results
        self.logger = logging.getLogger(__name__)

        # Mock database
        self.mock_database = {
            "users": [
                {"id": 1, "name": "Alice", "role": "admin"},
                {"id": 2, "name": "Bob", "role": "user"},
                {"id": 3, "name": "Charlie", "role": "user"}
            ],
            "products": [
                {"id": 1, "name": "Laptop", "price": 999.99},
                {"id": 2, "name": "Phone", "price": 699.99},
                {"id": 3, "name": "Tablet", "price": 499.99}
            ]
        }

    def execute(self, query: str) -> Dict[str, Any]:
        """
        Execute database query (mock mode).

        ⚠️ VULNERABLE BY DESIGN - minimal validation for research.

        Args:
            query: Database query string

        Returns:
            Dictionary with query results
        """
        try:
            # Check for dangerous operations (optional defense)
            dangerous_keywords = ["DROP", "DELETE", "UPDATE", "INSERT", "ALTER"]
            query_upper = query.upper()

            for keyword in dangerous_keywords:
                if keyword in query_upper:
                    self.logger.warning(f"Blocked dangerous query: {query}")
                    return {
                        'success': False,
                        'error': f"Dangerous operation detected: {keyword}",
                        'results': []
                    }

            if self.mock_mode:
                results = self._mock_query(query)
            else:
                return {
                    'success': False,
                    'error': "Real database not implemented",
                    'results': []
                }

            self.logger.info(f"DatabaseQuery: '{query}' returned {len(results)} results")

            return {
                'success': True,
                'query': query,
                'results': results[:self.max_results],
                'num_results': len(results),
                'error': None
            }

        except Exception as e:
            self.logger.error(f"DatabaseQuery error: {e}")
            return {
                'success': False,
                'error': str(e),
                'results': []
            }

    def _mock_query(self, query: str) -> List[Dict[str, Any]]:
        """Execute mock query."""
        query_lower = query.lower()

        # Simple query parsing
        if "from users" in query_lower:
            return self.mock_database["users"]
        elif "from products" in query_lower:
            return self.mock_database["products"]
        else:
            return []

    def get_schema(self) -> Dict[str, Any]:
        """Get tool schema for function calling."""
        return {
            'name': self.name,
            'description': self.description,
            'parameters': self.parameters
        }