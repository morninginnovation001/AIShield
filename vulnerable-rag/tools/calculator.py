"""
Calculator Tool for Agentic RAG
Performs basic mathematical calculations.
"""

import logging
import re
from typing import Dict, Any


class CalculatorTool:
    """Simple calculator tool for mathematical operations."""

    def __init__(self):
        self.name = "calculator"
        self.description = "Performs mathematical calculations. Supports basic arithmetic operations."
        self.parameters = {
            "expression": {
                "type": "string",
                "description": "Mathematical expression to evaluate (e.g., '2 + 2', '15 * 23')",
                "required": True
            }
        }
        self.logger = logging.getLogger(__name__)

    def execute(self, expression: str) -> Dict[str, Any]:
        """
        Execute a mathematical calculation.

        Args:
            expression: Mathematical expression as string

        Returns:
            Dictionary with result and status
        """
        try:
            # Basic sanitization - only allow numbers and operators
            # NOTE: Still vulnerable to injection if not properly validated
            allowed_chars = re.compile(r'^[0-9+\-*/().\s]+$')

            if not allowed_chars.match(expression):
                return {
                    'success': False,
                    'error': f"Invalid characters in expression: {expression}",
                    'result': None
                }

            # Evaluate expression (⚠️ VULNERABLE to code injection if validation bypassed)
            result = eval(expression)

            self.logger.info(f"Calculator: {expression} = {result}")

            return {
                'success': True,
                'result': float(result),
                'expression': expression,
                'error': None
            }

        except ZeroDivisionError:
            return {
                'success': False,
                'error': "Division by zero",
                'result': None
            }
        except Exception as e:
            self.logger.error(f"Calculator error: {e}")
            return {
                'success': False,
                'error': str(e),
                'result': None
            }

    def get_schema(self) -> Dict[str, Any]:
        """Get tool schema for function calling."""
        return {
            'name': self.name,
            'description': self.description,
            'parameters': self.parameters
        }