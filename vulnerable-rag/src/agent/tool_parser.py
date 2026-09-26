"""
Tool Parser for Agentic RAG
Parses tool calls from Gemma 3 LLM outputs.

Gemma 3 doesn't have special tool call tokens, so we parse JSON structures.
"""

import json
import logging
import re
from typing import List, Dict, Any, Optional


class ToolCall:
    """Represents a parsed tool call."""

    def __init__(self, tool_name: str, parameters: Dict[str, Any], raw_text: str = ""):
        self.tool_name = tool_name
        self.parameters = parameters
        self.raw_text = raw_text

    def __repr__(self):
        return f"ToolCall(tool={self.tool_name}, params={self.parameters})"


class ToolParser:
    """Parses tool calls from LLM output."""

    def __init__(self, strict_validation: bool = False):
        """
        Initialize tool parser.

        Args:
            strict_validation: Require strict JSON validation (False for research)
        """
        self.strict_validation = strict_validation
        self.logger = logging.getLogger(__name__)

    def parse(self, text: str) -> List[ToolCall]:
        """
        Parse tool calls from LLM output.

        Supports multiple formats:
        1. JSON format: {"tool": "calculator", "args": {"expression": "2+2"}}
        2. Function format: calculator(expression="2+2")
        3. Action format: Action: calculator {"expression": "2+2"}

        Args:
            text: LLM output text

        Returns:
            List of parsed ToolCall objects
        """
        tool_calls = []

        # Try JSON format first
        json_calls = self._parse_json_format(text)
        tool_calls.extend(json_calls)

        # Try function call format
        if not tool_calls:
            func_calls = self._parse_function_format(text)
            tool_calls.extend(func_calls)

        # Try action format (ReACT style)
        if not tool_calls:
            action_calls = self._parse_action_format(text)
            tool_calls.extend(action_calls)

        return tool_calls

    def _parse_json_format(self, text: str) -> List[ToolCall]:
        """
        Parse JSON-formatted tool calls.

        Format: {"tool": "tool_name", "args": {...}} or
                {"tool_name": "tool_name", "parameters": {...}}
        """
        tool_calls = []

        # Find all JSON-like structures
        json_pattern = r'\{[^{}]*"tool"[^{}]*\}|\{[^{}]*"tool_name"[^{}]*\}'

        matches = re.finditer(json_pattern, text, re.DOTALL)

        for match in matches:
            try:
                json_str = match.group()
                data = json.loads(json_str)

                tool_name = data.get('tool') or data.get('tool_name')
                parameters = data.get('args') or data.get('parameters') or data.get('arguments') or {}

                if tool_name:
                    tool_call = ToolCall(tool_name, parameters, json_str)
                    tool_calls.append(tool_call)
                    self.logger.debug(f"Parsed JSON tool call: {tool_call}")

            except json.JSONDecodeError as e:
                if self.strict_validation:
                    self.logger.error(f"Failed to parse JSON: {e}")
                else:
                    # Try to extract tool name and params anyway (for attack research)
                    tool_call = self._fallback_parse(match.group())
                    if tool_call:
                        tool_calls.append(tool_call)

        return tool_calls

    def _parse_function_format(self, text: str) -> List[ToolCall]:
        """
        Parse function call format.

        Format: tool_name(arg1="value1", arg2="value2")
        """
        tool_calls = []

        # Pattern: function_name(args)
        func_pattern = r'(\w+)\((.*?)\)'

        matches = re.finditer(func_pattern, text)

        for match in matches:
            tool_name = match.group(1)
            args_str = match.group(2)

            # Parse arguments
            parameters = self._parse_args_string(args_str)

            tool_call = ToolCall(tool_name, parameters, match.group())
            tool_calls.append(tool_call)
            self.logger.debug(f"Parsed function tool call: {tool_call}")

        return tool_calls

    def _parse_action_format(self, text: str) -> List[ToolCall]:
        """
        Parse ReACT-style action format.

        Format: Action: tool_name {"arg1": "value1"}
                or Action: tool_name(arg1="value1")
        """
        tool_calls = []

        # Pattern: Action: tool_name ...
        action_pattern = r'Action:\s*(\w+)\s*(\{.*?\}|\(.*?\))?'

        matches = re.finditer(action_pattern, text, re.DOTALL)

        for match in matches:
            tool_name = match.group(1)
            args_part = match.group(2) if match.group(2) else ""

            parameters = {}
            if args_part:
                if args_part.startswith('{'):
                    # JSON args
                    try:
                        parameters = json.loads(args_part)
                    except json.JSONDecodeError:
                        parameters = self._fallback_parse_args(args_part)
                elif args_part.startswith('('):
                    # Function args
                    args_str = args_part[1:-1]  # Remove parentheses
                    parameters = self._parse_args_string(args_str)

            tool_call = ToolCall(tool_name, parameters, match.group())
            tool_calls.append(tool_call)
            self.logger.debug(f"Parsed action tool call: {tool_call}")

        return tool_calls

    def _parse_args_string(self, args_str: str) -> Dict[str, Any]:
        """Parse argument string like 'arg1="value1", arg2=123'."""
        parameters = {}

        # Split by comma (simple parsing)
        parts = args_str.split(',')

        for part in parts:
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                key = key.strip().strip('"\'')
                value = value.strip().strip('"\'')

                # Try to convert to appropriate type
                try:
                    # Try int
                    value = int(value)
                except ValueError:
                    try:
                        # Try float
                        value = float(value)
                    except ValueError:
                        # Keep as string
                        pass

                parameters[key] = value

        return parameters

    def _fallback_parse(self, text: str) -> Optional[ToolCall]:
        """Fallback parser for malformed JSON (for attack research)."""
        try:
            # Try to extract tool name and parameters with regex
            tool_match = re.search(r'"tool":\s*"(\w+)"', text)
            if not tool_match:
                tool_match = re.search(r'"tool_name":\s*"(\w+)"', text)

            if tool_match:
                tool_name = tool_match.group(1)
                parameters = self._fallback_parse_args(text)
                return ToolCall(tool_name, parameters, text)

        except Exception as e:
            self.logger.debug(f"Fallback parse failed: {e}")

        return None

    def _fallback_parse_args(self, text: str) -> Dict[str, Any]:
        """Fallback argument parser."""
        parameters = {}

        # Extract key-value pairs
        pattern = r'"(\w+)":\s*"([^"]*)"'
        matches = re.finditer(pattern, text)

        for match in matches:
            key = match.group(1)
            value = match.group(2)
            if key not in ['tool', 'tool_name']:
                parameters[key] = value

        return parameters


def create_tool_parser(strict_validation: bool = False) -> ToolParser:
    """Factory function to create a ToolParser."""
    return ToolParser(strict_validation)