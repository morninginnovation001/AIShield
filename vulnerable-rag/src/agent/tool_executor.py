"""
Tool Executor for Agentic RAG
Executes parsed tool calls with optional safety checks.
"""

import logging
from typing import Dict, Any, Optional

from .tool_registry import ToolRegistry
from .tool_parser import ToolCall


class ToolExecutionResult:
    """Result of a tool execution."""

    def __init__(self, success: bool, result: Any = None, error: Optional[str] = None,
                 tool_call: Optional[ToolCall] = None):
        self.success = success
        self.result = result
        self.error = error
        self.tool_call = tool_call

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'success': self.success,
            'result': self.result,
            'error': self.error,
            'tool_name': self.tool_call.tool_name if self.tool_call else None,
            'parameters': self.tool_call.parameters if self.tool_call else None
        }

    def __repr__(self):
        return f"ToolExecutionResult(success={self.success}, error={self.error})"


class ToolExecutor:
    """Executes tool calls with optional safety checks."""

    def __init__(self, tool_registry: ToolRegistry, enable_logging: bool = True,
                 require_approval: bool = False):
        """
        Initialize tool executor.

        Args:
            tool_registry: ToolRegistry instance
            enable_logging: Log all tool executions
            require_approval: Require human approval for tool execution (research feature)
        """
        self.tool_registry = tool_registry
        self.enable_logging = enable_logging
        self.require_approval = require_approval
        self.logger = logging.getLogger(__name__)

        # Execution statistics
        self.execution_count = 0
        self.success_count = 0
        self.failure_count = 0

    def execute(self, tool_call: ToolCall) -> ToolExecutionResult:
        """
        Execute a tool call.

        Args:
            tool_call: Parsed ToolCall object

        Returns:
            ToolExecutionResult
        """
        self.execution_count += 1

        if self.enable_logging:
            self.logger.info(f"Executing tool: {tool_call}")

        # Validate tool exists
        tool = self.tool_registry.get_tool(tool_call.tool_name)
        if not tool:
            self.failure_count += 1
            error_msg = f"Tool '{tool_call.tool_name}' not found"
            self.logger.error(error_msg)
            return ToolExecutionResult(False, error=error_msg, tool_call=tool_call)

        # Validate parameters
        is_valid, validation_error = self.tool_registry.validate_tool_call(
            tool_call.tool_name,
            tool_call.parameters
        )

        if not is_valid:
            self.failure_count += 1
            self.logger.error(f"Tool validation failed: {validation_error}")
            return ToolExecutionResult(False, error=validation_error, tool_call=tool_call)

        # Optional: Require approval (for defense research)
        if self.require_approval:
            approved = self._request_approval(tool_call)
            if not approved:
                self.failure_count += 1
                return ToolExecutionResult(
                    False,
                    error="Tool execution not approved",
                    tool_call=tool_call
                )

        # Execute tool
        try:
            result = tool.execute(**tool_call.parameters)

            # Check if tool returned an error
            if isinstance(result, dict) and not result.get('success', True):
                self.failure_count += 1
                error = result.get('error', 'Unknown error')
                self.logger.warning(f"Tool execution failed: {error}")
                return ToolExecutionResult(False, result=result, error=error, tool_call=tool_call)

            self.success_count += 1
            if self.enable_logging:
                self.logger.info(f"Tool execution successful: {tool_call.tool_name}")

            return ToolExecutionResult(True, result=result, tool_call=tool_call)

        except Exception as e:
            self.failure_count += 1
            error_msg = f"Tool execution error: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            return ToolExecutionResult(False, error=error_msg, tool_call=tool_call)

    def _request_approval(self, tool_call: ToolCall) -> bool:
        """
        Request human approval for tool execution.

        For research purposes, this is a simple yes/no prompt.
        In production, this would be a proper approval workflow.
        """
        print(f"\n⚠️  TOOL EXECUTION APPROVAL REQUIRED ⚠️")
        print(f"Tool: {tool_call.tool_name}")
        print(f"Parameters: {tool_call.parameters}")
        response = input("Approve execution? (yes/no): ")
        return response.lower() in ['yes', 'y']

    def get_stats(self) -> Dict[str, Any]:
        """Get execution statistics."""
        return {
            'total_executions': self.execution_count,
            'successful': self.success_count,
            'failed': self.failure_count,
            'success_rate': self.success_count / self.execution_count if self.execution_count > 0 else 0
        }


def create_tool_executor(tool_registry: ToolRegistry, **kwargs) -> ToolExecutor:
    """Factory function to create a ToolExecutor."""
    return ToolExecutor(tool_registry, **kwargs)