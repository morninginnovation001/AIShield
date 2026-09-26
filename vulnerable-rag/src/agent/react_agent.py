"""
ReACT Agent for Agentic RAG
Implements Reasoning + Acting loop for multi-step problem solving.
"""

import logging
from typing import Dict, Any, List, Optional
from pathlib import Path

try:
    import yaml
except Exception:
    yaml = None

from ..core.rag_pipeline import RAGPipeline
from .tool_registry import ToolRegistry, build_tool_registry_from_config
from .tool_parser import ToolParser
from .tool_executor import ToolExecutor
try:
    from ..defenses.defense_manager import DefenseManager, create_defense_manager
except Exception:
    DefenseManager = None  # type: ignore


class ReACTAgent:
    """
    ReACT (Reasoning + Acting) Agent.

    Implements iterative loop:
    1. Thought: Agent reasons about the problem
    2. Action: Agent decides to use a tool or provide final answer
    3. Observation: Tool execution result
    4. Repeat until final answer
    """

    def __init__(self, rag_pipeline: RAGPipeline, tool_registry: ToolRegistry,
                 max_iterations: int = 10, temperature: float = 0.7,
                 parser_strict_validation: bool = False,
                 enable_logging: bool = True,
                 require_approval: bool = False,
                 defense_manager: Optional["DefenseManager"] = None):
        """
        Initialize ReACT agent.

        Args:
            rag_pipeline: RAG pipeline for context retrieval and LLM generation
            tool_registry: Registry of available tools
            max_iterations: Maximum reasoning iterations
            temperature: LLM temperature for reasoning
        """
        self.rag_pipeline = rag_pipeline
        self.tool_registry = tool_registry
        self.max_iterations = max_iterations
        self.temperature = temperature

        self.tool_parser = ToolParser(strict_validation=parser_strict_validation)
        self.tool_executor = ToolExecutor(
            tool_registry,
            enable_logging=enable_logging,
            require_approval=require_approval,
        )

        self.logger = logging.getLogger(__name__)

        # Reasoning trace
        self.trace = []
        # Optional defenses
        self.defense_manager = defense_manager

    def run(self, query: str, use_rag: bool = True, collection_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Run the ReACT agent on a query.

        Args:
            query: User query
            use_rag: Whether to use RAG retrieval
            collection_id: Optional collection to search

        Returns:
            Dictionary with final answer and reasoning trace
        """
        self.logger.info(f"ReACT Agent: Starting query - {query[:100]}...")
        self.trace = []

        # Build initial prompt
        system_prompt = self._build_system_prompt()
        current_prompt = self._build_initial_prompt(query)

        # ReACT loop
        for iteration in range(self.max_iterations):
            self.logger.debug(f"Iteration {iteration + 1}/{self.max_iterations}")

            # Generate thought/action
            if use_rag:
                response = self.rag_pipeline.query(
                    current_prompt,
                    k=3,
                    system_prompt=system_prompt,
                    collection_id=collection_id,
                    temperature=self.temperature
                )
                llm_output = response['answer']
            else:
                response = self.rag_pipeline.query_without_rag(
                    current_prompt,
                    system_prompt=system_prompt,
                    temperature=self.temperature
                )
                llm_output = response['answer']

            self.trace.append({'step': iteration + 1, 'type': 'thought', 'content': llm_output})

            # Check for final answer
            if self._is_final_answer(llm_output):
                final_answer = self._extract_final_answer(llm_output)
                self.logger.info("ReACT Agent: Final answer reached")
                return {
                    'success': True,
                    'answer': final_answer,
                    'trace': self.trace,
                    'iterations': iteration + 1
                }

            # Parse tool calls
            tool_calls = self.tool_parser.parse(llm_output)

            # Apply output-stage defenses (validation, guardrails)
            if self.defense_manager is not None and tool_calls:
                _, tool_calls, _ = self.defense_manager.apply_output_defenses(llm_output, tool_calls)

            if not tool_calls:
                # No tool calls found, treat as final answer
                self.logger.info("ReACT Agent: No tool calls, treating as final answer")
                return {
                    'success': True,
                    'answer': llm_output,
                    'trace': self.trace,
                    'iterations': iteration + 1
                }

            # Execute first tool call
            tool_call = tool_calls[0]
            self.trace.append({'step': iteration + 1, 'type': 'action', 'tool_call': str(tool_call)})

            execution_result = self.tool_executor.execute(tool_call)
            self.trace.append({'step': iteration + 1, 'type': 'observation', 'result': execution_result.to_dict()})

            # Update prompt with observation
            observation = self._format_observation(execution_result)
            current_prompt = self._build_continuation_prompt(query, llm_output, observation)

        # Max iterations reached
        self.logger.warning("ReACT Agent: Max iterations reached")
        return {
            'success': False,
            'answer': "Max iterations reached without final answer",
            'trace': self.trace,
            'iterations': self.max_iterations
        }

    def _build_system_prompt(self) -> str:
        """Build system prompt for ReACT agent."""
        tools_desc = self.tool_registry.get_tools_description()

        return f"""You are a helpful AI assistant that can use tools to answer questions.

{tools_desc}

You should follow this format:
Thought: [Your reasoning about what to do]
Action: [Tool to use] {{"parameter": "value"}}
Observation: [Tool result will be provided]
... (repeat Thought/Action/Observation as needed)
Final Answer: [Your final answer to the user]

Always provide a Final Answer when you have enough information."""

    def _build_initial_prompt(self, query: str) -> str:
        """Build initial prompt for the agent."""
        return f"Question: {query}\n\nThought:"

    def _build_continuation_prompt(self, query: str, previous_thought: str, observation: str) -> str:
        """Build continuation prompt with observation."""
        return f"Question: {query}\n\nThought: {previous_thought}\n\nObservation: {observation}\n\nThought:"

    def _is_final_answer(self, text: str) -> bool:
        """Check if text contains a final answer."""
        final_keywords = ["Final Answer:", "final answer:", "FINAL ANSWER:"]
        return any(keyword in text for keyword in final_keywords)

    def _extract_final_answer(self, text: str) -> str:
        """Extract final answer from text."""
        for keyword in ["Final Answer:", "final answer:", "FINAL ANSWER:"]:
            if keyword in text:
                parts = text.split(keyword, 1)
                if len(parts) > 1:
                    return parts[1].strip()
        return text

    def _format_observation(self, execution_result) -> str:
        """Format tool execution result as observation."""
        if execution_result.success:
            if isinstance(execution_result.result, dict):
                # Extract main result from dict
                result = execution_result.result.get('result') or execution_result.result.get('content') or execution_result.result
                return f"Success: {result}"
            return f"Success: {execution_result.result}"
        else:
            return f"Error: {execution_result.error}"


def create_react_agent(
    rag_pipeline: RAGPipeline,
    tool_registry: Optional[ToolRegistry] = None,
    tools: Optional[List[str]] = None,
    agent_config_path: Optional[str] = None,
    defense_config_path: Optional[str] = None,
    **kwargs,
) -> ReACTAgent:
    """Factory function to create a ReACTAgent.

    Supports either passing an existing ToolRegistry or a list of tool names.
    Optionally reads configuration from agent_config.yaml.
    """
    # Load config if available
    cfg = {}
    if agent_config_path is None:
        default_cfg = Path("config") / "agent_config.yaml"
        if default_cfg.exists() and yaml is not None:
            agent_config_path = str(default_cfg)
    if agent_config_path and yaml is not None and Path(agent_config_path).exists():
        try:
            with open(agent_config_path, "r") as f:
                cfg = yaml.safe_load(f) or {}
        except Exception:
            cfg = {}

    # Tool registry construction
    if tool_registry is None:
        tool_registry = build_tool_registry_from_config(
            config_path=agent_config_path,
            enabled_tools=tools,
        )

    # Defaults from config with kwargs override
    react_cfg = cfg.get("react", {}) if isinstance(cfg, dict) else {}
    parsing_cfg = cfg.get("parsing", {}) if isinstance(cfg, dict) else {}
    safety_cfg = cfg.get("safety", {}) if isinstance(cfg, dict) else {}

    max_iterations = kwargs.pop("max_iterations", react_cfg.get("max_iterations", 10))
    temperature = kwargs.pop("temperature", react_cfg.get("temperature", 0.7))
    enable_logging = kwargs.pop("enable_logging", react_cfg.get("enable_logging", True))
    parser_strict = kwargs.pop("parser_strict_validation", parsing_cfg.get("strict_validation", False))
    require_approval = kwargs.pop("require_approval", safety_cfg.get("require_approval", False))

    # Optional defense manager
    defense_manager = None
    try:
        defense_manager = create_defense_manager(tool_registry=tool_registry, config_path=defense_config_path)
    except Exception:
        defense_manager = None

    return ReACTAgent(
        rag_pipeline,
        tool_registry,
        max_iterations=max_iterations,
        temperature=temperature,
        parser_strict_validation=parser_strict,
        enable_logging=enable_logging,
        require_approval=require_approval,
        defense_manager=defense_manager,
        **kwargs,
    )
