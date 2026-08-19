"""
Atlas Python SDK: 1-Line Drop-in Runtime Security Guard for LangChain, CrewAI, AutoGen, and OpenAI.
"""

import functools
import inspect
from collections.abc import Callable
from typing import Any

from atlas.auth.delegation import AgentDelegationManager
from atlas.detectors.inter_tool_scrubber import InterToolScrubber
from atlas.detectors.prompt_injection import PromptInjectionDetector
from atlas.engine.evaluator import PolicyEvaluator
from atlas.models import (
    AgentIdentity,
    PolicyDecision,
    SessionState,
    UserIdentity,
)


class SecurityViolationError(Exception):
    """Raised when an agent tool invocation violates runtime security policy."""

    def __init__(self, decision: PolicyDecision):
        self.decision = decision
        super().__init__(f"Security Policy Violation [{decision.policy_name}]: {', '.join(decision.reasons)}")


class AtlasGuard:
    """
    Client SDK to wrap agents, tools, and LLM completions with runtime policy enforcement.
    """

    def __init__(
        self,
        default_user_id: str = "default_user",
        default_agent_role: str = "analyst",
        enforce_step_up: bool = True,
        default_scopes: list[str] | None = None,
    ):
        self.evaluator = PolicyEvaluator()
        self.scrubber = InterToolScrubber()
        self.injection_detector = PromptInjectionDetector()
        self.delegation_manager = AgentDelegationManager()
        self.default_user = UserIdentity(user_id=default_user_id, scopes=default_scopes or [])
        self.default_role = default_agent_role
        self.enforce_step_up = enforce_step_up

    def inspect_prompt(self, prompt: str) -> None:
        """Scan ingress user prompt for direct prompt injection or jailbreak attempts."""
        scan = self.injection_detector.scan(prompt)
        if scan.is_suspicious and scan.confidence >= 0.9:
            raise ValueError(f"Direct prompt injection blocked: {scan.description}")

    def protect_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        agent_id: str = "agent_default",
        role: str | None = None,
        session_id: str = "session_default",
        user_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Evaluate tool invocation before execution.
        Returns modified/hardened arguments (e.g. injected SQL LIMIT) if allowed,
        or raises SecurityViolationError if blocked.
        """
        user = UserIdentity(user_id=user_id, scopes=self.default_user.scopes) if user_id else self.default_user
        agent = AgentIdentity(agent_id=agent_id, role=role or self.default_role)
        session = SessionState(session_id=session_id)

        decision = self.evaluator.evaluate_tool_call(
            user=user,
            agent=agent,
            tool=tool_name,
            args=arguments,
            session=session,
        )

        if not decision.allowed:
            raise SecurityViolationError(decision)

        # Return rewritten/hardened arguments if available
        return decision.modified_args if decision.modified_args else arguments

    def sanitize_tool_return(self, tool_name: str, raw_output: Any) -> Any:
        """Sanitize tool return values before ingesting into LLM context."""
        if isinstance(raw_output, str):
            res = self.scrubber.scrub(tool_name=tool_name, raw_output=raw_output)
            return res.sanitized_content
        return raw_output

    def wrap_tool(self, tool_func: Callable, tool_name: str | None = None) -> Callable:
        """Decorator to wrap any Python tool function with runtime Atlas protection."""
        name = tool_name or tool_func.__name__
        sig = inspect.signature(tool_func)

        if inspect.iscoroutinefunction(tool_func):
            @functools.wraps(tool_func)
            async def async_wrapper(*args, **kwargs):
                bound_args = sig.bind(*args, **kwargs)
                bound_args.apply_defaults()
                evaluated_dict = dict(bound_args.arguments)

                hardened_dict = self.protect_call(tool_name=name, arguments=evaluated_dict)

                # Call original function with hardened kwargs
                raw_result = await tool_func(**hardened_dict)
                return self.sanitize_tool_return(name, raw_result)
            return async_wrapper
        else:
            @functools.wraps(tool_func)
            def wrapper(*args, **kwargs):
                bound_args = sig.bind(*args, **kwargs)
                bound_args.apply_defaults()
                evaluated_dict = dict(bound_args.arguments)

                hardened_dict = self.protect_call(tool_name=name, arguments=evaluated_dict)

                # Call original function with hardened kwargs
                raw_result = tool_func(**hardened_dict)
                return self.sanitize_tool_return(name, raw_result)
            return wrapper
