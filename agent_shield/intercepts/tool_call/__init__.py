"""Tool-call intercept. Framework adapters turn a call into an Agent Event."""

from agent_shield.intercepts.tool_call.adapters import tool_call_to_event

__all__ = ["tool_call_to_event"]
