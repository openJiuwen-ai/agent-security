"""Framework adapters. They build Agent Events and do not call the PDP."""

from agent_shield.intercepts.tool_call.adapters.jiuwenswarm import tool_call_to_event

__all__ = ["tool_call_to_event"]
