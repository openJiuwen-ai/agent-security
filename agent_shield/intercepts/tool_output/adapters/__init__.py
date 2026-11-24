"""Framework adapters. They extract tool-result text and do not run detection."""

from agent_shield.intercepts.tool_output.adapters.jiuwenswarm import tool_result_text

__all__ = ["tool_result_text"]
