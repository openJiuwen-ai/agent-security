"""Tool-result entry. The text is checked by detection."""

from __future__ import annotations

from agent_shield.detection import (
    GuardrailContentType,
    GuardrailContext,
    RuleBasedPromptInjectionBackend,
)


async def inspect(tool_name: str, text: str, *, backend=None):
    """Return a detection assessment for one tool result."""
    ctx = GuardrailContext(
        content_type=GuardrailContentType.TEXT,
        content=text if isinstance(text, str) else "",
        event="tool_output",
        metadata={"tool_name": tool_name or ""},
    )
    checker = backend if backend is not None else RuleBasedPromptInjectionBackend()
    return await checker.analyze(ctx)
