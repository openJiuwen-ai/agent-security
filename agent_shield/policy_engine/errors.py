"""Failures while loading a ruleset or checking a when clause."""


class PolicyError(ValueError):
    """The policy document is missing or would weaken a builtin control."""
