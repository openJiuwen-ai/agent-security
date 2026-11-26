"""Emit CLI messages through logging while preserving their console format."""

import logging
import sys


def log_console(message: str, *, error: bool = False) -> None:
    """Send a bare message to stdout, or to stderr for command errors."""
    stream, level = (sys.stderr, logging.ERROR) if error else (sys.stdout, logging.INFO)
    # Keep root logging handlers and prefixes out of command output.
    logger = logging.Logger(__name__, level)
    logger.addHandler(logging.StreamHandler(stream))
    logger.log(level, "%s", message)
