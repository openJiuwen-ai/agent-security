"""Status lines for suite scripts. Routed through logging for G.LOG.02."""

from __future__ import annotations

import logging
import sys


class _ScriptStatusHandler(logging.StreamHandler):
    """Write the log record text only, with no level or timestamp prefix."""

    def __init__(self) -> None:
        super().__init__(sys.stdout)

    def format(self, record: logging.LogRecord) -> str:
        return record.getMessage()


_SCRIPT_LOG = logging.getLogger("agent_shield.script")
_SCRIPT_LOG.setLevel(logging.INFO)
_SCRIPT_LOG.propagate = False
if not _SCRIPT_LOG.handlers:
    _SCRIPT_LOG.addHandler(_ScriptStatusHandler())


def log_line(message: str, *, flush: bool = False) -> None:
    _SCRIPT_LOG.info("%s", message)
    if flush:
        for handler in _SCRIPT_LOG.handlers:
            handler.flush()
