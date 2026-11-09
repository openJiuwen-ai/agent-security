"""The clock the store's timestamps come from.

One place, so every table stamps a row with the same kind of value.
"""

from __future__ import annotations

import time


def now() -> int:
    """The current unix time in seconds."""
    return int(time.time())
