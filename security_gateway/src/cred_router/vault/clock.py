"""The clock the vault's records are stamped with.

The authority's records carry a timestamp type, and the vault has to
stamp them the way the Go does — so the type comes from the authority's
own package, and the import is deferred so the vault stays importable
without it.
"""

from __future__ import annotations

from typing import Any


def now_timestamp() -> Any:
    """The current time, in the form the authority's records carry."""
    from cred_router.credmgr.etcdstore.entry import Timestamp

    return Timestamp.now()
