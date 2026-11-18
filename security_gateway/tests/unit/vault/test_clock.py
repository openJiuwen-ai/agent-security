"""The vault clock must expose the authority's timestamp type."""

from __future__ import annotations

from security_gateway.vault.clock import now_timestamp
from security_gateway.vault.etcdstore.entry import Timestamp


def test_now_timestamp_is_the_authority_type():
    stamp = now_timestamp()

    assert isinstance(stamp, Timestamp)
    assert str(stamp).endswith("Z")
    assert Timestamp(str(stamp)) == stamp
