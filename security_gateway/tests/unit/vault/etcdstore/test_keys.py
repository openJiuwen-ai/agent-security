"""The keyspace layout and the prefix upper bound.

The Go original is ``internal/credmgr/etcdstore/keys.go``.
"""

from __future__ import annotations

import pytest
from security_gateway.vault.etcdstore.keys import (
    KEYSPACE_PREFIX,
    cred_key,
    creds_prefix,
    prefix_upper_bound,
    proxy_key_from_cred_key,
    record_id_from_key,
    record_key,
    records_prefix,
    rotation_key,
)


def test_keyspace_prefix_is_the_agreed_one() -> None:
    # The "/security_gateway/" prefix must not collide with the agent-os
    # tree's "/sn/" keyspace, and it avoids reserving the "/nodes/" and
    # "/boots/" subtrees agent-os depends on.
    """Test keyspace prefix is the agreed one."""
    assert KEYSPACE_PREFIX == "/security_gateway/"


def test_cred_key_layout() -> None:
    """Test cred key layout."""
    assert cred_key("prod", "abc123") == "/security_gateway/prod/creds/abc123"


def test_creds_prefix_layout() -> None:
    """Test creds prefix layout."""
    prefix = creds_prefix("prod")
    assert prefix == "/security_gateway/prod/creds/"


def test_creds_prefix_ends_in_a_slash() -> None:
    # The trailing slash is load-bearing: it stops a future sibling
    # prefix such as "/security_gateway/<ns>/creds-extra/" from being matched
    # by the same prefix range.
    """Test creds prefix ends in a slash."""
    assert creds_prefix("prod").endswith("/")
    assert not creds_prefix("prod").endswith("creds")


def test_rotation_key_layout() -> None:
    """Test rotation key layout."""
    assert rotation_key("prod") == "/security_gateway/prod/rotation"


def test_record_key_layout() -> None:
    """Test record key layout."""
    assert record_key("prod", "r1") == "/security_gateway/prod/records/r1"
    assert records_prefix("prod") == "/security_gateway/prod/records/"


def test_every_key_is_under_the_keyspace_prefix() -> None:
    """Test every key is under the keyspace prefix."""
    assert cred_key("prod", "k").startswith(KEYSPACE_PREFIX)
    assert creds_prefix("prod").startswith(KEYSPACE_PREFIX)
    assert rotation_key("prod").startswith(KEYSPACE_PREFIX)
    assert record_key("prod", "r").startswith(KEYSPACE_PREFIX)
    assert records_prefix("prod").startswith(KEYSPACE_PREFIX)


def test_namespaces_do_not_bleed_into_each_other() -> None:
    """Test namespaces do not bleed into each other."""
    assert cred_key("prod", "k") != cred_key("staging", "k")
    assert creds_prefix("prod") != creds_prefix("staging")


def test_proxy_key_from_cred_key_is_the_inverse() -> None:
    """Test proxy key from cred key is the inverse."""
    assert proxy_key_from_cred_key("prod", cred_key("prod", "abc123")) == "abc123"


def test_proxy_key_from_cred_key_rejects_a_foreign_key() -> None:
    """Test proxy key from cred key rejects a foreign key."""
    with pytest.raises(Exception):
        proxy_key_from_cred_key("prod", "/security_gateway/prod/rotation")
    with pytest.raises(Exception):
        proxy_key_from_cred_key("prod", "/security_gateway/other/creds/abc")


def test_record_id_from_key_is_the_inverse() -> None:
    """Test record id from key is the inverse."""
    assert record_id_from_key("prod", record_key("prod", "r1")) == "r1"


# -- the prefix upper bound ------------------------------------------------


def test_prefix_upper_bound_increments_the_last_byte() -> None:
    """Test prefix upper bound increments the last byte."""
    upper, ok = prefix_upper_bound(b"abc")
    assert ok is True
    assert upper == b"abd"


def test_prefix_upper_bound_truncates_after_the_increment() -> None:
    # The last byte that is not 0xff is incremented and everything after
    # it is dropped: "abc\xff" becomes "abd", not "abc\xff\x00".
    """Test prefix upper bound truncates after the increment."""
    upper, ok = prefix_upper_bound(b"abc\xff")
    assert ok is True
    assert upper == b"abd"


def test_prefix_upper_bound_carries_over_a_full_byte() -> None:
    # The last byte that is not 0xff is incremented; the 0xff bytes are
    # dropped. "a\xff" becomes "b", not "a\xff\x00".
    """Test prefix upper bound carries over a full byte."""
    upper, ok = prefix_upper_bound(b"a\xff")
    assert ok is True
    assert upper == b"b"


def test_prefix_upper_bound_carries_over_several_bytes() -> None:
    """Test prefix upper bound carries over several bytes."""
    upper, ok = prefix_upper_bound(b"ab\xff\xff")
    assert ok is True
    assert upper == b"ac"


def test_prefix_upper_bound_has_none_for_an_all_ff_prefix() -> None:
    # No successor exists, so there is no upper bound: the caller filters
    # on the lower bound alone.
    """Test prefix upper bound has none for an all ff prefix."""
    upper, ok = prefix_upper_bound(b"\xff\xff")
    assert ok is False
    assert upper == b""


def test_prefix_upper_bound_of_the_credential_prefix() -> None:
    """Test prefix upper bound of the credential prefix."""
    upper, ok = prefix_upper_bound(creds_prefix("prod"))
    assert ok is True
    assert upper == b"/security_gateway/prod/creds0"


def test_prefix_upper_bound_is_not_the_nul_sentinel() -> None:
    # prefix + "\x00" sorts before every key sharing the prefix and
    # therefore yields an empty range. The bound is the incremented
    # prefix, and nothing else.
    """Test prefix upper bound is not the nul sentinel."""
    prefix = creds_prefix("prod")
    upper, ok = prefix_upper_bound(prefix)
    assert ok is True
    assert upper != (prefix + "\x00").encode("utf-8")
    assert upper > prefix.encode("utf-8")


def test_the_upper_bound_brackets_exactly_the_prefix_set() -> None:
    """Test the upper bound brackets exactly the prefix set."""
    prefix = creds_prefix("prod")
    upper, ok = prefix_upper_bound(prefix)
    assert ok is True
    inside = [prefix + suffix for suffix in ("", "a", "abc", "zzz")]
    outside = [
        creds_prefix("production"),
        "/security_gateway/prod/creds-extra/thing",
        "/security_gateway/prod/rotation",
    ]
    for key in inside:
        assert prefix.encode("utf-8") <= key.encode("utf-8") < upper
    for key in outside:
        assert not (prefix.encode("utf-8") <= key.encode("utf-8") < upper)
