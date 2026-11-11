"""The fleet's key: minting it, adopting it, and the predecessor beside it.

The Go original is ``internal/credmgr/clusterkey/clusterkey.go``. The Go
has no ``clusterkey_test.go``; what is pinned here is what the Go's
comments in that file say, plus the crash-injection seam the Go keeps in
``fault.go`` and ``testing.go``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from security_gateway.vault.clusterdek import Fingerprint
from security_gateway.vault.clusterkey.authority import (
    ROTATION_STATE_IN_PROGRESS,
    KVClusterStore,
)
from security_gateway.vault.clusterkey.clusterkey import (
    Config,
    ErrNoPeerSealed,
    HeldDEK,
    anchor_for,
    load_identity,
    obtain,
    obtain_pair,
    obtain_predecessor,
)
from security_gateway.vault.clusterkey.fault import (
    invoke_handover_fault,
    set_handover_fault_hook_for_testing,
)
from security_gateway.vault.etcdstore.keys import rotation_key

from .conftest import handover_test_dek, make_test_node, make_test_roster, serve


def _write_keypair(tmp_path: Path, node: object) -> tuple[Path, Path]:
    """Write a node's certificate and key where ``load_identity`` can read
    them.
    """
    cert_path = tmp_path / f"{node.id}.crt"
    key_path = tmp_path / f"{node.id}.key"
    cert_path.write_bytes(node.cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        node.priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


# -- the identity ---------------------------------------------------------


def test_an_identity_is_loaded_from_the_client_keypair(tmp_path: Path) -> None:
    """The node identifies itself with the keypair it already presents to the
    authority, so participation requires no new secret.
    """
    node = make_test_node("router-a")
    cert_path, key_path = _write_keypair(tmp_path, node)

    identity = load_identity("router-a", str(cert_path), str(key_path))

    assert identity.node_id == "router-a"
    assert identity.cert is not None
    assert (
        identity.public.public_numbers()
        == identity.private.public_key().public_numbers()
    )


def test_a_client_certificate_that_is_not_the_client_key_is_refused(
    tmp_path: Path,
) -> None:
    """A certificate and a key that are not a pair must not load: the node
    would sign with one key and the roster would vouch for another.
    """
    node = make_test_node("router-a")
    other = make_test_node("router-b")
    cert_path, _ = _write_keypair(tmp_path, node)
    _, other_key_path = _write_keypair(tmp_path, other)

    with pytest.raises(ValueError):
        load_identity("router-a", str(cert_path), str(other_key_path))


def test_a_missing_client_keypair_is_refused(tmp_path: Path) -> None:
    """Test a missing client keypair is refused."""
    with pytest.raises(ValueError):
        load_identity(
            "router-a", str(tmp_path / "absent.crt"), str(tmp_path / "absent.key")
        )


def test_a_client_key_that_is_not_ecdsa_is_refused(tmp_path: Path) -> None:
    """Sealing needs ECDSA; an RSA key is refused rather than pretended
    with.
    """
    node = make_test_node("router-a")
    cert_path, _ = _write_keypair(tmp_path, node)
    key_path = tmp_path / "rsa.key"
    key_path.write_bytes(
        rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

    with pytest.raises(ValueError):
        load_identity("router-a", str(cert_path), str(key_path))


# -- the trust anchor -----------------------------------------------------


def test_no_anchor_configured_is_no_anchor() -> None:
    """A node with nothing configured hands nothing over, and says so by
    having no anchor.
    """
    assert anchor_for(None, None) is None
    assert anchor_for("", []) is None


def test_an_anchor_that_cannot_be_built_is_an_error(tmp_path: Path) -> None:
    """A node that meant to have a trust anchor and does not have one must
    not quietly become a node that hands nothing over.
    """
    with pytest.raises(ValueError):
        anchor_for(str(tmp_path / "absent-ca.pem"), None)

    node = make_test_node("router-a")
    assert anchor_for(None, [Fingerprint(node.cert)]) is not None


# -- obtaining the key ----------------------------------------------------


def test_the_first_node_mints_the_fleets_key(store: KVClusterStore) -> None:
    """Minting is the one step that cannot be delegated, and it needs a
    trust anchor.
    """
    node = make_test_node("router-a")
    anchor = make_test_roster(store, (node,))

    dek, generation = obtain(Config(node_id="router-a"), store, node.identity(), anchor)

    assert generation == 1
    assert len(dek) > 0
    assert store.mint_owner() == "router-a"
    assert store.generation() == 1


def test_a_second_node_adopts_the_key_from_a_peer(store: KVClusterStore) -> None:
    """A node that invents its own key would be unable to read anything the
    rest of the fleet published, and the failure is silent.
    """
    holder = make_test_node("router-a")
    requester = make_test_node("router-b")
    anchor = make_test_roster(store, (holder, requester))
    dek = handover_test_dek(0x41)

    # The holder won the mint, so the requester has to ask for the key.
    assert store.claim_mint("router-a") is True

    with serve(store, holder.identity(), anchor, [HeldDEK(dek=dek, generation=1)]):
        adopted, generation = obtain(
            Config(node_id="router-b", fetch_timeout=5.0),
            store,
            requester.identity(),
            anchor,
        )

    assert adopted == dek
    assert generation == 1


def test_obtaining_fails_when_nobody_answers(store: KVClusterStore) -> None:
    """Nobody sealing the key is not a transport failure: the authority was
    reachable the whole time, and the answer it gave was that nobody holds
    the key.
    """
    holder = make_test_node("router-a")
    requester = make_test_node("router-b")
    anchor = make_test_roster(store, (holder, requester))

    assert store.claim_mint("router-a") is True

    with pytest.raises(ErrNoPeerSealed):
        obtain(
            Config(node_id="router-b", fetch_timeout=0.3),
            store,
            requester.identity(),
            anchor,
        )


def test_a_node_without_an_anchor_does_not_mint(store: KVClusterStore) -> None:
    """A node with no trust anchor cannot decide who may hold the fleet's
    key, so it waits for a peer instead of minting.
    """
    node = make_test_node("router-a")

    with pytest.raises(ErrNoPeerSealed):
        obtain(
            Config(node_id="router-a", fetch_timeout=0.3),
            store,
            node.identity(),
            None,
        )

    assert store.list_handover_requests(), "the node asked for the key"


# -- the predecessor ------------------------------------------------------


def test_the_predecessor_is_only_fetched_during_a_rotation(
    store: KVClusterStore,
) -> None:
    """Asking outside the rotation window would leave a request standing in
    the authority that nobody has any reason to answer.
    """
    holder = make_test_node("router-a")
    requester = make_test_node("router-b")
    anchor = make_test_roster(store, (holder, requester))
    old = handover_test_dek(0x21)
    held = [
        HeldDEK(dek=old, generation=2),
        HeldDEK(dek=handover_test_dek(0x31), generation=3),
    ]

    # No rotation state at all: there is nothing to fetch.
    assert obtain_predecessor(store, requester.identity(), 3) == b""

    # A rotation that is heading somewhere else: this node's generation is
    # not the one being rotated to.
    _write_rotation_state(store, state=ROTATION_STATE_IN_PROGRESS, target=4)
    assert obtain_predecessor(store, requester.identity(), 3) == b""

    # The rotation is heading for this node's generation: now the older key
    # is the one the records still under it need.
    _write_rotation_state(store, state=ROTATION_STATE_IN_PROGRESS, target=3)
    with serve(store, holder.identity(), anchor, held):
        assert obtain_predecessor(store, requester.identity(), 3) == old


def test_the_first_generation_has_no_predecessor(store: KVClusterStore) -> None:
    """Test the first generation has no predecessor."""
    requester = make_test_node("router-b")
    assert obtain_predecessor(store, requester.identity(), 1) == b""


def test_the_pair_carries_the_predecessor_only_when_it_is_there(
    store: KVClusterStore,
) -> None:
    """The predecessor is best-effort: a node runs on the current key alone
    when there is nothing to fetch.
    """
    holder = make_test_node("router-a")
    requester = make_test_node("router-b")
    anchor = make_test_roster(store, (holder, requester))
    dek = handover_test_dek(0x41)

    assert store.claim_mint("router-a") is True

    with serve(store, holder.identity(), anchor, [HeldDEK(dek=dek, generation=1)]):
        current, generation, previous = obtain_pair(
            Config(node_id="router-b", fetch_timeout=5.0),
            store,
            requester.identity(),
            anchor,
        )

    assert current == dek
    assert generation == 1
    assert previous == b""


# -- the crash-injection seam ---------------------------------------------


def test_the_fault_hook_is_inert_until_one_is_installed() -> None:
    """The hook is ``None`` outside a test, and the check costs one nil
    comparison.
    """
    invoke_handover_fault("cluster_handover_answered")


def test_the_fault_hook_can_be_taken_back() -> None:
    """A test that installs a hook leaves the package as it found it."""
    seen: list[str] = []

    restore = set_handover_fault_hook_for_testing(seen.append)
    try:
        invoke_handover_fault("cluster_handover_answered")
    finally:
        restore()

    assert seen == ["cluster_handover_answered"]

    invoke_handover_fault("cluster_handover_answered")
    assert seen == ["cluster_handover_answered"], "the hook was not taken back"


def _write_rotation_state(
    store: KVClusterStore, *, state: str, target: int, holder: str = "router-a"
) -> None:
    """Record the rotation state the way the authority does."""
    payload = json.dumps(
        {
            "state": state,
            "holder": holder,
            "target_dek_version": target,
            "started_at": "2026-01-01T00:00:00Z",
        },
        separators=(",", ":"),
    ).encode("utf-8")
    store.kv.put(rotation_key(store.ns), payload)
