"""Random watch sequences must converge to the same state as replaying them.

etcd may replay, coalesce or reorder nothing: the order it gives is the
order that happened.  A mirror that applies an old PUT after a newer one,
or an old DELETE after a newer PUT, invents a state the authority never
had.  These tests drive the applier with random sequences and compare it
with a simple reference model instead of asserting a hand-written script.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from tests._fuzz_rng import FuzzRandom
from security_gateway.vault.etcdstore.watch import WatchEventType
from security_gateway.vault.sync import Listed, Listing, SyncError
from security_gateway.vault.sync.loop import Config, Syncer


class _Revisions:
    def __init__(self) -> None:
        self.value = 0

    def load_applied_rev(self) -> int:
        return self.value

    def save_applied_rev(self, rev: int) -> None:
        self.value = rev


class _Source:
    def __init__(self) -> None:
        self.seen: list[tuple[str, int]] = []

    @staticmethod
    def namespace() -> str:
        return "/test"

    @staticmethod
    def key_of(key: str) -> str:
        return key

    def decode(self, value: bytes, revision: int):
        self.seen.append((value.decode("utf-8"), revision))
        return value.decode("utf-8")


class _Applier:
    """A tiny revision-aware materialisation of the watched keys."""

    def __init__(self) -> None:
        self.items: dict[str, tuple[str, int]] = {}
        self._source = None

    def reconcile(self, listed) -> None:  # pragma: no cover - not used here
        self.items = {item.key: (item.value, item.revision) for item in listed}

    def apply_upsert(self, key: str, item: str) -> None:
        revision = self._source.seen[-1][1]
        current = self.items.get(key)
        if current is None or revision >= current[1]:
            self.items[key] = (item, revision)

    def apply_delete(self, key: str, mod_revision: int) -> None:
        current = self.items.get(key)
        if current is not None and mod_revision >= current[1]:
            del self.items[key]


@pytest.mark.parametrize("seed", range(12))
def test_random_watch_sequences_match_a_replay_model(seed: int) -> None:
    rng = FuzzRandom(seed)
    source = _Source()
    applier = _Applier()
    applier._source = source
    syncer = Syncer(source, applier, _Revisions())

    keys = [f"/records/{i}" for i in range(6)]
    # One pass produces a reference result by applying the same events
    # in order; the syncer must not change the order or the winner.
    events = []
    for revision in range(1, 80):
        key = rng.choice(keys)
        if rng.random() < 0.65:
            value = f"v{rng.randrange(5)}"
            events.append(
                SimpleNamespace(
                    type=WatchEventType.PUT,
                    key=key.encode(),
                    value=value.encode(),
                    mod_revision=revision,
                )
            )
        else:
            events.append(
                SimpleNamespace(
                    type=WatchEventType.DELETE,
                    key=key.encode(),
                    value=b"",
                    mod_revision=revision,
                )
            )

    getattr(syncer, "_apply_batch")(SimpleNamespace(events=events))

    expected: dict[str, str] = {}
    revisions: dict[str, int] = {}
    for event in events:
        key = event.key.decode()
        if event.type is WatchEventType.PUT:
            if event.mod_revision >= revisions.get(key, -1):
                expected[key] = event.value.decode()
                revisions[key] = event.mod_revision
        elif event.mod_revision >= revisions.get(key, -1):
            expected.pop(key, None)
            revisions[key] = event.mod_revision

    assert {k: v[0] for k, v in applier.items.items()} == expected


def test_a_bad_key_or_value_is_a_sync_error() -> None:
    source = _Source()
    applier = _Applier()
    applier._source = source
    syncer = Syncer(source, applier, _Revisions())

    with pytest.raises(SyncError, match="decode watch key"):
        getattr(syncer, "_apply_batch")(
            SimpleNamespace(
                events=[
                    SimpleNamespace(
                        type=WatchEventType.PUT,
                        key=b"\xff",
                        value=b"x",
                        mod_revision=1,
                    )
                ]
            )
        )


def test_a_bad_value_is_a_sync_error() -> None:
    class BadSource(_Source):
        def decode(self, value: bytes, revision: int):
            raise ValueError("not a record")

    source = BadSource()
    applier = _Applier()
    applier._source = source
    syncer = Syncer(source, applier, _Revisions())

    with pytest.raises(SyncError, match="decode /records/1"):
        getattr(syncer, "_apply_batch")(
            SimpleNamespace(
                events=[
                    SimpleNamespace(
                        type=WatchEventType.PUT,
                        key=b"/records/1",
                        value=b"x",
                        mod_revision=1,
                    )
                ]
            )
        )



class _Lister:
    def __init__(self, items, revision=42):
        self.items = items
        self.revision = revision
        self.calls = 0

    def list_entries(self, limit):
        self.calls += 1
        return Listing(items=tuple(Listed(key=k, value=v) for k, v in self.items), revision=self.revision)


class _Reconciler:
    def __init__(self):
        self.items = None

    def reconcile(self, listed):
        self.items = {item.key: item.value for item in listed}


def test_a_resync_replaces_the_local_view_with_the_listing():
    source = _Lister([("a", "1"), ("b", "2")])
    applier = _Reconciler()
    revisions = _Revisions()
    syncer = Syncer(source, applier, revisions)

    getattr(syncer, "_resync")()

    assert applier.items == {"a": "1", "b": "2"}
    assert revisions.value == 42
    assert syncer.stats().resync_count == 1


def test_a_listing_at_the_limit_is_refused_as_truncated():
    source = _Lister([("a", "1"), ("b", "2"), ("c", "3")])
    applier = _Reconciler()
    syncer = Syncer(source, applier, _Revisions(), Config(list_limit=3))

    with pytest.raises(SyncError, match="refusing to reconcile a partial view"):
        getattr(syncer, "_resync")()
    assert applier.items is None
