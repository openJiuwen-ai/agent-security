"""The real watch source asks for progress notifications."""

from __future__ import annotations

from typing import Any

from security_gateway.vault.etcdstore.errors import CompactedError
from security_gateway.vault.etcdstore.watch import (
    RealWatcherSource,
    response_from_event,
    responses_from_item,
)


class RecordingClient:
    """A client that only remembers how it was asked to watch."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def watch(self, key: str, **kwargs: Any) -> tuple[Any, Any]:
        """Record a single-key watch."""
        self.calls.append(("watch", key, kwargs))
        return iter(()), lambda: None

    def watch_prefix(self, prefix: str, **kwargs: Any) -> tuple[Any, Any]:
        """Record a prefix watch."""
        self.calls.append(("watch_prefix", prefix, kwargs))
        return iter(()), lambda: None


def test_a_prefix_watch_asks_for_progress_notifications() -> None:
    """A silent stream must still produce signs of life."""
    client = RecordingClient()
    watcher = RealWatcherSource(client).watch_prefix("/security_gateway/ns/creds/")
    watcher.close()

    assert client.calls[0][2]["progress_notify"] is True


def test_a_single_key_watch_asks_for_progress_notifications() -> None:
    """The generation watch gets the same treatment."""
    client = RecordingClient()
    watcher = RealWatcherSource(client).watch_key("/security_gateway/ns/generation")
    watcher.close()

    assert client.calls[0][2]["progress_notify"] is True
    assert client.calls[0][2].get("start_revision") is None


def test_a_resumed_watch_starts_at_the_revision() -> None:
    """Resuming keeps the requested start revision."""
    client = RecordingClient()
    watcher = RealWatcherSource(client).watch_prefix("/security_gateway/ns/creds/", rev=42)
    watcher.close()

    assert client.calls[0][2]["start_revision"] == 42


def test_a_heartbeat_is_not_reported_as_a_change() -> None:
    """A progress notification carries no event."""

    class Heartbeat:
        """A bare client event: no key, no value, only a revision."""

        key = b""
        value = b""
        mod_revision = 7
        progress_notify = True

    response = response_from_event(Heartbeat())

    assert response.events == ()
    assert response.progress_notify is True
    assert response.header_revision == 7


class _Event:
    """A client event carrying a change."""

    def __init__(self, key: bytes, value: bytes) -> None:
        self.key = key
        self.value = value
        self.mod_revision = 3
        self.version = 1


class _WatchResponse:
    """A client watch response: a header plus the events it carries."""

    def __init__(
        self,
        events: list[Any],
        revision: int = 0,
        created: bool = False,
        canceled: bool = False,
        compact_revision: int = 0,
    ) -> None:
        self.events = events
        self.header = type("Header", (), {"revision": revision})()
        self.created = created
        self.canceled = canceled
        self.compact_revision = compact_revision


def test_a_client_response_is_unpacked_into_its_events() -> None:
    """The client hands out responses, and each event is one change."""
    item = _WatchResponse([_Event(b"/a", b"1"), _Event(b"/b", b"2")], revision=9)

    responses = responses_from_item(item)

    assert len(responses) == 2
    assert [event.key for response in responses for event in response.events] == [
        b"/a",
        b"/b",
    ]
    assert all(response.header_revision == 9 for response in responses)


def test_a_response_without_events_is_a_progress_notification() -> None:
    """A response with no events proves the stream is alive."""
    responses = responses_from_item(_WatchResponse([], revision=9))

    assert len(responses) == 1
    assert responses[0].events == ()
    assert responses[0].progress_notify is True
    assert responses[0].header_revision == 9


def test_a_canceled_watch_is_a_compacted_error() -> None:
    """A server cancel is a dead stream, not a heartbeat."""
    item = _WatchResponse([], revision=9, canceled=True, compact_revision=7)

    responses = responses_from_item(item)

    assert len(responses) == 1
    assert isinstance(responses[0].error, CompactedError)
    assert responses[0].progress_notify is False
