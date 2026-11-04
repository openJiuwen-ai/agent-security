"""How the plugin reaches the store.

Two backends, one interface:

``UdsBackend``
    Talks to the service over its unix socket. This is what the plugin
    does today, and it is what a deployment that wants the store in its
    own process keeps using.

``InProcessBackend``
    Calls the store directly, in this process: no socket, no permission
    model on the hot path, no frame codec.

The interface is expressed in terms of the secret, not in terms of the
wire protocol, so the plugin does not care which backend it has.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import socket
import struct
import threading
from typing import Any, Protocol

from .shape import Shape, VaultError, decode_payload, encode_put, resolve_shape

#: The default socket the service listens on.
DEFAULT_SOCKET = "/var/run/credential-router/vault.sock"

#: How long a call waits for the service.
DEFAULT_TIMEOUT = 5.0

#: The largest frame the service accepts. A client that reads a longer
#: one is talking to something that is not the service.
MAX_FRAME = 1 << 20


class SecretBackend(Protocol):
    """Where the plugin gets its secrets from."""

    def read_sync(self, name: str) -> bytes | None:
        """The secret, or None when the store does not hold it."""

    async def read_async(self, name: str) -> bytes | None:
        """The secret, or None when the store does not hold it."""

    def write_sync(self, name: str, kind: str, value: bytes,
                   meta: dict[str, Any] | None = None) -> None:
        ...

    async def write_async(self, name: str, kind: str, value: bytes,
                          meta: dict[str, Any] | None = None) -> None:
        ...

    def delete_sync(self, name: str) -> bool:
        """True when something was deleted."""
        ...

    async def delete_async(self, name: str) -> bool:
        ...

    def schema_fields_sync(self) -> list[dict[str, Any]]:
        ...

    async def schema_fields_async(self) -> list[dict[str, Any]]:
        ...

    def list_sync(self, prefix: str = "") -> list[dict[str, Any]]:
        """The records whose id begins with ``prefix``."""
        ...

    async def list_async(self, prefix: str = "") -> list[dict[str, Any]]:
        ...

    def status_sync(self) -> dict[str, Any]:
        """What the store reports about itself."""
        ...

    async def status_async(self) -> dict[str, Any]:
        ...

    def healthy_sync(self) -> bool:
        ...

    async def healthy_async(self) -> bool:
        ...


# --- the unix socket backend -------------------------------------------------


class UdsBackend:
    """The client of the store's local socket.

    Every call opens a new connection. Building a unix socket connection
    costs tens of microseconds, while reusing one long-lived connection
    means handling "the other end closed it quietly", which is a problem
    that only shows up in production. The read path is cached anyway, so
    the call rate is low.
    """

    def __init__(self, path: str = DEFAULT_SOCKET,
                 timeout: float = DEFAULT_TIMEOUT) -> None:
        self.path = path
        self.timeout = timeout
        self._shape: Shape | None = None
        self._schema_fields: list[dict[str, Any]] = []
        self._shape_lock = threading.Lock()

    # -- the raw calls ----------------------------------------------------

    def call(self, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        frame = struct.pack("!I", len(body)) + body

        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.settimeout(self.timeout)
        try:
            conn.connect(self.path)
            conn.sendall(frame)
            return self._read(conn)
        except OSError as exc:
            raise VaultError(
                f"the vault at {self.path} did not answer: {exc}") from exc
        finally:
            conn.close()

    async def call_async(self, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        frame = struct.pack("!I", len(body)) + body

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(self.path), timeout=self.timeout
            )
        except OSError as exc:
            raise VaultError(
                f"the vault at {self.path} did not answer: {exc}") from exc

        try:
            writer.write(frame)
            await writer.drain()
            header = await reader.readexactly(4)
            (length,) = struct.unpack("!I", header)
            if length > MAX_FRAME:
                raise VaultError(
                    f"the vault answered with {length} bytes, over the limit")
            answer = await reader.readexactly(length)
            return json.loads(answer.decode("utf-8"))
        except (OSError, asyncio.IncompleteReadError) as exc:
            raise VaultError(
                f"the vault at {self.path} did not answer: {exc}") from exc
        finally:
            writer.close()

    def _read(self, conn: socket.socket) -> dict[str, Any]:
        header = self._read_exactly(conn, 4)
        (length,) = struct.unpack("!I", header)
        if length > MAX_FRAME:
            raise VaultError(
                f"the vault answered with {length} bytes, over the limit")
        return json.loads(self._read_exactly(conn, length).decode("utf-8"))

    @staticmethod
    def _read_exactly(conn: socket.socket, count: int) -> bytes:
        chunks = []
        remaining = count
        while remaining:
            chunk = conn.recv(remaining)
            if not chunk:
                raise VaultError("the vault closed the connection mid-answer")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    # -- the backend interface --------------------------------------------

    def read_sync(self, name: str) -> bytes | None:
        answer = self.call({"op": "get", "id": name})
        return self._consume(answer, name, self.schema_fields_sync())

    async def read_async(self, name: str) -> bytes | None:
        answer = await self.call_async({"op": "get", "id": name})
        return self._consume(answer, name, await self.schema_fields_async())

    def write_sync(self, name: str, kind: str, value: bytes,
                   meta: dict[str, Any] | None = None) -> None:
        answer = self.call({
            "op": "put",
            "id": name,
            "fields": encode_put(self._shape_sync(), kind, value, meta),
        })
        self._require_ok(answer, name)

    async def write_async(self, name: str, kind: str, value: bytes,
                           meta: dict[str, Any] | None = None) -> None:
        answer = await self.call_async({
            "op": "put",
            "id": name,
            "fields": encode_put(await self._shape_async(), kind, value, meta),
        })
        self._require_ok(answer, name)

    def delete_sync(self, name: str) -> bool:
        answer = self.call({"op": "delete", "id": name})
        if answer.get("ok"):
            return True
        error = answer.get("error") or {}
        if error.get("code") == "not_found":
            return False
        raise VaultError(
            f"the vault refused to delete {name!r}: "
            f"{error.get('code')} {error.get('message')}"
        )

    async def delete_async(self, name: str) -> bool:
        answer = await self.call_async({"op": "delete", "id": name})
        if answer.get("ok"):
            return True
        error = answer.get("error") or {}
        if error.get("code") == "not_found":
            return False
        raise VaultError(
            f"the vault refused to delete {name!r}: "
            f"{error.get('code')} {error.get('message')}"
        )

    def schema_fields_sync(self) -> list[dict[str, Any]]:
        with self._shape_lock:
            if self._shape is None:
                answer = self.call({"op": "status"})
                self._require_ok(answer, "status")
                schema = (answer.get("status") or {}).get("schema") or {}
                self._schema_fields = list(schema.get("fields") or [])
                self._shape = resolve_shape(self._schema_fields)
            return self._schema_fields

    async def schema_fields_async(self) -> list[dict[str, Any]]:
        if self._shape is None:
            answer = await self.call_async({"op": "status"})
            self._require_ok(answer, "status")
            schema = (answer.get("status") or {}).get("schema") or {}
            self._schema_fields = list(schema.get("fields") or [])
            self._shape = resolve_shape(self._schema_fields)
        return self._schema_fields

    def list_sync(self, prefix: str = "") -> list[dict[str, Any]]:
        answer = self.call({"op": "list", "prefix": prefix})
        self._require_ok(answer, "list")
        return list(answer.get("objects") or [])

    async def list_async(self, prefix: str = "") -> list[dict[str, Any]]:
        answer = await self.call_async({"op": "list", "prefix": prefix})
        self._require_ok(answer, "list")
        return list(answer.get("objects") or [])

    def status_sync(self) -> dict[str, Any]:
        answer = self.call({"op": "status"})
        self._require_ok(answer, "status")
        return dict(answer.get("status") or {})

    async def status_async(self) -> dict[str, Any]:
        answer = await self.call_async({"op": "status"})
        self._require_ok(answer, "status")
        return dict(answer.get("status") or {})

    def healthy_sync(self) -> bool:
        try:
            answer = self.call({"op": "status"})
        except VaultError:
            return False
        return bool(answer.get("ok"))

    async def healthy_async(self) -> bool:
        try:
            answer = await self.call_async({"op": "status"})
        except VaultError:
            return False
        return bool(answer.get("ok"))

    # -- internals --------------------------------------------------------

    def _shape_sync(self) -> Shape:
        self.schema_fields_sync()
        shape = self._shape
        if shape is None:
            raise VaultError("the store did not report its schema")
        return shape

    async def _shape_async(self) -> Shape:
        await self.schema_fields_async()
        shape = self._shape
        if shape is None:
            raise VaultError("the store did not report its schema")
        return shape

    @staticmethod
    def _consume(answer: dict[str, Any], name: str,
                 fields: list[dict[str, Any]]) -> bytes | None:
        if not answer.get("ok"):
            error = answer.get("error") or {}
            if error.get("code") == "not_found":
                return None
            raise VaultError(
                f"the vault refused to answer for {name!r}: "
                f"{error.get('code')} {error.get('message')}"
            )
        obj = answer.get("object") or {}
        if "id" not in obj:
            return None
        shape = resolve_shape(fields)
        payload = decode_payload(shape, obj.get("fields") or [])
        if payload is None:
            raise VaultError(
                f"the object {name!r} has no field {shape.secret!r}")
        return payload

    @staticmethod
    def _require_ok(answer: dict[str, Any], subject: str) -> None:
        if answer.get("ok"):
            return
        error = answer.get("error") or {}
        raise VaultError(
            f"the vault refused {subject!r}: "
            f"{error.get('code')} {error.get('message')}"
        )


def default_socket_path() -> str:
    """The socket the plugin talks to unless told otherwise."""
    return os.environ.get("CRED_ROUTER_VAULT_SOCKET", DEFAULT_SOCKET)


def default_timeout() -> float:
    """How long a call waits, unless told otherwise."""
    return float(os.environ.get("CRED_ROUTER_VAULT_TIMEOUT", DEFAULT_TIMEOUT))


def b64(data: bytes) -> str:
    """Base64 for the wire."""
    return base64.b64encode(data).decode("ascii")
