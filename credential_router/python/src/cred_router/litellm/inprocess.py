"""Read and write the store directly, in this process.

The socket version of the plugin pays for a connection, a permission check
and a frame codec on every read; this one is a function call into the same
process.

The security story is different, and deliberately so: the store's key
material now lives in this process's memory, so anything that can read
this process can read the secrets. The socket backend keeps that
boundary, and stays available for deployments that want it.
"""

from __future__ import annotations

import base64
import logging
import os
import threading
from typing import Any, Callable

from ..vault import FieldDef, NotFoundError, Record, Schema, Type, Value
from .shape import Shape, VaultError, encode_put, resolve_shape

_log = logging.getLogger(__name__)

#: The protocol's type names, and the value constructors that make them.
_VALUE_FOR_TYPE = {
    "string": Value.new_string,
    "bytes": Value.new_bytes,
}


def _value_bytes(value: Value) -> bytes:
    """The raw bytes of a stored value."""
    try:
        return value.as_bytes()
    except Exception:
        return value.as_string().encode("utf-8")


def _protocol_type(field_type: Type) -> str:
    """The protocol's spelling of a field type."""
    if field_type is Type.STRING:
        return "string"
    if field_type is Type.BYTES:
        return "bytes"
    if field_type is Type.INT64:
        return "int64"
    if field_type is Type.BOOL:
        return "bool"
    raise VaultError(f"the store's schema uses an unknown field type: "
                     f"{field_type}")


def _schema_fields(schema: Schema) -> list[dict[str, Any]]:
    """The schema in the shape the protocol reports it in."""
    return [
        {
            "name": f.name,
            "type": _protocol_type(f.type),
            "encrypted": bool(f.encrypted),
        }
        for f in schema.fields
    ]


class InProcessBackend:
    """The store, in this process.

    The vault is opened lazily, on the first call, so that constructing
    the plugin does not create a data directory or read a key shard.
    """

    def __init__(
        self,
        vault: Any,
        shape: Shape | None = None,
        rotate_stop: Callable[[], None] | None = None,
    ) -> None:
        self._vault = vault
        self._shape = shape
        self._lock = threading.Lock()
        #: The stop callable of the store's DEK rotator, when one is
        #: attached.  This process holds the store, so it is the one that
        #: can rotate it — whether or not anybody is listening on a socket.
        self._rotate_stop = rotate_stop

    # -- letting go ---------------------------------------------------------

    def close(self) -> None:
        """Stop the rotator and close the store."""
        stop = self._rotate_stop
        self._rotate_stop = None
        if stop is not None:
            try:
                stop()
            except Exception:  # noqa: BLE001 - shutting down anyway
                pass
        self._vault.close()

    # -- the backend interface ---------------------------------------------

    def read_sync(self, name: str) -> bytes | None:
        try:
            record = self._vault.get(name)
        except NotFoundError:
            return None
        shape = self._shape_sync()
        value = record.get(shape.secret)
        if value is None:
            raise VaultError(
                f"the object {name!r} has no field {shape.secret!r}")
        return _value_bytes(value)

    async def read_async(self, name: str) -> bytes | None:
        import asyncio

        return await asyncio.to_thread(self.read_sync, name)

    def write_sync(self, name: str, kind: str, value: bytes,
                   meta: dict[str, Any] | None = None) -> None:
        shape = self._shape_sync()
        fields = encode_put(shape, kind, value, meta)
        self._vault.put(self._to_record(name, fields))

    async def write_async(self, name: str, kind: str, value: bytes,
                           meta: dict[str, Any] | None = None) -> None:
        import asyncio

        await asyncio.to_thread(self.write_sync, name, kind, value, meta)

    def delete_sync(self, name: str) -> bool:
        try:
            self._vault.delete(name)
        except NotFoundError:
            return False
        return True

    async def delete_async(self, name: str) -> bool:
        import asyncio

        return await asyncio.to_thread(self.delete_sync, name)

    def schema_fields_sync(self) -> list[dict[str, Any]]:
        # ``schema`` is a property of the store, not a method: the Go's
        # ``Schema()`` is a method, and the Python port made it a
        # property.  Calling it raises "Schema object is not callable".
        return _schema_fields(self._vault.schema)

    async def schema_fields_async(self) -> list[dict[str, Any]]:
        import asyncio

        return await asyncio.to_thread(self.schema_fields_sync)

    def list_sync(self, prefix: str = "") -> list[dict[str, Any]]:
        """The records whose id begins with ``prefix``.

        The entries go through the protocol's own conversion, so a
        listing looks exactly like the one a client gets over the
        socket. A caller that can talk to both must not be able to tell
        which one it is talking to.
        """
        from ..vaultsvc.protocol import entry_to_object, object_to_dict

        return [object_to_dict(entry_to_object(entry))
                for entry in self._vault.list(prefix)]

    async def list_async(self, prefix: str = "") -> list[dict[str, Any]]:
        import asyncio

        return await asyncio.to_thread(self.list_sync, prefix)

    def status_sync(self) -> dict[str, Any]:
        """What the store reports about itself."""
        from ..vaultsvc.protocol import store_status_to_dict

        return store_status_to_dict(self._vault.status(), self._vault.schema)

    async def status_async(self) -> dict[str, Any]:
        import asyncio

        return await asyncio.to_thread(self.status_sync)

    def healthy_sync(self) -> bool:
        try:
            self._vault.status()
        except Exception:
            return False
        return True

    async def healthy_async(self) -> bool:
        import asyncio

        return await asyncio.to_thread(self.healthy_sync)

    # -- internals ---------------------------------------------------------

    def _shape_sync(self) -> Shape:
        if self._shape is None:
            with self._lock:
                if self._shape is None:
                    self._shape = resolve_shape(self.schema_fields_sync())
        return self._shape

    @staticmethod
    def _to_record(name: str, fields: list[dict[str, Any]]) -> Record:
        """Turn the protocol's fields into a record to store."""
        record = Record(id=name)
        for f in fields:
            raw = base64.b64decode(f.get("data") or "")
            kind = f.get("type", "")
            if kind == "string":
                record.set(f["name"], Value.new_string(raw.decode("utf-8")))
            elif kind == "bytes":
                record.set(f["name"], Value.new_bytes(raw))
            elif kind == "int64":
                record.set(f["name"], Value.new_int64(int(raw.decode())))
            elif kind == "bool":
                record.set(f["name"], Value.new_bool(raw.decode() == "true"))
            else:
                raise VaultError(
                    f"the store's schema uses a type this plugin cannot "
                    f"write: {kind!r}"
                )
        return record


# --- opening the store ------------------------------------------------------

#: The protocol's type names, and the field types they mean.
_TYPES = {
    "string": Type.STRING,
    "bytes": Type.BYTES,
    "int64": Type.INT64,
    "bool": Type.BOOL,
}

#: The environment variable that says how hard the in-process path should
#: try to keep the key material out of the disk.
#:
#: ``best-effort`` (the default) forbids core dumps and tries to pin the
#: process's memory.  ``off`` does nothing.
#:
#: The switch is here because the core dump limit is a **process-wide,
#: one-way** change: it is lowered for the hard limit too, so nothing in
#: the process can raise it again.  A library that did that to its host
#: without being asked would be a library that changed the host's
#: behaviour.  The host gets the final word.
MEMLOCK_ENV = "CRED_ROUTER_VAULT_MEMLOCK"

#: The values the switch accepts.
MEMLOCK_OFF = "off"
MEMLOCK_BEST_EFFORT = "best-effort"


def _protect_process_memory() -> None:
    """Keep the key material out of the disk, as far as this process can.

    Both steps are best effort: how much may be locked is the operating
    system's limit, so a failure is reported rather than fatal. The keys
    themselves are pinned separately, where they are made.
    """
    mode = os.environ.get(MEMLOCK_ENV, MEMLOCK_BEST_EFFORT).strip().lower()
    if mode == MEMLOCK_OFF:
        return
    if mode != MEMLOCK_BEST_EFFORT:
        _log.warning(
            "%s is %r, which is not a mode this path knows; treating it as %r",
            MEMLOCK_ENV, mode, MEMLOCK_BEST_EFFORT)

    from ..platform import memlock

    try:
        memlock.disable_core_dumps()
    except Exception as exc:  # noqa: BLE001 - reported, not fatal
        _log.warning("core dumps are not forbidden: %s", exc)

    try:
        memlock.lock_all()
    except Exception as exc:  # noqa: BLE001 - reported, not fatal
        # Not a warning: this is what "best effort" means.  The limit is
        # the operating system's, and a container without an unlimited
        # memlock limit cannot pin its whole address space — the Python
        # runtime's arena alone is larger than a typical limit.  What
        # protects the keys is that the key material is pinned separately,
        # where it is made.  A warning here would fire on every start in
        # every ordinary container and teach the operator to ignore it.
        _log.info(
            "the whole address space could not be locked; the keys "
            "themselves are locked separately: %s (%s)",
            exc, memlock.report())


def _warn_if_the_store_is_not_there(store_dir: str, config_path: str) -> None:
    """Say so when the store is not there — it is about to be created."""
    from ..vault import DEFAULT_DB_NAME

    db_path = os.path.join(store_dir, DEFAULT_DB_NAME)
    if os.path.exists(db_path):
        return
    _log.warning(
        "the vault store at %s does not exist yet, so it is being created "
        "now with a fresh key set; if you expected an existing store, this "
        "is the wrong directory (the configuration %s names the store's "
        "directory on the host, which is not the directory it is mounted "
        "at inside a container)",
        store_dir, config_path,
    )


def open_in_process_backend(config_path: str,
                            data_dir: str | None = None) -> InProcessBackend:
    """Open the store in this process, from a configuration file."""
    from ..crypto.mode import parse_mode
    from ..platform.config import load_for_store as load_config
    from ..vault import Config as VaultConfig
    from ..vault import Vault

    config = load_config(config_path)
    if not config.vault.enabled():
        raise VaultError(
            f"the configuration {config_path} has no vault.data_dir, so "
            "there is no store to open in this process"
        )
    store_dir = data_dir or config.vault.data_dir

    fields = [
        FieldDef(
            name=f.name,
            type=_TYPES.get(f.type, Type.INVALID),
            encrypted=f.encrypted,
        )
        for f in config.vault.schema.fields
    ]
    schema = Schema(version=config.vault.schema.version, fields=fields)

    _warn_if_the_store_is_not_there(store_dir, config_path)

    vault = Vault.open(
        VaultConfig(
            data_dir=store_dir,
            # The vault's key material is derived with the mode's own
            # PRF, so a vault opened under the wrong cipher derives a
            # different KEK — and then it opens the database fine and
            # cannot decrypt a single record. Passing the mode is
            # therefore not a default, it is a correctness requirement.
            crypto_mode=parse_mode(config.crypto_mode),
        ),
        schema)

    try:
        # This process now holds the store's key material, so it protects
        # itself the way the service does.  It happens after the store is
        # open — the keys exist by then, which is what has to be protected.
        _protect_process_memory()

        # The store's DEK rotation is a capability of the store, and this
        # process is the one holding it — so the rotation is attached here
        # too, and the question of whether anybody is listening on a socket
        # does not arise.  A period of zero attaches nothing.
        rotate_stop = None
        period = config.vault.rotation.period
        if period > 0:
            from ..vault import start_auto_rotate

            rotate_stop = start_auto_rotate(vault, period)
    except BaseException:
        vault.close()
        raise

    return InProcessBackend(vault, rotate_stop=rotate_stop)
