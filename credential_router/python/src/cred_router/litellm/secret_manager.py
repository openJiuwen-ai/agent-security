"""The litellm plugin.

litellm has a custom secret manager mechanism: ``config.yaml`` says

    general_settings:
      key_management_system: custom
      key_management_settings:
        access_mode: read_only
        custom_secret_manager: "cred_router_litellm.CredRouterSecretManager"

and litellm instantiates the class at startup — **it must be constructible
with no arguments** — and then every ``get_secret()`` lands here.

The class must therefore live in a module litellm can import by path.
That module may import this package; this package must never import
litellm, or the core would drag litellm in with it.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Any

from .backends import (
    SecretBackend,
    UdsBackend,
    default_socket_path,
    default_timeout,
)
from .ids import KIND_MASTER_KEY, KIND_VKEY, MASTER_KEY_ID, NAMESPACE_PREFIX
from .shape import VaultError

#: The cache is off by default. litellm only asks for secrets at startup
#: and when it reloads its models, both of which are infrequent, so a
#: cache hides little; but a cache makes "the store deleted it" visible up
#: to a TTL late, and a revocation that is a second late is a risk.
DEFAULT_CACHE_TTL = 0.0

#: How the plugin reaches the store. ``inprocess`` opens the store in
#: this process; ``uds`` talks to the service over its socket.
MODE_INPROCESS = "inprocess"
MODE_UDS = "uds"


def default_backend() -> SecretBackend:
    """The backend the plugin uses unless it is given one."""
    mode = os.environ.get("CRED_ROUTER_VAULT_MODE", MODE_UDS).strip().lower()
    if mode == MODE_INPROCESS:
        from .inprocess import open_in_process_backend

        config_path = os.environ.get("CRED_ROUTER_VAULT_CONFIG", "")
        if not config_path:
            raise VaultError(
                "CRED_ROUTER_VAULT_MODE is inprocess, so "
                "CRED_ROUTER_VAULT_CONFIG must name the service's "
                "configuration file"
            )
        # The store's directory on the host is not the directory it is
        # mounted at inside a container, so it can be named separately.
        data_dir = os.environ.get("CRED_ROUTER_VAULT_DATA_DIR", "") or None
        return open_in_process_backend(config_path, data_dir)
    if mode == MODE_UDS:
        return UdsBackend(default_socket_path(), default_timeout())
    raise VaultError(
        f"CRED_ROUTER_VAULT_MODE must be {MODE_INPROCESS} or {MODE_UDS}, "
        f"got {mode!r}"
    )


def _load_secret_manager_base() -> type:
    """Import litellm's base class, or say why we cannot."""
    try:
        from litellm.integrations.custom_secret_manager import (
            CustomSecretManager,
        )
    except ImportError as exc:  # pragma: no cover - depends on the extra
        raise ImportError(
            "the litellm secret manager needs litellm itself; install it "
            "with `pip install cred-router-python[litellm]`"
        ) from exc
    return CustomSecretManager


class CredRouterSecretManagerBase:
    """The behaviour, independent of litellm.

    Keeping it separate means the logic can be tested without litellm
    installed, and it keeps litellm's import inside one small place.
    """

    def __init__(self, backend: SecretBackend | None = None,
                 seed_names: tuple[str, ...] | None = None,
                 cache_ttl: float | None = None) -> None:
        self._backend = backend if backend is not None else default_backend()
        if cache_ttl is not None:
            self._cache_ttl = float(cache_ttl)
        else:
            self._cache_ttl = float(
                os.environ.get("CRED_ROUTER_VAULT_CACHE_TTL",
                               DEFAULT_CACHE_TTL))
        seed_env = os.environ.get("CRED_ROUTER_VAULT_SEED_NAMES")
        if seed_names is not None:
            self._seed_names = tuple(seed_names)
        elif seed_env:
            self._seed_names = tuple(
                name.strip() for name in seed_env.split(",") if name.strip()
            )
        else:
            self._seed_names = (MASTER_KEY_ID,)
        self._cache: dict[str, tuple[float, str]] = {}
        self._cache_lock = threading.Lock()

    # -- the namespace filter ---------------------------------------------

    def _is_ours(self, secret_name: str) -> bool:
        """Whether this name could be one we put in the store.

        The seed names are let through too — the operator named them
        explicitly, so the namespace filter must not drop them.
        """
        if secret_name == MASTER_KEY_ID or secret_name in self._seed_names:
            return True
        return secret_name.startswith(NAMESPACE_PREFIX)

    # -- reading ------------------------------------------------------------

    def sync_read_secret(self, secret_name: str,
                         optional_params: dict | None = None,
                         timeout: Any = None) -> str | None:
        if not self._is_ours(secret_name):
            return None
        cached = self._cached(secret_name)
        if cached is not None:
            return cached
        value = self._backend.read_sync(secret_name)
        if value is None:
            return self._seed_sync(secret_name)
        text = value.decode("utf-8")
        self._remember(secret_name, text)
        return text

    async def async_read_secret(self, secret_name: str,
                                optional_params: dict | None = None,
                                timeout: Any = None) -> str | None:
        if not self._is_ours(secret_name):
            return None
        cached = self._cached(secret_name)
        if cached is not None:
            return cached
        value = await self._backend.read_async(secret_name)
        if value is None:
            return await self._seed_async(secret_name)
        text = value.decode("utf-8")
        self._remember(secret_name, text)
        return text

    # -- writing and deleting ----------------------------------------------

    async def async_write_secret(self, secret_name: str,
                                 secret_value: str,
                                 description: str | None = None,
                                 optional_params: dict | None = None,
                                 tags: Any = None) -> dict[str, Any]:
        """Write a virtual key litellm generated into the store."""
        await self._backend.write_async(
            secret_name,
            KIND_VKEY,
            secret_value.encode("utf-8"),
            {"description": description or "", "tags": tags or {}},
        )
        self._forget(secret_name)
        return {"status": "written", "secret_name": secret_name}

    async def async_delete_secret(self, secret_name: str,
                                  optional_params: dict | None = None,
                                  ) -> dict[str, Any]:
        deleted = await self._backend.delete_async(secret_name)
        self._forget(secret_name)
        if not deleted:
            # A delete of something that is not there has achieved what it
            # was asked to do.
            return {"status": "deleted", "secret_name": secret_name}
        return {"status": "deleted", "secret_name": secret_name}

    # -- the environment check ---------------------------------------------

    def validate_environment(self) -> bool:
        return self._backend.healthy_sync()

    async def async_health_check(self, timeout: Any = None) -> bool:
        return await self._backend.healthy_async()

    # -- seeding ------------------------------------------------------------

    def _seed_value(self, secret_name: str) -> str | None:
        """The migration-period seed from the environment."""
        if secret_name not in self._seed_names:
            return None
        value = os.environ.get(secret_name)
        return value if value else None

    def _seed_sync(self, secret_name: str) -> str | None:
        value = self._seed_value(secret_name)
        if value is None:
            return None
        self._backend.write_sync(
            secret_name,
            KIND_MASTER_KEY,
            value.encode("utf-8"),
            {"seeded_from": "environment"},
        )
        self._remember(secret_name, value)
        return value

    async def _seed_async(self, secret_name: str) -> str | None:
        value = self._seed_value(secret_name)
        if value is None:
            return None
        await self._backend.write_async(
            secret_name,
            KIND_MASTER_KEY,
            value.encode("utf-8"),
            {"seeded_from": "environment"},
        )
        self._remember(secret_name, value)
        return value

    # -- the cache ----------------------------------------------------------

    def _cached(self, secret_name: str) -> str | None:
        with self._cache_lock:
            hit = self._cache.get(secret_name)
        if hit is None:
            return None
        expires_at, value = hit
        if expires_at <= time.monotonic():
            self._forget(secret_name)
            return None
        return value

    def _remember(self, secret_name: str, value: str) -> None:
        if self._cache_ttl <= 0:
            return
        with self._cache_lock:
            self._cache[secret_name] = (
                time.monotonic() + self._cache_ttl, value)

    def _forget(self, secret_name: str) -> None:
        with self._cache_lock:
            self._cache.pop(secret_name, None)


def _build_secret_manager_class() -> type:
    """Build the class litellm instantiates."""
    base = _load_secret_manager_base()

    # The order of the bases is load-bearing, and getting it wrong is
    # silent until litellm tries to instantiate the class: litellm's
    # ``CustomSecretManager`` declares ``sync_read_secret`` and
    # ``async_read_secret`` as abstract methods, and the implementation
    # class here defines them too. With litellm's base first, the method
    # resolution order finds litellm's **abstract** versions before ours,
    # so the class is still abstract and litellm fails with
    # "Can't instantiate abstract class ... without an implementation for
    # abstract methods 'async_read_secret', 'sync_read_secret'".
    #
    # Putting the implementation class first means ours wins, and
    # ``__abstractmethods__`` comes out empty.
    class CredRouterSecretManager(CredRouterSecretManagerBase, base):  # type: ignore[misc,valid-type]
        """Connects litellm's secret lookup to the secure store.

        Not finding a secret returns None: litellm's ``get_secret``
        turns that None into a ValueError and falls back to the
        environment. That fallback is litellm's existing behaviour and
        not ours to change.
        """

        def __init__(self) -> None:
            base.__init__(self, secret_manager_name="cred_router_vault")
            CredRouterSecretManagerBase.__init__(self)

    return CredRouterSecretManager


def __getattr__(name: str) -> Any:
    """Build the litellm-facing class on first use."""
    if name == "CredRouterSecretManager":
        return _build_secret_manager_class()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [  # noqa: F822 - CredRouterSecretManager is built by __getattr__
    "CredRouterSecretManager",
    "CredRouterSecretManagerBase",
    "VaultError",
]
