"""Reading secrets from the store on litellm's behalf.

This package holds the contract litellm and the management backend share:
the object ids, the kinds, the shape of a record, and how to reach the
store.

Importing this package does **not** import litellm. The plugin class that
litellm needs lives in :mod:`cred_router.litellm.secret_manager` and is
built on first use, so the core never drags litellm in with it.
"""

from __future__ import annotations

from .backends import (
    DEFAULT_SOCKET,
    DEFAULT_TIMEOUT,
    MAX_FRAME,
    SecretBackend,
    UdsBackend,
)
from .inprocess import InProcessBackend, open_in_process_backend
from .ids import (
    KIND_MASTER_KEY,
    KIND_MODEL_KEY,
    KIND_SECRET,
    KIND_VKEY,
    MASTER_KEY_ID,
    MODEL_KEY_PREFIX,
    NAMESPACE_PREFIX,
    VKEY_PREFIX,
    model_key_id,
    vkey_id,
)
from .shape import Shape, VaultError, decode_payload, encode_put, resolve_shape

__all__ = [
    "DEFAULT_SOCKET",
    "DEFAULT_TIMEOUT",
    "KIND_MASTER_KEY",
    "KIND_MODEL_KEY",
    "KIND_SECRET",
    "KIND_VKEY",
    "MASTER_KEY_ID",
    "MAX_FRAME",
    "MODEL_KEY_PREFIX",
    "NAMESPACE_PREFIX",
    "InProcessBackend",
    "SecretBackend",
    "Shape",
    "UdsBackend",
    "VKEY_PREFIX",
    "VaultError",
    "decode_payload",
    "encode_put",
    "model_key_id",
    "open_in_process_backend",
    "resolve_shape",
    "vkey_id",
]
