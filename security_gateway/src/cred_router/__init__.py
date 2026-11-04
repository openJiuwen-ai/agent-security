"""cred_router: a generic secure store and credential router.

The package is layered:

``cred_router.crypto``
    The cryptographic primitives and the on-disk formats. Everything else
    builds on it.
``cred_router.vault``
    The generic encrypted field store: a schema, a record container, key
    material and rotation.
``cred_router.vaultsvc``
    The service that exposes the vault over a unix socket and TCP.
``cred_router.credmgr``
    The credential router itself: the credential store, the key material
    it uses, the admin API and the proxy.
``cred_router.litellm``
    The adapter that lets litellm read secrets in-process. Importing this
    package must not pull in litellm; that module is an optional extra.
"""

from __future__ import annotations

__version__ = "0.1.0"
