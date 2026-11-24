"""security_gateway: a generic secure store and credential router.

The package is layered:

``security_gateway.crypto``
    The cryptographic primitives and the on-disk formats. Everything else
    builds on it.
``security_gateway.platform``
    The error envelope, configuration and process-level guards.
``security_gateway.vault``
    The generic encrypted field store: a schema, a record container, key
    material and rotation.
"""

from __future__ import annotations

__version__ = "0.1.0"
