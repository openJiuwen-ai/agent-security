"""Small helpers for tests that talk to a real etcd."""

from __future__ import annotations

from urllib.parse import urlparse


def host_port(endpoint: str) -> tuple[str, int]:
    """Split an etcd endpoint into the host and port etcd3 expects."""
    parsed = urlparse(endpoint if "://" in endpoint else f"http://{endpoint}")
    return parsed.hostname or "127.0.0.1", parsed.port or 2379


def drop_namespace(
    endpoint: str,
    namespace: str,
    *,
    ca: str | None = None,
    cert: str | None = None,
    key: str | None = None,
) -> None:
    """Delete every key a test wrote under ``namespace``.

    Every test uses a unique namespace, so this is safe to call after its
    Vaults are closed.  Leaving the keys behind makes a long-running soak
    fill the etcd data directory and eventually the filesystem.
    """
    import etcd3

    host, port = host_port(endpoint)
    kwargs: dict[str, str] = {}
    if ca:
        kwargs["ca_cert"] = ca
    if cert:
        kwargs["cert_cert"] = cert
    if key:
        kwargs["cert_key"] = key
    client = etcd3.client(host=host, port=port, **kwargs)
    try:
        client.delete_prefix(f"/security_gateway/{namespace}/")
    finally:
        client.close()
