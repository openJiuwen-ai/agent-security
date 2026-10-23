"""Package URL rules; connection address restrictions live in address_policy.

These four detectors retain the migrated defaults. Effective host policy can
override an identical pattern's action; independent matching rules stay strict.
"""

_BUILTIN_NET_URLS = (
    ("169.254.169.254", "deny"),
    ("metadata.google.internal", "deny"),
    ("localhost", "deny"),
    ("127.0.0.1", "deny"),
)


def package_net_urls() -> dict[str, str]:
    """Return a fresh collection so config composition cannot mutate defaults."""
    return dict(_BUILTIN_NET_URLS)


def package_rules_enabled(value: object) -> bool:
    """Parse the package switch, enabling defaults unless explicitly disabled."""
    if isinstance(value, bool):
        return value
    return not (isinstance(value, str) and value.strip().lower() in {"false", "0", "no", "off"})
