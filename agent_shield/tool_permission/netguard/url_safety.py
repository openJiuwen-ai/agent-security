"""Pure URL parsing and redacted network risk facts. No DNS resolution."""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from encodings.idna import ToASCII, ToUnicode
from urllib.parse import parse_qsl, quote, urlsplit

MAX_URL_CHARS = 8192
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\Z")
_AMBIGUOUS_URL = re.compile(r"[\x00-\x20\x7f\\]|\s")
_NUMERIC_HOST = re.compile(r"(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*\Z")
_PERCENT_ESCAPE = re.compile(r"%([0-9a-fA-F]{2})|%")
_UNRESERVED = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")
_SECRET_WORDS = frozenset(
    {
        "auth",
        "authorization",
        "bearer",
        "credential",
        "credentials",
        "jwt",
        "key",
        "passwd",
        "password",
        "pwd",
        "secret",
        "session",
        "token",
    }
)
_SECRET_COMPACT = frozenset(
    {
        "accesstoken",
        "apikey",
        "authkey",
        "clientsecret",
        "idtoken",
        "privatekey",
        "refreshtoken",
        "sessionid",
        "signature",
    }
)


@dataclass(frozen=True, slots=True)
class UrlTarget:
    scheme: str
    host: str
    port: int
    path: str
    query: str
    has_query: bool


def normalize_host(value: str, *, pattern: bool = False) -> str:
    """Canonicalize an IP literal or IDNA host, optionally with host globs."""
    host = value.lower().removesuffix(".")
    if not host or host.endswith(".") or "%" in host:
        raise ValueError("Invalid network host")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        return str(address)
    if _NUMERIC_HOST.fullmatch(host):
        raise ValueError("Non-canonical numeric network host")
    if ":" in host or len(host) > 253:
        raise ValueError("Invalid network host")
    labels = []
    for label in host.split("."):
        if not label.isascii() and any(char in label for char in "*?"):
            raise ValueError("Unicode host globs require separate ASCII wildcard labels")
        try:
            ascii_label = label if label.isascii() else ToASCII(label).decode("ascii").lower()
            # The stdlib codec implements IDNA2003; HTTP clients can use IDNA2008.
            # Reject lossy mappings (e.g. ß -> ss) instead of authorizing another
            # DNS name. Explicit ASCII A-labels and stable Unicode remain usable.
            if not label.isascii() and ToUnicode(ascii_label) != unicodedata.normalize(
                "NFC", label
            ):
                raise ValueError("Ambiguous IDNA network host")
        except UnicodeError:
            raise ValueError("Invalid network host") from None
        check = ascii_label.replace("*", "x").replace("?", "x") if pattern else ascii_label
        if len(ascii_label) > 63 or not _HOST_LABEL.fullmatch(check):
            raise ValueError("Invalid network host")
        labels.append(ascii_label)
    normalized = ".".join(labels)
    if len(normalized) > 253:
        raise ValueError("Invalid network host")
    return normalized


def _normalize_component(value: str, *, path: bool) -> str:
    def escape(match: re.Match[str]) -> str:
        digits = match.group(1)
        if digits is None:
            raise ValueError("Invalid URL percent escape")
        code = int(digits, 16)
        if code < 32 or code == 127 or (path and code in {37, 47, 92}):
            raise ValueError("Ambiguous encoded URL character")
        char = chr(code)
        return char if char in _UNRESERVED else "%" + digits.upper()

    if "%" in value:
        value = _PERCENT_ESCAPE.sub(escape, value)
    # Clients disagree on removing raw/encoded dot segments and decoding path
    # separators. Reject those inputs rather than guessing the executed path.
    if path and any(segment in {".", ".."} for segment in value.split("/")):
        raise ValueError("Ambiguous URL dot segment")
    try:
        return quote(value, safe="/:@!$&'()*+,;=-._~%" + ("?=" if not path else ""))
    except UnicodeError:
        raise ValueError("Invalid URL text") from None


def parse_url(value: str, *, pattern: bool = False) -> UrlTarget:
    """Parse without silently discarding whitespace, credentials or bad ports."""
    if not isinstance(value, str) or not value or len(value) > MAX_URL_CHARS:
        raise ValueError("URL must be a non-empty string of at most 8192 characters")
    if _AMBIGUOUS_URL.search(value) is not None:
        raise ValueError("URL contains ambiguous characters")
    parsed_value = value
    if pattern and "://" in value and "?" in value.split("#", 1)[0]:
        scheme_text, rest = value.split("://", 1)
        authority, slash, resource = rest.partition("/")
        if not slash or "#" in authority:
            raise ValueError("URL patterns with ? require an explicit / path boundary")
        # Patterns use the explicit slash as authority boundary. Protect host
        # question globs from urlsplit; literal control characters were rejected
        # above, so the sentinel cannot collide with caller input.
        parsed_value = scheme_text + "://" + authority.replace("?", "\x01") + "/" + resource
    try:
        parts = urlsplit(parsed_value)
        scheme = parts.scheme.lower()
        host = parts.hostname
        port = parts.port
        userinfo = parts.username is not None or parts.password is not None
    except ValueError:
        raise ValueError("Invalid URL authority") from None
    if scheme not in {"http", "https"} or not host or userinfo:
        raise ValueError("URL requires HTTP(S), a host, and no userinfo")
    if parts.netloc.endswith(":") or port == 0:
        raise ValueError("Invalid URL port")
    if pattern:
        host = host.replace("\x01", "?")
    normalized = normalize_host(host, pattern=pattern)
    if parts.netloc.startswith("["):
        # Keep the same boundary on older supported urllib.parse versions.
        closing = parts.netloc.find("]")
        remainder = parts.netloc[closing + 1 :]
        if remainder and not re.fullmatch(r":[0-9]+", remainder):
            raise ValueError("Invalid IPv6 URL authority")
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            raise ValueError("Bracketed URL host must be an IPv6 literal") from None
    elif ":" in normalized:
        raise ValueError("IPv6 URL host must be bracketed")
    return UrlTarget(
        scheme,
        normalized,
        port or (443 if scheme == "https" else 80),
        _normalize_component(parts.path or "/", path=True),
        _normalize_component(parts.query, path=False),
        "?" in parsed_value.split("#", 1)[0],
    )


def has_secret_query(query: str) -> bool:
    """Inspect key names only; never return credentials or query values."""
    for key, _value in parse_qsl(query, keep_blank_values=True):
        words = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key)
        tokens = re.findall(r"[a-z0-9]+", words.lower())
        if "".join(tokens) in _SECRET_COMPACT or _SECRET_WORDS.intersection(tokens):
            return True
    return False


def rule_label(pattern: str, *, query: str) -> str:
    """Keep rule identity useful without exposing secret query values."""
    pattern = pattern.split("#", 1)[0]
    if "://" in pattern and has_secret_query(query):
        path_start = pattern.index("/", pattern.index("://") + 3)
        return pattern[: pattern.index("?", path_start)] + "?<redacted>"
    return pattern
