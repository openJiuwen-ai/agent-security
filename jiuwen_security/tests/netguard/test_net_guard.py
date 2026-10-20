"""Pipeline C behavior, host boundary regressions and isolated configuration."""

from __future__ import annotations

import asyncio
import builtins
import io
import socket
from pathlib import Path

import pytest

import jiuwen_security
from jiuwen_security import PermissionEngine, PermissionResult
from jiuwen_security import PermissionLevel as L
from jiuwen_security.policy.netguard.component import NetGuardComponent


def checker(urls=None, *, default="allow", include_package=True, connection=None):
    component = NetGuardComponent()
    component.configure(
        {
            "tools": {
                name: "allow"
                for name in ("mcp_fetch_webpage", "fetch_webpage", "web_fetch_webpage")
            },
            "package_builtin_rules": include_package,
            "net_guard": {
                "enabled": True,
                "defaults": default,
                "urls": urls or {},
                "connection": connection or {},
            },
        }
    )
    return component


def evaluate(component, url=None, *, tool="mcp_fetch_webpage", args=None):
    # These tests isolate URL/address rules; production component aggregation is
    # covered through PermissionEngine in test_permission_entrypoint.py.
    return component._evaluate_url_policy(tool, args if args is not None else {"url": url})


@pytest.mark.parametrize("tool", ["mcp_fetch_webpage", "fetch_webpage", "web_fetch_webpage"])
@pytest.mark.parametrize("key", ["url", "uri", "href", "webpage", "page_url", "target_url"])
def test_legacy_tools_and_argument_keys(tool, key):
    result = evaluate(
        checker({"example.com": "ask"}), tool=tool, args={key: "https://example.com/a"}
    )
    assert result.permission is L.ASK
    assert result.matched_rule == "net_guard:url:example.com"


def test_key_priority_and_legacy_missing_url_defaults():
    component = checker({"example.com": "deny"}, default="ask")
    assert (
        evaluate(
            component, args={"url": "https://other.com", "uri": "https://example.com"}
        ).permission
        is L.ASK
    )
    assert evaluate(component, args={"url": " ", "uri": "https://example.com"}).permission is L.DENY
    result = evaluate(component, args={"url": 123})
    assert result.permission is L.ASK
    assert result.matched_rule == "net_guard:defaults"


def test_explicit_allow_is_distinct_from_not_applicable():
    component = checker()
    assert evaluate(component, "https://example.com").permission is L.ALLOW
    assert evaluate(component, tool="mcp_free_search", args={"url": "https://localhost"}) is None
    assert evaluate(component, tool="bash", args={"command": "curl https://localhost"}) is None
    component.configure({})
    assert evaluate(component, args=[]) is None
    with pytest.raises(RuntimeError):
        evaluate(NetGuardComponent(), "https://example.com")


def test_same_object_override_and_independent_strictest_matches():
    component = checker({"localhost": "ask", "*.example.com": "deny", "api.example.com": "allow"})
    assert evaluate(component, "https://localhost").permission is L.ASK
    assert evaluate(component, "https://127.0.0.1").permission is L.DENY
    assert evaluate(component, "https://169.254.169.254").permission is L.DENY
    assert evaluate(component, "https://metadata.google.internal").permission is L.DENY
    assert evaluate(component, "https://api.example.com").permission is L.DENY
    assert evaluate(component, "https://example.com").permission is L.ALLOW
    assert evaluate(checker({"localhost": "allow"}), "https://localhost").permission is L.ALLOW
    assert evaluate(checker(include_package=False), "https://localhost").permission is L.ALLOW


@pytest.mark.parametrize(
    "rules, expected",
    [
        ({"example.com": "allow", "*.com": "ask"}, L.ASK),
        ({"example.com": "ask", "*.com": "deny"}, L.DENY),
        ({"example.com": "allow", "*.com": "allow"}, L.ALLOW),
    ],
)
def test_all_matching_objects_participate(rules, expected):
    config = {
        "composition": {
            "source_order": ["user", "cloud"],
            "net_url_layers": {"example.com": "user", "*.com": "cloud"},
        },
        "net_guard": {"enabled": True, "urls": rules},
    }
    component = NetGuardComponent()
    component.configure(config)
    assert evaluate(component, "https://example.com").permission is expected


@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://good.example/a", L.DENY),
        ("HTTPS://GOOD.EXAMPLE.:443/a", L.DENY),
        ("https://good.example.attacker.invalid/a", L.ALLOW),
        ("http://good.example/a", L.ALLOW),
        ("https://good.example:444/a", L.ALLOW),
    ],
)
def test_url_prefix_requires_same_origin(url, expected):
    assert evaluate(checker({"https://good.example": "deny"}), url).permission is expected


def test_host_globs_cannot_consume_another_authority_or_port():
    component = checker({"https://*.good.example/safe*": "deny"})
    assert evaluate(component, "https://api.good.example/safe/a").permission is L.DENY
    assert (
        evaluate(component, "https://api.good.example.attacker.invalid/safe/a").permission
        is L.ALLOW
    )
    assert evaluate(component, "https://api.good.example:444/safe/a").permission is L.ALLOW
    assert (
        evaluate(component, "https://attacker.invalid/api.good.example/safe/a").permission
        is L.ALLOW
    )


def test_idna_ipv6_default_ports_and_legacy_path_prefix():
    component = checker(
        {"https://bücher.example:443/safe": "deny", "https://[2001:4860:4860::8888]/x": "ask"}
    )
    assert evaluate(component, "https://xn--bcher-kva.example/safe-other").permission is L.DENY
    assert evaluate(component, "https://[2001:4860:4860:0:0:0:0:8888]:443/xyz").permission is L.ASK
    component = checker({"https://example.com/a[0]*": "deny"})
    assert evaluate(component, "https://example.com/a[0]xyz").permission is L.DENY
    assert evaluate(component, "https://example.com/a0xyz").permission is L.ALLOW


@pytest.mark.parametrize(
    "url",
    [
        "https://good.example@attacker.invalid/",
        "https://@example.com/",
        "file:///tmp/key",
        "ftp://example.com",
        "example.com",
        "https:///a",
        "https://example.com:",
        "https://example.com:0",
        "https://example.com:65536",
        "https://example.com:abc",
        "https://[::1",
        "https://example.com\\@other.com",
        "https://exam\nple.com",
        "https://example.com/a b",
        "https://example.com/\x00",
        "https://[fe80::1%25eth0]/",
        "https://bad_host.example",
        "https://-bad.example",
        "https://[v1.example]/",
        "https://" + "a" * 254 + ".example",
        "https://a..example",
        "https://" + ".".join(["bücher"] * 30),
        "https://\ud800.example",
    ],
)
def test_unsafe_or_ambiguous_url_is_an_input_error(url):
    with pytest.raises(ValueError):
        evaluate(checker(), url)


@pytest.mark.parametrize(
    "key", ["token", "api_key", "accessToken", "private-key", "x_session_id", "signature", "key"]
)
def test_query_secrets_are_redacted_soft_warnings(key):
    url = "https://example.com/data?" + key + "=SENSITIVE_VALUE"
    result = evaluate(checker({url: "allow"}), url)
    assert result.permission is L.ALLOW
    assert result.warnings == ["network_secret_query"]
    assert "SENSITIVE_VALUE" not in repr(result)
    assert evaluate(checker(), "https://example.com/?monkey=abc").warnings == []


@pytest.mark.parametrize(
    "config",
    [
        [],
        {"net_guard": None},
        {"net_guard": {"enabled": "true"}},
        {"net_guard": {"defaults": "undetermined"}},
        {"net_guard": {"urls": []}},
        {"net_guard": {"urls": {"example.com": "bad"}}},
        {"net_guard": {"urls": {"": "deny"}}},
        {"net_guard": {"urls": {123: "deny"}}},
        {"net_guard": {"urls": {"localhost": "allow", " localhost ": "deny"}}},
        {"net_guard": {"urls": {"https://user:secret@example.com": "deny"}}},
        {"net_guard": {"connection": {"allow_http": "false"}}},
        {"net_guard": {"connection": None}},
        {"net_guard": {"connection": {"unknown": False}}},
    ],
)
def test_bad_configuration_keeps_previous_snapshot(config):
    component = checker({"example.com": "deny"})
    with pytest.raises(ValueError):
        component.configure(config)
    assert evaluate(component, "https://example.com").permission is L.DENY


def test_config_instances_inputs_and_results_are_isolated():
    config = {"net_guard": {"enabled": True, "urls": {"example.com": "deny"}}}
    first, second = NetGuardComponent(), checker({"example.com": "allow"})
    first.configure(config)
    config["net_guard"]["urls"]["example.com"] = "allow"
    result = evaluate(first, "https://example.com")
    result.permission = L.ALLOW
    result.warnings.append("mutated")
    assert evaluate(first, "https://example.com").permission is L.DENY
    assert evaluate(second, "https://example.com").permission is L.ALLOW
    first.configure(config)
    assert evaluate(first, "https://example.com").permission is L.ALLOW


def test_evaluation_performs_no_io_or_configuration_loading(monkeypatch):
    component = checker({"example.com": "ask"})

    def forbidden(*args, **kwargs):
        raise AssertionError("Evaluation attempted IO")

    # Create the event loop before replacing socket.socket (used by its wakeup pipe).
    loop = asyncio.new_event_loop()
    try:
        with monkeypatch.context() as patch:
            for owner, name in [
                (builtins, "open"),
                (io, "open"),
                (Path, "open"),
                (Path, "read_text"),
                (Path, "read_bytes"),
                (socket, "getaddrinfo"),
                (socket, "create_connection"),
                (socket, "socket"),
            ]:
                patch.setattr(owner, name, forbidden)
            result = loop.run_until_complete(
                component.evaluate(
                    "network_connect",
                    {
                        "url": "https://example.com/?token=secret",
                        "resolved_addresses": ["8.8.8.8"],
                        "connect_address": "8.8.8.8",
                    },
                )
            )
            assert result.permission is L.ASK
            assert result.warnings == ["network_secret_query"]
            result = loop.run_until_complete(
                component.evaluate(
                    "mcp_fetch_webpage",
                    {
                        "url": "https://bücher.example/café",
                    },
                )
            )
            assert result.permission is L.ALLOW
    finally:
        loop.close()


def test_component_can_be_attached_without_changing_engine_or_exports():
    component = checker({"example.com": "allow"})

    class Baseline:
        def configure(self, config):
            pass

        async def evaluate(self, tool_name, tool_args):
            return PermissionResult(L.ASK, "tool_baseline")

    class TestEngine(PermissionEngine):
        def _build_components(self):
            return (Baseline(), component)

    engine = TestEngine({"net_guard": {"enabled": True, "urls": {"example.com": "allow"}}})
    result = asyncio.run(engine.check_permission("fetch_webpage", {"url": "https://example.com"}))
    assert result.permission is L.ASK
    engine.update_config({"net_guard": {"enabled": True, "urls": {"example.com": "deny"}}})
    assert (
        asyncio.run(
            engine.check_permission("fetch_webpage", {"url": "https://example.com"})
        ).permission
        is L.DENY
    )
    assert "NetGuardComponent" not in jiuwen_security.__all__


def test_redirect_targets_are_checked_again_without_an_implicit_grant():
    component = checker({"start.example": "allow", "redirect.example": "ask"})
    assert evaluate(component, "https://start.example").permission is L.ALLOW
    assert evaluate(component, "https://redirect.example").permission is L.ASK
    assert evaluate(component, "https://127.0.0.1").permission is L.DENY


def test_query_fragment_and_single_character_host_patterns():
    component = checker(
        {"https://example.com/page?lang=en#section": "deny", "api?.example.com": "ask"}
    )
    assert evaluate(component, "https://example.com/page?lang=en#section").permission is L.DENY
    assert evaluate(component, "https://example.com/page?lang=fr#section").permission is L.ALLOW
    assert evaluate(component, "https://api1.example.com").permission is L.ASK
    with pytest.raises(ValueError):
        evaluate(component, args=[])
