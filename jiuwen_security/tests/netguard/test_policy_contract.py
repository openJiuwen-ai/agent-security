"""Shared URL policy contracts and deliberate migration differences.

Rule scenarios were checked against agent-core develop 1fe6a036 and security
5951559a; dev-stable e6a3d8cb has no corresponding NetGuard/net_urls module.
Tests use frozen expectations and need neither those repositories nor IO.
"""

import pytest

from jiuwen_security import PermissionLevel as L
from jiuwen_security.policy.netguard.net_guard import NetGuardChecker

from .test_address_policy import connect
from .test_net_guard import checker, evaluate

# Common, unambiguous URL cases retain the original match outcome. Unsafe
# origin-prefix matching and permissive configuration parsing are not retained.
URL_RULE_CASES = (
    ("example.com", "https://EXAMPLE.COM.:8443/a", True),
    ("example.com", "http://other.example/a", False),
    ("*.example.com", "https://api.example.com/a", True),
    ("*.example.com", "https://example.com/a", False),
    ("api?.example.com", "https://api1.example.com/a", True),
    ("api?.example.com", "https://api12.example.com/a", False),
    ("https://example.com/safe", "https://example.com/safe-other", True),
    ("https://example.com/safe", "https://example.com/other", False),
    ("https://*.example.com/safe*", "https://api.example.com/safe/path", True),
    ("https://example.com/*", "https://example.com/abc", True),
    ("https://example.com/page?q=en", "https://example.com/page?q=en", True),
    ("https://example.com/page?q=en", "https://example.com/page?q=fr", False),
    ("https://[2001:4860::8888]/safe*", "https://[2001:4860::8888]/safe/path", True),
)


@pytest.mark.parametrize("pattern,url,matched", URL_RULE_CASES)
@pytest.mark.parametrize("action", ("allow", "ask", "deny"))
def test_url_rule_actions_preserve_shared_matching_contract(pattern, url, matched, action):
    default = "deny" if action == "allow" else "allow"
    result = evaluate(checker({pattern: action}, default=default, include_package=False), url)
    assert result.permission is L(action if matched else default)
    assert result.matched_rule == ("net_guard:url:" + pattern if matched else "net_guard:defaults")


@pytest.mark.parametrize("action", ("allow", "ask", "deny"))
@pytest.mark.parametrize(
    "url",
    (
        "https://search.provider.example/query?q=public",
        "https://hooks.partner.example:8443/callback",
        "https://remote.mcp.example/events",
    ),
)
def test_any_actual_exit_url_uses_the_same_policy_without_a_fetch_tool(url, action):
    component = checker({url: action}, default="deny", include_package=False)
    result = connect(component, ["8.8.8.8"], url=url)
    assert result.permission is L(action)
    assert result.matched_rule == "net_guard:url:" + url
    # The tool-independent capability is carried by the engine's internal
    # connection action; it does not broaden the supported fetch-tool set.
    assert evaluate(component, url, tool="custom_http_tool") is None


@pytest.mark.parametrize(
    "pattern",
    (
        "169.254.169.254",
        "metadata.google.internal",
        "localhost",
        "127.0.0.1",
    ),
)
@pytest.mark.parametrize("action", ("allow", "ask", "deny"))
def test_every_package_rule_can_be_overridden_by_its_exact_object_key(pattern, action):
    component = checker({pattern: action}, default="ask")
    result = evaluate(component, "https://" + pattern + "/")
    assert result.permission is L(action)
    assert result.matched_rule == "net_guard:url:" + pattern
    # Replacing a complete configuration must restore omitted package defaults.
    component.configure({"net_guard": {"enabled": True}})
    assert evaluate(component, "https://" + pattern + "/").permission is L.DENY


@pytest.mark.parametrize("pattern,expected", ((" localhost ", L.ALLOW), ("LOCALHOST.", L.DENY)))
def test_trimmed_object_keys_override_but_equivalent_spellings_still_take_strictest(
    pattern, expected
):
    result = evaluate(checker({pattern: "allow"}), "https://localhost")
    assert result.permission is expected


@pytest.mark.parametrize(
    "legacy_action", (" ALLOW ", "DENY", {"action": "allow"}, {"fetch": "deny"}, None, 1)
)
@pytest.mark.parametrize("field", ("defaults", "urls"))
def test_legacy_action_shapes_require_host_normalization_and_never_partially_apply(
    field, legacy_action
):
    component = checker({"example.com": "ask"})
    section = {"enabled": True, "urls": {"example.com": "allow"}}
    section[field] = {"example.com": legacy_action} if field == "urls" else legacy_action
    with pytest.raises(ValueError):
        component.configure({"net_guard": section})
    assert evaluate(component, "https://example.com").permission is L.ASK


def test_shared_rules_are_instance_owned_and_ignore_host_global_enable_shortcuts():
    first = checker({"example.com": "deny"})
    second = NetGuardChecker()
    # Global execution short-circuiting belongs to W6, including the exception
    # for raw policy queries. The W3 component owns only net_guard.enabled.
    second.configure(
        {"enabled": False, "net_guard": {"enabled": True, "urls": {"example.com": "allow"}}}
    )
    assert evaluate(first, "https://example.com").permission is L.DENY
    assert evaluate(second, "https://example.com").permission is L.ALLOW
