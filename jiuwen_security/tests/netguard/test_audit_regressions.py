"""Security regressions from the four-reference-branch W3 audit."""

import asyncio
from fnmatch import fnmatchcase
from random import Random

import pytest

from jiuwen_security import PermissionLevel as L

from .test_address_policy import connect
from .test_net_guard import checker, evaluate


@pytest.mark.parametrize(
    "host",
    [
        "faß.example",
        "ς.example",
        "ｅxample.com",
        "a\u200db.example",
        "127.1",
        "2130706433",
        "0x7f000001",
        "0177.0.0.1",
        "127.0.0.1..",
    ],
)
def test_ambiguous_host_cannot_authorize_a_different_client_target(host):
    with pytest.raises(ValueError):
        evaluate(checker(), "https://" + host + "/")
    with pytest.raises(ValueError):
        checker({host: "allow"})


def test_stable_idna_and_explicit_ascii_punycode_remain_supported():
    assert (
        evaluate(
            checker({"*.bücher.example": "deny"}), "https://a.xn--bcher-kva.example"
        ).permission
        is L.DENY
    )
    assert (
        evaluate(checker({"xn--fa-hia.example": "ask"}), "https://xn--fa-hia.example").permission
        is L.ASK
    )
    with pytest.raises(ValueError):
        checker({"*bücher.example": "allow"})


@pytest.mark.parametrize(
    "path",
    [
        "/safe/../private",
        "/safe/./private",
        "/safe/%2e%2E/private",
        "/safe/%252e%252e/private",
        "/safe%2f../private",
        "/safe%5c../private",
        "/safe/%00/private",
        "/safe/%7f/private",
        "/safe/%zz/private",
        "/safe/%",
    ],
)
def test_client_dependent_path_interpretation_is_rejected(path):
    # A /safe prefix ALLOW must not authorize a client's rewritten /private path.
    with pytest.raises(ValueError):
        evaluate(
            checker({"https://example.com/safe": "allow"}, default="deny"),
            "https://example.com" + path,
        )
    with pytest.raises(ValueError):
        checker({"https://example.com" + path: "allow"})


def test_path_percent_encoding_case_and_unicode_have_one_rule_identity():
    component = checker({"https://example.com/admin": "deny", "https://example.com/café": "ask"})
    assert evaluate(component, "https://example.com/%61dmin").permission is L.DENY
    assert evaluate(component, "https://example.com/caf%c3%a9").permission is L.ASK
    assert evaluate(component, "https://example.com/café").permission is L.ASK
    assert (
        evaluate(
            checker({"https://example.com": "deny"}), "https://example.com/?q=a%2Fb%25"
        ).permission
        is L.DENY
    )


def test_query_delimiter_is_not_a_wildcard_or_path_prefix():
    component = checker({"https://example.com/data?tenant=public": "allow"}, default="deny")
    assert evaluate(component, "https://example.com/data?tenant=public").permission is L.ALLOW
    for url in (
        "https://example.com/dataxtenant=public",
        "https://example.com/data/other?tenant=public",
        "https://example.com/data?tenant=private",
    ):
        assert evaluate(component, url).permission is L.DENY
    assert evaluate(component, "https://example.com/data?tenant=%70ublic").permission is L.ALLOW
    wildcard = checker({"https://example.com/data*?tenant=p?blic": "ask"})
    assert evaluate(wildcard, "https://example.com/data/other?tenant=public").permission is L.ASK


def test_absent_and_empty_query_have_the_same_http_resource():
    for pattern in ("https://example.com/data?", "https://example.com/data?*"):
        component = checker({pattern: "deny"})
        for url in ("https://example.com/data", "https://example.com/data?"):
            assert evaluate(component, url).permission is L.DENY
        assert evaluate(component, "https://example.com/data/other").permission is L.ALLOW


def test_fragments_do_not_change_the_http_resource_or_expose_rule_fragment():
    component = checker({"https://example.com/private#secret-fragment": "deny"})
    for fragment in ("", "#other", "#secret-fragment"):
        result = evaluate(component, "https://example.com/private" + fragment)
        assert result.permission is L.DENY
        assert "secret-fragment" not in result.matched_rule


@pytest.mark.parametrize("host", ["[::ffff:127.0.0.1]", "[::ffff:7f00:1]"])
def test_mapped_ipv6_cannot_evade_the_equivalent_ipv4_url_rule(host):
    component = checker(connection={"allow_loopback": True})
    assert evaluate(component, "https://" + host).permission is L.DENY
    assert connect(component, ["127.0.0.1"], url="https://" + host).permission is L.DENY
    assert evaluate(checker({"127.0.0.1": "ask"}), "https://" + host).permission is L.ASK


@pytest.mark.parametrize(
    "host",
    ["metadata.google.internal", "a.metadata.google.internal", "A.METADATA.GOOGLE.INTERNAL."],
)
def test_reference_metadata_host_restriction_survives_url_override_and_dns(host):
    component = checker(
        {"metadata.google.internal": "allow"},
        connection={"allow_loopback": True, "allow_private_network": True},
    )
    assert connect(component, ["8.8.8.8"], url="https://" + host).permission is L.DENY
    assert connect(component, ["10.0.0.1"], url="https://" + host).permission is L.DENY
    assert (
        connect(component, ["8.8.8.8"], url="https://metadata.google.internal.example").permission
        is L.ALLOW
    )


def test_limits_apply_before_trimming_or_hashing_snapshot_strings():
    with pytest.raises(ValueError):
        evaluate(checker(), " " * 8192 + "https://example.com")
    with pytest.raises(ValueError):
        evaluate(checker(), args={"url": " " * 8193, "uri": "https://example.com"})
    with pytest.raises(ValueError):
        checker({" " * 8192 + "example.com": "allow"})
    with pytest.raises(ValueError):
        connect(checker(), ["8.8.8.8", "1" * 8193])


@pytest.mark.parametrize(
    "address",
    [
        "fec0::1",
        "febf:ffff::1",
        "192.88.99.1",
        "192.88.99.2",
        "192.0.0.8",
        "192.0.0.11",
        "3fff::1",
        "100:0:0:1::1",
        "5f00::1",
    ],
)
def test_non_public_special_addresses_cannot_use_private_or_loopback_exceptions(address):
    component = checker(connection={"allow_loopback": True, "allow_private_network": True})
    assert connect(component, [address]).permission is L.DENY


@pytest.mark.parametrize("address", ["192.0.0.9", "192.0.0.10", "192.88.98.255", "192.88.100.0"])
def test_special_prefix_exclusions_preserve_neighboring_public_addresses(address):
    assert connect(checker(), [address]).permission is L.ALLOW


def test_glob_and_query_constraints_do_not_hide_independent_deny():
    component = checker({"example.com": "deny", "https://*.com/data*?q=*": "allow"})
    assert evaluate(component, "https://example.com/data?q=a").permission is L.DENY
    component = checker({"https://example.com/data*?q=*": "ask"})
    assert evaluate(component, "https://example.com/data").permission is L.ALLOW
    assert evaluate(component, "https://example.com/other?q=a").permission is L.ALLOW
    assert evaluate(component, "https://example.com/data?q=a").permission is L.ASK


@pytest.mark.parametrize(
    "url", ["https://[::1]evil.com/", "https://[::1]evil.com:443/", "https://example.com/\ud800"]
)
def test_invalid_authority_or_unicode_path_is_a_value_error(url):
    with pytest.raises(ValueError):
        evaluate(checker(), url)


@pytest.mark.parametrize(
    "pattern,url,expected",
    [
        ("api*.example.*", "https://api1.example.com", L.DENY),
        ("api*.example.*", "https://api.other.com", L.ALLOW),
        ("*host.example.com", "https://myhost.example.com", L.DENY),
        ("*", "https://example.com", L.DENY),
        ("api?", "https://api1", L.DENY),
        ("*?*", "https://example.com", L.DENY),
    ],
)
def test_host_glob_index_preserves_character_and_dns_label_boundaries(pattern, url, expected):
    assert evaluate(checker({pattern: "deny"}), url).permission is expected


def test_single_character_host_glob_in_full_url_keeps_query_structural():
    component = checker({"https://api?.example.com/data?tenant=public": "allow"}, default="deny")
    assert evaluate(component, "https://api1.example.com/data?tenant=public").permission is L.ALLOW
    for url in (
        "https://api.example.com/data?tenant=public",
        "https://api12.example.com/data?tenant=public",
        "https://api1.example.com/dataxtenant=public",
    ):
        assert evaluate(component, url).permission is L.DENY
    component = checker({"https://api?.example.com/data?token=SECRET": "deny"})
    result = evaluate(component, "https://api1.example.com/data?token=SECRET")
    assert "SECRET" not in repr(result)
    assert result.matched_rule == "net_guard:url:https://api?.example.com/data?<redacted>"
    assert (
        evaluate(
            checker({"https://api?.example.com/": "deny"}), "https://api1.example.com/"
        ).permission
        is L.DENY
    )
    # Without the separating slash the host wildcard and query have no unique grammar.
    with pytest.raises(ValueError):
        checker({"https://api?.example.com": "allow"})


def test_indexed_host_rules_agree_with_exhaustive_glob_matching():
    random = Random(3019)
    hosts = [f"api{i}.zone{i % 7}.example.com" for i in range(80)]
    rules = {}
    actions = ("allow", "ask", "deny")
    for host in hosts:
        patterns = (
            host,
            host[:4] + "*",
            "*" + host[4:],
            "api?." + host.split(".", 1)[1],
            "*zone?.example.*",
        )
        for pattern in patterns:
            rules[pattern] = random.choice(actions)
    component = checker(rules, default="ask", include_package=False)
    reverse = checker(dict(reversed(tuple(rules.items()))), default="ask", include_package=False)

    async def check():
        for host in [*hosts, "unmatched.invalid"]:
            matches = [
                actions.index(action)
                for pattern, action in rules.items()
                if fnmatchcase(host, pattern)
            ]
            expected = L(actions[max(matches)]) if matches else L.ASK
            args = {"url": "https://" + host}
            result = await component.evaluate("mcp_fetch_webpage", args)
            assert result.permission is expected
            assert result == await reverse.evaluate("mcp_fetch_webpage", args)

    asyncio.run(check())
