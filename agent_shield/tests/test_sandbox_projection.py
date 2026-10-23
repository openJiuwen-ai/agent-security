"""Sandbox policy projection from host permission rules."""

from agent_shield.tool_permission.sandbox_projection import project_sandbox_policy


def test_net_and_file_rules_split_into_lists_and_skipped():
    projected = project_sandbox_policy({
        "net_guard": {
            "enabled": True,
            "defaults": "ask",
            "urls": {
                "pypi.org": "allow",
                "evil.example": "deny",
                "169.254.169.254": "deny",
                "*.internal": "deny",
                "https://api.example/v1/secret": "deny",
                "maybe.example": "ask",
            },
        },
        "file_guard": {
            "paths": [
                {"path": "C:/work/repo", "read": "allow", "write": "allow"},
                {"path": "/etc/shadow", "read": "deny"},
                {"path": "/tmp/ask", "read": "ask", "write": "ask"},
                {"path": "/var/log/*", "match": "glob", "read": "deny"},
                {"path": "relative/notes", "read": "deny"},
            ],
        },
        "host_guard": {"enabled": True},
        "command_allowlist": {"enabled": True},
        "package_builtin_rules": False,
    })

    assert projected.allow_domains == ["pypi.org"]
    assert projected.deny_domains == ["evil.example"]
    assert "169.254.169.254/32" in projected.deny_ips
    assert projected.allow_read == ["C:/work/repo"]
    assert projected.allow_write == ["C:/work/repo"]
    assert projected.deny_read == ["/etc/shadow"]
    assert projected.deny_write == ["/etc/shadow"]

    skipped = {(item.component, item.rule) for item in projected.skipped}
    assert ("net_guard", "defaults") in skipped
    assert ("net_guard", "*.internal") in skipped
    assert ("net_guard", "https://api.example/v1/secret") in skipped
    assert ("net_guard", "maybe.example") in skipped
    assert ("file_guard", "/tmp/ask") in skipped
    assert ("file_guard", "/var/log/*") in skipped
    assert ("file_guard", "relative/notes") in skipped
    assert ("host_guard", "host_guard") in skipped
    assert ("tool_guard", "command_allowlist") in skipped


def test_disabled_net_guard_adds_no_package_denies():
    projected = project_sandbox_policy({
        "net_guard": {"enabled": False, "urls": {"pypi.org": "allow"}},
    })
    assert projected.allow_domains == []
    assert projected.deny_domains == []
    assert projected.deny_ips == []


def test_fragment_copies_lists_to_linux_and_windows():
    projected = project_sandbox_policy({
        "net_guard": {"enabled": True, "urls": {"pypi.org": "allow"}},
        "package_builtin_rules": False,
    })
    fragment = projected.to_policy_fragment()
    assert fragment["network"]["egress"]["allowed_domains"] == ["pypi.org"]
    assert fragment["windows"]["network"]["egress"]["allowed_domains"] == ["pypi.org"]
