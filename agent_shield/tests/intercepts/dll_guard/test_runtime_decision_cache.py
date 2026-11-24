"""Compiled SDK rule decisions are local to a single configuration snapshot."""

from unittest.mock import Mock

import pytest

from agent_shield.tool_permission.runtime.engine import PermissionEngine


def policy(action):
    return {
        "package_builtin_rules": False,
        "file_guard": {"enabled": True, "defaults": {"read": action, "write": "deny"}},
        "net_guard": {"enabled": True, "defaults": action},
    }


def test_read_cache_preserves_action_batches_and_live_guards(tmp_path, monkeypatch):
    engine = PermissionEngine(policy("allow"), workspace_root=tmp_path)
    files = getattr(engine, "_files")
    match = Mock(wraps=files.evaluate_accesses)
    monkeypatch.setattr(files, "evaluate_accesses", match)
    immutable = getattr(engine, "_immutable")
    immutable_match = Mock(wraps=immutable.evaluate_accesses)
    monkeypatch.setattr(immutable, "evaluate_accesses", immutable_match)
    path = tmp_path / "sample"
    for _ in range(2):
        assert engine.check_file_accesses([(path, "read")]).is_allowed
    assert match.call_count == 1 and immutable_match.call_count == 2
    assert engine.check_file_accesses([(path, "write")]).is_denied
    assert engine.check_file_accesses([(path, "read"), (path, "write")]).is_denied
    assert match.call_count == 3


def test_network_cache_keeps_endpoints_distinct_and_checks_urls(tmp_path, monkeypatch):
    engine = PermissionEngine(policy("ask"), workspace_root=tmp_path)
    network = getattr(engine, "_network")
    match = Mock(wraps=network.evaluate_url_policy)
    monkeypatch.setattr(network, "evaluate_url_policy", match)
    endpoint = ".".join(("192", "0", "2", "1"))
    for address in (f"{endpoint}:80", f"{endpoint}:80", f"{endpoint}:81"):
        result = engine.check_network_access(address)
        assert result.needs_approval and not result.warnings
        result.warnings.append("caller annotation")
    assert match.call_count == 2
    for _ in range(2):
        assert engine.check_network_access("http://example.com/path").needs_approval
    assert match.call_count == 4


def test_cache_follows_successful_updates_and_active_switch(tmp_path):
    engine = PermissionEngine(policy("allow"), workspace_root=tmp_path)
    path = tmp_path / "sample"

    def decisions():
        return (
            engine.check_file_accesses([(path, "read")]).permission.value,
            engine.check_network_access("example.com").permission.value,
        )

    assert decisions() == ("allow", "allow")
    with pytest.raises(ValueError):
        engine.update_config({"net_guard": {"defaults": "invalid"}})
    assert decisions() == ("allow", "allow")
    engine.update_config(policy("deny"))
    assert decisions() == ("deny", "deny")
    engine.set_permission_checks_active(lambda: False)
    assert decisions() == ("allow", "allow")
    engine.set_permission_checks_active(lambda: True)
    assert decisions() == ("deny", "deny")


def test_distinct_path_spellings_and_bounded_retention(tmp_path):
    engine = PermissionEngine(policy("allow"), workspace_root=tmp_path)
    read_cache = getattr(engine, "_read_decision")
    network_cache = getattr(engine, "_network_decision")
    for name in ("ABC", "abc"):
        engine.check_file_accesses([(tmp_path / name, "read")])
    assert read_cache.cache_info().misses == 2
    for index in range(520):
        engine.check_file_accesses([(tmp_path / str(index), "read")])
        engine.check_network_access(f"node{index}.example.com")
    for cache in (read_cache, network_cache):
        assert cache.cache_info().currsize == cache.cache_info().maxsize == 512
