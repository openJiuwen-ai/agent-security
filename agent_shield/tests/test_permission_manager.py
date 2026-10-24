from __future__ import annotations

import asyncio
import threading
from typing import Any

import pytest

from agent_shield import tool_permission
from agent_shield.tool_permission import (
    PermissionLevel,
    PermissionManager,
    get_permission_manager,
)

_BASE = {"tools": {"bash": "allow"}, "package_builtin_rules": False, "shell_allowlist": None}
_DENY = {**_BASE, "tools": {"bash": "deny"}}


def _level(manager: PermissionManager, key: str | None = None, command: str = "ls"):
    result = asyncio.run(manager.check_permission("bash", {"command": command}, key))
    return result.permission


# --- registration and replacement -----------------------------------------------------


def test_default_key_exists_with_empty_config() -> None:
    manager = PermissionManager()

    assert manager.has_config("default")
    assert dict(manager.get_config()) == {}


def test_update_without_key_targets_default() -> None:
    manager = PermissionManager()

    manager.update_config(_BASE)

    assert _level(manager) is PermissionLevel.ALLOW
    assert _level(manager, "default") is PermissionLevel.ALLOW


def test_update_new_key_registers_it() -> None:
    manager = PermissionManager()

    manager.update_config(_BASE, "s1")

    assert manager.has_config("s1")
    assert "s1" in set(manager.keys())
    assert _level(manager, "s1") is PermissionLevel.ALLOW


def test_update_existing_key_replaces_the_whole_config() -> None:
    manager = PermissionManager()
    manager.update_config(_DENY, "s1")
    assert _level(manager, "s1") is PermissionLevel.DENY

    manager.update_config(_BASE, "s1")

    assert _level(manager, "s1") is PermissionLevel.ALLOW
    assert manager.get_config("s1")["tools"] == {"bash": "allow"}


def test_invalid_config_on_existing_key_keeps_the_old_one() -> None:
    manager = PermissionManager()
    manager.update_config(_DENY, "s1")

    with pytest.raises(ValueError):
        manager.update_config({"enabled": "yes"}, "s1")

    assert _level(manager, "s1") is PermissionLevel.DENY


def test_invalid_config_on_new_key_does_not_register_it() -> None:
    manager = PermissionManager()

    with pytest.raises(ValueError):
        manager.update_config({"enabled": "yes"}, "s1")

    assert not manager.has_config("s1")


def test_registered_config_is_a_deep_copy() -> None:
    manager = PermissionManager()
    config: dict[str, Any] = {"tools": {"bash": "allow"}, "package_builtin_rules": False}
    manager.update_config(config, "s1")

    config["tools"]["bash"] = "deny"

    assert _level(manager, "s1") is PermissionLevel.ALLOW


def test_update_config_rejects_non_mapping() -> None:
    manager = PermissionManager()

    with pytest.raises(TypeError):
        manager.update_config([], "s1")  # type: ignore[arg-type]
    assert not manager.has_config("s1")


# --- isolation between keys -----------------------------------------------------------


def test_keys_decide_independently() -> None:
    manager = PermissionManager()
    manager.update_config(_BASE, "a")
    manager.update_config(_DENY, "b")

    assert _level(manager, "a") is PermissionLevel.ALLOW
    assert _level(manager, "b") is PermissionLevel.DENY


def test_updating_one_key_leaves_others_untouched() -> None:
    manager = PermissionManager()
    manager.update_config(_BASE)
    manager.update_config(_BASE, "a")
    manager.update_config(_BASE, "b")

    manager.update_config(_DENY, "a")

    assert _level(manager, "a") is PermissionLevel.DENY
    assert _level(manager, "b") is PermissionLevel.ALLOW
    assert _level(manager) is PermissionLevel.ALLOW


def test_evaluate_global_policy_directly_follows_the_key() -> None:
    manager = PermissionManager()
    manager.update_config(_BASE, "a")
    manager.update_config(_DENY, "b")

    async def run(key: str):
        return await manager.evaluate_global_policy_directly("bash", {"command": "ls"}, key)

    assert asyncio.run(run("a"))[0] is PermissionLevel.ALLOW
    assert asyncio.run(run("b"))[0] is PermissionLevel.DENY


# --- one-off config -------------------------------------------------------------------


def test_one_off_config_decides_without_registering() -> None:
    manager = PermissionManager()
    manager.update_config(_BASE, "a")
    keys_before = manager.keys()

    result = asyncio.run(manager.check_permission("bash", {"command": "ls"}, config=_DENY))

    assert result.permission is PermissionLevel.DENY
    assert manager.keys() == keys_before
    assert _level(manager, "a") is PermissionLevel.ALLOW
    assert dict(manager.get_config()) == {}


def test_one_off_config_for_global_policy() -> None:
    manager = PermissionManager()

    permission, _rule = asyncio.run(
        manager.evaluate_global_policy_directly("bash", {"command": "ls"}, config=_DENY)
    )

    assert permission is PermissionLevel.DENY


def test_one_off_config_is_not_affected_by_later_changes_to_the_dict() -> None:
    manager = PermissionManager()
    config = {"tools": {"bash": "deny"}, "package_builtin_rules": False, "shell_allowlist": None}
    result = asyncio.run(manager.check_permission("bash", {"command": "ls"}, config=config))
    config["tools"]["bash"] = "allow"

    assert result.permission is PermissionLevel.DENY
    assert config["tools"]["bash"] == "allow"


def test_config_takes_precedence_over_key() -> None:
    manager = PermissionManager()
    manager.update_config(_BASE, "a")

    result = asyncio.run(manager.check_permission("bash", {"command": "ls"}, "a", config=_DENY))
    permission, _rule = asyncio.run(
        manager.evaluate_global_policy_directly("bash", {"command": "ls"}, "missing", config=_DENY)
    )

    assert result.permission is PermissionLevel.DENY
    assert permission is PermissionLevel.DENY


def test_invalid_one_off_config_raises() -> None:
    manager = PermissionManager()

    with pytest.raises(ValueError):
        asyncio.run(manager.check_permission("bash", {"command": "ls"}, config={"enabled": "yes"}))
    with pytest.raises(TypeError):
        asyncio.run(manager.check_permission("bash", {"command": "ls"}, config=[]))  # type: ignore[arg-type]


# --- unregistered keys and argument validation ----------------------------------------


def test_unregistered_key_raises_and_does_not_fall_back_to_default() -> None:
    manager = PermissionManager()
    manager.update_config(_BASE)

    with pytest.raises(KeyError):
        _level(manager, "missing")
    with pytest.raises(KeyError):
        asyncio.run(manager.evaluate_global_policy_directly("bash", {"command": "ls"}, "missing"))
    with pytest.raises(KeyError):
        manager.get_config("missing")


@pytest.mark.parametrize("key", ["", "   "])
def test_empty_key_is_rejected(key: str) -> None:
    manager = PermissionManager()

    with pytest.raises(ValueError):
        manager.update_config(_BASE, key)
    with pytest.raises(ValueError):
        _level(manager, key)
    with pytest.raises(ValueError):
        manager.remove_config(key)


@pytest.mark.parametrize("key", [1, b"a", ("a",)])
def test_non_string_key_is_rejected(key: Any) -> None:
    manager = PermissionManager()

    with pytest.raises(TypeError):
        manager.update_config(_BASE, key)
    with pytest.raises(TypeError):
        _level(manager, key)


def test_invalid_call_arguments_still_raise() -> None:
    manager = PermissionManager()

    with pytest.raises(ValueError):
        asyncio.run(manager.check_permission("", {}))
    with pytest.raises(TypeError):
        asyncio.run(manager.check_permission("bash", "ls"))  # type: ignore[arg-type]


# --- removal --------------------------------------------------------------------------


def test_remove_makes_the_key_unregistered() -> None:
    manager = PermissionManager()
    manager.update_config(_BASE, "s1")

    assert manager.remove_config("s1") is True

    with pytest.raises(KeyError):
        _level(manager, "s1")


def test_remove_missing_key_returns_false() -> None:
    assert PermissionManager().remove_config("nope") is False


def test_default_cannot_be_removed() -> None:
    manager = PermissionManager()

    with pytest.raises(ValueError):
        manager.remove_config("default")
    assert manager.has_config("default")


def test_key_can_be_registered_again_after_removal() -> None:
    manager = PermissionManager()
    manager.update_config(_DENY, "s1")
    manager.remove_config("s1")

    manager.update_config(_BASE, "s1")

    assert _level(manager, "s1") is PermissionLevel.ALLOW


# --- key limit ------------------------------------------------------------------------


def test_new_key_beyond_limit_is_rejected() -> None:
    manager = PermissionManager(max_keys=3)
    for name in ("a", "b", "c"):
        manager.update_config(_BASE, name)

    with pytest.raises(RuntimeError):
        manager.update_config(_BASE, "d")

    assert not manager.has_config("d")
    assert set(manager.keys()) == {"default", "a", "b", "c"}


def test_default_does_not_count_towards_the_limit() -> None:
    manager = PermissionManager(max_keys=1)

    manager.update_config(_BASE, "a")

    assert set(manager.keys()) == {"default", "a"}


def test_replacing_an_existing_key_works_when_full() -> None:
    manager = PermissionManager(max_keys=1)
    manager.update_config(_BASE, "a")

    manager.update_config(_DENY, "a")

    assert _level(manager, "a") is PermissionLevel.DENY


def test_removal_frees_a_slot() -> None:
    manager = PermissionManager(max_keys=1)
    manager.update_config(_BASE, "a")
    manager.remove_config("a")

    manager.update_config(_BASE, "b")

    assert manager.has_config("b")


@pytest.mark.parametrize("limit", [-1, True, 1.5, "3"])
def test_invalid_limit_is_rejected(limit: Any) -> None:
    with pytest.raises((TypeError, ValueError)):
        PermissionManager(max_keys=limit)


def test_zero_limit_allows_only_default() -> None:
    manager = PermissionManager(max_keys=0)

    with pytest.raises(RuntimeError):
        manager.update_config(_BASE, "a")
    manager.update_config(_BASE)
    assert _level(manager) is PermissionLevel.ALLOW


# --- read-only view -------------------------------------------------------------------


def test_get_config_does_not_expose_internal_state() -> None:
    manager = PermissionManager()
    manager.update_config(_BASE, "s1")

    view = manager.get_config("s1")
    with pytest.raises(TypeError):
        view["tools"] = {}  # type: ignore[index]

    assert _level(manager, "s1") is PermissionLevel.ALLOW


# --- concurrency ----------------------------------------------------------------------


def test_in_flight_decision_keeps_the_config_it_started_with() -> None:
    manager = PermissionManager()
    manager.update_config(_BASE, "s1")

    async def scenario():
        task = asyncio.ensure_future(manager.check_permission("bash", {"command": "ls"}, "s1"))
        await asyncio.sleep(0)  # let the task take its engine snapshot
        manager.update_config(_DENY, "s1")
        manager.remove_config("s1")
        return await task

    assert asyncio.run(scenario()).permission is PermissionLevel.ALLOW


def test_concurrent_registration_never_exceeds_the_limit() -> None:
    manager = PermissionManager(max_keys=10)
    barrier = threading.Barrier(40)
    rejected: list[int] = []

    def worker(index: int) -> None:
        barrier.wait()
        try:
            manager.update_config(_BASE, f"k{index}")
        except RuntimeError:
            rejected.append(index)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(40)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(manager.keys()) == 11  # default + 10
    assert len(rejected) == 30


def test_concurrent_updates_of_one_key_leave_a_whole_config() -> None:
    manager = PermissionManager()
    barrier = threading.Barrier(20)
    configs = [
        {
            "tools": {"bash": "allow" if i % 2 else "deny"},
            "marker": i,
            "package_builtin_rules": False,
            "shell_allowlist": None,
        }
        for i in range(20)
    ]

    def worker(index: int) -> None:
        barrier.wait()
        manager.update_config(configs[index], "s1")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    final = manager.get_config("s1")
    expected = configs[final["marker"]]
    assert dict(final) == expected
    level = PermissionLevel.ALLOW if final["marker"] % 2 else PermissionLevel.DENY
    assert _level(manager, "s1") is level


# --- singleton and facade -------------------------------------------------------------


def test_get_permission_manager_returns_one_instance() -> None:
    assert get_permission_manager() is get_permission_manager()


def test_concurrent_first_access_creates_one_instance(monkeypatch: pytest.MonkeyPatch) -> None:
    import agent_shield.tool_permission.manager as manager_module

    monkeypatch.setattr(manager_module, "_instance", None)
    barrier = threading.Barrier(16)
    seen: list[PermissionManager] = []

    def worker() -> None:
        barrier.wait()
        seen.append(get_permission_manager())

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len({id(item) for item in seen}) == 1


def test_direct_construction_is_independent_of_the_singleton() -> None:
    own = PermissionManager()
    own.update_config(_DENY, "only-here")

    assert not get_permission_manager().has_config("only-here")


def test_manager_is_exported_from_the_facade() -> None:
    assert "PermissionManager" in tool_permission.__all__
    assert "get_permission_manager" in tool_permission.__all__
