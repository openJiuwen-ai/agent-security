"""Behavior when matching, action mapping, and one-event judgment."""

import pytest

from agent_shield.policy_engine.core.orchestrator import orchestrate
from agent_shield.policy_engine.core.action_mapping import (
    check_override,
    effective_action,
    reject_user_mapping,
)
from agent_shield.policy_engine.models.types import BehaviorRule, ObjectRule
from agent_shield.policy_engine.errors import PolicyError
from agent_shield.tests.net_addrs import PUBLIC_DNS

KUBECTL = BehaviorRule(
    id="tp.kubectl.delete",
    risk="medium",
    source="third_party",
    note="执行 kubectl delete",
    when={
        "effect": "process.exec",
        "argv0": ["kubectl", "oc"],
        "argv_prefix": ["delete"],
        "not": {"argv_has_any": ["--dry-run"]},
    },
)


def _event(**overrides):
    event = {
        "workspace": {"root": "C:/Users/me/proj", "os": "windows"},
        "action": {"category": "tool_call", "raw": {"name": "bash"}, "normalization": {"status": "ok"}},
        "execution": {"intercept": False},
    }
    event.update(overrides)
    return event


def _exec(argv, command_line=None):
    effect = {"type": "process.exec", "argv": argv}
    if command_line is not None:
        effect["command_line"] = command_line
    return effect


def _effects(effects):
    event = _event()
    event["action"]["effects"] = effects
    return event


def test_argv_prefix_not_and_argv0_list():
    hit = orchestrate(_event(), [_exec(["kubectl", "delete", "pod", "x"], "kubectl delete pod x")], behaviors=[KUBECTL])
    dry = orchestrate(_event(), [_exec(["kubectl", "delete", "--dry-run", "pod"])], behaviors=[KUBECTL])
    later = orchestrate(_event(), [_exec(["kubectl", "get", "delete"])], behaviors=[KUBECTL])
    assert hit.action == "ask"
    assert hit.winner_rule_id == "tp.kubectl.delete"
    assert hit.user_visible == {
        "summary": "执行 kubectl delete需要授权",
        "content": "执行 kubectl delete pod x",
        "risk": "中风险",
    }
    assert dry.action == "undetermined"
    assert later.action == "undetermined"


def test_behavior_reads_shell_argv_object_rule_reads_command_line():
    effect = _exec(["kubectl", "get", "delete"], "kubectl delete pod")
    behavior = orchestrate(_event(), [effect], behaviors=[KUBECTL])
    command = orchestrate(
        _event(),
        [effect],
        objects=[ObjectRule(id="tp-cmd", source="third_party", action="ask", object="command", match="kubectl delete")],
    )
    assert behavior.action == "undetermined"
    assert command.action == "ask"
    assert command.winner_rule_id == "tp-cmd"


def test_command_tokens_isolate_each_segment():
    allow_git = ObjectRule(id="allow-git", source="user_custom", action="allow", object="command", match="git status")
    shared_line = "git status && rm -rf /tmp"
    git = {
        "type": "process.exec",
        "argv": ["git", "status"],
        "command_line": shared_line,
        "command_tokens": ["git", "status"],
    }
    remove = {
        "type": "process.exec",
        "argv": ["rm", "-rf", "/tmp"],
        "command_line": shared_line,
        "command_tokens": ["rm", "-rf", "/tmp"],
    }
    assert orchestrate(_event(), [git], objects=[allow_git]).action == "allow"
    assert orchestrate(_event(), [remove], objects=[allow_git]).action == "undetermined"


def test_missing_command_line_denies_from_shell_argv_and_does_not_allow():
    effect = _exec(["git", "push", "--force"])
    deny = ObjectRule(id="deny-push", source="third_party", action="deny", object="command", match="git push")
    allow = ObjectRule(id="allow-push", source="user_custom", action="allow", object="command", match="git push")
    denied = orchestrate(_event(), [effect], objects=[deny])
    allowed = orchestrate(_event(), [effect], objects=[allow])
    assert denied.action == "deny"
    assert denied.user_visible["content"] == "执行 git push --force"
    assert allowed.action == "undetermined"


def test_visible_command_uses_segment_tokens_before_shell_argv():
    effect = {
        "type": "process.exec",
        "argv": ["cmd", "a b"],
        "command_line": 'git status && cmd "a b"',
        "command_tokens": ["cmd", '"a', 'b"'],
    }
    rule = ObjectRule(id="ask-cmd", source="third_party", action="ask", object="command", match='cmd "a b"')
    result = orchestrate(_event(), [effect], objects=[rule])
    assert result.action == "ask"
    assert result.user_visible["content"] == '执行 cmd "a b"'


def test_windows_strips_exe_for_argv0_only():
    rule = BehaviorRule(
        id="tp.kubectl.delete",
        risk="medium",
        source="third_party",
        note="执行 kubectl delete",
        when={"effect": "process.exec", "argv0": "kubectl"},
    )
    windows = orchestrate(_event(), [_exec([r"C:\Tools\kubectl.exe", "delete"])], behaviors=[rule])
    posix = orchestrate(
        _event(workspace={"root": "/work", "os": "posix"}),
        [_exec(["kubectl.exe", "delete"])],
        behaviors=[rule],
    )
    assert windows.action == "ask"
    assert posix.action == "undetermined"


def test_action_mapping_moves_builtin_hits_and_keeps_their_source():
    sensitive = BehaviorRule(
        id="fs.read.sensitiveFiles",
        risk="high",
        source="builtin",
        note="读取敏感文件",
        when={"effect": "fs.read", "path.glob_any": ["**/.env"]},
    )
    effect = {"type": "fs.read", "path": "C:/Users/me/proj/.env"}
    ask = orchestrate(_event(), [effect], behaviors=[sensitive])
    allowed = orchestrate(_event(), [effect], behaviors=[sensitive], action_mapping={"high": "allow"})
    assert ask.action == "ask"
    assert ask.winner_rule_id == "fs.read.sensitiveFiles"
    assert allowed.action == "allow"
    assert allowed.user_visible["risk"] == "高风险"
    assert allowed.user_visible["summary"] == "读取敏感文件已放行"


def test_mapping_examples_and_stricter_baseline():
    assert effective_action("critical", {}, {"critical": "ask"}) == "ask"
    assert effective_action("none", {}, {"none": "deny"}) == "deny"
    assert effective_action("low", {}, {"low": "ask"}) == "ask"
    assert effective_action("medium", {}, {"medium": "allow"}) == "allow"
    assert effective_action("high", {"high": "deny"}, {}) == "deny"
    assert effective_action("critical", {"critical": "deny"}, {"critical": "allow"}) == "deny"


def test_floor_blocks_open_and_closed_rules():
    with pytest.raises(PolicyError):
        check_override("fs.read.sensitiveFiles", "high", "medium")
    with pytest.raises(PolicyError):
        check_override("privilege.escalate", "critical", "none")
    with pytest.raises(PolicyError):
        check_override("fs.device.raw_write", "critical", "none")
    check_override("git.force_push", "medium", "none")
    check_override("fs.write.outside", "medium", "low")


def test_user_rules_cannot_carry_action_mapping():
    with pytest.raises(PolicyError):
        reject_user_mapping({"spec": "agent-user-rules/v1", "action_mapping": {"high": "allow"}})


def test_user_allow_does_not_cover_third_party_behavior_ask():
    result = orchestrate(
        _event(),
        [_exec(["kubectl", "delete", "pod", "x"], "kubectl delete pod x")],
        behaviors=[KUBECTL],
        objects=[ObjectRule(id="user-allow", source="user_custom", action="allow", object="command", match="*")],
    )
    assert result.action == "ask"
    assert result.winner_rule_id == "tp.kubectl.delete"


def test_command_grant_is_exact_and_allows_builtin_ask():
    behavior = BehaviorRule(
        id="git.force_push",
        risk="medium",
        source="builtin",
        note="强制推送",
        user_grantable=True,
        when={"effect": "process.exec", "argv0": "git", "argv_has_any": ["--force"]},
    )
    exact = ObjectRule(
        id="grant-git",
        source="user_grant",
        action="allow",
        object="command",
        tokens=("git", "push", "origin", "main"),
    )
    same = orchestrate(
        _event(),
        [_exec(["git", "push", "origin", "main", "--force"], "git push origin main")],
        behaviors=[behavior],
        objects=[exact],
    )
    longer = orchestrate(
        _event(),
        [_exec(["git", "push", "origin", "main", "--force"], "git push origin main --force")],
        behaviors=[behavior],
        objects=[exact],
    )
    assert same.action == "allow"
    assert same.user_visible["summary"] == "命中已批准的具体资源，已放行"
    assert longer.action == "ask"


def test_native_grant_clears_only_a_grantable_native_ask():
    native_ask = ObjectRule(
        id="ask-certutil",
        source="builtin",
        action="ask",
        object="nativeTools",
        names=("certutil",),
        user_grantable=True,
    )
    blocked = ObjectRule(id="ask-blocked", source="builtin", action="ask", object="nativeTools", names=("certutil",))
    command_ask = ObjectRule(
        id="user-cmd", source="user_custom", action="ask", object="command", match="certutil -urlcache"
    )
    grant = ObjectRule(
        id="grant-certutil", source="user_grant", action="allow", object="nativeTools", names=("certutil",)
    )
    effect = _exec(["certutil", "-urlcache", "-f", "http://x"], "certutil -urlcache -f http://x")
    cleared = orchestrate(_event(), [effect], objects=[native_ask, grant])
    kept = orchestrate(_event(), [effect], objects=[native_ask, command_ask, grant])
    still_ask = orchestrate(_event(), [effect], objects=[blocked, grant])
    assert cleared.action == "undetermined"
    assert kept.action == "ask"
    assert kept.winner_rule_id == "user-cmd"
    assert still_ask.action == "ask"
    assert still_ask.winner_rule_id == "ask-blocked"
    assert still_ask.grants == ()


def test_native_image_wins_over_argv0():
    deny = ObjectRule(id="deny-reg", source="builtin", action="deny", object="nativeTools", names=("reg",))
    effect = {"type": "process.exec", "argv": ["notepad", "add"], "image": r"C:\Windows\System32\reg.exe"}
    result = orchestrate(_event(), [effect], objects=[deny])
    assert result.action == "deny"
    assert result.user_visible["summary"] == "本机程序启动已拒绝"
    assert result.user_visible["content"] == "启动 reg"


def test_agent_tool_allow_does_not_release_an_effect_ask():
    tools = ObjectRule(id="allow-bash", source="user_custom", action="allow", object="agentTools", names=("bash",))
    outside = BehaviorRule(
        id="fs.write.outside",
        risk="medium",
        source="builtin",
        note="写入工作区外的文件",
        when={"effect": "fs.write", "path.scope": "outside"},
    )
    result = orchestrate(
        _event(),
        [{"type": "fs.write", "path": "D:/tmp/a.txt"}],
        behaviors=[outside],
        objects=[tools],
    )
    assert result.action == "ask"
    assert result.winner_rule_id == "fs.write.outside"


def test_intent_only_rewrites_a_medium_ask():
    medium = BehaviorRule(
        id="net.egress",
        risk="medium",
        source="builtin",
        note="向外发送数据",
        auto_intent=True,
        when={"effect": "net.egress"},
    )
    effect = {"type": "net.egress", "host": "example.com"}
    released = orchestrate(_event(), [effect], behaviors=[medium], intent_allows=True)
    forced = orchestrate(
        _event(),
        [effect],
        behaviors=[medium],
        action_mapping={"medium": "deny"},
        intent_allows=True,
    )
    assert released.action == "allow"
    assert forced.action == "deny"


def test_glob_catalog_and_inline_endpoint():
    catalogs = {
        "projectKeys": {"kind": "glob", "entries": ["**/secrets.yaml"]},
        "corpGit": {"kind": "host", "entries": ["github.example.com"]},
    }
    files = BehaviorRule(
        id="tp.fs.projectKeys",
        risk="high",
        source="third_party",
        note="读写项目密钥文件",
        when={"effect": ["fs.read", "fs.write", "fs.delete"], "path.glob_any": "projectKeys"},
    )
    egress = BehaviorRule(
        id="tp.net.egress.corpGit",
        risk="low",
        source="third_party",
        note="向外发送到企业 Git",
        when={"effect": "net.egress", "endpoint.in_any_catalog": ["corpGit"]},
    )
    file_hit = orchestrate(
        _event(),
        [{"type": "fs.read", "path": "C:/Users/me/proj/secrets.yaml"}],
        behaviors=[files],
        catalogs=catalogs,
    )
    net_hit = orchestrate(
        _event(),
        [{"type": "net.egress", "host": "github.example.com"}],
        behaviors=[egress],
        catalogs=catalogs,
    )
    assert file_hit.action == "ask"
    assert file_hit.user_visible["risk"] == "高风险"
    assert net_hit.action == "allow"
    assert net_hit.user_visible["summary"] == "向外发送到企业 Git已放行"


def test_unobserved_is_an_event_level_ask():
    event = _event()
    event["action"]["normalization"] = {"status": "partial"}
    event["action"]["command_line"] = "powershell -enc AA=="
    result = orchestrate(event, [])
    assert result.action == "ask"
    assert result.winner_rule_id == "exec.unobserved"
    assert result.user_visible["summary"] == "命令无法完整解析且没有运行时拦截需要授权"
    assert result.user_visible["content"] == "执行 powershell -enc AA=="


def test_empty_domain_rule_is_rejected():
    with pytest.raises(PolicyError):
        ObjectRule(id="bad", source="third_party", action="deny", object="domain").validate()


def test_grants_stay_on_one_literal_resource():
    from agent_shield.policy_engine.builtin.rules import load_builtin_ruleset

    rules = _with_grantable_read(load_builtin_ruleset())
    file_grant = ObjectRule(
        id="g-file", source="user_grant", action="allow", object="file", ops=("read",), path="D:/tmp/a*.pem"
    )
    fetch_grant = ObjectRule(
        id="g-ip", source="user_grant", action="allow", object="domain", ops=("fetch",), hosts=(PUBLIC_DNS,)
    )
    command_grant = ObjectRule(
        id="g-cmd",
        source="user_grant",
        action="allow",
        object="command",
        tokens=("git", "push", "origin", "main"),
    )
    exact = rules.decide(_effects([{"type": "fs.read", "path": "D:/tmp/a*.pem"}]), grants=[file_grant])
    sibling = rules.decide(_effects([{"type": "fs.read", "path": "D:/tmp/ab.pem"}]), grants=[file_grant])
    write = rules.decide(_effects([{"type": "fs.write", "path": "D:/tmp/a*.pem"}]), grants=[file_grant])
    fetched = rules.decide(
        _effects([{"type": "net.fetch", "host": None, "ip": PUBLIC_DNS, "method": "GET"}]), grants=[fetch_grant]
    )
    sent = rules.decide(_effects([{"type": "net.egress", "host": None, "ip": PUBLIC_DNS}]), grants=[fetch_grant])
    pushed = rules.decide(
        _effects(
            [
                {
                    "type": "process.exec",
                    "argv": ["git", "push", "origin", "main"],
                    "command_tokens": ["git", "push", "origin", "main"],
                }
            ]
        ),
        grants=[command_grant],
    )
    forced = rules.decide(
        _effects(
            [{"type": "process.exec", "argv": ["git", "push", "--force"], "command_tokens": ["git", "push", "--force"]}]
        ),
        grants=[command_grant],
    )
    argv_only = rules.decide(
        _effects([{"type": "process.exec", "argv": ["git", "push", "origin", "main"]}]),
        grants=[command_grant],
    )
    assert exact.action == "allow" and exact.winner_rule_id == "g-file"
    assert sibling.winner_rule_id == "fs.read.sensitiveFiles"
    assert write.winner_rule_id == "fs.write.sensitiveFiles"
    assert fetched.winner_rule_id == "g-ip"
    assert sent.winner_rule_id == "net.egress"
    assert pushed.winner_rule_id == "g-cmd"
    assert forced.winner_rule_id == "git.force_push"
    assert argv_only.winner_rule_id != "g-cmd"
    with pytest.raises(PolicyError):
        ObjectRule(id="wide", source="user_grant", action="allow", object="file", path="D:/tmp/a.pem").validate()
    with pytest.raises(PolicyError):
        ObjectRule(
            id="both",
            source="user_grant",
            action="allow",
            object="domain",
            ops=("fetch", "egress"),
            hosts=(PUBLIC_DNS,),
        ).validate()
    with pytest.raises(PolicyError):
        ObjectRule(id="star", source="user_grant", action="allow", object="command", tokens=("*",)).validate()


def test_suggested_file_grant_uses_a_normalized_path():
    from agent_shield.policy_engine.builtin.rules import load_builtin_ruleset

    result = _with_grantable_read(load_builtin_ruleset()).decide(
        _effects([{"type": "fs.read", "path": r"C:\Users\me\proj\.env"}])
    )
    assert result.grants[0]["path"] == "C:/Users/me/proj/.env"
    assert result.grants[0]["ops"] == ["read"]


def test_builtin_ask_is_not_grantable_until_the_rule_opts_in():
    from dataclasses import replace

    from agent_shield.policy_engine.builtin.rules import load_builtin_ruleset

    rules = load_builtin_ruleset()
    secret = [{"type": "fs.read", "path": "C:/Users/me/proj/.env"}]
    blocked = rules.decide(_effects(secret))
    grant = ObjectRule(
        id="g-file", source="user_grant", action="allow", object="file", ops=("read",), path="C:/Users/me/proj/.env"
    )
    carried = rules.decide(_effects(secret), grants=[grant])
    assert blocked.action == "ask"
    assert blocked.grants == ()
    assert carried.winner_rule_id == "fs.read.sensitiveFiles"
    opened = _with_grantable_read(rules).decide(_effects(secret), grants=[grant])
    assert opened.action == "allow"
    assert opened.winner_rule_id == "g-file"
    effect = _exec(["kubectl", "delete", "pod", "x"], "kubectl delete pod x")
    command = ObjectRule(
        id="g-cmd", source="user_grant", action="allow", object="command", tokens=("kubectl", "delete", "pod", "x")
    )
    third = orchestrate(_event(), [effect], behaviors=[KUBECTL], objects=[command])
    assert third.winner_rule_id == "tp.kubectl.delete"
    assert third.grants == ()
    allowed = orchestrate(_event(), [effect], behaviors=[replace(KUBECTL, user_grantable=True)], objects=[command])
    assert allowed.winner_rule_id == "g-cmd"


def _with_grantable_read(rules):
    from agent_shield.policy_engine.core.ruleset import load_ruleset

    return load_ruleset(
        {"spec": "agent-pdp/v1", "behavior_rules": [{"id": "fs.read.sensitiveFiles", "user_grantable": True}]},
        baseline=rules.behaviors,
        catalogs=rules.catalogs,
    )
