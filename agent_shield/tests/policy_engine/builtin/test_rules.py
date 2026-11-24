"""Builtin rules decide the packaged behaviors."""

from agent_shield.policy_engine.builtin.rules import load_builtin_ruleset
from agent_shield.tests.net_addrs import METADATA

RULES = load_builtin_ruleset()


def _event(effects, **workspace):
    event = {
        "workspace": {"root": "C:/Users/me/proj", "os": "windows"},
        "action": {
            "category": "tool_call",
            "raw": {"name": "bash"},
            "effects": effects,
            "normalization": {"status": "ok"},
        },
        "execution": {"intercept": False},
    }
    event["workspace"].update(workspace)
    return event


def _decide(effects, **workspace):
    return RULES.decide(_event(effects, **workspace))


def test_workspace_read_allows_and_secret_read_asks():
    read = _decide([{"type": "fs.read", "path": "C:/Users/me/proj/README.md"}])
    secret = _decide([{"type": "fs.read", "path": "C:/Users/me/proj/.env"}])
    assert read.action == "allow"
    assert read.winner_rule_id == "fs.read.userFiles"
    assert read.user_visible["risk"] == "低风险"
    assert secret.action == "ask"
    assert secret.winner_rule_id == "fs.read.sensitiveFiles"
    assert secret.user_visible["summary"] == "读取敏感文件需要授权"
    assert secret.user_visible["risk"] == "高风险"


def test_protected_read_is_narrower_than_system32():
    sam = _decide([{"type": "fs.read", "path": "C:/Windows/System32/config/SAM"}])
    dll = _decide([{"type": "fs.read", "path": "C:/Windows/System32/kernel32.dll"}])
    assert sam.action == "ask"
    assert sam.winner_rule_id == "fs.read.protectedReadFiles"
    assert dll.action == "allow"
    assert dll.winner_rule_id == "fs.read.nonsensitive_outside"


def test_protected_delete_denies_and_outside_write_asks():
    deleted = _decide([{"type": "fs.delete", "path": "C:/Windows/System32/drivers/etc/hosts", "force": False}])
    outside = _decide([{"type": "fs.write", "path": "D:/other/a.txt", "exists": False}])
    assert deleted.action == "deny"
    assert deleted.winner_rule_id == "fs.delete.protectedFiles"
    assert outside.action == "ask"
    assert outside.winner_rule_id == "fs.write.outside"


def test_unlisted_network_allows_and_secret_egress_denies():
    metadata = _decide([{"type": "net.connect", "host": None, "ip": METADATA}])
    pypi = _decide([{"type": "net.fetch", "method": "GET", "host": "pypi.org"}])
    egress = _decide([{"type": "net.egress", "host": "example.com", "secret_like": False}])
    secret = _decide([{"type": "net.egress", "host": "example.com", "secret_like": True}])
    assert metadata.action == "allow"
    assert metadata.winner_rule_id == "net.connect.unlisted"
    assert pypi.action == "allow"
    assert pypi.winner_rule_id == "net.fetch.get"
    assert egress.action == "ask"
    assert egress.winner_rule_id == "net.egress"
    assert secret.action == "deny"
    assert secret.winner_rule_id == "net.egress.secret"


def test_agent_tools_match_only_the_tool_name():
    from agent_shield.policy_engine.core.ruleset import load_user_rules

    rules = load_user_rules(
        {
            "spec": "agent-user-rules/v1",
            "rules": [{"id": "u.web", "object": "agentTools", "action": "deny", "names": ["web_search"]}],
        }
    )
    named = _event([])
    named["action"]["raw"] = {"name": "Web_Search", "args": {"query": "bash"}}
    named["action"]["effects"] = []
    other = _event([{"type": "process.exec", "argv": ["web_search"]}])
    other["action"]["raw"] = {"name": "bash", "args": {"command": "web_search"}}
    hit = RULES.decide(named, user_rules=rules)
    miss = RULES.decide(other, user_rules=rules)
    assert hit.action == "deny"
    assert hit.winner_rule_id == "u.web"
    assert miss.winner_rule_id != "u.web"


def test_native_tools_match_the_program_name():
    full = _decide([{"type": "process.exec", "argv": ["notepad"], "image": r"C:\Windows\System32\reg.exe"}])
    copied = _decide([{"type": "process.exec", "argv": ["notepad"], "image": r"D:\tools\reg.exe"}])
    renamed = _decide([{"type": "process.exec", "argv": ["reg"], "image": r"C:\Windows\System32\foo.exe"}])
    parent = _event([{"type": "process.exec", "argv": ["notepad"], "image": r"C:\Windows\System32\notepad.exe"}])
    parent["process"] = {"image": r"C:\Windows\System32\reg.exe"}
    assert full.winner_rule_id == "nativeTools.deny"
    assert copied.winner_rule_id == "nativeTools.deny"
    assert renamed.winner_rule_id != "nativeTools.deny"
    assert RULES.decide(parent).winner_rule_id != "nativeTools.deny"


def test_builtin_ask_list_excludes_shells():
    from agent_shield.policy_engine.builtin.rules import builtin_catalogs

    catalogs = builtin_catalogs()
    ask = catalogs["nativeToolsAskList"]
    names = {item.casefold() for item in [*ask["entries"], *ask["posix"], *ask["windows"]]}
    shells = {item.casefold() for item in catalogs["interpreter_sinks"]["entries"]}
    assert names.isdisjoint(shells)
    assert "powershell" not in names
    assert "cmd" not in names
    assert "bash" not in names


def test_sudo_and_certutil_and_a_plain_shell():
    sudo = _decide([{"type": "process.exec", "argv": ["sudo", "id"]}])
    certutil = _decide([{"type": "process.exec", "argv": ["certutil", "-urlcache"]}])
    shell = _decide([{"type": "process.exec", "argv": ["powershell", "-Command", "Get-Date"]}])
    assert sudo.action == "deny"
    assert sudo.winner_rule_id == "privilege.escalate"
    assert certutil.action == "ask"
    assert certutil.winner_rule_id == "nativeTools.ask"
    assert shell.action == "undetermined"


def test_appended_interpreter_sink_marks_a_pipe_target():
    from agent_shield.policy_engine.builtin.rules import builtin_catalogs
    from agent_shield.policy_engine.core.ruleset import load_ruleset

    piped = [
        {
            "type": "process.exec",
            "argv": ["python", "-"],
            "shell_meta": {"pipe_target": True, "interpreter_sink": False},
        }
    ]
    plain = [{"type": "process.exec", "argv": ["python", "-c", "print(1)"]}]
    assert _decide(piped).winner_rule_id != "exec.remote_script"
    assert _decide(plain).action == "undetermined"
    extended = load_ruleset(
        {"spec": "agent-pdp/v1", "catalogs": {"interpreter_sinks": ["python"]}},
        baseline=RULES.behaviors,
        catalogs=builtin_catalogs(),
    )
    hit = extended.decide(_event(piped))
    missed = extended.decide(_event(plain))
    assert hit.action == "ask"
    assert hit.winner_rule_id == "exec.remote_script"
    assert missed.action == "undetermined"


def test_medium_intent_can_allow_a_force_push():
    effect = [{"type": "process.exec", "argv": ["git", "push", "--force", "origin", "main"]}]
    asked = RULES.decide(_event(effect))
    allowed = RULES.decide(_event(effect), intent_allows=True)
    assert asked.action == "ask"
    assert asked.winner_rule_id == "git.force_push"
    assert allowed.action == "allow"
