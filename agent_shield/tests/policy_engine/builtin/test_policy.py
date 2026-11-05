"""Every builtin rule has a hit and a miss, and a ruleset cannot go below a floor."""

import pytest

from agent_shield.policy_engine.builtin.rules import builtin_catalogs, load_builtin_ruleset
from agent_shield.policy_engine.core.envelope import evaluate_event
from agent_shield.policy_engine.builtin.catalog import DEFAULT_RISK
from agent_shield.policy_engine.core.ruleset import load_ruleset
from agent_shield.policy_engine.errors import PolicyError

from agent_shield.tests.policy_engine._factory import exec_effect, fs, make_event
from agent_shield.tests.net_addrs import DOC_HOST, DOC_NET, PUBLIC_DNS


def evaluate(event, *, ruleset=None):
    active = ruleset
    if isinstance(ruleset, dict):
        base = load_builtin_ruleset()
        active = load_ruleset(ruleset, baseline=base.behaviors, catalogs=builtin_catalogs())
    return evaluate_event(event, ruleset=active)


def _hit(effects, rule_id, **kwargs):
    result = evaluate(make_event(effects, **kwargs))
    assert result["winner_rule_id"] == rule_id, result
    return result


def _miss(effects, rule_id, **kwargs):
    result = evaluate(make_event(effects, **kwargs))
    assert result["winner_rule_id"] != rule_id, result
    return result


def test_builtin_ruleset_covers_default_risks_except_unobserved():
    assert {rule.id for rule in load_builtin_ruleset().behaviors} == set(DEFAULT_RISK) - {"exec.unobserved"}


@pytest.mark.parametrize(
    ("rule_id", "hit", "miss"),
    [
        ("privilege.escalate", [exec_effect(["sudo", "id"])], [exec_effect(["git", "status"])]),
        ("fs.delete.protectedFiles", [fs("fs.delete", "/etc/passwd")], [fs("fs.delete", "C:/Users/me/proj/a.txt")]),
        (
            "net.egress.secret",
            [{"type": "net.egress", "method": "POST", "host": "example.com", "secret_like": True, "local_files": []}],
            [{"type": "net.egress", "method": "POST", "host": "example.com", "secret_like": False, "local_files": []}],
        ),
        (
            "fs.device.raw_write",
            [fs("fs.write", r"\\.\PhysicalDrive0", path_kind="device", device_class="raw_disk")],
            [fs("fs.read", r"\\.\PhysicalDrive0", path_kind="device", device_class="raw_disk")],
        ),
        (
            "fs.read.sensitiveFiles",
            [fs("fs.read", "C:/Users/me/proj/.env")],
            [fs("fs.read", "C:/Users/me/proj/README.md")],
        ),
        (
            "fs.write.protectedFiles",
            [fs("fs.write", r"C:\Windows\System32\drivers\etc\hosts", exists=True)],
            [fs("fs.write", r"C:\Windows\System32\brand-new.txt", exists=False)],
        ),
        (
            "fs.delete.outside_force",
            [fs("fs.delete", "D:/other/a.txt", force=True)],
            [fs("fs.delete", "D:/other/a.txt", force=False)],
        ),
        (
            "fs.device",
            [fs("fs.read", r"\\.\COM1", path_kind="device", device_class="other")],
            [fs("fs.read", "C:/Users/me/proj/README.md")],
        ),
        (
            "fs.delete.bulk",
            [fs("fs.delete", "C:/Users/me/proj/a.txt", bulk=True)],
            [fs("fs.delete", "C:/Users/me/proj/a.txt")],
        ),
        ("git.force_push", [exec_effect(["git", "push", "-f"])], [exec_effect(["git", "push", "origin", "main"])]),
        ("shell.obfuscated", [exec_effect(["bash"], obfuscated=True)], [exec_effect(["bash"])]),
        ("schedule.create", [{"type": "schedule.create"}], [exec_effect(["git", "status"])]),
        ("fs.write.outside", [fs("fs.write", "D:/other/a.txt")], [fs("fs.write", "C:/Users/me/proj/a.txt")]),
        ("fs.delete.outside", [fs("fs.delete", "D:/other/a.txt")], [fs("fs.delete", "C:/Users/me/proj/a.txt")]),
        (
            "net.egress",
            [{"type": "net.egress", "method": "POST", "host": "example.com", "secret_like": False, "local_files": []}],
            [{"type": "net.connect", "host": "example.com", "ip": None, "port": 443}],
        ),
        ("exec.remote_script", [exec_effect(["bash"], interpreter_sink=True)], [exec_effect(["bash"])]),
        (
            "fs.write.system_new",
            [fs("fs.write", "C:/Windows/Temp/new.txt", exists=False)],
            [fs("fs.write", "D:/other/new.txt", exists=False)],
        ),
        ("fs.delete.userFiles", [fs("fs.delete", "C:/Users/me/proj/a.txt")], [fs("fs.delete", "D:/other/a.txt")]),
        ("fs.write.userFiles", [fs("fs.write", "C:/Users/me/proj/a.txt")], [fs("fs.write", "D:/other/a.txt")]),
        (
            "net.fetch.get",
            [{"type": "net.fetch", "method": "GET", "host": "example.com"}],
            [{"type": "net.fetch", "method": "POST", "host": "example.com"}],
        ),
        (
            "net.connect.unlisted",
            [{"type": "net.connect", "host": None, "ip": PUBLIC_DNS, "port": 443}],
            [{"type": "net.fetch", "method": "GET", "host": "example.com"}],
        ),
        ("fs.read.userFiles", [fs("fs.read", "C:/Users/me/proj/README.md")], [fs("fs.read", "D:/other/README.md")]),
        (
            "fs.read.nonsensitive_outside",
            [fs("fs.read", "D:/other/README.md")],
            [fs("fs.read", "C:/Users/me/proj/README.md")],
        ),
    ],
)
def test_rule_positive_and_negative(rule_id, hit, miss):
    workspace = {}
    if rule_id == "fs.delete.protectedFiles":
        workspace = {"os": "posix", "root": "/home/me/proj", "trusted_dirs": []}
    _hit(hit, rule_id, workspace=workspace) if workspace else _hit(hit, rule_id)
    _miss(miss, rule_id, workspace=workspace) if workspace else _miss(miss, rule_id)


def test_domain_deny_covers_one_host():
    ruleset = {
        "spec": "agent-pdp/v1",
        "rules": [
            {
                "id": "org.blocked",
                "object": "domain",
                "action": "deny",
                "ops": ["connect"],
                "hosts": ["blocked.example"],
            }
        ],
    }
    hit = evaluate(
        make_event([{"type": "net.connect", "host": "blocked.example", "ip": None, "port": 443}]), ruleset=ruleset
    )
    miss = evaluate(
        make_event([{"type": "net.connect", "host": "example.com", "ip": None, "port": 443}]), ruleset=ruleset
    )
    assert hit["action"] == "deny"
    assert hit["winner_rule_id"] == "org.blocked"
    assert miss["winner_rule_id"] != "org.blocked"


def test_behavior_override_can_raise_but_not_go_below_the_floor():
    result = evaluate(
        make_event([exec_effect(["git", "push", "--force"])]),
        ruleset={"spec": "agent-pdp/v1", "behavior_rules": [{"id": "git.force_push", "risk": "high"}]},
    )
    assert result["action"] == "ask"
    assert result["winner_rule_id"] == "git.force_push"
    assert result["advice"]["user_visible"]["risk"] == "高风险"
    base = load_builtin_ruleset()
    with pytest.raises(PolicyError):
        load_ruleset(
            {"spec": "agent-pdp/v1", "behavior_rules": [{"id": "privilege.escalate", "risk": "low"}]},
            baseline=base.behaviors,
            catalogs=builtin_catalogs(),
        )
    with pytest.raises(PolicyError):
        load_ruleset(
            {
                "spec": "agent-pdp/v1",
                "behavior_rules": [
                    {"id": "privilege.escalate", "risk": "critical", "when": {"effect": "process.exec"}}
                ],
            },
            baseline=base.behaviors,
            catalogs=builtin_catalogs(),
        )


def test_catalog_append_does_not_drop_builtin_entries():
    ruleset = {
        "spec": "agent-pdp/v1",
        "catalogs": {"sensitiveFiles": ["**/secret.txt"], "allowlist_hosts": ["github.com"]},
    }
    secret = evaluate(make_event([fs("fs.read", "C:/Users/me/proj/secret.txt")]), ruleset=ruleset)
    env = evaluate(make_event([fs("fs.read", "C:/Users/me/proj/.env")]), ruleset=ruleset)
    github = evaluate(make_event([{"type": "net.fetch", "method": "GET", "host": "github.com"}]), ruleset=ruleset)
    other = evaluate(make_event([{"type": "net.fetch", "method": "GET", "host": "example.com"}]), ruleset=ruleset)
    assert secret["winner_rule_id"] == "fs.read.sensitiveFiles"
    assert env["winner_rule_id"] == "fs.read.sensitiveFiles"
    assert github["action"] == "allow"
    assert github["winner_rule_id"] == "net.fetch.allowlist"
    assert other["winner_rule_id"] == "net.fetch.get"


def test_allowlist_starts_empty_until_a_third_party_appends():
    bare = evaluate(make_event([{"type": "net.connect", "host": "github.com", "ip": None, "port": 443}]))
    assert bare["winner_rule_id"] == "net.connect.unlisted"
    ruleset = {
        "spec": "agent-pdp/v1",
        "catalogs": {"allowlist_hosts": ["github.com"], "allowlist_cidrs": [f"{DOC_NET}/24"]},
    }
    listed = evaluate(
        make_event([{"type": "net.connect", "host": "github.com", "ip": None, "port": 443}]), ruleset=ruleset
    )
    posted = evaluate(
        make_event(
            [{"type": "net.egress", "method": "POST", "host": "github.com", "secret_like": False, "local_files": []}]
        ),
        ruleset=ruleset,
    )
    addressed = evaluate(
        make_event([{"type": "net.connect", "host": None, "ip": DOC_HOST, "port": 443}]), ruleset=ruleset
    )
    assert listed["winner_rule_id"] == "net.connect.allowlist"
    assert posted["winner_rule_id"] == "net.egress.allowlist"
    assert addressed["winner_rule_id"] == "net.connect.allowlist"


def test_var_tmp_is_not_a_system_prefix():
    event = make_event(
        [fs("fs.write", "/var/tmp/a.txt", exists=False)],
        workspace={"os": "posix", "root": "/home/me/proj", "trusted_dirs": []},
    )
    result = evaluate(event)
    assert result["winner_rule_id"] != "fs.write.system_new"
    assert result["action"] == "ask"
    created = evaluate(
        make_event(
            [fs("fs.write", "/var/log/a.txt", exists=False)],
            workspace={"os": "posix", "root": "/home/me/proj", "trusted_dirs": []},
        )
    )
    assert created["winner_rule_id"] == "fs.write.system_new"


def test_chmod_and_chown_are_privilege():
    chmod = evaluate(make_event([exec_effect(["chmod", "u+s", "tool"])]))
    chown = evaluate(make_event([exec_effect(["chown", "root", "tool"])]))
    assert chmod["action"] == "deny"
    assert chmod["winner_rule_id"] == "privilege.escalate"
    assert chown["action"] == "deny"
    assert chown["winner_rule_id"] == "privilege.escalate"
