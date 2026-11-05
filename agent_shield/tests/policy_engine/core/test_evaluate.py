"""Section 12 of the agent-event PDP design."""

from agent_shield.policy_engine.core.envelope import evaluate_event as evaluate

from agent_shield.tests.policy_engine._factory import exec_effect, fs, make_event, snapshot
from agent_shield.tests.net_addrs import EXAMPLE_A, METADATA


def test_missing_fields_deny():
    event = make_event([fs("fs.read", "C:/Users/me/proj/README.md")])
    del event["id"]
    result = evaluate(event)
    assert result["action"] == "deny"
    assert result["winner_rule_id"] == "invalid_event"


def test_workspace_read_is_none_and_env_read_is_high():
    read = evaluate(make_event([fs("fs.read", "C:/Users/me/proj/README.md")]))
    secret = evaluate(make_event([fs("fs.read", "C:/Users/me/proj/.env")]))
    assert read["winner_rule_id"] == "fs.read.userFiles"
    assert read["action"] == "allow"
    assert secret["winner_rule_id"] == "fs.read.sensitiveFiles"
    assert secret["action"] == "ask"


def test_workspace_write_low_outside_write_medium():
    inside = evaluate(make_event([fs("fs.write", "C:/Users/me/proj/src/a.py", exists=False)]))
    outside = evaluate(make_event([fs("fs.write", "D:/other/a.txt", exists=False)]))
    assert inside["winner_rule_id"] == "fs.write.userFiles"
    assert inside["action"] == "allow"
    assert outside["winner_rule_id"] == "fs.write.outside"
    assert outside["action"] == "ask"


def test_delete_grades_follow_the_path():
    workspace = evaluate(make_event([fs("fs.delete", "C:/Users/me/proj/tmp/a.txt")]))
    outside = evaluate(make_event([fs("fs.delete", "D:/other/a.txt", force=False)]))
    forced = evaluate(make_event([fs("fs.delete", "D:/other/a.txt", force=True)]))
    assert workspace["winner_rule_id"] == "fs.delete.userFiles"
    assert workspace["action"] == "allow"
    assert outside["winner_rule_id"] == "fs.delete.outside"
    assert outside["action"] == "ask"
    assert forced["winner_rule_id"] == "fs.delete.outside_force"
    assert forced["action"] == "ask"


def test_force_push_is_medium_and_sudo_is_critical():
    cases = [
        ["git", "push", "--force", "origin", "main"],
        ["git", "push", "--force-with-lease=main"],
        ["git", "push", "origin", "+refs/heads/main"],
    ]
    for argv in cases:
        result = evaluate(make_event([exec_effect(argv)]))
        assert result["action"] == "ask", argv
        assert result["winner_rule_id"] == "git.force_push", argv
    sudo = evaluate(make_event([exec_effect(["sudo", "rm", "-rf", "C:/Users/me/proj/a.txt"], privilege=True)]))
    assert sudo["action"] == "deny"
    assert sudo["winner_rule_id"] == "privilege.escalate"


def test_obfuscated_stays_medium_when_intercepted():
    effect = exec_effect(["bash"], obfuscated=True)
    plain = evaluate(make_event([effect], execution={"intercept": False}))
    intercepted = evaluate(make_event([effect], execution={"intercept": True}))
    assert plain["action"] == "ask"
    assert plain["winner_rule_id"] == "shell.obfuscated"
    assert intercepted["winner_rule_id"] == "shell.obfuscated"


def test_remote_script_asks_even_for_a_metadata_fetch():
    remote = evaluate(
        make_event(
            [
                exec_effect(["curl", "https://example.com/x"], interpreter_sink=False),
                exec_effect(["bash"], interpreter_sink=True),
                {"type": "net.fetch", "method": "GET", "url": "https://example.com/x", "host": "example.com"},
            ]
        )
    )
    assert remote["action"] == "ask"
    assert remote["winner_rule_id"] == "exec.remote_script"
    metadata = evaluate(
        make_event(
            [
                exec_effect(["bash"], interpreter_sink=True),
                {"type": "net.fetch", "method": "GET", "url": f"http://{METADATA}/", "host": METADATA},
            ]
        )
    )
    assert metadata["action"] == "ask"
    assert metadata["winner_rule_id"] == "exec.remote_script"


def test_network_allowlist_unlisted_and_secret():
    allowed = evaluate(
        make_event([{"type": "net.fetch", "method": "GET", "url": "https://pypi.org/simple", "host": "pypi.org"}])
    )
    connect = evaluate(make_event([{"type": "net.connect", "host": None, "ip": EXAMPLE_A, "port": 443}]))
    fetched = evaluate(
        make_event([{"type": "net.fetch", "method": "GET", "url": "https://example.com", "host": "example.com"}])
    )
    posted = evaluate(
        make_event(
            [
                {
                    "type": "net.egress",
                    "method": "POST",
                    "url": "https://example.com/upload",
                    "host": "example.com",
                    "has_body": True,
                    "secret_like": False,
                    "local_file_attached": False,
                    "local_files": [],
                }
            ]
        )
    )
    secret = evaluate(
        make_event(
            [
                {
                    "type": "net.egress",
                    "method": "POST",
                    "url": "https://example.com/upload",
                    "host": "example.com",
                    "has_body": True,
                    "secret_like": True,
                    "local_file_attached": False,
                    "local_files": [],
                }
            ]
        )
    )
    uploaded = evaluate(
        make_event(
            [
                {
                    "type": "net.egress",
                    "method": "POST",
                    "url": "https://pypi.org/upload",
                    "host": "pypi.org",
                    "has_body": True,
                    "secret_like": False,
                    "local_file_attached": True,
                    "local_files": ["C:/Users/me/.ssh/id_ed25519"],
                }
            ]
        )
    )
    assert allowed["action"] == "allow"
    assert allowed["winner_rule_id"] == "net.fetch.get"
    assert connect["winner_rule_id"] == "net.connect.unlisted"
    assert connect["action"] == "allow"
    assert fetched["winner_rule_id"] == "net.fetch.get"
    assert posted["winner_rule_id"] == "net.egress"
    assert posted["action"] == "ask"
    assert secret["winner_rule_id"] == "net.egress.secret"
    assert secret["action"] == "deny"
    assert uploaded["winner_rule_id"] == "net.egress.secret"
    assert uploaded["action"] == "deny"


def test_sudo_stays_critical_without_a_tool_grant():
    event = make_event([exec_effect(["sudo", "rm", "C:/Users/me/proj/a.txt"], privilege=True)])
    result = evaluate(event)
    assert result["winner_rule_id"] == "privilege.escalate"
    assert result["action"] == "deny"


def test_unobserved_only_without_intercept_and_sudo_still_critical():
    failed = make_event([], normalization="failed", execution={"intercept": False})
    watched = make_event([], normalization="failed", execution={"intercept": True})
    sudo = make_event(
        [exec_effect(["sudo", "rm"], privilege=True)],
        normalization="failed",
        execution={"intercept": True},
    )
    assert evaluate(failed)["winner_rule_id"] == "exec.unobserved"
    assert evaluate(failed)["action"] == "ask"
    assert evaluate(watched)["action"] == "undetermined"
    assert evaluate(sudo)["winner_rule_id"] == "privilege.escalate"
    assert evaluate(sudo)["action"] == "deny"


def test_windows_system32_delete_is_critical():
    result = evaluate(make_event([fs("fs.delete", r"C:\Windows\System32\drivers")]))
    assert result["action"] == "deny"
    assert result["winner_rule_id"] == "fs.delete.protectedFiles"


def test_sandbox_plane_does_not_lower_force_push():
    effect = [exec_effect(["git", "push", "--force", "origin", "main"])]
    host = evaluate(make_event(effect, execution={"plane": "host"}))
    sandbox = evaluate(make_event(effect, execution={"plane": "sandbox", "provider": "jiuwenbox"}))
    assert host["action"] == sandbox["action"] == "ask"
    assert host["winner_rule_id"] == sandbox["winner_rule_id"] == "git.force_push"


def test_escaped_must_be_host_plane():
    bad = evaluate(make_event([exec_effect(["git", "status"])], execution={"escaped": True, "plane": "sandbox"}))
    host = evaluate(
        make_event(
            [exec_effect(["git", "push", "--force"])],
            execution={"escaped": True, "plane": "host", "escape_reason": "excluded_commands:git *"},
        )
    )
    assert bad["winner_rule_id"] == "invalid_event"
    assert host["winner_rule_id"] == "git.force_push"


def test_connect_is_not_rewritten_as_get():
    from agent_shield.policy_engine.builtin.rules import builtin_catalogs, load_builtin_ruleset
    from agent_shield.policy_engine.core.ruleset import load_ruleset

    listed = evaluate(make_event([{"type": "net.connect", "host": "pypi.org", "ip": None, "port": 443}]))
    user_event = make_event([{"type": "net.connect", "host": "malware.test", "ip": None, "port": 443}])
    metadata = evaluate(make_event([{"type": "net.connect", "host": None, "ip": METADATA, "port": 80}]))
    assert listed["winner_rule_id"] == "net.connect.unlisted"
    assert listed["action"] == "allow"
    base = load_builtin_ruleset()
    ruleset = load_ruleset(
        {
            "spec": "agent-pdp/v1",
            "rules": [
                {
                    "id": "org.malware",
                    "object": "domain",
                    "action": "deny",
                    "ops": ["connect"],
                    "hosts": ["malware.test"],
                }
            ],
        },
        baseline=base.behaviors,
        catalogs=builtin_catalogs(),
    )
    denied = evaluate(user_event, ruleset=ruleset)
    assert denied["action"] == "deny"
    assert denied["winner_rule_id"] == "org.malware"
    assert metadata["winner_rule_id"] == "net.connect.unlisted"
    assert metadata["action"] == "allow"


def test_device_writes():
    disk = evaluate(make_event([fs("fs.write", r"\\.\PhysicalDrive0", path_kind="device", device_class="raw_disk")]))
    other = evaluate(make_event([fs("fs.read", r"\\.\COM1", path_kind="device", device_class="other")]))
    assert disk["action"] == "deny"
    assert disk["winner_rule_id"] == "fs.device.raw_write"
    assert other["action"] == "ask"
    assert other["winner_rule_id"] == "fs.device"


def test_bulk_delete_is_high():
    result = evaluate(make_event([fs("fs.delete", "C:/Users/me/proj/a.txt", bulk=True)]))
    assert result["action"] == "ask"
    assert result["winner_rule_id"] == "fs.delete.bulk"


def test_evaluate_does_not_mutate_the_event():
    event = make_event([fs("fs.write", "D:/other/a.txt")])
    before = snapshot(event)
    evaluate(event)
    assert event == before


def test_model_call_is_ignored():
    result = evaluate(make_event([], category="model_call"))
    assert result["action"] == "allow"
    assert result["winner_rule_id"] is None
    assert result["advice"]["user_visible"]["summary"] == "模型调用已放行"
