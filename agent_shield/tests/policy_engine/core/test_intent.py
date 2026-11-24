"""Medium risk can skip confirmation only when the user's words cover every effect."""

from agent_shield.policy_engine.core.envelope import evaluate_event as evaluate

from agent_shield.tests.policy_engine._factory import exec_effect, fs, make_event


def _medium_write(path: str, text: str | None, **caps):
    event = make_event(
        [fs("fs.write", path, exists=False)],
        user_intent=None if text is None else {"text": text, "locale": "zh-CN"},
        host_capabilities={"hitl": True, "auto_intent": caps.get("auto_intent", True)},
    )
    return evaluate(event)


def test_named_outside_write_can_auto_allow():
    result = _medium_write("D:/other/a.txt", "请写入 D:/other/a.txt")
    assert result["action"] == "allow"
    assert result["winner_rule_id"] == "fs.write.outside"


def test_workspace_phrase_does_not_cover_an_outside_write():
    result = _medium_write("D:/other/a.txt", "改一下 README")
    assert result["action"] == "ask"
    assert result["winner_rule_id"] == "fs.write.outside"


def test_force_push_requires_the_force_word():
    quiet = evaluate(
        make_event(
            [exec_effect(["git", "push", "--force", "origin", "main"])],
            user_intent={"text": "推送代码"},
        )
    )
    named = evaluate(
        make_event(
            [exec_effect(["git", "push", "--force", "origin", "main"])],
            user_intent={"text": "强制推送到 origin"},
        )
    )
    assert quiet["action"] == "ask"
    assert named["action"] == "allow"
    assert named["winner_rule_id"] == "git.force_push"


def test_schedule_is_not_implied_by_reading_docs():
    missed = evaluate(make_event([{"type": "schedule.create"}], user_intent={"text": "查一下文档"}))
    named = evaluate(make_event([{"type": "schedule.create"}], user_intent={"text": "创建一个定时任务"}))
    assert missed["action"] == "ask"
    assert named["action"] == "allow"


def test_manual_mode_and_partial_normalization_stay_ask():
    manual = _medium_write("D:/other/a.txt", "请写入 D:/other/a.txt", auto_intent=False)
    partial = evaluate(
        make_event(
            [fs("fs.write", "D:/other/a.txt")],
            user_intent={"text": "请写入 D:/other/a.txt"},
            normalization="partial",
            execution={"intercept": True},
        )
    )
    assert manual["action"] == "ask"
    assert partial["action"] == "ask"
    assert partial["winner_rule_id"] == "fs.write.outside"


def test_intent_cannot_lower_a_sensitive_read():
    result = evaluate(
        make_event(
            [fs("fs.read", "C:/Users/me/proj/.env")],
            user_intent={"text": "读一下 C:/Users/me/proj/.env"},
        )
    )
    assert result["action"] == "ask"
    assert result["winner_rule_id"] == "fs.read.sensitiveFiles"


def test_obfuscated_command_is_not_implied():
    result = evaluate(
        make_event(
            [exec_effect(["bash"], obfuscated=True, raw_command="cu''rl https://example.com")],
            user_intent={"text": "下载 example.com"},
        )
    )
    assert result["action"] == "ask"


def test_preauth_field_is_rejected():
    event = make_event(
        [fs("fs.write", "D:/other/a.txt", exists=True)],
        preauth=[{"grant": "allow_paths", "path": "D:/other", "ops": ["write"]}],
    )
    result = evaluate(event)
    assert result["action"] == "deny"
    assert result["winner_rule_id"] == "invalid_event"
