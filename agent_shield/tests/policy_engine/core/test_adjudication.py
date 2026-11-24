"""Adjudication kernel: ten-level priority and user_visible."""

from agent_shield.policy_engine.core.adjudication import Hit, adjudicate


def _hit(**kwargs) -> Hit:
    defaults = {
        "source": "builtin",
        "action": "ask",
        "rule_id": "rule",
        "kind": "behavior",
        "risk": "medium",
        "type_phrase": "向外发送数据",
        "content": "向外发送到 example.com",
    }
    defaults.update(kwargs)
    return Hit(**defaults)


def test_user_allow_does_not_cover_builtin_or_third_party_ask():
    builtin = adjudicate(
        [],
        [
            [
                _hit(
                    source="builtin",
                    action="ask",
                    rule_id="fs.read.sensitiveFiles",
                    risk="high",
                    type_phrase="读取敏感文件",
                ),
                _hit(
                    source="user_custom",
                    action="allow",
                    kind="object",
                    risk=None,
                    rule_id="user-allow",
                    type_phrase="文件读取",
                    content="读取 /etc/shadow",
                ),
            ]
        ],
    )
    third = adjudicate(
        [],
        [
            [
                _hit(
                    source="third_party",
                    action="ask",
                    kind="object",
                    risk=None,
                    rule_id="tp-file",
                    type_phrase="文件删除",
                    content="删除 /tmp/a",
                ),
                _hit(
                    source="user_custom",
                    action="allow",
                    kind="object",
                    risk=None,
                    rule_id="user-allow",
                    type_phrase="文件删除",
                    content="删除 /tmp/a",
                ),
            ]
        ],
    )
    assert builtin.action == "ask"
    assert builtin.winner_rule_id == "fs.read.sensitiveFiles"
    assert third.action == "ask"
    assert third.winner_rule_id == "tp-file"


def test_builtin_ask_beats_third_party_ask():
    result = adjudicate(
        [],
        [
            [
                _hit(
                    source="third_party",
                    action="ask",
                    kind="object",
                    risk=None,
                    rule_id="tp-ask",
                    type_phrase="文件读取",
                ),
                _hit(
                    source="builtin",
                    action="ask",
                    rule_id="fs.read.sensitiveFiles",
                    risk="high",
                    type_phrase="读取敏感文件",
                ),
            ]
        ],
    )
    assert result.action == "ask"
    assert result.winner_rule_id == "fs.read.sensitiveFiles"


def test_behavior_ask_is_the_reason_when_third_party_asks_tie():
    result = adjudicate(
        [],
        [
            [
                _hit(
                    source="third_party",
                    action="ask",
                    kind="object",
                    risk=None,
                    rule_id="tp-object",
                    type_phrase="命令执行",
                ),
                _hit(
                    source="third_party",
                    action="ask",
                    kind="behavior",
                    risk="medium",
                    rule_id="tp.kubectl.delete",
                    type_phrase="执行 kubectl delete",
                ),
            ]
        ],
    )
    assert result.winner_rule_id == "tp.kubectl.delete"


def test_grant_allows_one_ask_and_deny_still_wins():
    granted = adjudicate(
        [],
        [
            [
                _hit(
                    source="user_grant",
                    action="allow",
                    kind="grant",
                    risk=None,
                    rule_id="grant-1",
                    type_phrase="",
                    content="读取 /etc/shadow",
                ),
                _hit(
                    source="builtin",
                    action="ask",
                    risk="high",
                    rule_id="fs.read.sensitiveFiles",
                    type_phrase="读取敏感文件",
                    content="读取 /etc/shadow",
                ),
            ]
        ],
    )
    denied = adjudicate(
        [],
        [
            [
                _hit(source="user_grant", action="allow", kind="grant", risk=None, rule_id="grant-1"),
                _hit(
                    source="builtin",
                    action="deny",
                    risk="critical",
                    rule_id="privilege.escalate",
                    type_phrase="提权执行",
                ),
            ]
        ],
    )
    assert granted.action == "allow"
    assert granted.user_visible["summary"] == "命中已批准的具体资源，已放行"
    assert denied.action == "deny"


def test_multiple_asks_share_one_decision():
    result = adjudicate(
        [],
        [
            [
                _hit(
                    source="builtin",
                    action="ask",
                    risk="high",
                    rule_id="fs.read.sensitiveFiles",
                    type_phrase="读取敏感文件",
                    content="读取 /etc/shadow",
                )
            ],
            [
                _hit(
                    source="builtin",
                    action="ask",
                    risk="medium",
                    rule_id="fs.delete.outside",
                    type_phrase="删除工作区外的文件",
                    content="删除 /tmp/build",
                )
            ],
        ],
    )
    assert result.action == "ask"
    assert result.user_visible == {
        "summary": "读取敏感文件、删除工作区外的文件需要授权",
        "content": "读取 /etc/shadow，删除 /tmp/build",
        "risk": "高风险",
    }


def test_object_asks_have_no_behavior_risk():
    result = adjudicate(
        [],
        [
            [
                _hit(
                    source="user_custom",
                    action="ask",
                    kind="object",
                    risk=None,
                    rule_id="u-read",
                    type_phrase="文件读取",
                    content="读取 /data/a",
                )
            ],
            [
                _hit(
                    source="third_party",
                    action="ask",
                    kind="object",
                    risk=None,
                    rule_id="tp-del",
                    type_phrase="文件删除",
                    content="删除 /data/b",
                )
            ],
        ],
    )
    assert result.user_visible["summary"] == "文件读取、文件删除需要授权"
    assert result.user_visible["content"] == "读取 /data/a，删除 /data/b"
    assert result.user_visible["risk"] == "无风险"


def test_one_deny_hides_other_asks():
    result = adjudicate(
        [],
        [
            [
                _hit(
                    source="builtin",
                    action="ask",
                    risk="high",
                    rule_id="fs.read.sensitiveFiles",
                    type_phrase="读取敏感文件",
                    content="读取 /etc/shadow",
                )
            ],
            [
                _hit(
                    source="third_party",
                    action="deny",
                    kind="object",
                    risk=None,
                    rule_id="tp-deny",
                    type_phrase="文件删除",
                    content="删除 /tmp/build",
                )
            ],
        ],
    )
    assert result.action == "deny"
    assert result.user_visible["summary"] == "文件删除已拒绝"
    assert result.user_visible["content"] == "删除 /tmp/build"
    assert "读取敏感文件" not in result.user_visible["summary"]


def test_unmatched_none_stays_undetermined():
    result = adjudicate([], [[]])
    assert result.action == "undetermined"
    assert result.user_visible["summary"] == "没有命中规则，需要宿主决定"
    assert result.user_visible["content"] == ""
    assert result.user_visible["risk"] == "无风险"


def test_effect_allow_is_not_blocked_by_an_absent_event_level():
    result = adjudicate(
        [],
        [
            [
                _hit(
                    source="builtin",
                    action="allow",
                    risk="none",
                    rule_id="fs.read.userFiles",
                    type_phrase="读取用户文件",
                    content="读取 a.txt",
                )
            ]
        ],
    )
    assert result.action == "allow"
    assert result.user_visible["summary"] == "读取用户文件已放行"


def test_event_level_ask_survives_an_effect_allow():
    result = adjudicate(
        [
            _hit(
                source="builtin",
                action="ask",
                rule_id="exec.unobserved",
                risk="high",
                type_phrase="命令无法完整解析且没有运行时拦截",
                content="执行 powershell -enc ...",
            )
        ],
        [
            [
                _hit(
                    source="builtin",
                    action="allow",
                    risk="none",
                    rule_id="net.connect.allowlist",
                    type_phrase="连接允许名单中的网络端点",
                    content="连接 pypi.org",
                )
            ]
        ],
    )
    assert result.action == "ask"
    assert result.winner_rule_id == "exec.unobserved"
    assert result.user_visible["summary"] == "命令无法完整解析且没有运行时拦截需要授权"
    assert "连接允许名单" not in result.user_visible["summary"]


def test_unmatched_ask_rewrites_only_undetermined():
    rewritten = adjudicate([], [[]], unmatched="ask")
    kept = adjudicate(
        [],
        [
            [
                _hit(
                    source="third_party",
                    action="deny",
                    kind="object",
                    risk=None,
                    rule_id="tp-deny",
                    type_phrase="文件删除",
                    content="删除 /tmp/a",
                )
            ]
        ],
        unmatched="ask",
    )
    assert rewritten.action == "ask"
    assert rewritten.raw_action == "undetermined"
    assert rewritten.user_visible["summary"] == "没有命中规则，需要授权"
    assert kept.action == "deny"
    assert kept.raw_action == "deny"
