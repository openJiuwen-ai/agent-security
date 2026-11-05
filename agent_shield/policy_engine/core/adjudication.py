"""Ten-level adjudication and the three user-visible fields.

Callers supply already-matched hits. An empty event-hit list means the event
level is not in play. An empty effect list is one unmatched effect.
"""

from __future__ import annotations

from dataclasses import dataclass

_POSITION = {
    ("third_party", "deny"): 1,
    ("builtin", "deny"): 2,
    ("user_custom", "deny"): 3,
    ("user_grant", "allow"): 4,
    ("builtin", "ask"): 5,
    ("third_party", "ask"): 6,
    ("user_custom", "ask"): 7,
    ("user_custom", "allow"): 8,
    ("third_party", "allow"): 9,
    ("builtin", "allow"): 10,
}
_ACTION_RANK = {"allow": 0, "undetermined": 1, "ask": 2, "deny": 3}
_RISK_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_RISK_WORD = {
    "none": "无风险",
    "low": "低风险",
    "medium": "中风险",
    "high": "高风险",
    "critical": "严重风险",
}
_ACTION_WORD = {"ask": "需要授权", "deny": "已拒绝", "allow": "已放行"}
_UNMATCHED_SUMMARY = {
    "none": "没有命中规则，需要宿主决定",
    "ask": "没有命中规则，需要授权",
    "deny": "没有命中规则，已拒绝",
    "allow": "没有命中规则，已放行",
}


@dataclass(frozen=True)
class Hit:
    source: str
    action: str
    rule_id: str
    kind: str
    risk: str | None = None
    type_phrase: str = ""
    content: str = ""
    user_grantable: bool = True


@dataclass(frozen=True)
class Decision:
    action: str
    winner_rule_id: str | None
    user_visible: dict[str, str]
    grants: tuple[dict, ...] = ()
    raw_action: str = "undetermined"


def best_hit(hits: list[Hit]) -> Hit | None:
    return _best(hits)


def adjudicate(
    event_hits: list[Hit],
    effect_hits: list[list[Hit]],
    *,
    unmatched: str = "none",
) -> Decision:
    parts = [_part(hits, unmatched) for hits in effect_hits]
    if event_hits:
        parts.insert(0, _part(event_hits, unmatched))
    action = _strictest(part.action for part in parts)
    raw_action = _strictest(part.raw_action for part in parts)
    included = _included(parts, action)
    winner = _winner_of(included)
    return Decision(
        action=action,
        winner_rule_id=None if winner is None else winner.rule_id,
        user_visible=_visible(included, action, unmatched),
        raw_action=raw_action,
    )


@dataclass(frozen=True)
class _Part:
    action: str
    raw_action: str
    winner: Hit | None


def _part(hits: list[Hit], unmatched: str) -> _Part:
    winner = _best(hits)
    raw_action = "undetermined" if winner is None else winner.action
    return _Part(_rewrite(raw_action, unmatched), raw_action, winner)


def _best(hits: list[Hit]) -> Hit | None:
    if not hits:
        return None
    return min(hits, key=lambda hit: (_position(hit), 0 if hit.kind == "behavior" else 1))


def _position(hit: Hit) -> int:
    return _POSITION[(hit.source, hit.action)]


def _rewrite(action: str, unmatched: str) -> str:
    if action != "undetermined" or unmatched == "none":
        return action
    return unmatched


def _strictest(actions) -> str:
    return max(actions, key=lambda action: _ACTION_RANK[action], default="undetermined")


def _included(parts: list[_Part], action: str) -> list[Hit]:
    if action == "undetermined":
        return []
    if action == "ask":
        return [part.winner for part in parts if part.winner is not None and part.action == "ask"]
    ranked = [part.winner for part in parts if part.winner is not None and part.action == action]
    if not ranked:
        return []
    return [_best(ranked)]


def _winner_of(hits: list[Hit]) -> Hit | None:
    return _best(hits)


def _visible(hits: list[Hit], action: str, unmatched: str) -> dict[str, str]:
    if not hits:
        return {"summary": _UNMATCHED_SUMMARY[unmatched], "content": "", "risk": "无风险"}
    if len(hits) == 1 and hits[0].kind == "grant":
        return {"summary": "命中已批准的具体资源，已放行", "content": hits[0].content, "risk": "无风险"}
    phrases: list[str] = []
    for hit in hits:
        if hit.type_phrase and hit.type_phrase not in phrases:
            phrases.append(hit.type_phrase)
    summary = "、".join(phrases) + _ACTION_WORD[action]
    content = "，".join(hit.content for hit in hits if hit.content)
    return {"summary": summary, "content": content, "risk": _highest_risk(hits)}


def _highest_risk(hits: list[Hit]) -> str:
    risks = [hit.risk for hit in hits if hit.risk in _RISK_RANK]
    if not risks:
        return "无风险"
    return _RISK_WORD[max(risks, key=lambda risk: _RISK_RANK[risk])]
