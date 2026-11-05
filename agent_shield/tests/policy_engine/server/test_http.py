"""Loopback PDP command and HTTP server."""

import json
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from agent_shield.policy_engine.server.cli import eval_payload
from agent_shield.policy_engine.server.http import serve

from agent_shield.tests.policy_engine._factory import make_event

EVALUATE = "evaluate-token"
CONTROL = "control-token"


def test_cli_exit_codes_follow_the_eval_command():
    allow_code, allow = eval_payload(json.dumps(_request(_read_event())))
    bare_code, bare = eval_payload(json.dumps(_read_event()))
    deny_code, deny = eval_payload("{")
    missing = dict(_request(_read_event()))
    del missing["subject_id"]
    missing_code, missing_body = eval_payload(json.dumps(missing))
    assert allow_code == 0 and allow["action"] == "allow"
    assert bare_code == 2 and bare["winner_rule_id"] == "invalid_ruleset"
    assert deny_code == 2 and deny["winner_rule_id"] == "invalid_ruleset"
    assert missing_code == 2 and missing_body["winner_rule_id"] == "missing_subject"


def test_http_separates_credentials_and_requires_a_decision_request():
    server = serve(host="127.0.0.1", port=0, evaluate_token=EVALUATE, control_token=CONTROL)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        assert _json(port, "GET", "/v1/health")["status"] == "ok"
        assert _status(port, "POST", "/v1/reload", {}) == 404
        bare = _post(port, "POST", "/v1/evaluate", _read_event(), EVALUATE)
        assert bare[0] == 200 and bare[1]["action"] == "deny" and bare[1]["winner_rule_id"] == "invalid_ruleset"
        missing = _post(port, "POST", "/v1/evaluate", _request(_read_event(), subject_id=""), EVALUATE)
        assert missing[0] == 401 and "action" not in missing[1]
        assert _status(port, "POST", "/v1/evaluate", _request(_read_event()), CONTROL) == 401
        assert _status(port, "POST", "/v1/rulesets", {"spec": "agent-pdp/v1"}, EVALUATE) == 401

        created = _post(port, "POST", "/v1/rulesets", {"spec": "agent-pdp/v1"}, CONTROL)
        assert created[0] == 201
        ruleset_id = created[1]["ruleset_id"]
        opened = _post(port, "POST", "/v1/tasks", _task(ruleset_id), CONTROL)
        assert opened[0] == 200 and opened[1]["version"] == 1
        again = _post(port, "POST", "/v1/tasks", _task(ruleset_id), CONTROL)
        assert again[0] == 409 and again[1]["error"] == "task_id_in_use"
        only_task = _post(port, "POST", "/v1/tasks/close", {"task_id": "task-a"}, CONTROL)
        assert only_task[0] == 400 and only_task[1]["error"] == "invalid_task"

        allowed = _post(port, "POST", "/v1/evaluate", _request(_read_event(), ruleset_id), EVALUATE)
        assert allowed[0] == 200 and allowed[1]["action"] == "allow"
        denied = _post(
            port,
            "POST",
            "/v1/evaluate",
            _request(
                _read_event(),
                ruleset_id,
                user_rules=[{"id": "block-readme", "object": "file", "action": "deny", "pattern": ["**/README.md"]}],
            ),
            EVALUATE,
        )
        assert denied[1]["action"] == "deny" and denied[1]["winner_rule_id"] == "block-readme"

        conflict = _post(
            port,
            "PUT",
            f"/v1/rulesets/{ruleset_id}",
            {"expected_version": 0, "ruleset": {"spec": "agent-pdp/v1"}},
            CONTROL,
        )
        assert conflict[0] == 409 and conflict[1]["error"] == "version_conflict"
        assert _json(port, "GET", f"/v1/rulesets/{ruleset_id}", CONTROL)["version"] == 1
        unknown = _post(port, "POST", "/v1/evaluate", _request(_read_event(), "missing"), EVALUATE)
        assert unknown[0] == 409 and unknown[1]["error"] == "unknown_ruleset"
    finally:
        server.shutdown()
        server.server_close()


def test_signed_grant_allows_the_next_request_for_the_same_subject():
    server = serve(host="127.0.0.1", port=0, evaluate_token=EVALUATE, control_token=CONTROL)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        created = _post(
            port,
            "POST",
            "/v1/rulesets",
            {"spec": "agent-pdp/v1", "behavior_rules": [{"id": "fs.read.sensitiveFiles", "user_grantable": True}]},
            CONTROL,
        )
        ruleset_id = created[1]["ruleset_id"]
        assert _post(port, "POST", "/v1/tasks", _task(ruleset_id), CONTROL)[0] == 200
        secret = make_event([{"type": "fs.read", "path": "C:/Users/me/proj/.env"}])
        first = _post(port, "POST", "/v1/evaluate", _request(secret, ruleset_id), EVALUATE)
        assert first[1]["action"] == "ask" and first[1]["grants"]
        assert "mac" not in first[1]["grants"][0]
        second = _post(
            port,
            "POST",
            "/v1/evaluate",
            _request(secret, ruleset_id, grants=first[1]["grants"]),
            EVALUATE,
        )
        assert second[1]["action"] == "allow"
        assert second[1]["winner_rule_id"] == "suggested-0"
    finally:
        server.shutdown()
        server.server_close()


def _read_event() -> dict:
    return make_event([{"type": "fs.read", "path": "C:/Users/me/proj/README.md"}])


def _request(event: dict, ruleset_id: str = "rs", *, subject_id: str = "user-a", user_rules=None, grants=None) -> dict:
    body = {
        "spec": "agent-decision-request/v1",
        "ruleset_id": ruleset_id,
        "subject_id": subject_id,
        "task_id": "task-a",
        "event": event,
    }
    if user_rules is not None:
        body["user_rules"] = user_rules
    if grants is not None:
        body["grants"] = grants
    return body


def _task(ruleset_id: str) -> dict:
    return {"ruleset_id": ruleset_id, "subject_id": "user-a", "task_id": "task-a"}


def _json(port: int, method: str, path: str, token: str | None = None) -> dict:
    status, body = _post(port, method, path, None, token)
    assert status == 200
    return body


def _status(port: int, method: str, path: str, payload: dict, token: str | None = None) -> int:
    return _post(port, method, path, payload, token)[0]


def test_control_audit_records_the_caller_and_the_closed_version():
    server = serve(host="127.0.0.1", port=0, evaluate_token=EVALUATE, control_token=CONTROL)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        created = _post(port, "POST", "/v1/rulesets", {"spec": "agent-pdp/v1"}, CONTROL, caller="host-a")
        ruleset_id = created[1]["ruleset_id"]
        assert server.state.registry.audit[-1]["caller"] == "host-a"
        closed = _post(port, "DELETE", f"/v1/rulesets/{ruleset_id}", None, CONTROL, caller="host-a")
        assert closed[0] == 200
        recorded = server.state.registry.audit[-1]
        assert recorded["op"] == "close"
        assert recorded["version"] == 1
        assert recorded["fingerprint"]
        assert recorded["caller"] == "host-a"
    finally:
        server.shutdown()
        server.server_close()


def test_serve_mints_credentials_in_memory():
    server = serve(host="127.0.0.1", port=0)
    try:
        evaluate_token = server.state.evaluate_token
        control_token = server.state.control_token
        assert evaluate_token and control_token and evaluate_token != control_token
    finally:
        server.server_close()


def _post(
    port: int, method: str, path: str, payload: dict | None, token: str | None, caller: str = ""
) -> tuple[int, dict]:
    data = None if payload is None else json.dumps(payload).encode()
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if caller:
        headers["X-Agent-PDP-Caller"] = caller
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = Request(f"http://127.0.0.1:{port}{path}", data=data, method=method, headers=headers)
    try:
        with urlopen(request) as response:
            return response.status, json.loads(response.read().decode())
    except HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())
