"""Loopback HTTP PDP. Control and evaluate use different host credentials."""

from __future__ import annotations

import hmac
import json
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml

from agent_shield.policy_engine.errors import PolicyError
from agent_shield.policy_engine.server.registry import RulesetRegistry, RulesetRejected

_LOOPBACK = {"127.0.0.1", "localhost", "::1"}
_MAX_BODY = 1024 * 1024
_CONFLICTS = {"version_conflict", "unknown_ruleset", "runtime_relax", "task_id_in_use"}


class ServerState:
    def __init__(self, registry: RulesetRegistry, *, evaluate_token: str, control_token: str) -> None:
        self.registry = registry
        self.evaluate_token = evaluate_token
        self.control_token = control_token


class Server(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], state: ServerState) -> None:
        if address[0] not in _LOOPBACK:
            raise ValueError("server must bind to loopback")
        super().__init__(address, ServerHandler)
        self.state = state


class ServerHandler(BaseHTTPRequestHandler):
    server: Server

    def handle_get(self) -> None:
        parts = _parts(self.path)
        if parts == ["v1", "health"]:
            self._send(200, {"status": "ok"})
            return
        if len(parts) == 3 and parts[:2] == ["v1", "rulesets"]:
            if not self._allows("control"):
                self._send(401, {"error": "unauthorized"})
                return
            self._status(parts[2])
            return
        self._send(404, {"error": "not_found"})

    def handle_post(self) -> None:
        parts = _parts(self.path)
        if parts == ["v1", "rulesets"]:
            self._control(self._register)
            return
        if parts == ["v1", "tasks"]:
            self._control(self._open_task)
            return
        if parts == ["v1", "tasks", "close"]:
            self._control(self._close_task)
            return
        if parts == ["v1", "evaluate"]:
            if not self._allows("evaluate"):
                self._send(401, {"error": "unauthorized"})
                return
            self._evaluate()
            return
        self._send(404, {"error": "not_found"})

    def handle_put(self) -> None:
        parts = _parts(self.path)
        if len(parts) == 3 and parts[:2] == ["v1", "rulesets"]:
            self._control(lambda payload: self._update(parts[2], payload))
            return
        self._send(404, {"error": "not_found"})

    def handle_delete(self) -> None:
        parts = _parts(self.path)
        if len(parts) != 3 or parts[:2] != ["v1", "rulesets"]:
            self._send(404, {"error": "not_found"})
            return
        if not self._allows("control"):
            self._send(401, {"error": "unauthorized"})
            return
        try:
            self.server.state.registry.close(parts[2], caller=self._caller())
        except RulesetRejected:
            self._send(409, {"error": "unknown_ruleset"})
            return
        self._send(200, {"status": "closed"})

    def log_message(self, fmt: str, *args) -> None:
        return

    def _caller(self) -> str:
        return self.headers.get("X-Agent-PDP-Caller", "")

    def _allows(self, kind: str) -> bool:
        expected = self.server.state.control_token if kind == "control" else self.server.state.evaluate_token
        supplied = _token(self.headers)
        if not supplied:
            return False
        return hmac.compare_digest(supplied, expected)

    def _control(self, handle) -> None:
        if not self._allows("control"):
            self._send(401, {"error": "unauthorized"})
            return
        payload = self._body()
        if payload is None:
            return
        handle(payload)

    def _register(self, payload: dict) -> None:
        try:
            info = self.server.state.registry.register(payload, caller=self._caller())
        except RulesetRejected as err:
            self._send(400, {"error": err.code, "reason": str(err)})
            return
        self._send(201, {"ruleset_id": info.ruleset_id, "version": info.version, "fingerprint": info.fingerprint})

    def _update(self, ruleset_id: str, payload: dict) -> None:
        if set(payload) != {"expected_version", "ruleset"} or not isinstance(payload.get("expected_version"), int):
            self._send(400, {"error": "invalid_ruleset"})
            return
        try:
            updated = self.server.state.registry.update(
                ruleset_id,
                payload["ruleset"],
                payload["expected_version"],
                caller=self._caller(),
            )
        except RulesetRejected as err:
            status = 409 if err.code in _CONFLICTS else 400
            self._send(status, {"error": err.code, "reason": str(err)})
            return
        self._send(
            200,
            {
                "ruleset_id": updated.ruleset_id,
                "version": updated.version,
                "fingerprint": updated.fingerprint,
                "classification": updated.classification,
                "changes": list(updated.changes),
            },
        )

    def _open_task(self, payload: dict) -> None:
        self._task(payload, self.server.state.registry.open_task)

    def _close_task(self, payload: dict) -> None:
        self._task(payload, self.server.state.registry.close_task)

    def _task(self, payload: dict, operation) -> None:
        if set(payload) != {"ruleset_id", "subject_id", "task_id"}:
            self._send(400, {"error": "invalid_task"})
            return
        try:
            result = operation(payload["ruleset_id"], payload["subject_id"], payload["task_id"])
        except RulesetRejected as err:
            status = 409 if err.code in _CONFLICTS else 400
            self._send(status, {"error": err.code})
            return
        self._send(200, {"version": result} if isinstance(result, int) else {"status": "closed"})

    def _status(self, ruleset_id: str) -> None:
        try:
            status = self.server.state.registry.status(ruleset_id)
        except RulesetRejected:
            self._send(409, {"error": "unknown_ruleset"})
            return
        self._send(
            200,
            {
                "ruleset_id": status.ruleset_id,
                "version": status.version,
                "fingerprint": status.fingerprint,
                "updated_at": status.updated_at,
                "task_count": status.task_count,
            },
        )

    def _evaluate(self) -> None:
        payload = self._body()
        if payload is None:
            return
        state = self.server.state
        status, body = state.registry.evaluate_request(payload, isolated=True)
        self._send(status, body)

    def _body(self) -> dict | None:
        length = int(self.headers.get("Content-Length") or 0)
        if length > _MAX_BODY:
            self._send(400, {"error": "too_large"})
            return None
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._send(400, {"error": "invalid_json"})
            return None
        if not isinstance(payload, dict):
            self._send(400, {"error": "invalid_json"})
            return None
        return payload

    def _send(self, status: int, body: dict) -> None:
        encoded = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def _bind_http_verbs() -> None:
    for verb in ("GET", "POST", "PUT", "DELETE"):
        setattr(ServerHandler, "do_" + verb, getattr(ServerHandler, "handle_" + verb.lower()))


_bind_http_verbs()


def read_ruleset_document(path: str) -> dict:
    text = Path(path).read_text(encoding="utf-8")
    document = json.loads(text) if path.endswith(".json") else yaml.safe_load(text)
    if not isinstance(document, dict) or document.get("spec") != "agent-pdp/v1":
        raise PolicyError("eval --policy must be agent-pdp/v1")
    return document


def serve(
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    evaluate_token: str | None = None,
    control_token: str | None = None,
    unmatched: str = "none",
) -> Server:
    evaluate_token, control_token = _minted_tokens(evaluate_token, control_token)
    registry = RulesetRegistry(unmatched=unmatched)
    state = ServerState(registry, evaluate_token=evaluate_token, control_token=control_token)
    return Server((host, port), state)


def _minted_tokens(evaluate_token: str | None, control_token: str | None) -> tuple[str, str]:
    if evaluate_token is None and control_token is None:
        return secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    if not evaluate_token or not control_token or evaluate_token == control_token:
        raise ValueError("control and evaluate tokens must be different")
    return evaluate_token, control_token


def _parts(path: str) -> list[str]:
    return [part for part in path.split("?", 1)[0].split("/") if part]


def _token(headers) -> str:
    header = headers.get("Authorization", "")
    if header.startswith("Bearer "):
        return header[7:]
    return headers.get("X-Agent-PDP-Token", "")
