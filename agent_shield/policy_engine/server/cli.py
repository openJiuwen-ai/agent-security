"""The `agent-pdp` command: eval one payload, or serve the loopback HTTP PDP."""

from __future__ import annotations

import argparse
import json
import logging
import sys

from agent_shield.policy_engine.builtin.rules import builtin_catalogs, load_builtin_ruleset
from agent_shield.policy_engine.core.envelope import decision_denied
from agent_shield.policy_engine.core.ruleset import load_ruleset
from agent_shield.policy_engine.evaluate import evaluate
from agent_shield.policy_engine.errors import PolicyError
from agent_shield.policy_engine.server.http import read_ruleset_document, serve


def eval_payload(payload: str, *, policy_path: str | None = None) -> tuple[int, dict]:
    try:
        request = json.loads(payload)
    except json.JSONDecodeError:
        return 2, decision_denied("", "invalid_ruleset")
    try:
        ruleset = _ruleset(policy_path)
    except PolicyError:
        return 2, decision_denied("", "invalid_ruleset")
    result = evaluate(request, ruleset=ruleset)
    code = 0 if result.get("action") == "allow" else 2
    return code, result


def _ruleset(policy_path: str | None):
    if not policy_path:
        return None
    document = read_ruleset_document(policy_path)
    base = load_builtin_ruleset()
    return load_ruleset(document, baseline=base.behaviors, catalogs=builtin_catalogs())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agent-pdp")
    commands = parser.add_subparsers(dest="command", required=True)
    evaluate_parser = commands.add_parser("eval")
    evaluate_parser.add_argument("--policy")
    serve_parser = commands.add_parser("serve")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=0)
    serve_parser.add_argument("--unmatched", default="none", choices=["none", "allow", "ask", "deny"])
    args = parser.parse_args(argv)
    if args.command == "eval":
        code, result = eval_payload(sys.stdin.read(), policy_path=args.policy)
        _stdout(json.dumps(result, ensure_ascii=False))
        if code != 0:
            visible = result.get("advice", {}).get("user_visible", "")
            text = visible.get("summary", "") if isinstance(visible, dict) else str(visible)
            _stderr(text or result.get("winner_rule_id") or "")
        return code
    try:
        http_server = serve(
            host=args.host,
            port=args.port,
            unmatched=args.unmatched,
        )
    except (PolicyError, ValueError) as err:
        _stderr(str(err))
        return 2
    address = http_server.server_address
    _stderr(
        json.dumps(
            {
                "url": f"http://{address[0]}:{address[1]}",
                "evaluate_token": http_server.state.evaluate_token,
                "control_token": http_server.state.control_token,
            },
            ensure_ascii=False,
        )
    )
    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        http_server.server_close()
    return 0


def _stream_logger(name: str, stream) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(stream)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


def _stdout(text: str) -> None:
    _stream_logger("agent_shield.pdp.stdout", sys.stdout).info("%s", text)


def _stderr(text: str) -> None:
    _stream_logger("agent_shield.pdp.stderr", sys.stderr).info("%s", text)


if __name__ == "__main__":
    raise SystemExit(main())
