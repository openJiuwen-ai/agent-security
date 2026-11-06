"""POST each saved agent event to /v1/evaluate and record the response."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from agent_shield.policy_engine.server.http import serve
from agent_shield.tests.stdio import log_line

HERE = Path(__file__).resolve().parent
EVENTS = HERE / "evaluate_events.json"
RESULTS = HERE / "evaluate_results.jsonl"


EVALUATE = "evaluate-token"
CONTROL = "control-token"


def main() -> None:
    cases = json.loads(EVENTS.read_text(encoding="utf-8"))
    server = serve(host="127.0.0.1", port=0, evaluate_token=EVALUATE, control_token=CONTROL)
    info = server.state.registry.register({"spec": "agent-pdp/v1"})
    server.state.registry.open_task(info.ruleset_id, "e2e", "task-e2e")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    url = f"http://127.0.0.1:{port}/v1/evaluate"
    rows = []
    try:
        for case in cases:
            request_body = {
                "spec": "agent-decision-request/v1",
                "ruleset_id": info.ruleset_id,
                "subject_id": "e2e",
                "task_id": "task-e2e",
                "event": case["body"],
            }
            payload = json.dumps(request_body, ensure_ascii=False).encode("utf-8")
            request = Request(
                url,
                data=payload,
                method="POST",
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {EVALUATE}"},
            )
            status, body = _post(request)
            rows.append(
                {
                    "id": case["id"],
                    "label": case["label"],
                    "http_status": status,
                    "response": body,
                }
            )
    finally:
        server.shutdown()
        server.server_close()
    RESULTS.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")
    counts: dict[str, int] = {}
    for row in rows:
        action = row["response"].get("action") if isinstance(row["response"], dict) else "error"
        key = f"{row['http_status']} {action}"
        counts[key] = counts.get(key, 0) + 1
    log_line(f"recorded {len(rows)} responses in {RESULTS}")
    for key in sorted(counts):
        log_line(f"  {key}: {counts[key]}")


def _post(request: Request) -> tuple[int, dict]:
    try:
        with urlopen(request) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


if __name__ == "__main__":
    main()
