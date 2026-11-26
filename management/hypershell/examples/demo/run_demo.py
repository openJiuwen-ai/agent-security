"""Run three preview scenarios and save their JSON artifacts."""

import json
import logging
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = Path(__file__).resolve().parent
OUTPUT = ROOT / "demo-output"


def main():
    errors = logging.Logger(__name__, logging.ERROR)
    errors.addHandler(logging.StreamHandler(sys.stderr))
    OUTPUT.mkdir(exist_ok=True)
    scenarios = [
        ("allowed", "request-allowed.yaml", 0),
        ("denied-write", "request-denied-write.yaml", 2),
        ("denied-unapproved", "request-denied-desktop.yaml", 2),
    ]
    for name, request, expected_code in scenarios:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "hypershell",
                "plan",
                "--config",
                str(EXAMPLES / "hypershell.yaml"),
                "--request",
                str(EXAMPLES / request),
                "--demo-user",
                "u1",
            ],
            cwd=ROOT,
            capture_output=True,
            encoding="utf-8",
        )
        if result.returncode != expected_code:
            errors.error("%s%s", result.stdout, result.stderr)
            return 1
        payload = json.loads(result.stdout if expected_code == 0 else result.stderr)
        if expected_code == 2 and payload["error"]["code"] != "PERMISSION_EXCEEDS_BOUNDARY":
            errors.error("Unexpected denial reason: %s", payload)
            return 1
        (OUTPUT / (name + ".json")).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        if expected_code == 0:
            logging.info("PASS allowed: identity=hs-u1, CPU=1, memory=2GiB, pids=128")
            for mount in payload["jiuwenbox_policy"]["filesystem_policy"]["bind_mounts"]:
                logging.info("  %s : %s", mount["sandbox_path"], mount["mode"])
        else:
            logging.info("PASS %s: %s", name, payload["error"]["code"])
    logging.info("Preview only: no sandbox created and no running instance changed.")
    logging.info("Artifacts: %s", OUTPUT)
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)
    raise SystemExit(main())
