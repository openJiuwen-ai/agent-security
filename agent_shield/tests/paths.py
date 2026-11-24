"""Suite paths derived from the agent_shield tree, not a fixed parent count."""

from pathlib import Path


def repo_root() -> Path:
    here = Path(__file__).resolve()
    for candidate in (here, *here.parents):
        schema = candidate / "schema" / "agent-event.v1.json"
        engine = candidate / "policy_engine" / "evaluate.py"
        if schema.is_file() and engine.is_file():
            return candidate
    raise RuntimeError("agent_shield root was not found from the test suite")


REPO_ROOT = repo_root()
SCHEMA_DIR = REPO_ROOT / "schema"
