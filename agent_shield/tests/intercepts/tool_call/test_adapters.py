"""jiuwen tool calls become events."""

from agent_shield.policy_engine.core.envelope import evaluate_event
from agent_shield.policy_engine.builtin.policy import load_builtin_policy
from agent_shield.intercepts.tool_call.adapters.jiuwenswarm import tool_call_to_event

WORKSPACE = {"root": "C:/Users/me/proj", "trusted_dirs": [], "os": "windows"}


def test_tool_call_read_and_shell():
    context = {
        "source": {"framework": "jiuwenswarm", "session_id": "s", "agent_id": "leader"},
        "workspace": WORKSPACE,
        "host_capabilities": {"hitl": True, "auto_intent": True},
        "intercept": False,
    }
    read = tool_call_to_event("read_file", {"path": "README.md"}, context=context, policy=load_builtin_policy())
    assert read["action"]["effects"][0]["type"] == "fs.read"
    assert read["action"]["effects"][0]["path"].endswith("README.md")
    assert evaluate_event(read)["action"] == "allow"
    shell = tool_call_to_event("bash", {"command": "git status"}, context=context, policy=load_builtin_policy())
    assert evaluate_event(shell)["action"] == "undetermined"
