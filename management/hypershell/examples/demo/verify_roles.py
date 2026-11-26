"""Linux role acceptance using real sandboxes; restore the base profiles afterward.

Requires the updated package installed at /opt/hypershell-demo and two existing
lab users. Stops/rebuilds the lab instances, preserving their private data.
Uses synthetic files only; no model calls or secrets are needed.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
import json
import logging
import os
from pathlib import Path
import pwd
import subprocess
import sys
import uuid

import yaml

from hypershell.config import AdminConfig, load_document
from hypershell.console import log_console
from hypershell.runner.client import BoxClient
from hypershell.runner.workspaces import workspace_state_path


def require(value, message):
    if not value:
        raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="/etc/hypershell-demo/admin.yaml")
    parser.add_argument("--runtime", default="/etc/hypershell-demo/runtime.yaml")
    parser.add_argument("--report", default="/var/lib/hypershell-managed/role-verification.json")
    args = parser.parse_args()
    require(os.geteuid() == 0, "run with sudo")
    base = AdminConfig.load(args.config)
    require({"u1", "u2"}.issubset(base.users), "requires existing u1/u2 workspaces")
    runtime = load_document(args.runtime)
    run_id = uuid.uuid4().hex[:12]
    lab = Path("/var/lib/hypershell-managed") / ("role-check-" + run_id)
    lab.mkdir(mode=0o700)
    config_path = lab / "admin.yaml"
    shared_id, extra_id = "role-shared-" + run_id, "role-extra-" + run_id
    role_id = "role-reader-" + run_id
    root = Path("/srv/hypershell-managed") / ("role-check-" + run_id)
    root.mkdir(mode=0o755)
    shared, extra = root / "shared", root / "extra"
    shared.mkdir(mode=0o777)
    os.chmod(shared, 0o777)
    extra.mkdir(mode=0o700)
    owner = pwd.getpwnam(base.users["u1"].run_as_user)
    os.chown(extra, owner.pw_uid, owner.pw_gid)
    token = "ROLE_" + run_id
    for directory in (shared, extra):
        (directory / "marker.txt").write_text(token)
    os.chmod(shared / "marker.txt", 0o666)
    os.chown(extra / "marker.txt", owner.pw_uid, owner.pw_gid)
    before = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (shared / "marker.txt", extra / "marker.txt")}
    report = {"passed": False, "run_id": run_id, "checks": {}, "restored": False}
    states = {}
    users = ("u1", "u2")

    def command(user, action, *arguments, config=config_path, expected=0):
        result = subprocess.run(
            [
                "/usr/local/bin/hypershell-demo",
                action,
                "--config",
                str(config),
                "--runtime",
                args.runtime,
                "--user",
                user,
                *map(str, arguments),
            ],
            capture_output=True,
            text=True,
            timeout=240,
            cwd="/",
        )
        if result.returncode != expected:
            try:
                detail = json.loads(result.stderr).get("error", {}).get("message", "unknown")
            except ValueError:
                detail = "unstructured CLI failure"
            raise AssertionError(f"{user} {action}: {detail}")
        return json.loads(result.stdout if expected == 0 else result.stderr)

    def parallel(function):
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = {user: pool.submit(function, user) for user in users}
            return {user: future.result() for user, future in futures.items()}

    def write_config(value):
        config_path.write_text(yaml.safe_dump(value, sort_keys=False))
        os.chmod(config_path, 0o600)
        config = AdminConfig.load(config_path)
        for user in users:
            path = lab / ("request-" + user + ".yaml")
            path.write_text(
                yaml.safe_dump(
                    {
                        "resources": [
                            {"id": rid, "mode": mode.name.lower()} for rid, mode in config.users[user].grants.items()
                        ]
                    }
                )
            )
            os.chmod(path, 0o600)
        return config

    def start(user):
        return command(user, "start", "--request", lab / ("request-" + user + ".yaml"))

    def execute(user, code):
        state_path = workspace_state_path(runtime, user, len(base.users))
        result = BoxClient(Path(state_path) / "engine.sock").execute(
            states[user]["sandbox_id"],
            [str(Path(runtime["source_dir"]) / ".venv/bin/python"), "-B", "-c", code],
            timeout=45,
        )
        require(result["exit_code"] == 0, user + " real sandbox probe failed")
        return json.loads(result["stdout"])

    def check(name, details=True):
        report["checks"][name] = details
        logging.info("PASS %s", name)

    def probe(user, visible=True):
        code = "import pathlib,json\nout={}\n"
        code += "p=pathlib.Path('/resources/role-shared/marker.txt')\n"
        if visible:
            code += "out['shared_read']=p.read_text()==" + repr(token) + "\n"
            code += (
                "try:\n p.write_text('UNEXPECTED')\n out['shared_ro']=False\nexcept OSError:\n out['shared_ro']=True\n"
            )
        else:
            code += "out['shared_hidden']=not p.exists()\n"
        if user == "u1" and visible:
            code += (
                "p=pathlib.Path('/resources/role-extra/marker.txt')\nout['extra_read']=p.read_text()=="
                + repr(token)
                + "\n"
            )
            code += (
                "try:\n p.write_text('UNEXPECTED')\n out['extra_ro']=False\nexcept OSError:\n out['extra_ro']=True\n"
            )
        else:
            code += "out['extra_hidden']=not pathlib.Path('/resources/role-extra/marker.txt').exists()\n"
        code += "print(json.dumps(out))\n"
        observed = execute(user, code)
        require(all(observed.values()), user + " role boundary mismatch")
        return observed

    changed_instances = False
    try:
        value = deepcopy(load_document(args.config))
        value["version"] = 2
        value.setdefault("roles", {})[role_id] = {"grants": {shared_id: "read"}}
        for rid, path, target in (
            (shared_id, shared, "/resources/role-shared"),
            (extra_id, extra, "/resources/role-extra"),
        ):
            value["resources"][rid] = {
                "type": "directory",
                "host_path": str(path),
                "sandbox_path": target,
                "max_mode": "read_write",
            }
        for user in users:
            value["users"][user].setdefault("roles", []).append(role_id)
        value["users"]["u1"].setdefault("grants", {})[extra_id] = "read_write"
        value["users"]["u1"].setdefault("resource_limits", {})[extra_id] = "read"
        config = write_config(value)
        check("role_and_direct_grants_resolved", config.explain("u1", extra_id))
        changed_instances = True
        parallel(lambda user: command(user, "stop", config=args.config))
        states = parallel(start)
        require(
            all(state["roles"] and state["authorization_digest"] for state in states.values()),
            "missing authorization snapshot",
        )
        check("parallel_role_start_and_authorization_snapshots")
        for user in users:
            check(user + "_actual_role_read_and_write_boundaries", probe(user))

        # Assert denied requests through the real CLI, independently of kernel probes.
        for user, rid, mode in (("u1", shared_id, "read_write"), ("u2", extra_id, "read")):
            request = yaml.safe_load((lab / ("request-" + user + ".yaml")).read_text())
            request["resources"] = [item for item in request["resources"] if item["id"] != rid] + [
                {"id": rid, "mode": mode}
            ]
            path = lab / "denied.yaml"
            path.write_text(yaml.safe_dump(request))
            result = subprocess.run(
                [
                    "/usr/local/bin/hypershell-demo",
                    "plan",
                    "--config",
                    str(config_path),
                    "--request",
                    str(path),
                    "--demo-user",
                    user,
                ],
                capture_output=True,
                text=True,
                timeout=30,
                cwd="/",
            )
            require(
                result.returncode == 2 and json.loads(result.stderr)["error"]["code"] == "PERMISSION_EXCEEDS_BOUNDARY",
                "overprivileged request was not rejected",
            )
        check("write_escalation_and_unassigned_extra_rejected")

        value["roles"][role_id]["grants"].pop(shared_id)
        value["users"]["u1"]["resource_limits"][extra_id] = "none"
        write_config(value)
        check("configuration_edit_does_not_claim_live_revocation", probe("u1"))
        peer = states["u2"]["sandbox_id"]
        old_id = states["u1"]["sandbox_id"]
        command("u1", "stop")
        require(not Path("/var/run/netns", "jbx-" + old_id).exists(), "old namespace remains after stop")
        states["u1"] = start("u1")
        require(states["u1"]["sandbox_id"] != old_id, "instance was not rebuilt")
        require(command("u2", "status")["sandbox_id"] == peer, "peer instance changed")
        check("u1_rebuild_revokes_role_and_direct_grants", probe("u1", visible=False))
        check("u2_remains_unchanged_until_rebuild", probe("u2"))
        command("u2", "stop")
        states["u2"] = start("u2")
        check("u2_rebuild_revokes_shared_role", probe("u2", visible=False))
        require(
            all(hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest for path, digest in before.items()),
            "read-only files changed",
        )
        check("host_file_hashes_unchanged")
        report["passed"] = True
    except Exception as exc:
        report["failure"] = str(exc)
        raise
    finally:
        try:
            if changed_instances:
                parallel(lambda user: command(user, "stop", config=args.config))
                states = parallel(lambda user: command(user, "start", config=args.config))
                report["restored"] = all(state["phase"] == "RUNNING" for state in states.values())
                report["final_instances"] = {user: state["sandbox_id"] for user, state in states.items()}
        finally:
            Path(args.report).write_text(json.dumps(report, indent=2))
            os.chmod(args.report, 0o600)
            log_console(json.dumps({"passed": report["passed"], "restored": report["restored"], "report": args.report}))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)
    main()
