"""VM-specific lab installer. Run as root from a staged copy of this repository.

Uses a verified runtime bundle and the lab's existing model config.
Creates hs-demo (and optionally hs-demo-u2), /opt/hypershell-demo,
/etc/hypershell-demo, /srv/hypershell-managed and /var/lib/hypershell-managed.
"""

import argparse
from importlib.machinery import PathFinder
from importlib.util import module_from_spec
import json
import os
from pathlib import Path
import pwd
import shlex
import shutil
import stat
import subprocess
import sys

import yaml


class DemoInstallError(RuntimeError):
    """The demo installation encountered an invalid prerequisite."""


def control_wrapper(control):
    return (
        "#!/bin/sh\n"
        "exec env -i PATH=/usr/bin:/bin LANG=C.UTF-8 "
        "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/opt/hypershell-demo "
        + shlex.quote(str(control))
        + ' -P -B -m hypershell "$@"\n'
    )


def add_second_workspace(config, runtime, root, model_env):
    """Initialize a fresh u2 from app templates, never from u1's private data."""
    from dotenv import dotenv_values, set_key

    resources = config.get("resources")
    if not isinstance(resources, dict):
        raise DemoInstallError("workspace configuration must define a resource mapping")
    try:
        account = pwd.getpwnam("hs-demo-u2")
    except KeyError:
        subprocess.run(
            [
                "/usr/sbin/useradd",
                "--system",
                "--user-group",
                "--no-create-home",
                "--shell",
                "/usr/sbin/nologin",
                "hs-demo-u2",
            ],
            check=True,
        )
        account = pwd.getpwnam("hs-demo-u2")
    user_root = root / "u2"
    user_root.mkdir(mode=0o755, exist_ok=True)
    paths = {"state": user_root / "data", "home": user_root / "home", "project": user_root / "project"}
    for path in paths.values():
        if path.is_symlink():
            raise DemoInstallError("workspace directory must not be a symlink")
        path.mkdir(mode=0o700, exist_ok=True)
        if path.stat().st_uid not in (0, account.pw_uid):
            raise DemoInstallError("existing u2 directory has unexpected ownership")
        os.chown(path, account.pw_uid, account.pw_gid)
        os.chmod(path, 0o700)
    data = paths["state"]
    if not (data / "config/config.yaml").exists():
        environment = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(paths["home"]),
            "JIUWENSWARM_DATA_DIR": str(data),
            "LANG": "C.UTF-8",
            "PYTHONPATH": runtime.get("dependency_overlay", ""),
        }
        result = subprocess.run(
            [
                str(Path(runtime["source_dir"]) / ".venv/bin/python"),
                "-P",
                "-B",
                "-c",
                "import os\n"
                "from pathlib import Path\n"
                "from jiuwenswarm.common.utils import init_user_workspace\n"
                "workspace = Path(os.environ['JIUWENSWARM_DATA_DIR'])\n"
                "if init_user_workspace(overwrite=False, workspace_dir=workspace) == 'cancelled':\n"
                "    raise RuntimeError('workspace initialization cancelled')\n",
            ],
            env=environment,
            cwd="/tmp",
            user=account.pw_uid,
            group=account.pw_gid,
            extra_groups=[],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=120,
        )
        if result.returncode:
            raise DemoInstallError("fresh u2 initialization failed; no u1 private data was copied")
        # Only the lab's approved model connection is shared. No user history,
        # custom skills, memory, arbitrary environment or other credentials.
        approved = dotenv_values(model_env)
        env_path = data / "config/.env"
        for key in ("API_BASE", "API_KEY", "MODEL_NAME", "MODEL_PROVIDER", "ENDPOINT_PROFILE", "CUSTOM_HEADERS"):
            value = approved.get(key)
            if value is not None:
                set_key(str(env_path), key, value)
        os.chown(env_path, account.pw_uid, account.pw_gid)
        os.chmod(env_path, 0o600)
    (paths["home"] / "tmp").mkdir(mode=0o700, exist_ok=True)
    os.chown(paths["home"] / "tmp", account.pw_uid, account.pw_gid)
    grants = {"company-knowledge": "read"}
    for suffix, target in [("state", "/data"), ("home", "/home/agent"), ("project", "/workspace")]:
        host_path = paths.get(suffix)
        if host_path is None:
            raise DemoInstallError(f"workspace path is missing for {suffix}")
        rid = "u2." + suffix
        resources[rid] = {
            "type": "directory",
            "host_path": str(host_path),
            "sandbox_path": target,
            "max_mode": "read_write",
        }
        grants[rid] = "read_write"
    config["users"]["u2"] = {
        "login_uid": account.pw_uid,
        "run_as_user": "hs-demo-u2",
        "run_as_group": "hs-demo-u2",
        "grants": grants,
        "required": {k: v for k, v in grants.items() if k.startswith("u2.")},
        "quotas": {"cpu": 1, "memory_bytes": 3221225472, "pids": 128},
    }
    runtime.pop("state_dir", None)
    runtime["state_root"] = "/var/lib/hypershell-managed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sqlite-compat-overlay",
        action="store_true",
        help="prepare the verified filelock fix in a private root-owned overlay",
    )
    parser.add_argument("--multi-user", action="store_true", help="install independent u1/u2 workspaces")
    parser.add_argument(
        "--runtime-bundle",
        type=Path,
        required=True,
        help="previously built and verified root-controlled runtime snapshot",
    )
    parser.add_argument(
        "--control-python",
        type=Path,
        required=True,
        help="independent root-controlled Python 3.11 venv with HyperShell's dependencies",
    )
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("run with sudo")
    repository = Path(__file__).resolve().parents[2]
    # Establish ownership before importing HyperShell's validation helpers.
    for path in (repository, *repository.parents):
        info = path.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or not stat.S_ISDIR(info.st_mode):
            raise SystemExit("stage the installer in a root-controlled source directory")
    count = 0
    if not (repository / "hypershell").is_dir():
        raise SystemExit("staged HyperShell control package is missing")
    for directory, dirs, files in os.walk(repository / "hypershell", followlinks=False):
        for path in [Path(directory), *(Path(directory) / name for name in dirs + files)]:
            count += 1
            info = path.lstat()
            is_root_controlled = info.st_uid == 0 and not info.st_mode & 0o022
            is_regular_entry = stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)
            if count > 10000 or not is_root_controlled or not is_regular_entry:
                raise SystemExit("HyperShell control code must be a bounded root-controlled tree without symlinks")
    # Load the staged package from the verified source tree.
    spec = PathFinder.find_spec("hypershell", [str(repository)])
    if spec is None or spec.loader is None:
        raise DemoInstallError("staged HyperShell control package is missing")
    package = module_from_spec(spec)
    sys.modules[spec.name] = package
    spec.loader.exec_module(package)
    from hypershell.console import log_console
    from hypershell.runner.managed import trusted
    from hypershell.runner.runtime_bundle import verify_bundle
    from hypershell.runner.runtime_trust import require_trusted_runtime

    trusted(repository, directory=True)
    verified = verify_bundle(args.runtime_bundle)
    if not verified["matched"]:
        raise SystemExit("runtime bundle drift; refusing installation")
    selected_runtime = verified["runtime"]
    control = args.control_python.absolute()
    if control.parent.name != "bin" or not control.is_file():
        raise SystemExit("control-python must name an existing dedicated venv interpreter")
    control_root = control.parent.parent
    application_root = Path(selected_runtime["source_dir"])
    if (
        control_root == application_root
        or application_root in control_root.parents
        or control_root in application_root.parents
    ):
        raise SystemExit("control interpreter must be independent of application source/venv")
    require_trusted_runtime([control_root, Path(selected_runtime["python_prefix"])])
    try:
        account = pwd.getpwnam("hs-demo")
    except KeyError:
        subprocess.run(
            [
                "/usr/sbin/useradd",
                "--system",
                "--user-group",
                "--no-create-home",
                "--shell",
                "/usr/sbin/nologin",
                "hs-demo",
            ],
            check=True,
        )
        account = pwd.getpwnam("hs-demo")
    install = Path("/opt/hypershell-demo")
    for state_path in Path("/var/lib/hypershell-managed").glob("*/instance.json"):
        if json.loads(state_path.read_text())["phase"] != "STOPPED":
            raise SystemExit("stop all managed demo workspaces before reinstalling")
    existing_admin = Path("/etc/hypershell-demo/admin.yaml")
    if existing_admin.exists() and len(yaml.safe_load(existing_admin.read_text())["users"]) > 1 and not args.multi_user:
        raise SystemExit("existing multi-user installation requires --multi-user")
    install.mkdir(exist_ok=True)
    shutil.copytree(
        repository / "hypershell",
        install / "hypershell",
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    for directory in [install, *install.rglob("*")]:
        os.chown(directory, 0, 0)
        os.chmod(directory, 0o755 if directory.is_dir() else 0o644)
    etc = Path("/etc/hypershell-demo")
    etc.mkdir(mode=0o755, exist_ok=True)
    root = Path("/srv/hypershell-managed")
    root.mkdir(mode=0o755, exist_ok=True)
    user_root = root / "u1"
    user_root.mkdir(mode=0o755, exist_ok=True)
    data = user_root / "data"
    if not data.exists():
        shutil.copytree(
            "/srv/hypershell/users/u1/agent-state",
            data,
            ignore=shutil.ignore_patterns("run", "*.sock", "*.log", "*.lock"),
        )
        shutil.copy("/home/demo/.jiuwenswarm/config/.env", data / "config/.env")
    home, project = user_root / "home", user_root / "project"
    (home / "tmp").mkdir(parents=True, exist_ok=True)
    project.mkdir(exist_ok=True)
    if not (project / "README.md").exists():
        (project / "README.md").write_text("Managed HyperShell demo\n")
    for target in [data, home, project]:
        for path in [target, *target.rglob("*")]:
            if not path.is_symlink():
                os.chown(path, account.pw_uid, account.pw_gid)
        os.chmod(target, 0o700)
    os.chmod(data / "config/.env", 0o600)
    knowledge = root / "knowledge"
    knowledge.mkdir(mode=0o755, exist_ok=True)
    if not (knowledge / "guide.txt").exists():
        (knowledge / "guide.txt").write_text("KNOWLEDGE_READ_ONLY\n")
    resources = {}
    for rid, path, target, mode in [
        ("u1.state", data, "/data", "read_write"),
        ("u1.home", home, "/home/agent", "read_write"),
        ("u1.project", project, "/workspace", "read_write"),
        ("company-knowledge", knowledge, "/resources/knowledge", "read"),
    ]:
        resources[rid] = {"type": "directory", "host_path": str(path), "sandbox_path": target, "max_mode": mode}
    grants = {rid: item["max_mode"] for rid, item in resources.items()}
    config = {
        "version": 1,
        "allowed_roots": [str(root)],
        "resources": resources,
        "quotas": {"cpu": 2, "memory_bytes": 4294967296, "pids": 256},
        "users": {
            "u1": {
                "login_uid": pwd.getpwnam(os.environ.get("HYPERSHELL_LOGIN_USER", "demo")).pw_uid,
                "run_as_user": "hs-demo",
                "run_as_group": "hs-demo",
                "grants": grants,
                "required": {k: v for k, v in grants.items() if k.startswith("u1.")},
                "quotas": {"cpu": 1, "memory_bytes": 3221225472, "pids": 128},
            }
        },
    }
    from dotenv import dotenv_values
    from urllib.parse import urlsplit

    approved_model_env = Path("/home/demo/.jiuwenswarm/config/.env")
    model_host = urlsplit(dotenv_values(approved_model_env)["API_BASE"]).hostname
    runtime = {
        "version": 1,
        "state_dir": "/var/lib/hypershell-managed/u1",
        **selected_runtime,
        "runtime_bundle": str(args.runtime_bundle.absolute()),
        "model_host": model_host,
        "landlock": "hard_requirement",
    }
    if args.sqlite_compat_overlay:
        import filelock

        overlay = install / "compat"
        overlay.mkdir(mode=0o755, exist_ok=True)
        if not (overlay / "filelock").exists():
            shutil.copytree(
                Path(filelock.__file__).parent, overlay / "filelock", ignore=shutil.ignore_patterns("__pycache__")
            )
        subprocess.run(
            [sys.executable, str(repository / "scripts/dev/apply_sqlite_compat.py"), "--apply"],
            env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(overlay)},
            check=True,
        )
        for path in [overlay, *overlay.rglob("*")]:
            if path.is_symlink():
                raise SystemExit("dependency overlay must not contain symlinks")
            os.chown(path, 0, 0)
            os.chmod(path, 0o755 if path.is_dir() else 0o644)
        runtime["dependency_overlay"] = str(overlay)
    Path("/var/lib/hypershell-managed").mkdir(mode=0o700, exist_ok=True)
    if args.multi_user:
        add_second_workspace(config, runtime, root, approved_model_env)
    request = {"resources": [{"id": rid, "mode": mode} for rid, mode in grants.items()]}
    for name, payload in [("admin.yaml", config), ("runtime.yaml", runtime), ("request.yaml", request)]:
        path = etc / name
        path.write_text(yaml.safe_dump(payload, sort_keys=False))
        os.chmod(path, 0o600)
    if args.multi_user:
        for name, profile in config["users"].items():
            path = etc / ("request-" + name + ".yaml")
            path.write_text(
                yaml.safe_dump(
                    {"resources": [{"id": rid, "mode": mode} for rid, mode in profile["grants"].items()]},
                    sort_keys=False,
                )
            )
            os.chmod(path, 0o600)
    wrapper = Path("/usr/local/bin/hypershell-demo")
    wrapper.write_text(control_wrapper(control))
    os.chmod(wrapper, 0o755)
    log_console(
        json.dumps(
            {
                "installed": True,
                "users": list(config["users"]),
                "workload_uid": account.pw_uid,
                "config": str(etc),
                "runtime": runtime,
            }
        )
    )


if __name__ == "__main__":
    try:
        main()
    except DemoInstallError as exc:
        raise SystemExit(str(exc)) from None
