"""Linux-only, administrator-operated isolated workspace lifecycle demo.

Each workspace uses a private UDS, root-owned state and its own file lock.
It is not a multi-tenant API or a substitute for the production controller.
"""

from contextlib import contextmanager
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import threading
import time
import uuid

from .client import BoxClient, RunnerError
from .jiuwenbox_policy import policy_digest, to_jiuwenbox_policy
from .workspaces import validate_live_profiles, workspace_state_path
from .network import host_network_locked, install_boundary
from .terminal_session import run_terminal_session
from .recovery import boot_id, process_start_ticks, reboot_evidence, assert_no_residuals, durable_write, sync_directory

# Web/TUI sessions write a lease file and refresh it from a heartbeat thread.
# A lease is reclaimed when its pid is gone or its heartbeat is older than TTL.
SESSION_HEARTBEAT_SECONDS = 5
SESSION_TTL_SECONDS = 90


def require_admin():
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise RunnerError("live demo commands require a Linux administrator (sudo)")


def trusted(path, *, directory=False):
    """Refuse writable config ancestors and symlink substitution."""
    path = Path(path).absolute()
    if path.resolve() != path:
        raise RunnerError("trusted path must not contain symlinks", path=str(path))
    for item in [path, *path.parents]:
        info = item.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise RunnerError("admin paths must be root-owned and not group/world writable", path=str(item))
    if directory and not path.is_dir():
        raise RunnerError("expected directory", path=str(path))
    return path


def verify_projection(expected, actual, prefix="policy"):
    """Compare supplied fields while permitting engine-added defaults."""
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            raise RunnerError("policy readback mismatch", field=prefix)
        for key, value in expected.items():
            if key not in actual:
                raise RunnerError("policy readback field missing", field=prefix + "." + key)
            verify_projection(value, actual[key], prefix + "." + key)
    elif isinstance(expected, (list, tuple)):
        if not isinstance(actual, (list, tuple)) or len(expected) != len(actual):
            raise RunnerError("policy readback list mismatch", field=prefix)
        for index, (left, right) in enumerate(zip(expected, actual)):
            verify_projection(left, right, prefix + f"[{index}]")
    elif expected != actual:
        raise RunnerError("policy readback value mismatch", field=prefix)


def engine_command_matches(command, socket_path, launcher_suffix=b"/hypershell/runner/engine.py"):
    """True when an argv looks like a Hypershell workspace engine for ``socket_path``.

    The engine may be launched from a different checkout than the control code:
    e.g. a pinned runtime under ``/opt`` while the controller runs from a
    development tree, or vice versa. Identify the engine by its script suffix
    (``.../hypershell/runner/engine.py``) rather than an exact deployment path,
    while still requiring that it was pointed at *this* workspace's engine
    socket.
    """
    if socket_path.encode() not in b" ".join(command):
        return False
    return any(b"jiuwenbox-server" in item or item.endswith(launcher_suffix) for item in command)


class ManagedRunner:
    def __init__(self, config, runtime_path, user_id):
        require_admin()
        from ..config import _fields, _path, load_document

        self.config = config
        self.user_id = user_id
        if user_id not in config.users:
            raise RunnerError("unknown user profile")
        raw = load_document(trusted(runtime_path))
        _fields(
            raw,
            {
                "version",
                "state_dir",
                "state_root",
                "source_dir",
                "python_prefix",
                "node_prefix",
                "model_host",
                "landlock",
                "dependency_overlay",
                "runtime_bundle",
            },
            {"version", "source_dir", "python_prefix", "model_host"},
            "runtime",
        )
        if type(raw["version"]) is not int or raw["version"] != 1:
            raise RunnerError("unsupported runtime version")
        import pwd
        import grp

        validate_live_profiles(config, pwd.getpwnam, grp.getgrnam)
        self.base = Path(workspace_state_path(raw, user_id, len(config.users)))
        trusted(self.base.parent, directory=True)
        self.base.mkdir(mode=0o700, exist_ok=True)
        trusted(self.base, directory=True)
        os.chmod(self.base, 0o700)
        self.source = Path(_path(raw["source_dir"], "source_dir"))
        self.prefix = Path(_path(raw["python_prefix"], "python_prefix"))
        self.node_prefix = Path(_path(raw.get("node_prefix", "/opt/node20"), "node_prefix"))
        self.runtime_bundle = Path(_path(raw["runtime_bundle"], "runtime_bundle")) if "runtime_bundle" in raw else None
        for path in [self.source, self.prefix, self.node_prefix]:
            if path.resolve() != path or not path.is_dir():
                raise RunnerError("runtime directory missing or symlinked", path=str(path))
        host = raw["model_host"]
        if (
            not isinstance(host, str)
            or not host
            or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-." for c in host)
        ):
            raise RunnerError("model_host must be an exact DNS hostname")
        self.model_host = host
        self.landlock = raw.get("landlock", "hard_requirement")
        if self.landlock not in ("hard_requirement", "best_effort"):
            raise RunnerError("invalid Landlock compatibility")
        self.bin = self.source / ".venv/bin"
        self.dependency_overlay = None
        if "dependency_overlay" in raw:
            self.dependency_overlay = trusted(_path(raw["dependency_overlay"], "dependency_overlay"), directory=True)
            for item in self.dependency_overlay.rglob("*"):
                trusted(item)
        self.client = BoxClient(self.base / "engine.sock")

    @contextmanager
    def locked(self):
        import fcntl

        with open(self.base / "lock", "a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RunnerError("workspace is busy; exit its TUI or wait for the active operation") from exc
            yield

    # ----- long-lived session leases (web/TUI) -------------------------------
    #
    # The op lock above guards short lifecycle operations. A web/TUI session is
    # long-lived, so it instead holds a *lease* recorded under ``sessions/``.
    # Leases never block ``stop``/``recover``: those revoke leases first.

    def _sessions_dir(self):
        sessions = self.base / "sessions"
        if sessions.is_symlink():
            raise RunnerError("session directory must not be a symlink")
        sessions.mkdir(mode=0o700, exist_ok=True)
        os.chmod(sessions, 0o700)
        return sessions

    @staticmethod
    def _session_alive(record):
        pid = record.get("pid")
        if type(pid) is not int or pid <= 0:
            return False
        try:
            if record.get("boot_id") and record["boot_id"] != boot_id():
                return False
            ticks = process_start_ticks(pid)
        except (OSError, ValueError, IndexError):
            return False
        return record.get("start_ticks") is None or record["start_ticks"] == ticks

    def list_sessions(self):
        """Return live web/TUI sessions, reclaiming dead or expired records."""
        sessions = self.base / "sessions"
        if not sessions.is_dir():
            return []
        now = time.time()
        live = []
        for path in sorted(sessions.glob("*.json")):
            try:
                record = json.loads(path.read_text())
            except (OSError, ValueError):
                continue
            session_id = record.get("id")
            if not isinstance(session_id, str) or path.stem != session_id:
                continue
            last_seen = record.get("last_seen")
            expired = not isinstance(last_seen, (int, float)) or now - last_seen > SESSION_TTL_SECONDS
            if expired or not self._session_alive(record):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
                continue
            started = record.get("started")
            live.append(
                {
                    "id": session_id,
                    "kind": record.get("kind"),
                    "pid": record.get("pid"),
                    "user_id": self.user_id,
                    "started": started,
                    "last_seen": last_seen,
                }
            )
        live.sort(key=lambda item: item["started"] if isinstance(item["started"], (int, float)) else 0)
        return live

    def terminate_session(self, session_id):
        """Terminate one session by pid (SIGTERM then SIGKILL) and drop its lease."""
        if (
            not isinstance(session_id, str)
            or len(session_id) != 32
            or any(c not in "0123456789abcdef" for c in session_id)
        ):
            raise RunnerError("invalid session id")
        path = self._sessions_dir() / (session_id + ".json")
        try:
            record = json.loads(path.read_text())
        except FileNotFoundError as exc:
            raise RunnerError("session not found", session_id=session_id) from exc
        except ValueError as exc:
            raise RunnerError("session record is corrupt", session_id=session_id) from exc
        pid = record.get("pid")
        self.audit("SESSION_TERMINATE_REQUESTED", session_id=session_id, pid=pid)
        if self._session_alive(record):
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and self._session_alive(record):
                time.sleep(0.1)
            if self._session_alive(record):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        self.audit("SESSION_TERMINATED", session_id=session_id, pid=pid)
        return {"session_id": session_id, "terminated": True}

    def revoke_sessions(self):
        """Terminate every live session of this user; used before stop/recover."""
        terminated = []
        for session in self.list_sessions():
            try:
                self.terminate_session(session["id"])
                terminated.append(session["id"])
            except RunnerError:
                continue
        return terminated

    @contextmanager
    def session_lease(self, kind):
        """Register a long-lived session that does not block the op lock."""
        if kind not in ("web", "tui"):
            raise RunnerError("invalid session kind")
        sessions = self._sessions_dir()
        session_id = uuid.uuid4().hex
        pid = os.getpid()
        try:
            start_ticks = process_start_ticks(pid)
        except (OSError, ValueError, IndexError):
            start_ticks = None
        record = {
            "id": session_id,
            "kind": kind,
            "pid": pid,
            "user_id": self.user_id,
            "started": time.time(),
            "last_seen": time.time(),
            "boot_id": boot_id(),
            "start_ticks": start_ticks,
        }
        path = sessions / (session_id + ".json")
        durable_write(path, json.dumps(record).encode(), exclusive=True)
        sync_directory(sessions)
        stop_heartbeat = threading.Event()
        heartbeat = threading.Thread(
            target=self._session_heartbeat, args=(path, session_id, stop_heartbeat), daemon=True
        )
        heartbeat.start()
        self.audit("SESSION_OPENED", session_id=session_id, kind=kind, pid=pid)
        try:
            yield session_id
        finally:
            stop_heartbeat.set()
            heartbeat.join(timeout=5)
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            self.audit("SESSION_CLOSED", session_id=session_id, kind=kind)

    @staticmethod
    def _session_heartbeat(path, session_id, stop_event):
        while not stop_event.wait(SESSION_HEARTBEAT_SECONDS):
            try:
                record = json.loads(path.read_text())
                if record.get("id") != session_id:
                    return
                record["last_seen"] = time.time()
                temp = path.with_suffix(".tmp")
                durable_write(temp, json.dumps(record).encode())
                temp.replace(path)
            except (OSError, ValueError):
                return

    def read_state(self):
        path = self.base / "instance.json"
        if not path.exists():
            return {"phase": "STOPPED", "user_id": self.user_id}
        state = json.loads(path.read_text())
        if state["user_id"] != self.user_id:
            raise RunnerError("state directory belongs to another workspace")
        return state

    def save(self, state):
        temp = self.base / "instance.tmp"
        durable_write(temp, json.dumps(state, indent=2).encode())
        temp.replace(self.base / "instance.json")
        sync_directory(self.base)

    def audit(self, event, **details):
        with open(self.base / "audit.jsonl", "a") as file:
            file.write(
                json.dumps(
                    {"time": time.time(), "actor_uid": os.getuid(), "user_id": self.user_id, "event": event, **details}
                )
                + "\n"
            )
            file.flush()
            os.fsync(file.fileno())

    def _engine_alive(self, state):
        pid = state.get("engine_pid")
        if type(pid) is not int or pid <= 0:
            return False
        try:
            if state.get("boot_id") and state["boot_id"] != boot_id():
                return False
            if state.get("engine_start_ticks") is not None and state["engine_start_ticks"] != process_start_ticks(pid):
                return False
            command = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            return engine_command_matches(command, str(self.base / "engine.sock"))
        except (OSError, ValueError, IndexError):
            return False

    def _stop(self, state):
        sid = state.get("sandbox_id")
        if sid:
            if not self._engine_alive(state):
                raise RunnerError("engine lost; cannot confirm sandbox cleanup", sandbox_id=sid)
            with host_network_locked():
                self.client.call("DELETE", f"/api/v1/sandboxes/{sid}")
                if Path("/var/run/netns", "jbx-" + sid).exists():
                    raise RunnerError("sandbox namespace remains after deletion")
        if self._engine_alive(state):
            os.kill(state["engine_pid"], signal.SIGTERM)
            for _ in range(40):
                if not self._engine_alive(state):
                    break
                time.sleep(0.1)
            else:
                raise RunnerError("management engine did not stop")
        state.update(phase="STOPPED", sandbox_id=None, engine_pid=None)
        self.save(state)
        self.audit("STOPPED")

    def stop(self):
        with self.locked():
            self.revoke_sessions()
            state = self.read_state()
            self._stop(state)
            return state

    def recover(self, *, legacy_after_reboot=False):
        """Archive a dead previous-boot instance, leaving data and other users intact.

        Does not start an application or attempt same-boot orphan cleanup.
        """
        with self.locked():
            self.revoke_sessions()
            state = self.read_state()
            if state["phase"] == "STOPPED":
                return {**state, "recovered": False}
            evidence = reboot_evidence(state, self.base / "instance.json", legacy_after_reboot=legacy_after_reboot)
            with host_network_locked():
                if self._engine_alive(state):
                    raise RunnerError("management engine is alive; recovery refused")
                assert_no_residuals(self.base, state)
                backup = self.base / ("recovery-" + uuid.uuid4().hex + ".json")
                durable_write(backup, (self.base / "instance.json").read_bytes(), exclusive=True)
                sync_directory(self.base)
                self.audit(
                    "RECOVERY_PREPARED", backup=backup.name, evidence=evidence, sandbox_id=state.get("sandbox_id")
                )
                # Remove only this workspace's unbound socket, after the backup is durable.
                socket_path = self.base / "engine.sock"
                if socket_path.exists():
                    socket_path.unlink()
                recovered = {
                    "phase": "STOPPED",
                    "user_id": self.user_id,
                    "recovery": {"backup": backup.name, "evidence": evidence},
                }
                self.save(recovered)
                self.audit("RECOVERY_COMPLETED", backup=backup.name)
                return {**recovered, "recovered": True}

    def start(self, request):
        import pwd
        import grp

        with self.locked():
            old = self.read_state()
            if old["phase"] != "STOPPED":
                raise RunnerError("workspace already exists; stop it before starting", phase=old["phase"])
            self.verify_engine_contract()
            user = self.config.users[self.user_id]
            account, group = pwd.getpwnam(user.run_as_user), grp.getgrnam(user.run_as_group)
            if account.pw_uid == 0 or group.gr_gid == 0:
                raise RunnerError("workload identity must not resolve to root")
            plan = self.config.compile(self.user_id, request)
            mounts = []
            reserved = [
                "/usr",
                "/bin",
                "/sbin",
                "/lib",
                "/lib64",
                "/etc",
                "/proc",
                "/dev",
                "/jiuwenbox",
                str(self.source),
                str(self.prefix),
                str(self.node_prefix),
            ]
            if self.dependency_overlay:
                reserved.append(str(self.dependency_overlay))
            for mount in plan.mounts:
                path = Path(mount.source)
                if path.resolve() != path or not path.exists():
                    raise RunnerError("resource path missing or symlinked", resource=mount.resource_id)
                trusted(path.parent, directory=True)
                if not stat.S_ISDIR(path.stat().st_mode):
                    raise RunnerError("live demo supports directory resources only")
                if not mount.read_only and path.stat().st_uid != account.pw_uid:
                    raise RunnerError("writable resource must belong to workload UID", resource=mount.resource_id)
                for target in reserved + [m.target for m in mounts]:
                    if (
                        mount.target == target
                        or mount.target.startswith(target + "/")
                        or target.startswith(mount.target + "/")
                    ):
                        raise RunnerError("overlapping or reserved mount target", target=mount.target)
                mounts.append(mount)
            if not {"/data", "/home/agent", "/workspace"}.issubset({m.target for m in mounts if not m.read_only}):
                raise RunnerError("JiuwenSwarm requires writable /data, /home/agent and /workspace")
            addresses = sorted(
                {x[4][0] for x in socket.getaddrinfo(self.model_host, 443, socket.AF_INET, socket.SOCK_STREAM)}
            )
            if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
                raise RunnerError("demo model DNS must resolve to public IPv4 addresses")
            hosts = self.base / "hosts"
            hosts.write_text("127.0.0.1 localhost\n" + "".join(ip + " " + self.model_host + "\n" for ip in addresses))
            environment = {
                "PATH": f"{self.bin}:{self.prefix}/bin:{self.node_prefix}/bin:/usr/local/bin:/usr/bin:/bin",
                "HOME": "/home/agent",
                "JIUWENSWARM_HOME": "/home/agent",
                "JIUWENSWARM_DATA_DIR": "/data",
                "TMPDIR": "/home/agent/tmp",
                "LANG": "C.UTF-8",
                "PYTHONUNBUFFERED": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
                "AGENT_SERVER_HOST": "127.0.0.1",
            }
            if self.dependency_overlay:
                environment["PYTHONPATH"] = str(self.dependency_overlay)
            policy = to_jiuwenbox_policy(
                plan,
                run_as_user=user.run_as_user,
                run_as_group=user.run_as_group,
                allowed_roots=self.config.allowed_roots,
                environment=environment,
                landlock=self.landlock,
            )
            runtime_paths = [
                "/usr",
                "/bin",
                "/sbin",
                "/lib",
                "/lib64",
                str(self.source),
                str(self.prefix),
                str(self.node_prefix),
                "/etc/passwd",
                "/etc/group",
                "/etc/ssl",
                "/etc/localtime",
                "/etc/nsswitch.conf",
            ]
            if self.dependency_overlay:
                runtime_paths.append(str(self.dependency_overlay))
            policy["filesystem_policy"]["bind_mounts"] += [
                {"host_path": p, "sandbox_path": p, "mode": "ro"} for p in runtime_paths if Path(p).exists()
            ]
            policy["filesystem_policy"]["bind_mounts"].append(
                {"host_path": str(hosts), "sandbox_path": "/etc/hosts", "mode": "ro"}
            )
            policy["filesystem_policy"]["read_only"] = runtime_paths
            policy["network"]["egress"] = {"default": "deny", "allowed_ips": addresses, "allowed_ports": [443]}
            policy["network"]["ingress"] = {"default": "deny", "allowed_ips": ["127.0.0.1"]}
            state = {
                "phase": "STARTING",
                "user_id": self.user_id,
                "plan_digest": plan.digest,
                "boot_id": boot_id(),
                "generation": uuid.uuid4().hex,
                "policy_digest": policy_digest(policy),
                "profile": self.landlock,
                "sandbox_id": None,
                "authorization_digest": self.config.explain(self.user_id)["authorization_digest"],
                "roles": list(user.roles),
            }
            self.save(state)
            self.audit("START_REQUESTED", plan_digest=plan.digest, profile=self.landlock)
            try:
                engine_env = self.engine_environment()
                socket_path = self.base / "engine.sock"
                if socket_path.exists():
                    socket_path.unlink()
                with open(self.base / "engine.log", "a") as log:
                    engine = subprocess.Popen(
                        [
                            str(self.bin / "python"),
                            str(Path(__file__).with_name("engine.py")),
                            "--state-dir",
                            str(self.base / "engine-home"),
                            "--listen",
                            "unix://" + str(socket_path),
                            "--save-logs",
                            str(self.base / "box-audit"),
                        ],
                        env=engine_env,
                        stdout=log,
                        stderr=log,
                        start_new_session=True,
                    )
                state["engine_pid"] = engine.pid
                state["engine_start_ticks"] = process_start_ticks(engine.pid)
                self.save(state)
                for _ in range(100):
                    try:
                        self.client.call("GET", "/health", timeout=2)
                        break
                    except RunnerError as exc:
                        if engine.poll() is not None:
                            raise RunnerError("engine exited during startup") from exc
                        time.sleep(0.2)
                else:
                    raise RunnerError("management health timeout")
                with host_network_locked():
                    ref = self.client.call("POST", "/api/v1/sandboxes", {"policy": policy, "policy_mode": "override"})
                    state["sandbox_id"] = ref["id"]
                    self.save(state)
                    self.require_sandbox_ready(ref["id"])
                    policy_path = "/".join(("/api/v1/policies", ref["id"]))
                    actual = self.client.call("GET", policy_path)
                    verify_projection(policy, actual)
                    (self.base / "policy.json").write_text(json.dumps(actual, indent=2))
                    sid = ref["id"]
                    state["network_boundary"] = install_boundary(sid, addresses)
                    self.save(state)
                probe = self.client.execute(
                    sid,
                    [
                        str(self.bin / "python"),
                        "-c",
                        "import os, pathlib, sys\n"
                        "status = pathlib.Path('/proc/self/status').read_text()\n"
                        f"if os.getuid() != {account.pw_uid} or os.getgroups():\n"
                        "    raise RuntimeError('unexpected workload identity')\n"
                        "required = ('NoNewPrivs:\\t1', 'Seccomp:\\t2', 'CapEff:\\t0000000000000000')\n"
                        "if not all(value in status for value in required):\n"
                        "    raise RuntimeError('missing process restrictions')\n"
                        "if pathlib.Path('/home/demo/Desktop').exists():\n"
                        "    raise RuntimeError('unexpected desktop access')\n"
                        "pathlib.Path('/workspace/hs-check').write_text('ok')\n"
                        "sys.stdout.write('BOUNDARY_OK\\n')\n",
                    ],
                )
                if probe["exit_code"] != 0 or "BOUNDARY_OK" not in probe["stdout"]:
                    raise RunnerError("prelaunch boundary probe failed")
                state["boundary_probe"] = "BOUNDARY_OK"
                result = self.client.call(
                    "POST",
                    f"/api/v1/sandboxes/{sid}/exec_background",
                    {"command": [str(self.bin / "jiuwenswarm-start"), "app"], "workdir": "/workspace"},
                )
                state["app_job_id"] = result["job_id"]
                self.save(state)
                for _ in range(60):
                    result = self.client.execute(
                        sid,
                        [
                            str(self.bin / "python"),
                            "-c",
                            "import socket; s=socket.create_connection(('127.0.0.1',19001),timeout=1); s.close()",
                        ],
                        timeout=3,
                    )
                    if result["exit_code"] == 0:
                        break
                    time.sleep(1)
                else:
                    raise RunnerError("application WebSocket listener health timeout")
                state["phase"] = "RUNNING"
                self.save(state)
                self.audit("RUNNING", sandbox_id=sid, policy_digest=state["policy_digest"])
                return state
            except Exception as exc:
                self.audit("START_FAILED", error_type=type(exc).__name__)
                try:
                    self._stop(state)
                except Exception:
                    state["phase"] = "ERROR_CLEANUP_REQUIRED"
                    self.save(state)
                raise

    def engine_environment(self):
        # The engine's global sweep assumes a single server per host and can
        # kill another workspace. DELETE /sandboxes/{id} still cleans this one.
        return {
            "PATH": f"{self.bin}:{self.prefix}/bin:{self.node_prefix}/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(self.base),
            "LANG": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "JIUWENBOX_SKIP_ORPHAN_NET_CLEANUP": "1",
        }

    def require_sandbox_ready(self, sandbox_id):
        """A create response can contain an id even when daemon setup failed."""
        sandbox_path = "/".join(("/api/v1/sandboxes", sandbox_id))
        observed = self.client.call("GET", sandbox_path)
        phase = observed.get("phase") if isinstance(observed, dict) else None
        if phase != "ready":
            raise RunnerError(
                "sandbox daemon was not ready after creation; inspect the private engine log",
                phase=(
                    phase
                    if isinstance(phase, str) and phase in {"creating", "failed", "error", "stopped"}
                    else "unknown"
                ),
            )

    def verify_engine_contract(self):
        self.require_runtime_bundle()
        code = (
            "import inspect\n"
            "from jiuwenbox.supervisor import network\n"
            "source = inspect.getsource(network.cleanup_orphaned_uplinks)\n"
            "if network.ENV_SKIP_ORPHAN_NET_CLEANUP != 'JIUWENBOX_SKIP_ORPHAN_NET_CLEANUP':\n"
            "    raise RuntimeError('unexpected orphan network cleanup setting')\n"
            "if 'ENV_SKIP_ORPHAN_NET_CLEANUP' not in source:\n"
            "    raise RuntimeError('orphan network cleanup ignores the setting')\n"
        )
        result = subprocess.run(
            [str(self.bin / "python"), "-I", "-B", "-c", code],
            env=self.engine_environment(),
            capture_output=True,
            timeout=30,
        )
        if result.returncode:
            raise RunnerError("JiuwenBox lacks the required per-workspace cleanup contract")

    def require_runtime_bundle(self):
        from .runtime_bundle import require_bundle_config

        return require_bundle_config(
            {
                "runtime_bundle": str(self.runtime_bundle) if self.runtime_bundle else None,
                "source_dir": str(self.source),
                "python_prefix": str(self.prefix),
                "node_prefix": str(self.node_prefix),
            }
        )

    def status(self):
        state = self.read_state()
        if state["phase"] != "STOPPED" and not self._engine_alive(state):
            return {
                **state,
                "phase": "LOST",
                "recorded_phase": state["phase"],
                "reason": "ENGINE_IDENTITY_MISSING",
                "recovery_required": True,
            }
        if state["phase"] == "RUNNING":
            try:
                sandbox_path = "/".join(("/api/v1/sandboxes", state["sandbox_id"]))
                ref = self.client.call("GET", sandbox_path, timeout=3)
                job = self.client.call(
                    "GET", f"/api/v1/sandboxes/{state['sandbox_id']}/background/{state['app_job_id']}", timeout=3
                )
            except RunnerError:
                return {
                    **state,
                    "phase": "ERROR",
                    "recorded_phase": state["phase"],
                    "reason": "ENGINE_QUERY_FAILED",
                    "recovery_required": True,
                }
            return {
                **state,
                "phase": "RUNNING" if job.get("running") and ref["phase"] == "ready" else "ERROR",
                "observed_sandbox": ref,
                "observed_app": job,
            }
        return state

    def doctor(self):
        """Inspect the configured interpreter without starting/stopping the app."""
        import platform

        self.require_runtime_bundle()
        from .diagnostics import inspect_python

        environment = {
            "PATH": f"{self.bin}:{self.prefix}/bin:/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        if self.dependency_overlay:
            environment["PYTHONPATH"] = str(self.dependency_overlay)
        report = inspect_python(self.bin / "python", environment=environment)
        blockers = []
        if not report["file_lock_compatible"]:
            blockers.append("APPLICATION_FILE_LOCK_INCOMPATIBLE")
        return {
            "ready": not blockers,
            "scope": "host_runtime_compatibility",
            "kernel": platform.release(),
            "runtime": report,
            "blockers": blockers,
            "warnings": [] if report["sqlite_schema_supported"] else ["SQLITE_SCHEMA_UNSUPPORTED"],
            "limitations": ["Does not certify sandbox isolation or application tool behavior."],
        }

    def exec_in_workspace(self, command, *, timeout=60, workdir="/workspace", _audit_event=None):
        """Execute through the same locked backend path used by chat.

        This is an administrator-side Python interface, not a user-facing
        arbitrary-command endpoint. ``_audit_event`` keeps chat's completion
        event bound to the instance and lock used for the execution.
        """
        with self.locked():
            state = self.status()
            if state["phase"] != "RUNNING":
                raise RunnerError("managed workspace is not running; no host fallback")
            result = self.client.execute(state["sandbox_id"], command, timeout=timeout, workdir=workdir)
            if _audit_event:
                self.audit(_audit_event, sandbox_id=state["sandbox_id"], exit_code=result["exit_code"])
            return result

    def chat(self, prompt, session):
        return self.exec_in_workspace(
            [
                str(self.bin / "jiuwenswarm"),
                "chat",
                "--gateway-url",
                "ws://127.0.0.1:19001/tui",
                "--session",
                session,
                "--json",
                "--timeout",
                "90",
                prompt,
            ],
            timeout=110,
            _audit_event="CHAT_COMPLETED",
        )

    def run_probe(self, entry, command, *, timeout=60):
        """Capture a fixed probe via a real entry; only privileged code calls this.

        No CLI or Web route exposes this arbitrary-command Python interface.
        The verification orchestrator supplies the fixed probe, not user input.
        """
        require_admin()
        if entry == "chat":
            return self.exec_in_workspace(command, timeout=timeout)
        if entry != "tui":
            raise RunnerError("unknown execution entry", entry=entry)
        with self.locked():
            state = self.status()
            if state["phase"] != "RUNNING":
                raise RunnerError("managed workspace is not running; no host fallback")
            return run_terminal_session(self, state, command, capture=True, timeout=timeout)

    def tui(self):
        # A TUI session holds a revocable lease, not the long-lived op lock, so
        # an administrator can still stop/recover while it is attached.
        with self.session_lease("tui"):
            with self.locked():
                state = self.status()
                if state["phase"] != "RUNNING":
                    raise RunnerError("managed workspace is not running; no host fallback")
                sid = state["sandbox_id"]
                self.audit("TUI_ATTACH_REQUESTED", sandbox_id=sid)
            result = run_terminal_session(
                self, state, [str(self.bin / "jiuwenswarm-tui"), "--url", "ws://127.0.0.1:19001/tui"], capture=False
            )
            self.audit("TUI_EXITED", sandbox_id=sid, exit_code=result["exit_code"])
            return result["exit_code"]

    # ----- web UI entry (P1 prototype: raw byte relay to loopback app_web) -----

    def _web_environment(self, frontend_port):
        # app_web reads FRONTEND_PORT for its static listener and proxies /api,/ws
        # to WEB_PORT (the in-sandbox WebChannel, HTTP+WS on one port). The rest
        # mirrors the sandbox launch environment so the static front has the same
        # PATH/HOME/PYTHONPATH as the already-running app, independent of whether
        # the backend merges vs replaces per-exec env.
        env = {
            "PATH": f"{self.bin}:{self.prefix}/bin:{self.node_prefix}/bin:/usr/local/bin:/usr/bin:/bin",
            "HOME": "/home/agent",
            "JIUWENSWARM_HOME": "/home/agent",
            "JIUWENSWARM_DATA_DIR": "/data",
            "TMPDIR": "/home/agent/tmp",
            "LANG": "C.UTF-8",
            "PYTHONUNBUFFERED": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "AGENT_SERVER_HOST": "127.0.0.1",
            "FRONTEND_PORT": str(frontend_port),
            "FRONTEND_HOST": "127.0.0.1",
            "WEB_PORT": "19000",
            "GATEWAY_URL": "http://127.0.0.1:19000",
        }
        if self.dependency_overlay:
            env["PYTHONPATH"] = str(self.dependency_overlay)
        return env

    def _live_state(self):
        """Return RUNNING state, verified through the live engine API.

        This reads the recorded instance and asks the engine whether the
        sandbox is ``ready``. It does not require an outer op lock: the caller
        either holds one briefly (attach) or runs as a revocable session.
        """
        state = self.read_state()
        sid = state.get("sandbox_id")
        if state.get("phase") != "RUNNING" or not sid:
            raise RunnerError("managed workspace is not running; no host fallback")
        try:
            sandbox_path = "/".join(("/api/v1/sandboxes", sid))
            ref = self.client.call("GET", sandbox_path, timeout=5)
        except RunnerError as exc:
            raise RunnerError("managed workspace engine is not reachable", sandbox_id=sid) from exc
        if not isinstance(ref, dict) or ref.get("phase") != "ready":
            raise RunnerError("managed workspace sandbox is not ready", sandbox_id=sid)
        return state

    def _ensure_web_frontend_locked(self, state, frontend_port):
        """Start the jiuwenswarm app_web static front inside the sandbox (idempotent)."""
        sid = state.get("sandbox_id")
        if not sid:
            raise RunnerError("workspace has no sandbox; start it first")
        dist = self.source / "jiuwenswarm/channels/web/frontend/dist"
        if not (dist / "index.html").exists():
            raise RunnerError("web frontend dist is missing; build it before enabling web", path=str(dist))
        if state.get("web_job_id") and state.get("web_frontend_port") == frontend_port:
            try:
                observed = self.client.call(
                    "GET", f"/api/v1/sandboxes/{sid}/background/{state['web_job_id']}", timeout=3
                )
                if observed.get("running"):
                    return state
            except RunnerError:
                pass
        result = self.client.call(
            "POST",
            f"/api/v1/sandboxes/{sid}/exec_background",
            {
                "command": [
                    str(self.bin / "jiuwenswarm-web"),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(frontend_port),
                    "--dist",
                    str(dist),
                ],
                "workdir": "/workspace",
                "env": self._web_environment(frontend_port),
            },
        )
        state["web_job_id"] = result["job_id"]
        state["web_frontend_port"] = frontend_port
        self.save(state)
        for _ in range(60):
            probe = self.client.execute(
                sid,
                [
                    str(self.bin / "python"),
                    "-c",
                    "import socket; socket.create_connection(('127.0.0.1', %d), timeout=1).close()" % frontend_port,
                ],
                timeout=3,
            )
            if probe["exit_code"] == 0:
                self.audit("WEB_FRONTEND_READY", sandbox_id=sid, port=frontend_port)
                return state
            time.sleep(1)
        raise RunnerError("web frontend did not become reachable")

    def start_web_frontend(self, *, frontend_port=5173):
        """Ensure the static front is running (does not start the relay)."""
        with self.locked():
            state = self._live_state()
            state = self._ensure_web_frontend_locked(state, frontend_port)
            return {**state, "web_ready": True, "frontend_port": frontend_port}

    def web(self, *, host="127.0.0.1", port=8091, frontend_port=5173, gate_url=None, login_url=None):
        """Serve the managed workspace's jiuwenswarm web UI through a byte relay.

        When ``gate_url`` is set, each new browser connection is authorized
        against the HyperShell gateway session before any bytes reach the sandbox;
        unauthenticated requests are redirected to ``login_url``.
        """
        from .web_relay import make_gate_authorizer, serve_web_relay

        authorize = make_gate_authorizer(gate_url, self.user_id) if gate_url else None
        with self.session_lease("web"):
            with self.locked():
                state = self._live_state()
                state = self._ensure_web_frontend_locked(state, frontend_port)
            sid = state["sandbox_id"]
            self.audit("WEB_ATTACH_REQUESTED", sandbox_id=sid, listen_port=port, gated=bool(gate_url))
            try:
                serve_web_relay(
                    self,
                    state,
                    host=host,
                    port=port,
                    frontend_port=frontend_port,
                    authorize=authorize,
                    login_url=login_url,
                )
            finally:
                self.audit("WEB_ATTACH_EXITED", sandbox_id=sid, listen_port=port)
        return {
            "phase": state.get("phase"),
            "sandbox_id": sid,
            "listen": f"http://{host}:{port}",
            "frontend_port": frontend_port,
            "gated": bool(gate_url),
        }
