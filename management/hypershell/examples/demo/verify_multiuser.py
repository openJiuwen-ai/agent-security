"""Run the two-workspace Linux VM acceptance; leave both instances running.

Uses synthetic markers, same session/skill/memory names, concurrent chats,
real listening peers (including TCP/UDP 53), and independent stop/rebuilds.
Temporary root network listeners are always terminated, including on failure.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import logging
import os
from pathlib import Path
import platform
import posixpath
import select
import subprocess
import sys
import uuid

from hypershell.config import AdminConfig, load_document
from hypershell.console import log_console
from hypershell.policy import LaunchRequest, PermissionExceedsBoundary
from hypershell.runner.client import BoxClient
from hypershell.runner.workspaces import workspace_state_path

USERS = ("u1", "u2")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class Acceptance:
    def __init__(self, args):
        self.args = args
        self.config = AdminConfig.load(args.config)
        self.runtime = load_document(args.runtime)
        self.python = str(Path(self.runtime["source_dir"]) / ".venv/bin/python")
        self.bases = {user: Path(workspace_state_path(self.runtime, user, len(self.config.users))) for user in USERS}
        self.clients = {user: BoxClient(self.bases[user] / "engine.sock") for user in USERS}
        self.run_id = uuid.uuid4().hex[:12]
        self.session = "multiuser-" + self.run_id
        self.tokens = {user: user.upper() + uuid.uuid4().hex[:16] for user in USERS}
        self.report = {
            "passed": False,
            "run_id": self.run_id,
            "checks": {},
            "scope": "two administrator-operated workspaces; not login/SSO or production certification",
        }
        import hypershell
        from importlib.metadata import PackageNotFoundError, version

        package = Path(hypershell.__file__).parent
        manifest = {
            str(path.relative_to(package)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(package.rglob("*.py"))
        }
        versions = {}
        for name in ("openjiuwen", "filelock", "jiuwenbox", "workswarm"):
            try:
                versions[name] = version(name)
            except PackageNotFoundError:
                versions[name] = "unknown (source installation)"
        self.report["environment"] = {
            "kernel": platform.release(),
            "python": platform.python_version(),
            "versions": versions,
            "installed_package_files": manifest,
            "installed_package_digest": hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest(),
        }
        self.states = {}

    def check(self, name, details=True):
        self.report["checks"][name] = details
        logging.info("PASS %s", name)

    def command(self, user, action, *arguments, expected=0):
        result = subprocess.run(
            [
                "/usr/local/bin/hypershell-demo",
                action,
                "--config",
                self.args.config,
                "--runtime",
                self.args.runtime,
                "--user",
                user,
                *arguments,
            ],
            capture_output=True,
            text=True,
            timeout=240,
        )
        if result.returncode != expected:
            try:
                error = json.loads(result.stderr).get("error", {})
                detail = str(error.get("code", "")) + ": " + str(error.get("message", ""))
            except (ValueError, AttributeError):
                detail = "unstructured CLI failure"
            raise AssertionError(f"{user} {action} returned {result.returncode}, expected {expected}: {detail}")
        return json.loads(result.stdout if expected == 0 else result.stderr)

    def execute(self, user, code):
        result = self.clients[user].execute(
            self.states[user]["sandbox_id"], [self.python, "-B", "-c", code], timeout=45
        )
        require(result["exit_code"] == 0, user + " sandbox probe failed: " + result.get("stderr", "")[-2000:])
        return json.loads(result["stdout"])

    def chat(self, user, prompt):
        result = self.command(user, "chat", "--session", self.session, prompt)
        require(result["exit_code"] == 0, user + " chat process failed")
        payload = json.loads(result["stdout"])
        require(payload.get("ok"), user + " application chat failed")
        return payload["content"].strip()

    @staticmethod
    def parallel(function):
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = {user: pool.submit(function, user) for user in USERS}
            return {user: future.result() for user, future in futures.items()}

    def start(self, user):
        state = self.command(user, "status")
        if state["phase"] == "STOPPED":
            state = self.command(user, "start")
        require(state["phase"] == "RUNNING", user + " must be running")
        return self.command(user, "status")

    def private_paths(self):
        name = f"hs-isolation-{self.run_id}"
        return [
            posixpath.join("/workspace", f"{name}.txt"),
            posixpath.join("/data/config", f"{name}.json"),
            posixpath.join("/data/agent/workspace/skills", name, "SKILL.md"),
            posixpath.join("/data/agent/workspace/memory", f"{name}.md"),
        ]

    def check_files(self):
        import pwd

        knowledge = self.config.catalog["company-knowledge"].backend_ref
        knowledge_file = Path(knowledge) / "guide.txt"
        before = hashlib.sha256(knowledge_file.read_bytes()).hexdigest()
        for user in USERS:
            other = "u2" if user == "u1" else "u1"
            paths = self.private_paths()
            token = self.tokens[user]
            other_roots = [
                self.config.catalog[other + "." + suffix].backend_ref for suffix in ("state", "home", "project")
            ]
            code = "import os,pathlib,json,socket\n"
            code += "paths=" + repr(paths) + "; token=" + repr(token) + "\n"
            code += (
                "for p in paths:\n p=pathlib.Path(p); p.parent.mkdir(parents=True,exist_ok=True); p.write_text(token)\n"
            )
            code += (
                "out={'uid':os.getuid(),'groups':os.getgroups(),'netns':os.readlink('/proc/self/ns/net'),"
                "'status':pathlib.Path('/proc/self/status').read_text()}\n"
            )
            code += "out['own_files']=[pathlib.Path(p).read_text()==token for p in paths]\n"
            code += "out['peer_hidden']=[not pathlib.Path(p).exists() for p in " + repr(other_roots) + "]\n"
            code += "out['management_hidden']=not pathlib.Path('/var/lib/hypershell-managed').exists()\n"
            code += "out['same_gateway_port']=socket.socket().connect_ex(('127.0.0.1',19001))==0\n"
            code += (
                "try:\n"
                " with open('/resources/knowledge/guide.txt','a') as f:f.write('UNEXPECTED')\n"
                " out['knowledge_denied']=False\n"
                "except OSError:\n"
                " out['knowledge_denied']=True\n"
            )
            code += "print(json.dumps(out))\n"
            observed = self.execute(user, code)
            expected_uid = pwd.getpwnam(self.config.users[user].run_as_user).pw_uid
            require(observed["uid"] == expected_uid and observed["groups"] == [], "wrong workload identity")
            require(all(observed["own_files"]) and all(observed["peer_hidden"]), "private resource visibility failure")
            require(
                observed["management_hidden"] and observed["knowledge_denied"] and observed["same_gateway_port"],
                "workspace boundary failure",
            )
            require(
                "CapEff:\t0000000000000000" in observed["status"] and "NoNewPrivs:\t1" in observed["status"],
                "missing process boundary",
            )
            self.check(
                user + "_identity_and_files",
                {"uid": expected_uid, "groups": [], "netns": observed["netns"], "own_files": True, "peer_hidden": True},
            )
        require(
            self.report["checks"]["u1_identity_and_files"]["netns"]
            != self.report["checks"]["u2_identity_and_files"]["netns"],
            "shared network namespace",
        )
        # Each denied path is known to exist on the host. Check actual reads
        # through Python and shell, rather than accepting a missing fixture.
        for user in USERS:
            other = "u2" if user == "u1" else "u1"
            private = Path(self.config.catalog[other + ".project"].backend_ref) / Path(self.private_paths()[0]).name
            require(private.read_text() == self.tokens[other], "peer fixture missing on host")
            code = (
                "import pathlib,subprocess,json\np=" + repr(str(private)) + "\n"
                "try:\n pathlib.Path(p).read_text(); denied=False\nexcept OSError:\n denied=True\n"
                "r=subprocess.run(['cat',p],capture_output=True)\n"
                "print(json.dumps({'python_denied':denied,'shell_denied':r.returncode!=0}))"
            )
            require(all(self.execute(user, code).values()), "cross-user read succeeded")
            request = LaunchRequest.from_dict({"resources": [{"id": other + ".project", "mode": "read_write"}]})
            try:
                self.config.compile(user, request)
                raise AssertionError("cross-user resource request accepted")
            except PermissionExceedsBoundary:
                pass
        require(hashlib.sha256(knowledge_file.read_bytes()).hexdigest() == before, "knowledge changed")
        self.check("cross_user_python_shell_and_policy_denied")
        self.check("shared_knowledge_unchanged")

    def check_network(self):
        listeners = []
        # A root-only test fixture provides real listening peers on privileged
        # ports. It does not read user files or execute received data.
        server = """import socket,select
sockets=[]
for port in (53,443,19555):
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 s.bind(('0.0.0.0',port));s.listen();sockets.append(s)
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind(('0.0.0.0',53));sockets.append(u)
print('READY',flush=True)
while True:
 for s in select.select(sockets,[],[],1)[0]:
  if s is u:
   data,addr=u.recvfrom(256);u.sendto(b'HS_TEST_LISTENER',addr)
  else:
   conn,addr=s.accept();conn.sendall(b'HS_TEST_LISTENER');conn.close()
"""
        try:
            for user in USERS:
                namespace = "jbx-" + self.states[user]["sandbox_id"]
                child = subprocess.Popen(
                    ["/usr/sbin/ip", "netns", "exec", namespace, "/usr/bin/python3", "-I", "-B", "-u", "-c", server],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    start_new_session=True,
                )
                listeners.append(child)
                require(select.select([child.stdout], [], [], 10)[0], "listener readiness timeout")
                require(child.stdout.readline().strip() == "READY", "listener failed to bind")
                udp_positive = subprocess.run(
                    [
                        "/usr/sbin/ip",
                        "netns",
                        "exec",
                        namespace,
                        "/usr/bin/python3",
                        "-I",
                        "-B",
                        "-c",
                        "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2); "
                        "s.sendto(b'probe',('127.0.0.1',53))\n"
                        "if s.recv(256) != b'HS_TEST_LISTENER':\n"
                        "    raise RuntimeError('unexpected UDP listener response')\n",
                    ],
                    capture_output=True,
                    timeout=5,
                )
                require(udp_positive.returncode == 0, "UDP listener positive control failed")
            for user in USERS:
                other = "u2" if user == "u1" else "u1"
                peer_ip = self.states[other]["observed_sandbox"]["ip_address"]
                code = "import socket,json\nout={'own':[],'peer_denied':[]}\n"
                code += (
                    "for port in (53,443,19555):\n"
                    " s=socket.socket();s.settimeout(2);s.connect(('127.0.0.1',port))\n"
                    " out['own'].append(s.recv(256)==b'HS_TEST_LISTENER');s.close()\n"
                )
                code += (
                    "for port in (53,443,19555,19001):\n"
                    " s=socket.socket();s.settimeout(1)\n"
                    " out['peer_denied'].append(s.connect_ex((" + repr(peer_ip) + ",port))!=0);s.close()\n"
                )
                # Some backend seccomp profiles deny UDP socket creation itself.
                # Preserve that stronger boundary; the root positive control
                # above proves that the peer UDP listener really works.
                code += (
                    "try:\n s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(1);s.sendto(b'probe',("
                    + repr(peer_ip)
                    + ",53));s.recv(256);out['peer_udp53_denied']=False\n"
                    "except OSError as exc:\n"
                    " out['peer_udp53_denied']=True;out['udp_denial']=type(exc).__name__\n"
                )
                code += "print(json.dumps(out))"
                observed = self.execute(user, code)
                require(
                    all(observed["own"]) and all(observed["peer_denied"]) and observed["peer_udp53_denied"],
                    "cross-user network boundary failed",
                )
                for binary in ("iptables", "ip6tables"):
                    result = subprocess.run(
                        [
                            "/usr/sbin/ip",
                            "netns",
                            "exec",
                            "jbx-" + self.states[user]["sandbox_id"],
                            binary,
                            "-C",
                            "OUTPUT",
                            "-j",
                            "HS_OUTPUT",
                        ],
                        capture_output=True,
                    )
                    require(result.returncode == 0, "network boundary hook missing")
                self.check(user + "_peer_network_denied", observed)
        finally:
            for child in listeners:
                if child.poll() is None:
                    child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)

    def check_chat(self):
        first = self.parallel(
            lambda user: self.chat(
                user, "Remember private code " + self.tokens[user] + ". Reply exactly ACK. Do not use tools."
            )
        )
        require(all(reply == "ACK" for reply in first.values()), "concurrent first-turn response failed")
        recalled = self.parallel(
            lambda user: self.chat(
                user, "What private code did I ask you to remember? Reply only the code. Do not use tools."
            )
        )
        require(recalled == self.tokens, "same-session chat crossed workspaces")
        for user in USERS:
            other = "u2" if user == "u1" else "u1"
            data = Path(self.config.catalog[user + ".state"].backend_ref)
            history = data / "agent/sessions" / self.session / "history.jsonl"
            text = history.read_text()
            require(
                self.tokens[user] in text and self.tokens[other] not in text,
                "session history leaked between workspaces",
            )
        self.check("concurrent_chat_same_session_id_isolated")
        from verify_native_file import verify_events

        self.parallel(
            lambda user: self.chat(
                user,
                "Use only the native read_file tool to read "
                + self.private_paths()[0]
                + ". You must actually call read_file. Do not use shell or Python. Return its contents.",
            )
        )
        for user in USERS:
            history = (
                Path(self.config.catalog[user + ".state"].backend_ref)
                / "agent/sessions"
                / self.session
                / "history.jsonl"
            )
            events = [json.loads(line) for line in history.read_text().splitlines() if line.strip()]
            verify_events(events, self.tokens[user])
        self.check("both_users_native_read_file")

    def check_rebuild(self):
        for user in USERS:
            other = "u2" if user == "u1" else "u1"
            old_id = self.states[user]["sandbox_id"]
            peer_id = self.states[other]["sandbox_id"]
            peer_policy = self.bases[other] / "engine-home/policies" / (peer_id + "_sandbox_policy.yaml")
            peer_digest = hashlib.sha256(peer_policy.read_bytes()).hexdigest()
            self.command(user, "stop")
            require(not Path("/var/run/netns", "jbx-" + old_id).exists(), "stopped namespace remains")
            rejected = self.command(user, "chat", "must refuse", expected=2)
            require("no host fallback" in rejected["error"]["message"], "stopped user fell back to host")
            peer = self.command(other, "status")
            require(peer["phase"] == "RUNNING" and peer["sandbox_id"] == peer_id, "stopping user disrupted peer")
            require(
                hashlib.sha256(peer_policy.read_bytes()).hexdigest() == peer_digest,
                "stopping user deleted peer engine policy",
            )
            self.states[user] = self.start(user)
            require(self.states[user]["sandbox_id"] != old_id, "sandbox was not rebuilt")
            require(self.command(other, "status")["sandbox_id"] == peer_id, "starting user disrupted peer")
            require(
                hashlib.sha256(peer_policy.read_bytes()).hexdigest() == peer_digest,
                "starting user modified peer engine policy",
            )
            paths = self.private_paths()
            observed = self.execute(
                user,
                "import pathlib,json; print(json.dumps([pathlib.Path(p).read_text() for p in " + repr(paths) + "]))",
            )
            require(observed == [self.tokens[user]] * len(paths), "personal data not preserved")
            if not self.args.skip_chat:
                require(
                    self.chat(user, "What was my private code? Reply only the code. Do not use tools.")
                    == self.tokens[user],
                    "session did not survive rebuild",
                )
                require(
                    self.chat(other, "What was my private code? Reply only the code. Do not use tools.")
                    == self.tokens[other],
                    "peer chat disrupted",
                )
            self.check(user + "_stop_rebuild_preserves_both_users")

    def run(self):
        try:
            for round_number in range(self.args.cold_start_rounds):
                self.states = self.parallel(self.start)
                for field in ("sandbox_id", "engine_pid"):
                    require(self.states["u1"][field] != self.states["u2"][field], "shared " + field)
                for user in USERS:
                    root = self.bases[user] / "engine-home"
                    sid = self.states[user]["sandbox_id"]
                    require(
                        (root / "policies" / (sid + "_sandbox_policy.yaml")).is_file(), "private engine policy missing"
                    )
                    require((root / "sandboxes" / (sid + ".json")).is_file(), "private engine state missing")
                self.check("parallel_start_and_private_engine_storage_round_" + str(round_number + 1))
                if round_number + 1 < self.args.cold_start_rounds:
                    self.parallel(lambda user: self.command(user, "stop"))
            self.check("concurrent_start_and_same_application_port")
            self.check_files()
            self.check_network()
            if not self.args.skip_chat:
                self.check_chat()
            self.check_rebuild()
            self.report["chat_tested"] = not self.args.skip_chat
            self.report["final_instances"] = {
                user: {"sandbox_id": self.states[user]["sandbox_id"], "phase": self.command(user, "status")["phase"]}
                for user in USERS
            }
            self.report["passed"] = True
        except Exception as exc:
            self.report["failure_type"] = type(exc).__name__
            # Probe stderr is limited to our synthetic test programs. Never
            # include raw model replies, session records or environment data.
            self.report["failure"] = str(exc)
            raise
        finally:
            Path(self.args.report).write_text(json.dumps(self.report, indent=2))
            os.chmod(self.args.report, 0o600)
            log_console(json.dumps({"passed": self.report["passed"], "report": self.args.report}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="/etc/hypershell-demo/admin.yaml")
    parser.add_argument("--runtime", default="/etc/hypershell-demo/runtime.yaml")
    parser.add_argument("--report", default="/var/lib/hypershell-managed/multiuser-verification.json")
    parser.add_argument(
        "--skip-chat", action="store_true", help="only run OS isolation checks; not full application acceptance"
    )
    parser.add_argument(
        "--cold-start-rounds", type=int, default=3, help="parallel start rounds, with stops between rounds (default: 3)"
    )
    args = parser.parse_args()
    require(os.geteuid() == 0, "run with sudo")
    require(1 <= args.cold_start_rounds <= 10, "cold-start-rounds must be between 1 and 10")
    Acceptance(args).run()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)
    main()
