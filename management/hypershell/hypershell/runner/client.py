"""JiuwenBox HTTP client over a private Unix domain socket."""

import http.client
import json
import socket

from ..policy.errors import PolicyError


class RunnerError(PolicyError):
    code = "RUNNER_ERROR"


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__("localhost", timeout=timeout)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class BoxClient:
    def __init__(self, path):
        self.path = path

    def call(self, method, path, body=None, timeout=150):
        connection = UnixConnection(self.path, timeout)
        try:
            connection.request(
                method,
                path,
                body=None if body is None else json.dumps(body),
                headers={"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            raw = response.read()
            if response.status >= 400:
                raise RunnerError("JiuwenBox request failed", status=response.status, endpoint=path)
            return json.loads(raw) if raw else None
        except (OSError, http.client.HTTPException, ValueError) as exc:
            raise RunnerError("JiuwenBox transport failure", endpoint=path) from exc
        finally:
            connection.close()

    def execute(self, sid, command, timeout=60, workdir="/workspace"):
        return self.call(
            "POST",
            f"/api/v1/sandboxes/{sid}/exec",
            {
                "command": command,
                "workdir": workdir,
                "timeout_seconds": timeout,
            },
            timeout=timeout + 20,
        )
