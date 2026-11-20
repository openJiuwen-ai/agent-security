"""Delete-path coverage for the jiuwenbox HTTP API.

Relies only on the fixtures already provided by ``tests/system_tests/conftest.py``
(``client``, ``wait_for_sandbox_ready``, ``exec_command``).

Run (from inside the container that hosts the service):

    pytest tests/system_tests/test_delete_semantics.py \
        --server-endpoint http://127.0.0.1:8321

What the delete path actually does
----------------------------------
``DELETE /api/v1/sandboxes/{id}`` -> ``SandboxManager.delete_sandbox`` ->
``ProcessRuntime.cleanup``, which

1. sends a ``shutdown`` frame over the sandbox's control socket and waits for
   the ``shutdown_ack``,
2. waits up to ``DAEMON_SHUTDOWN_TIMEOUT_SECONDS`` (3 s) for in-flight IPC to
   drain,
3. escalates to SIGTERM, then SIGKILL (10 s),
4. tears down the netns, iptables rules, cgroup and workspace directories,
5. drops the manager entry and returns 204.

These tests pin the externally visible parts of that contract: idempotence,
concurrency, in-flight exec behaviour and host-side cleanup. They deliberately
avoid wall-clock assertions that would be flaky on a loaded CI machine, except
where the 3 s drain budget is the behaviour under test.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest

pytestmark = pytest.mark.system

# Delete should finish well inside drain budget + SIGTERM grace when the exec
# it is waiting on is already long past the budget.
LONG_EXEC_DELETE_BOUND_SECONDS = 8.0

SANDBOXES_PATH = "/api/v1/sandboxes"

# How long to wait for netns/bwrap teardown to converge after the last delete.
# Teardown itself is synchronous inside ``cleanup``, but the kernel can still be
# releasing the last process when the HTTP response returns.
RESOURCE_SETTLE_SECONDS = 5.0

# Endpoint status codes used by the delete contract. Spelled out so a future
# change in the API surface trips a name error rather than silently asserting
# the wrong number.
HTTP_OK_CREATED = 201
HTTP_OK_NO_CONTENT = 204
HTTP_NOT_FOUND = 404


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _create_ready(client, wait_for_sandbox_ready, prefix: str = "deltest") -> str:
    sandbox_id = _new_id(prefix)
    resp = client.post(SANDBOXES_PATH, json={"sandbox_id": sandbox_id})
    assert resp.status_code == HTTP_OK_CREATED, resp.text
    wait_for_sandbox_ready(sandbox_id)
    return sandbox_id


def _sh(cmd: str) -> str:
    """Run a shell command and return its stdout.

    ``sh`` is resolved to an absolute path before use: relying on ``PATH`` to
    find an interpreter lets a different binary shadow it (G.EDV.05).
    """
    shell = shutil.which("sh") or "/bin/sh"
    return subprocess.run(
        [shell, "-c", cmd],
        capture_output=True,
        text=True,
        check=False,
    ).stdout


def _host_snapshot() -> dict[str, int]:
    """Count the host artefacts the process runtime allocates per sandbox.

    Nothing is pre-allocated: every sandbox gets its own netns, bwrap process
    and iptables rules at create time and must release them at delete time.
    Only the delta across a create/delete batch matters, so a non-empty
    baseline from other sandboxes does not matter - but the delta must return
    to zero.

    Every sandbox netns is named ``jbx-<sandbox_id>`` (see
    ``network.NETNS_NAME_PREFIX``), so the filter must cover that whole prefix
    rather than a single id prefix - narrowing it would hide user sandboxes and
    make the leak assertion pass unconditionally.
    """
    workspace = _sh(f"ls -1 {_workspace_root()} 2>/dev/null").split()
    return {
        "netns": len([n for n in _sh("ip netns list").splitlines() if "jbx-" in n]),
        "bwrap": len(_sh("pgrep -a bwrap").splitlines()),
        "iptables_nat_rules": len(
            [ln for ln in _sh("iptables -t nat -S 2>/dev/null").splitlines() if "jwb" in ln]
        ),
        "workspace_dirs": len(workspace),
    }


def _workspace_root() -> str:
    """Resolve the sandbox workspace dir without assuming the service runs as root."""
    home = os.environ.get("HOME") or os.path.expanduser("~")
    return os.path.join(home, ".jiuwenbox", "workspace")


def _wait_for_baseline(baseline: dict[str, int]) -> dict[str, int]:
    """Poll the host snapshot until it matches *baseline*, or the budget runs out.

    Returns the last snapshot taken, so the caller can report the actual delta
    in the assertion message.
    """
    deadline = time.monotonic() + RESOURCE_SETTLE_SECONDS
    snapshot = _host_snapshot()
    while time.monotonic() < deadline:
        if all(snapshot[key] <= baseline[key] for key in baseline):
            return snapshot
        time.sleep(0.1)
        snapshot = _host_snapshot()
    return snapshot


def _can_inspect_host() -> bool:
    if shutil.which("ip") is None or shutil.which("iptables") is None:
        return False
    netns = _sh("ip netns list")
    # Empty output is legitimate (no netns yet); an error message is not.
    return "Operation not permitted" not in netns and "not found" not in netns


class TestDeleteIdempotence:
    """DELETE must be safe to retry, including concurrently."""

    @staticmethod
    def test_delete_is_idempotent(client, wait_for_sandbox_ready):
        """First DELETE 204, second DELETE 404, GET 404.

        ``delete_sandbox`` pops the manager entry, so a retry after a
        client-side timeout must look "already gone" rather than 500.
        """
        sandbox_id = _create_ready(client, wait_for_sandbox_ready)

        first = client.delete(f"{SANDBOXES_PATH}/{sandbox_id}")
        assert first.status_code == HTTP_OK_NO_CONTENT, first.text

        second = client.delete(f"{SANDBOXES_PATH}/{sandbox_id}")
        assert second.status_code == HTTP_NOT_FOUND, second.text
        assert client.get(f"{SANDBOXES_PATH}/{sandbox_id}").status_code == HTTP_NOT_FOUND

    @staticmethod
    def test_delete_unknown_id_returns_404(client):
        resp = client.delete(f"{SANDBOXES_PATH}/{_new_id('missing')}")
        assert resp.status_code == HTTP_NOT_FOUND, resp.text

    @staticmethod
    def test_concurrent_duplicate_delete_does_not_error(
        client,
        wait_for_sandbox_ready,
    ):
        """Two simultaneous DELETEs for one id must not 500.

        Both requests can win the race into ``cleanup``; ``stop`` and the
        teardown helpers are individually idempotent, so the acceptable
        surface is 204/204 or 204/404, never 5xx, and the sandbox must be gone.
        """
        sandbox_id = _create_ready(client, wait_for_sandbox_ready)

        codes: list[int] = [0, 0]

        def _delete(idx: int) -> None:
            codes[idx] = client.delete(
                f"{SANDBOXES_PATH}/{sandbox_id}",
            ).status_code

        threads = [threading.Thread(target=_delete, args=(i,)) for i in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(30)

        assert all(code in (204, 404) for code in codes), codes
        assert 204 in codes, codes
        assert client.get(f"{SANDBOXES_PATH}/{sandbox_id}").status_code == HTTP_NOT_FOUND


class TestDeleteDuringLifecycle:
    """DELETE while the sandbox is not (yet) READY."""

    @staticmethod
    def test_delete_while_provisioning(client):
        """Deleting a just-created sandbox must not deadlock or 500."""
        sandbox_id = _new_id("prov")
        resp = client.post(SANDBOXES_PATH, json={"sandbox_id": sandbox_id})
        assert resp.status_code == HTTP_OK_CREATED, resp.text

        delete = client.delete(f"{SANDBOXES_PATH}/{sandbox_id}")
        assert delete.status_code == HTTP_OK_NO_CONTENT, delete.text
        assert client.get(f"{SANDBOXES_PATH}/{sandbox_id}").status_code == HTTP_NOT_FOUND

    @staticmethod
    def test_delete_stopped_sandbox(client, wait_for_sandbox_ready):
        sandbox_id = _create_ready(client, wait_for_sandbox_ready)
        stop = client.post(f"{SANDBOXES_PATH}/{sandbox_id}/stop")
        assert stop.status_code == 200, stop.text

        delete = client.delete(f"{SANDBOXES_PATH}/{sandbox_id}")
        assert delete.status_code == HTTP_OK_NO_CONTENT, delete.text
        assert client.get(f"{SANDBOXES_PATH}/{sandbox_id}").status_code == HTTP_NOT_FOUND


class TestConcurrentDelete:
    """Deleting many sandboxes at once."""

    @staticmethod
    def test_parallel_delete_all_succeed(client, wait_for_sandbox_ready):
        """N parallel deletes: every one 204, every id gone, none left listed.

        Each sandbox has its own daemon, so this exercises N shutdown
        handshakes at once. No wall-clock assertion here - that would be
        flaky on a shared machine; ``perf/`` in the benchmark bundle has the
        measured numbers.
        """
        sandbox_ids = [
            _create_ready(client, wait_for_sandbox_ready, "par")
            for _ in range(4)
        ]

        def _delete(sandbox_id: str) -> int:
            return client.delete(f"{SANDBOXES_PATH}/{sandbox_id}").status_code

        with ThreadPoolExecutor(max_workers=len(sandbox_ids)) as pool:
            statuses = list(pool.map(_delete, sandbox_ids))

        assert statuses == [HTTP_OK_NO_CONTENT] * len(sandbox_ids), statuses
        for sandbox_id in sandbox_ids:
            assert client.get(f"{SANDBOXES_PATH}/{sandbox_id}").status_code == HTTP_NOT_FOUND
        # Only this test's ids must be gone; other tests or users may share the
        # server, so a global "list is empty" assertion would be a false signal.
        listed = {item.get("id") for item in client.get(SANDBOXES_PATH).json()}
        assert not (listed & set(sandbox_ids)), listed & set(sandbox_ids)


class TestDeleteWithInFlightExec:
    """What a caller sees when an exec is running during delete.

    The daemon drains in-flight IPC for up to 3 s, then the runtime escalates
    to SIGTERM/SIGKILL. Both outcomes are tested: a short exec completes
    normally, a long one is cut off.
    """

    @staticmethod
    def test_short_exec_survives_delete(
        client,
        wait_for_sandbox_ready,
        exec_command,
    ):
        """An exec shorter than the drain budget finishes before deletion.

        ``delete`` blocks until the handler returns, so the caller must still
        get a normal 200/exit_code 0 response.
        """
        sandbox_id = _create_ready(client, wait_for_sandbox_ready, "drain")

        result: dict[str, object] = {}

        def _exec() -> None:
            resp = exec_command(sandbox_id, ["sleep", "1"], timeout_seconds=10)
            result["status"] = resp.status_code
            result["body"] = resp.json()

        thread = threading.Thread(target=_exec)
        thread.start()
        time.sleep(0.2)  # let the request reach the daemon

        delete = client.delete(f"{SANDBOXES_PATH}/{sandbox_id}")
        thread.join(30)

        assert delete.status_code == HTTP_OK_NO_CONTENT, delete.text
        assert result["status"] == 200, result
        assert result["body"]["exit_code"] == 0, result
        assert client.get(f"{SANDBOXES_PATH}/{sandbox_id}").status_code == HTTP_NOT_FOUND

    @staticmethod
    def test_long_exec_is_cut_off_by_delete(
        client,
        wait_for_sandbox_ready,
        exec_command,
    ):
        """An exec longer than the drain budget is interrupted, not awaited.

        DELETE must return in bounded time (drain budget + SIGTERM grace),
        the sandbox must be gone, and the exec must not report success - the
        transport is closed underneath it.
        """
        sandbox_id = _create_ready(client, wait_for_sandbox_ready, "cut")

        result: dict[str, object] = {}

        def _exec() -> None:
            resp = exec_command(sandbox_id, ["sleep", "20"], timeout_seconds=30)
            result["status"] = resp.status_code
            result["body"] = resp.json()

        thread = threading.Thread(target=_exec)
        thread.start()
        time.sleep(0.3)

        started = time.monotonic()
        delete = client.delete(f"{SANDBOXES_PATH}/{sandbox_id}")
        elapsed = time.monotonic() - started
        thread.join(30)

        assert delete.status_code == HTTP_OK_NO_CONTENT, delete.text
        assert elapsed < LONG_EXEC_DELETE_BOUND_SECONDS, elapsed
        assert result["status"] == 200, result
        assert result["body"]["exit_code"] != 0, result
        assert "socket" in (result["body"].get("stderr") or "").lower(), result
        assert client.get(f"{SANDBOXES_PATH}/{sandbox_id}").status_code == HTTP_NOT_FOUND


class TestDeleteReleasesHostResources:
    """No netns / bwrap / iptables / workspace leftovers after a batch."""

    @staticmethod
    @pytest.mark.skipif(
        not _can_inspect_host(),
        reason="needs ip/iptables and visibility into the sandbox host namespaces",
    )
    def test_batch_create_delete_returns_to_baseline(
        client,
        wait_for_sandbox_ready,
    ):
        baseline = _host_snapshot()

        sandbox_ids = [
            _create_ready(client, wait_for_sandbox_ready, "clean")
            for _ in range(5)
        ]
        for sandbox_id in sandbox_ids:
            assert client.delete(f"{SANDBOXES_PATH}/{sandbox_id}").status_code == HTTP_OK_NO_CONTENT

        # Teardown of the last netns/bwrap pair can trail the HTTP response by
        # a few milliseconds, so wait for convergence instead of sleeping a
        # fixed amount and risking a flake on a loaded machine.
        final = _wait_for_baseline(baseline)
        delta = {key: final[key] - baseline[key] for key in baseline}
        # Nothing is pre-allocated or pooled, so every artefact must be gone.
        assert all(value == 0 for value in delta.values()), delta
