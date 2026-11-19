"""Concurrent compare-and-swap writers must not lose a committed step.

Every successful writer reads a counter, writes ``counter + 1`` and passes
the value it read as ``expected``.  A lost update would leave the final
counter below the number of successful writes; a conflict must retry, not
overwrite.  The test fuzzes the interleaving with several threads.
"""

from __future__ import annotations

import threading

from security_gateway.vault import (
    Config,
    FieldDef,
    Record,
    Schema,
    Type,
    Value,
    Vault,
)
from security_gateway.vault.errors import ConflictError

ROUNDS = 30
WRITERS = 6


def _schema() -> Schema:
    return Schema(
        version=1,
        fields=[FieldDef(name="counter", type=Type.STRING)],
    )


def _record(value: int) -> Record:
    return Record(id="counter", fields={"counter": Value.new_string(str(value))})


def test_concurrent_cas_writers_do_not_lose_a_committed_step(tmp_path) -> None:
    vault = Vault.open(Config(data_dir=str(tmp_path)), _schema())
    committed: list[int] = []
    lock = threading.Lock()
    start = threading.Barrier(WRITERS)

    def writer() -> None:
        start.wait()
        done = 0
        while done < ROUNDS:
            current = int(vault.get("counter").fields["counter"].as_string())
            try:
                vault.put(
                    _record(current + 1),
                    expected={"counter": Value.new_string(str(current))},
                )
            except ConflictError:
                continue
            with lock:
                committed.append(current + 1)
            done += 1

    try:
        vault.put(_record(0))
        threads = [threading.Thread(target=writer) for _ in range(WRITERS)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        final = int(vault.get("counter").fields["counter"].as_string())
    finally:
        vault.close()

    assert len(committed) == WRITERS * ROUNDS
    assert final == len(committed)
    assert sorted(committed) == list(range(1, len(committed) + 1))
