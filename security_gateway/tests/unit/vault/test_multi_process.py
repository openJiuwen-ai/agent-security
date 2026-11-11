"""The local multi-process model, on the Python side.

The Go counterpart is ``pkg/vault/multi_process_test.go`` and
``pkg/vault/takeover_test.go``.  Those are the specification of the
behaviour; this file is the same behaviour, expressed in Python.

The model in one paragraph: the key metadata row belongs to the *database*,
not to a process, so the generation of a record is a fact about the store
rather than about whoever wrote it.  Several processes may open the same
store at once; each holds its own key snapshot, and the store's write path
reads the generation back inside the write transaction, so a writer always
stamps a record with the generation that is authoritative at that moment.

The rules these tests pin down:

  - A writer follows the pending marker: while a rotation is in flight the
    records land on the generation the rotation is about to commit, so the
    writes of the other processes cannot starve the rotation.
  - Opening a store does not take a pending rotation away from the process
    that claimed it.
  - A reader picks up the generation it does not hold yet, on demand.
  - A takeover adopts the generation a dead rotation left behind — it never
    mints a second key under the same generation — and only one process can
    commit it.
"""

from __future__ import annotations

import importlib.util
import os
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from security_gateway.vault import rotate
from security_gateway.vault.errors import (
    NotFoundError,
    RotationInProgressError,
    StaleGenerationError,
)
from security_gateway.vault.store import count_stragglers, get_record

#: The helper the cross-process test starts as a child.
#:
#: It is loaded by path rather than imported by name: the tests directory is
#: a package, and a module that is not part of it would not be importable
#: under the package's name.
_HELPER_PATH = Path(__file__).with_name("_mp_helper.py")

#: The source tree, so that a child process can import the package.
_SRC = Path(__file__).resolve().parents[3] / "src"

_spec = importlib.util.spec_from_file_location("_mp_helper", _HELPER_PATH)
assert _spec is not None and _spec.loader is not None
helper = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(helper)


# -- the fixtures ------------------------------------------------------------


@pytest.fixture
def stores(tmp_path):
    """A store's directory, and a way to open more stores on it.

    Two calls are two processes as far as the vault is concerned: each holds
    its own key snapshot, and both talk to the same database file.
    """
    directory = str(tmp_path / "vault")
    opened = []

    def open_one():
        vault = helper.open_store(directory)
        opened.append(vault)
        return vault

    yield directory, open_one

    for vault in opened:
        try:
            vault.close()
        except Exception:  # noqa: BLE001 - the test already failed
            pass


@pytest.fixture
def short_jitter(monkeypatch):
    """Shorten the stagger the takeover waits before it looks again.

    The wait is there to keep several processes from starting at once; the
    tests are about the outcome, not about how long the processes take to
    notice.
    """
    monkeypatch.setattr(rotate, "PENDING_LEASE_JITTER_SECONDS", 0.02)


def age_lease(vault, seconds: float) -> None:
    """Backdate the lease so that it looks stale.

    The lease is the store's own ``updated_at`` timestamp.  Backdating it is
    what a rotation that died leaves behind: the claim wrote the timestamp
    and nothing has refreshed it since.
    """
    vault.db.execute(
        "UPDATE vault_key_metadata SET updated_at = ? WHERE id = 1",
        (int(time.time() - seconds),),
    )


def require_secret(vault, record_id: str, want: str) -> None:
    """Read a record back and check its encrypted field."""
    rec = vault.get(record_id)
    got = rec.get_string("api_key")
    assert got == want, f"the api_key field of {record_id!r} is {got!r}, want {want!r}"


# -- the multi-process model ------------------------------------------------


def test_write_during_pending_uses_pending_generation(stores):
    """A write from another process during a rotation lands on the pending one.

    The pending generation is the one the rotator is about to commit.  A
    record written under the old active generation is a straggler, and a
    straggler keeps the rotation from ever committing.
    """
    _directory, open_one = stores
    a = open_one()
    b = open_one()

    target = helper.claim_pending(a)

    b.put(helper.multi_process_record("rec-1", "https://a.example.com", "secret-1"))

    row = get_record(b.db, "rec-1")
    assert row is not None, "the record B wrote is not in the database"
    assert row.dek_version == target, (
        f"the record is stamped with generation {row.dek_version}, "
        f"want the pending generation {target}"
    )

    # B holds the key it wrote with ...
    require_secret(b, "rec-1", "secret-1")
    # ... and A, whose snapshot predates the claim, has to pick it up.
    require_secret(a, "rec-1", "secret-1")


def test_open_during_pending_does_not_steal_it(stores):
    """Opening a store does not promote a pending rotation another process runs.

    The key metadata row belongs to the database, not to a process, so
    promoting the pending generation at open time takes the rotation away
    from the process that claimed it — and leaves two generations with a DEK
    each.
    """
    _directory, open_one = stores
    a = open_one()

    active_before = helper.key_meta(a).active_dek_version
    target = helper.claim_pending(a)

    # A second process opens the same store while the rotation is in flight.
    open_one()

    km = helper.key_meta(a)
    assert km.pending_dek_version == target, (
        f"the pending generation is {km.pending_dek_version}, want the claimed "
        f"generation {target}: opening the store took the rotation away"
    )
    assert km.active_dek_version == active_before, (
        f"the active generation is {km.active_dek_version}, want the unchanged "
        f"{active_before}: opening the store promoted the pending rotation"
    )


def test_write_during_pending_does_not_strand_the_rotation(stores):
    """A write from another process during a rotation leaves no record behind.

    A record under the old generation is counted as a straggler by the
    rotation, over and over, so the rotation can never commit.
    """
    _directory, open_one = stores
    a = open_one()
    b = open_one()

    target = helper.claim_pending(a)

    b.put(helper.multi_process_record("rec-1", "https://a.example.com", "secret-1"))

    n = count_stragglers(a.db, target)
    assert n == 0, (
        f"{n} records are still under the generation before the pending one, "
        "so the rotation can never commit"
    )


def test_read_after_another_process_rotated(stores):
    """A process whose snapshot predates a rotation can still read its records.

    The rotation itself is the single-process path and needs nothing
    special: the store is only asked to hold two generations at once.
    """
    _directory, open_one = stores
    a = open_one()
    b = open_one()

    # A record from before the rotation.
    a.put(helper.multi_process_record("old", "https://old.example.com", "secret-old"))

    # The rotation is not gated on the rotation period — only the schedule
    # is — so nothing has to be marked due here.
    rotate.rotate_dek(a)

    # And one from after it.
    a.put(helper.multi_process_record("new", "https://new.example.com", "secret-new"))

    want = {"old": "secret-old", "new": "secret-new"}
    for record_id, expected in want.items():
        row = get_record(a.db, record_id)
        assert row is not None, f"the record {record_id!r} is not in the database"
        try:
            rec = b.get(record_id)
        except Exception as exc:  # noqa: BLE001 - the message names the record
            pytest.fail(
                f"B cannot read {record_id!r} (generation {row.dek_version}): {exc}"
            )
        got = rec.get_string("api_key")
        assert got == expected, (
            f"the api_key field of {record_id!r} is {got!r}, want {expected!r}"
        )


def test_the_status_reports_the_store_generation(stores):
    """A process that did not rotate still reports the store's generation.

    The status is the database's point of view, not this process's private
    snapshot.  A snapshot that fell behind another process's rotation must
    not make the status report a generation the store has already left
    behind — and the straggler count, which is measured against that
    number, must not be measured against it either: a record still under
    the committed generation is a straggler, and counting it against the
    older one hides it.
    """
    directory, open_one = stores
    a = open_one()
    b = open_one()

    before = b.status()

    # A record from before the rotation, so the rotation has something to
    # re-encrypt.
    a.put(helper.multi_process_record("old", "https://old.example.com", "secret-old"))

    rotate.rotate_dek(a)

    after = b.status()
    want = before.dek_version + 1
    assert after.dek_version == want, (
        f"B reports generation {after.dek_version} after A rotated to {want}; "
        "B's snapshot is behind and it reported its own instead of the store's"
    )
    assert after.straggler_count == 0, (
        f"B reports {after.straggler_count} stragglers after the rotation finished"
    )


def test_rotate_behind_another_process(stores):
    """A process whose snapshot fell behind another process's rotation can rotate.

    The rotation opens each record with the key for its generation. A
    process that has not seen the other process's rotation does not hold
    that generation, so the re-encryption reloads the key metadata and
    looks again, the way the read path does.
    """
    _directory, open_one = stores
    a = open_one()
    b = open_one()

    a.put(helper.multi_process_record("rec-1", "https://a.example.com", "secret-1"))

    rotate.rotate_dek(a)

    # B's snapshot still holds the generation from before A's rotation.
    rotate.rotate_dek(b)

    km = helper.key_meta(a)
    assert km.active_dek_version == 3, (
        f"the store is on generation {km.active_dek_version}, want 3: the two "
        "rotations did not both land"
    )
    assert km.pending_dek_version == 0, (
        f"the store still has a pending rotation to generation {km.pending_dek_version}"
    )
    n = count_stragglers(a.db, km.active_dek_version)
    assert n == 0, f"{n} records are still under an older generation"
    require_secret(a, "rec-1", "secret-1")
    require_secret(b, "rec-1", "secret-1")


def test_the_converge_write_waits_out_a_busy_store(stores):
    """The re-encryption's write waits out a store that is busy.

    The write lock belongs to whoever holds it at that moment, and a rotation
    gives up its turn like anybody else.  A rotation that failed on a busy
    lock would leave the store in the pending state until the lease expires
    and somebody takes the rotation over — a much worse outcome than waiting.
    """
    directory, open_one = stores
    v = open_one()

    v.put(helper.multi_process_record("rec-1", "https://a.example.com", "secret-1"))
    target = helper.claim_pending(v)
    # The claimed generation is in the store; the snapshot has to see it.
    v.reload_snapshot()
    pending = v.keys.pend()
    assert pending is not None and pending.version == target

    # Another connection takes the write lock and holds it for longer than
    # the database's own busy timeout — so the first attempt times out.
    locker = sqlite3.connect(
        str(Path(directory) / "vault.db"),
        timeout=5.0,
        isolation_level=None,
        check_same_thread=False,
    )
    locker.execute("PRAGMA busy_timeout=5000")
    locker.execute("BEGIN IMMEDIATE")

    released = threading.Event()

    def release() -> None:
        time.sleep(6)
        locker.execute("ROLLBACK")
        locker.close()
        released.set()

    threading.Thread(target=release, daemon=True).start()

    rotate.converge_to(v, pending)
    released.wait(30)

    row = get_record(v.db, "rec-1")
    assert row is not None, "the record is not in the database"
    assert row.dek_version == target, (
        f"the record is under generation {row.dek_version}, want {target}"
    )
    require_secret(v, "rec-1", "secret-1")


def test_delete_is_visible_immediately(stores):
    """A delete by one process is visible to another one at once.

    The vault keeps no record cache, so a delete is a delete for everybody.
    """
    _directory, open_one = stores
    a = open_one()
    b = open_one()

    a.put(helper.multi_process_record("rec-1", "https://a.example.com", "secret-1"))
    require_secret(b, "rec-1", "secret-1")

    a.delete("rec-1")

    with pytest.raises(NotFoundError):
        b.get("rec-1")


def test_rotation_under_concurrent_writes_leaves_no_straggler(stores):
    """A rotation survives a writer in another process.

    The writer stamps its records with the generation that is current when
    it writes them.  A record under the old generation is a straggler, and a
    straggler keeps the rotation from committing — the writer starves it.

    The writer keeps going until the rotation has returned, and for at least
    a few records either way, so the rotation really does have to cope with
    a live writer rather than with an empty store.
    """
    _directory, open_one = stores
    a = open_one()
    b = open_one()

    max_records = 200
    min_records = 20
    write_delay = 0.001

    rotation_done = threading.Event()
    rot_error: list[BaseException] = []
    write_error: list[BaseException] = []
    written: list[str] = []

    def do_rotate() -> None:
        try:
            rotate.rotate_dek(a)
        except BaseException as exc:  # noqa: BLE001 - reported below
            rot_error.append(exc)
        finally:
            rotation_done.set()

    def do_write() -> None:
        for i in range(max_records):
            record_id = f"rec-{i:03d}"
            try:
                b.put(
                    helper.multi_process_record(
                        record_id, "https://b.example.com", "secret-" + record_id
                    )
                )
            except BaseException as exc:  # noqa: BLE001 - reported below
                write_error.append(exc)
                return
            written.append(record_id)
            if len(written) >= min_records and rotation_done.is_set():
                return
            time.sleep(write_delay)

    rotator = threading.Thread(target=do_rotate, name="rotator")
    writer = threading.Thread(target=do_write, name="writer")
    rotator.start()
    writer.start()
    rotator.join(timeout=120)
    writer.join(timeout=120)

    assert not write_error, (
        f"B could not write while the rotation was running: {write_error[0]}"
    )
    assert written, "B wrote no records at all, so the rotation never met a writer"

    if rot_error:
        assert "did not converge" not in str(rot_error[0]), (
            f"the rotation did not converge while another process was writing: "
            f"{rot_error[0]}"
        )
        pytest.fail(
            f"the rotation failed while another process was writing: {rot_error[0]}"
        )

    # The generation the rotation was aiming at: the active one once it has
    # committed, the pending one while it is still in flight.
    km = helper.key_meta(a)
    target = km.active_dek_version
    if km.pending_dek_version != 0:
        target = km.pending_dek_version
    n = count_stragglers(a.db, target)
    assert n == 0, (
        f"{n} records are still under the generation before {target}, so the "
        "rotation left the store stranded"
    )

    # Everything the other process wrote has to be readable by the process
    # that rotated.
    for record_id in written:
        require_secret(a, record_id, "secret-" + record_id)


# -- the takeover ------------------------------------------------------------


def test_takeover_finishes_an_unfinished_rotation(stores, short_jitter):
    """A takeover adopts the pending generation and commits it.

    The record written while the rotation was in flight is the proof that
    the adopter used the key the dead rotation had put in the store: a
    takeover that minted a second key under the same generation would leave
    that record unreadable.
    """
    _directory, open_one = stores
    a = open_one()
    b = open_one()

    target = helper.claim_pending(a)

    # A record written while the rotation was in flight. It is under the
    # pending generation.
    b.put(helper.multi_process_record("rec-1", "https://b.example.com", "secret-1"))
    row = get_record(b.db, "rec-1")
    assert row is not None
    assert row.dek_version == target

    # The rotation died: nobody has refreshed the lease.
    age_lease(a, rotate.PENDING_LEASE_SECONDS + 1)

    b.takeover_pending()

    km = helper.key_meta(b)
    assert km.pending_dek_version == 0, (
        f"the pending generation is {km.pending_dek_version}, want 0: the "
        "takeover did not commit"
    )
    assert km.active_dek_version == target, (
        f"the active generation is {km.active_dek_version}, want the adopted "
        f"generation {target}"
    )
    assert km.superseded_dek_version == target - 1, (
        f"the superseded generation is {km.superseded_dek_version}, want {target - 1}"
    )

    # The record written under the pending generation is still readable, by
    # the process that took over and by the one whose rotation it was.
    require_secret(b, "rec-1", "secret-1")
    require_secret(a, "rec-1", "secret-1")


def test_takeover_declines_while_the_rotation_is_alive(stores):
    """A takeover does not steal a rotation that is still running.

    The lease is what says "still running": the rotation refreshes it while
    it works, so a fresh lease means somebody is on it.
    """
    _directory, open_one = stores
    a = open_one()
    b = open_one()

    target = helper.claim_pending(a)
    active_before = helper.key_meta(a).active_dek_version

    with pytest.raises(RotationInProgressError):
        b.takeover_pending()

    km = helper.key_meta(b)
    assert km.pending_dek_version == target, (
        f"the pending generation is {km.pending_dek_version}, want the untouched {target}"
    )
    assert km.active_dek_version == active_before, (
        f"the active generation is {km.active_dek_version}, want the unchanged {active_before}"
    )


def test_two_processes_take_over_the_same_pending_rotation(stores, short_jitter):
    """Two processes noticing the same stale lease do not both finish it.

    The compare-and-swap on the pending generation is what decides it: one
    of them commits and the other finds nothing left to do.  Neither may
    leave the store half-rotated.
    """
    _directory, open_one = stores
    a = open_one()
    b = open_one()
    c = open_one()

    target = helper.claim_pending(a)
    b.put(helper.multi_process_record("rec-1", "https://b.example.com", "secret-1"))
    age_lease(a, rotate.PENDING_LEASE_SECONDS + 1)

    errors: list[BaseException] = []

    def take_over(vault) -> None:
        try:
            vault.takeover_pending()
        except BaseException as exc:  # noqa: BLE001 - reported below
            errors.append(exc)

    takers = [threading.Thread(target=take_over, args=(v,)) for v in (b, c)]
    for thread in takers:
        thread.start()
    for thread in takers:
        thread.join(timeout=60)

    # Both may report success: the loser of the compare-and-swap finds the
    # rotation already finished, which is not a failure.  What must not
    # happen is a rotation that was finished twice.
    for exc in errors:
        assert isinstance(exc, RotationInProgressError), (
            f"the takeover failed with {exc}"
        )

    km = helper.key_meta(a)
    assert km.pending_dek_version == 0, (
        f"the pending generation is {km.pending_dek_version}, want 0"
    )
    assert km.active_dek_version == target, (
        f"the active generation is {km.active_dek_version}, want {target}"
    )

    # The record is readable by everyone: one key under that generation,
    # whichever process won the race.
    require_secret(a, "rec-1", "secret-1")
    require_secret(b, "rec-1", "secret-1")
    require_secret(c, "rec-1", "secret-1")


def test_takeover_on_a_clean_store_does_nothing(stores):
    """A takeover of a store with no pending rotation is a no-op."""
    _directory, open_one = stores
    a = open_one()

    before = helper.key_meta(a)
    a.takeover_pending()
    after = helper.key_meta(a)
    assert after.active_dek_version == before.active_dek_version, (
        f"the active generation moved from {before.active_dek_version} to {after.active_dek_version}"
    )
    assert after.pending_dek_version == before.pending_dek_version, (
        f"the pending generation moved from {before.pending_dek_version} "
        f"to {after.pending_dek_version}"
    )


def test_claiming_a_rotation_against_a_moved_generation_fails(stores):
    """A rotation cannot claim a generation that has already moved.

    Two rotations that both saw generation v1 would both mint a key for v2 —
    two data keys under one generation, and records neither could open.  The
    claim therefore tests the generation it read as well as the pending
    marker, and a rotation whose generation moved underneath it starts over.
    """
    _directory, open_one = stores
    v = open_one()

    stale = helper.key_meta(v).active_dek_version

    # Another rotation finishes, and the generation moves.
    rotate.rotate_dek(v)
    moved = helper.key_meta(v).active_dek_version
    assert moved != stale, "the rotation did not move the generation"

    # A rotation that still holds the old generation cannot claim.
    wrapped = helper.mint_wrapped_dek(v)
    claimed = rotate._claim_rotation(v, stale + 1, wrapped, stale)
    assert not claimed, (
        f"the claim landed against the generation {stale}, but the store is on {moved}"
    )

    km = helper.key_meta(v)
    assert km.pending_dek_version == 0, (
        f"the pending generation is {km.pending_dek_version}, want 0: the claim landed"
    )
    assert km.active_dek_version == moved, (
        f"the active generation is {km.active_dek_version}, want the unchanged {moved}"
    )


# -- the rotation's failure taxonomy -----------------------------------------


def test_losing_the_claim_to_a_finished_rotation_starts_a_new_round(stores):
    """A rotation that loses the claim to a finished rotation starts a new round.

    The claim is a compare-and-swap on the generation the rotation read, so it
    loses to any rotation that commits first.  Losing the claim is only a
    failure while that other rotation is still running.  Once it has finished,
    nothing is pending, the claim is free again, and this rotation rotates
    the store once more — every request for a rotation buys one rotation.
    """
    _directory, open_one = stores
    a = open_one()
    b = open_one()

    # The other rotation finishes in the window between the second process's
    # read of the key metadata and its claim.
    fired = []

    def hook() -> None:
        if fired:
            return
        fired.append(True)
        rotate.rotate_dek(a)

    rotate.set_rotate_before_claim_hook(hook)
    try:
        rotate.rotate_dek(b)
    finally:
        rotate.set_rotate_before_claim_hook(None)

    # Two rotations, two generations: the first one committed v2, and the
    # second one started a new round on top of it and committed v3.
    km = helper.key_meta(a)
    assert km.active_dek_version == 3, (
        f"the store is on generation {km.active_dek_version}, want 3: the second "
        "rotation did not start a new round"
    )
    assert km.pending_dek_version == 0, (
        f"the store still has a pending generation {km.pending_dek_version}"
    )


def test_the_rotation_reports_another_rotation_as_in_progress(stores):
    """A rotation that finds somebody else's claim pending says so.

    This is the one contention a rotation is allowed to fail on: another
    rotation is running, and this one has nothing to add to it.
    """
    _directory, open_one = stores
    v = open_one()

    helper.claim_pending(v)

    with pytest.raises(RotationInProgressError):
        rotate.rotate_dek(v)


# -- across processes --------------------------------------------------------


def test_across_processes(stores):
    """The local authority model with two real processes on one store.

    The claim and the write happen in different processes: the write must
    land on the pending generation, and the rotation must still be able to
    commit afterwards.

    The store has to exist before the children open it: the key material is
    minted by whoever opens it first, and two processes minting at once is a
    different (older) race.
    """
    directory, open_one = stores
    v = open_one()

    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(_SRC), env.get("PYTHONPATH", "")]).strip(
        os.pathsep
    )
    env[helper.ROLE_ENV] = helper.ROLE_CLAIM
    env[helper.DIR_ENV] = directory

    claim = subprocess.Popen(
        [sys.executable, str(_HELPER_PATH)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        helper.wait_for_file(Path(directory) / helper.CLAIMED_FILE)

        env[helper.ROLE_ENV] = helper.ROLE_WRITE
        write = subprocess.run(
            [sys.executable, str(_HELPER_PATH)],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if write.returncode != 0:
            pytest.fail(
                f"the writing process failed: {write.returncode}\n"
                f"{write.stdout}\n{write.stderr}"
            )

        # Let the claiming process finish.
        (Path(directory) / helper.PROCEED_FILE).write_text("1")
        claim.wait(timeout=120)
        if claim.returncode != 0:
            pytest.fail(
                f"the claiming process failed: {claim.returncode}\n"
                f"{claim.stdout.read()}\n{claim.stderr.read()}"
            )
    finally:
        if claim.poll() is None:
            claim.kill()
            claim.wait(timeout=30)

    # The record must be under the pending generation, and the rotation
    # must still be able to commit: nothing may be left under the old
    # generation.
    km = helper.key_meta(v)
    assert km.pending_dek_version != 0, (
        "the pending generation is gone; the claim did not take"
    )

    row = get_record(v.db, "cross-process")
    assert row is not None, "the record the other process wrote is not in the database"
    assert row.dek_version == km.pending_dek_version, (
        f"the record is stamped with generation {row.dek_version}, want the "
        f"pending generation {km.pending_dek_version}"
    )

    n = count_stragglers(v.db, km.pending_dek_version)
    assert n == 0, (
        f"{n} records are still under the generation before the pending one, "
        "so the rotation can never commit"
    )

    # And the record is readable here: the key for the pending generation is
    # in the store, and a process that has not seen the claim has to find it.
    require_secret(v, "cross-process", "secret-x")


def test_several_processes_can_initialize_the_same_new_store(tmp_path):
    """Three real processes open an empty directory at the same time.

    Exactly one has to mint the key; the others must load that key rather
    than create a second shard/metadata pair.
    """
    directory = str(tmp_path / "vault")
    Path(directory).mkdir()
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(_SRC), env.get("PYTHONPATH", "")]).strip(
        os.pathsep
    )
    env[helper.ROLE_ENV] = helper.ROLE_OPEN
    env[helper.DIR_ENV] = directory
    children = [
        subprocess.Popen(
            [sys.executable, str(_HELPER_PATH)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(3)
    ]
    (Path(directory) / helper.GO_FILE).write_text("1")
    for child in children:
        stdout, stderr = child.communicate(timeout=120)
        assert child.returncode == 0, f"{stdout}\n{stderr}"

    vault = helper.open_store(directory)
    try:
        vault.put(
            helper.multi_process_record(
                "after-init", "https://x.example.com", "secret-x"
            )
        )
        assert vault.get("after-init").get_string("api_key") == "secret-x"
    finally:
        vault.close()


def test_every_process_can_trigger_a_rotation(stores):
    """All three processes on the store can rotate, not just the first one.

    The rotation lock is the fleet's, not the process's; a process that
    only reads the store still has the authority handle and must be able
    to start the next generation.
    """
    _directory, open_one = stores
    a = open_one()
    b = open_one()
    c = open_one()

    a.put(helper.multi_process_record("rec-1", "https://a.example.com", "secret-1"))

    for process in (a, b, c):
        rotate.rotate_dek(process)

    km = helper.key_meta(a)
    assert km.active_dek_version == 4, (
        f"the store is on generation {km.active_dek_version}, want 4: three "
        "processes did not each get a rotation"
    )
    assert km.pending_dek_version == 0
    assert count_stragglers(a.db, km.active_dek_version) == 0
    for process in (a, b, c):
        require_secret(process, "rec-1", "secret-1")


def test_a_stale_rotation_refreshes_from_the_fleet_and_tries_again(monkeypatch):
    """A process behind the fleet adopts the current key and rotates.

    The local row can lag the authority when another node rotated.  The
    rotation asks the fleet for what it is missing and retries once; if
    the key cannot be adopted, the stale error is still reported.
    """

    class Target:
        rotate_mu = threading.Lock()

        def __init__(self):
            self.refreshed = 0

        def refresh_from_fleet(self):
            self.refreshed += 1
            return True

    calls = []

    def rotate_once(vault, store, stop=None):
        calls.append(1)
        if len(calls) == 1:
            raise StaleGenerationError("behind")

    target = Target()
    monkeypatch.setattr(rotate, "_rotate_locked", rotate_once)
    rotate.rotate_dek(target)

    assert len(calls) == 2, "the rotation did not retry after refreshing"
    assert target.refreshed == 1

    calls.clear()
    target.refreshed = 0
    monkeypatch.setattr(
        rotate,
        "_rotate_locked",
        lambda vault, store, stop=None: (_ for _ in ()).throw(
            StaleGenerationError("still behind")
        ),
    )
    target.refresh_from_fleet = lambda: False
    with pytest.raises(StaleGenerationError):
        rotate.rotate_dek(target)
