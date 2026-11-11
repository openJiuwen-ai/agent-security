"""The credential CRUD over the etcd seam, and its compare-and-swap paths.

The Go original is ``internal/credmgr/etcdstore/store.go`` and
``internal/credmgr/etcdstore/records.go``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from security_gateway.vault.etcdstore.entry import (
    Entry,
    RecordEntry,
    Timestamp,
    marshal_entry,
    marshal_record,
    unmarshal_entry,
)
from security_gateway.vault.etcdstore.errors import ConflictError, NotFoundError
from security_gateway.vault.etcdstore.keys import cred_key, record_key
from security_gateway.vault.etcdstore.store import (
    Compare,
    PutOp,
    Store,
    compare_create,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from conftest import FakeKV


def _entry(**kw: object) -> Entry:
    base = dict(
        api_key_cipher=b"cipher",
        auth_type="openai",
        user_id="acct-1",
        api_base="https://api.example.test/v1",
        key_tag="primary",
        dek_version=1,
        mod_revision=0,
        created_at=Timestamp("2026-01-01T00:00:00Z"),
        updated_at=Timestamp("2026-01-01T00:00:00Z"),
    )
    base.update(kw)
    return Entry(**base)  # type: ignore[arg-type]


# -- reading ---------------------------------------------------------------


def test_get_entry_returns_the_entry_and_the_etcd_revision(
    store: Store, fake_kv: "FakeKV"
) -> None:
    """Test get entry returns the entry and the etcd revision."""
    key = cred_key("prod", "abc123")
    fake_kv.seed(key, marshal_entry(_entry(mod_revision=7)))
    got = store.get_entry("abc123")
    # The revision etcd reports wins over the copy in the payload: the
    # embedded copy is not authoritative.
    assert got.mod_revision == fake_kv.stored_revision(key)
    assert got.user_id == "acct-1"


def test_get_entry_on_an_absent_key_is_not_found(store: Store) -> None:
    """Test get entry on an absent key is not found."""
    with pytest.raises(NotFoundError):
        store.get_entry("missing")


def test_get_entry_rejects_a_value_that_is_not_an_entry(
    store: Store, fake_kv: "FakeKV"
) -> None:
    """Test get entry rejects a value that is not an entry."""
    fake_kv.seed(cred_key("prod", "broken"), b"not json")
    with pytest.raises(Exception):
        store.get_entry("broken")


# -- creating --------------------------------------------------------------


def test_create_entry_writes_the_value(store: Store, fake_kv: "FakeKV") -> None:
    """Test create entry writes the value."""
    created = store.create_entry("abc123", _entry())
    key = cred_key("prod", "abc123")
    assert fake_kv.stored(key) == marshal_entry(_entry())
    assert created.mod_revision == fake_kv.stored_revision(key)
    assert created.mod_revision > 0


def test_create_entry_reports_the_new_revision_in_the_value(
    store: Store, fake_kv: "FakeKV"
) -> None:
    """Test create entry reports the new revision in the value."""
    created = store.create_entry("abc123", _entry())
    key = cred_key("prod", "abc123")
    # The persisted payload carries no revision of its own; the returned
    # entry carries the one etcd assigned.
    assert json.loads(fake_kv.stored(key))["mod_revision"] == 0
    assert created.mod_revision > 0


def test_create_entry_on_an_existing_key_is_a_conflict(
    store: Store, fake_kv: "FakeKV"
) -> None:
    """Test create entry on an existing key is a conflict."""
    key = cred_key("prod", "abc123")
    original = marshal_entry(_entry(user_id="first"))
    fake_kv.seed(key, original)
    with pytest.raises(ConflictError):
        store.create_entry("abc123", _entry(user_id="second"))
    # The value is untouched: a rejected create wrote nothing.
    assert fake_kv.stored(key) == original


def test_the_create_comparison_holds_only_when_the_key_is_absent(
    fake_kv: "FakeKV",
) -> None:
    """Test the create comparison holds only when the key is absent."""
    key = cred_key("prod", "handover")

    # The key is absent: the comparison holds and the write happens.
    result = fake_kv.transaction([compare_create(key)], [PutOp(key, b"first")])
    assert result.succeeded is True
    assert fake_kv.stored(key) == b"first"

    # The key exists: the comparison does not hold, nothing is written,
    # and the caller is told so by the verdict.
    result = fake_kv.transaction([compare_create(key)], [PutOp(key, b"second")])
    assert result.succeeded is False
    assert fake_kv.stored(key) == b"first"


def test_the_create_comparison_holds_again_after_a_delete(fake_kv: "FakeKV") -> None:
    """Test the create comparison holds again after a delete."""
    key = cred_key("prod", "handover")
    fake_kv.seed(key, b"first")
    fake_kv.delete(key)
    result = fake_kv.transaction([compare_create(key)], [PutOp(key, b"second")])
    assert result.succeeded is True
    assert fake_kv.stored(key) == b"second"


def test_a_compare_on_an_absent_key_reads_zero(fake_kv: "FakeKV") -> None:
    """Test a compare on an absent key reads zero."""
    key = cred_key("prod", "nothing")
    result = fake_kv.transaction(
        [Compare(target="create", key=key, op="==", value=0)],
        [PutOp(key, b"written")],
    )
    assert result.succeeded is True


# -- updating --------------------------------------------------------------


def test_update_entry_cas_succeeds_when_the_comparison_holds(
    store: Store, fake_kv: "FakeKV"
) -> None:
    """Test update entry cas succeeds when the comparison holds."""
    key = cred_key("prod", "abc123")
    fake_kv.seed(key, marshal_entry(_entry()))
    current = store.get_entry("abc123")
    updated = store.update_entry_cas(
        "abc123", _entry(user_id="acct-2", mod_revision=current.mod_revision)
    )
    assert updated.mod_revision == fake_kv.stored_revision(key)
    assert unmarshal_entry(fake_kv.stored(key)).user_id == "acct-2"


def test_update_entry_cas_fails_when_the_comparison_does_not_hold(
    store: Store, fake_kv: "FakeKV"
) -> None:
    """Test update entry cas fails when the comparison does not hold."""
    key = cred_key("prod", "abc123")
    fake_kv.seed(key, marshal_entry(_entry(user_id="acct-1")))

    # Somebody else committed between the read and the write.
    current = store.get_entry("abc123")
    fake_kv.seed(key, marshal_entry(_entry(user_id="acct-other")))

    with pytest.raises(ConflictError):
        store.update_entry_cas(
            "abc123", _entry(user_id="acct-2", mod_revision=current.mod_revision)
        )
    # The value is left untouched, and the conflict is reported rather
    # than a silent success.
    assert unmarshal_entry(fake_kv.stored(key)).user_id == "acct-other"


def test_a_rejected_update_does_not_write(store: Store, fake_kv: "FakeKV") -> None:
    """Test a rejected update does not write."""
    key = cred_key("prod", "abc123")
    fake_kv.seed(key, marshal_entry(_entry()))
    before = fake_kv.stored_revision(key)
    with pytest.raises(ConflictError):
        store.update_entry_cas("abc123", _entry(mod_revision=999))
    assert fake_kv.stored_revision(key) == before


def test_update_entry_cas_does_not_touch_the_callers_entry(
    store: Store, fake_kv: "FakeKV"
) -> None:
    """Test update entry cas does not touch the callers entry."""
    fake_kv.seed(cred_key("prod", "abc123"), marshal_entry(_entry()))
    current = store.get_entry("abc123")
    entry = _entry(mod_revision=current.mod_revision)
    store.update_entry_cas("abc123", entry)
    assert entry.mod_revision == current.mod_revision


# -- deleting --------------------------------------------------------------


def test_delete_entry_cas_removes_the_value(store: Store, fake_kv: "FakeKV") -> None:
    """Test delete entry cas removes the value."""
    key = cred_key("prod", "abc123")
    fake_kv.seed(key, marshal_entry(_entry()))
    current = store.get_entry("abc123")
    store.delete_entry_cas("abc123", current.mod_revision)
    assert fake_kv.stored(key) is None


def test_delete_entry_cas_fails_on_a_stale_revision(
    store: Store, fake_kv: "FakeKV"
) -> None:
    """Test delete entry cas fails on a stale revision."""
    key = cred_key("prod", "abc123")
    original = marshal_entry(_entry())
    fake_kv.seed(key, original)
    with pytest.raises(ConflictError):
        store.delete_entry_cas("abc123", 999)
    assert fake_kv.stored(key) == original


def test_delete_entry_cas_on_an_absent_key_is_not_found(store: Store) -> None:
    """Test delete entry cas on an absent key is not found."""
    with pytest.raises(NotFoundError):
        store.delete_entry_cas("missing", 1)


# -- listing ---------------------------------------------------------------


def test_list_entries_returns_the_entries_and_the_revision(
    store: Store, fake_kv: "FakeKV"
) -> None:
    """Test list entries returns the entries and the revision."""
    fake_kv.seed(cred_key("prod", "aaa"), marshal_entry(_entry(user_id="a")))
    fake_kv.seed(cred_key("prod", "bbb"), marshal_entry(_entry(user_id="b")))
    entries, revision = store.list_entries()
    assert [e.proxy_key for e in entries] == ["aaa", "bbb"]
    assert [e.entry.user_id for e in entries] == ["a", "b"]
    assert revision == fake_kv.revision


def test_list_entries_does_not_sweep_in_a_sibling_prefix(
    store: Store, fake_kv: "FakeKV"
) -> None:
    # The trailing slash on the prefix is what keeps
    # "/security_gateway/prod/creds-extra/" out of the same range.
    """Test list entries does not sweep in a sibling prefix."""
    fake_kv.seed(cred_key("prod", "aaa"), marshal_entry(_entry()))
    fake_kv.seed("/security_gateway/prod/creds-extra/zzz", marshal_entry(_entry()))
    fake_kv.seed("/security_gateway/prod/rotation", b"not an entry")
    entries, _ = store.list_entries()
    assert [e.proxy_key for e in entries] == ["aaa"]


def test_list_entries_from_walks_past_the_cursor(
    store: Store, fake_kv: "FakeKV"
) -> None:
    """Test list entries from walks past the cursor."""
    for key in ("aaa", "bbb", "ccc"):
        fake_kv.seed(cred_key("prod", key), marshal_entry(_entry()))
    entries = store.list_entries_from("aaa")
    assert [e.proxy_key for e in entries] == ["bbb", "ccc"]


def test_list_entries_honours_the_limit(store: Store, fake_kv: "FakeKV") -> None:
    """Test list entries honours the limit."""
    for key in ("aaa", "bbb", "ccc"):
        fake_kv.seed(cred_key("prod", key), marshal_entry(_entry()))
    entries, _ = store.list_entries(limit=2)
    assert len(entries) == 2


# -- records ---------------------------------------------------------------


def test_the_record_crud_round_trips(store: Store, fake_kv: "FakeKV") -> None:
    """Test the record crud round trips."""
    record = RecordEntry(data=b"payload", schema_version=1, dek_version=1)
    created = store.create_record("r1", record)
    assert fake_kv.stored(record_key("prod", "r1")) is not None
    got = store.get_record("r1")
    assert got.data == b"payload"
    assert got.mod_revision == created.mod_revision
    store.delete_record_cas("r1", created.mod_revision)
    assert fake_kv.stored(record_key("prod", "r1")) is None


def test_delete_records_cas_deletes_and_reports_missing(
    store: Store, fake_kv: "FakeKV"
) -> None:
    """Existing ids are deleted together; missing ids are reported."""
    store.create_record("r1", RecordEntry(data=b"one"))
    store.create_record("r2", RecordEntry(data=b"two"))
    deleted, missing = store.delete_records_cas(["r1", "nope", "r2"])
    assert deleted == ["r1", "r2"]
    assert missing == ["nope"]
    assert fake_kv.stored(record_key("prod", "r1")) is None
    assert fake_kv.stored(record_key("prod", "r2")) is None


def test_delete_records_cas_is_all_or_nothing(
    store: Store, fake_kv: "FakeKV", monkeypatch: pytest.MonkeyPatch
) -> None:
    """A concurrent update to one record rolls the whole batch back."""
    store.create_record("r1", RecordEntry(data=b"one"))
    store.create_record("r2", RecordEntry(data=b"two"))
    original = fake_kv.transaction

    def racing_transaction(compare, success, failure=()):
        # Simulate another writer landing between our reads and the Txn.
        fake_kv.put(
            record_key("prod", "r2"),
            marshal_record(RecordEntry(data=b"changed", mod_revision=2)),
        )
        return original(compare, success, failure)

    monkeypatch.setattr(fake_kv, "transaction", racing_transaction)
    with pytest.raises(ConflictError):
        store.delete_records_cas(["r1", "r2"])
    assert fake_kv.stored(record_key("prod", "r1")) is not None
    assert fake_kv.stored(record_key("prod", "r2")) is not None


def test_create_record_on_an_existing_id_is_a_conflict(
    store: Store, fake_kv: "FakeKV"
) -> None:
    """Test create record on an existing id is a conflict."""
    store.create_record("r1", RecordEntry(data=b"first"))
    with pytest.raises(ConflictError):
        store.create_record("r1", RecordEntry(data=b"second"))
    assert store.get_record("r1").data == b"first"


# -- the seam ---------------------------------------------------------------


def test_the_fake_satisfies_the_kv_seam(fake_kv: "FakeKV") -> None:
    """Test the fake satisfies the kv seam."""
    from security_gateway.vault.etcdstore.store import KV

    # The seam is what makes the package testable without a server: the
    # fake and the real client are interchangeable behind it.
    assert isinstance(fake_kv, KV)


# -- the optional dependency ----------------------------------------------


def test_the_package_imports_without_etcd3(tmp_path) -> None:
    # The etcd extra is optional and cannot be installed here, so the
    # package must import cleanly without it. The import happens inside
    # the function that builds the client, nowhere else.
    """Test the package imports without etcd3."""
    src = Path(__file__).resolve().parents[4] / "src"
    # The package root is ``src`` itself; exposing it as ``security_gateway``
    # makes the import below use the sources rather than an installed copy.
    (tmp_path / "security_gateway").symlink_to(src, target_is_directory=True)
    code = (
        "import sys\n"
        "class Blocker:\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name == 'etcd3' or name.startswith('etcd3.'):\n"
        "            raise ImportError('etcd3 is not installed')\n"
        "        return None\n"
        "sys.meta_path.insert(0, Blocker())\n"
        "import security_gateway.vault.etcdstore.store\n"
        "import security_gateway.vault.etcdstore.entry\n"
        "import security_gateway.vault.etcdstore.keys\n"
        "import security_gateway.vault.etcdstore.errors\n"
        "assert 'etcd3' not in sys.modules\n"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(tmp_path)
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_building_the_client_without_etcd3_says_so(monkeypatch) -> None:
    """Test building the client without etcd3 says so."""
    from security_gateway.vault.etcdstore.store import build_etcd_client

    # The extra is blocked outright, so the test says the same thing
    # whether or not the environment happens to have it installed.
    monkeypatch.setitem(sys.modules, "etcd3", None)
    with pytest.raises(ImportError, match="optional extra"):
        build_etcd_client()
