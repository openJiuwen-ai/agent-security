"""A dependency patch must fail closed against unexpected source versions."""

import importlib.util
from pathlib import Path
import sqlite3

import pytest


def load_patch():
    # The patch tool imports filelock only in main; tests need no runtime SDK.
    path = Path(__file__).resolve().parents[1] / "scripts/dev/apply_sqlite_compat.py"
    spec = importlib.util.spec_from_file_location("sqlite_compat", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_alias_change_preserves_the_rest_of_source():
    patch = load_patch()
    source = b"BEGIN TRANSACTION;\n" + patch.OLD + b"\nCOMMIT;"
    assert patch.patch_bytes(source) == b"BEGIN TRANSACTION;\n" + patch.NEW + b"\nCOMMIT;"
    with sqlite3.connect(":memory:") as connection:
        assert connection.execute(patch.NEW.decode()).fetchall() == []


@pytest.mark.parametrize("source", [b"", b"SELECT unexpected", b"SELECT name FROM sqlite_schema LIMIT 1;" * 2])
def test_unknown_source_refused(source):
    with pytest.raises(ValueError):
        load_patch().patch_bytes(source)
