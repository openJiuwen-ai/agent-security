"""Guarded lab patch for filelock 3.29.0 on the recorded SQLite 3.31 VM.

Default is inspection. --apply preserves a backup and applies only the known
SELECT alias change, retaining the existing transaction and lock semantics.
Run with the target runtime interpreter while its applications are stopped.
"""

import argparse
import hashlib
import json
import logging
from pathlib import Path
import sys

OLD = b"SELECT name FROM sqlite_schema LIMIT 1;"
NEW = b"SELECT name FROM sqlite_master LIMIT 1;"
EXPECTED_SOURCE_SHA256 = "e6d54f9b54c35ef02ed2c82f6bf2d02780c7f920e8d2b571b980052c4406670e"


def patch_bytes(source):
    if source.count(OLD) != 1 or NEW in source:
        raise ValueError("unexpected filelock source; refusing to patch")
    return source.replace(OLD, NEW, 1)


def main():
    import filelock

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    logger = logging.Logger(__name__, logging.INFO)
    logger.addHandler(logging.StreamHandler(sys.stdout))
    if filelock.__version__ != "3.29.0":
        raise SystemExit("only the verified filelock 3.29.0 profile is supported")
    target = Path(filelock.__file__).parent / "_read_write.py"
    source = target.read_bytes()
    backup = target.with_suffix(".py.hypershell-original")
    if OLD not in source:
        if backup.exists() and source == patch_bytes(backup.read_bytes()):
            logger.info("%s", json.dumps({"status": "already_applied"}))
            return
        raise SystemExit("unexpected installed source; refusing to patch")
    updated = patch_bytes(source)
    if hashlib.sha256(source).hexdigest() != EXPECTED_SOURCE_SHA256:
        raise SystemExit("source digest differs from the VM-verified profile; refusing to patch")
    if args.apply:
        if backup.exists():
            raise SystemExit("backup already exists; inspect it before applying")
        with backup.open("xb") as output:
            output.write(source)
        # Keep existing owner/mode. Installed processes must be stopped first.
        target.write_bytes(updated)
    logger.info(
        "%s",
        json.dumps(
            {
                "status": "applied" if args.apply else "available",
                "filelock": filelock.__version__,
                "before_sha256": hashlib.sha256(source).hexdigest(),
                "after_sha256": hashlib.sha256(updated).hexdigest(),
            }
        ),
    )


if __name__ == "__main__":
    main()
