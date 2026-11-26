"""Read, validate and atomically save the administrator YAML configuration.

The web layer must not invent its own permission rules: :meth:`ConfigStore.validate`
reuses :meth:`AdminConfig.load`, so "valid in the UI" means "valid for the CLI".
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from pathlib import Path

from ..config import AdminConfig, ConfigError
from ..policy import PolicyError


class ConfigStore:
    def __init__(self, path: str | Path, backup_dir: str | Path, audit_path: str | Path):
        self.path = Path(path)
        self.backup_dir = Path(backup_dir)
        self.audit_path = Path(audit_path)

    def read_text(self) -> str:
        return self.path.read_text(encoding="utf-8")

    def validate(self, text: str) -> tuple[bool, dict]:
        """Validate YAML text without touching the live file."""
        try:
            self.load_config(text)
            return True, {"ok": True}
        except PolicyError as exc:
            return False, {"ok": False, "error": exc.to_dict()}
        except (OSError, ValueError) as exc:
            return False, {"ok": False, "error": {"code": "INVALID_CONFIG", "message": str(exc)}}

    def load_config(self, text: str) -> AdminConfig:
        """Load a draft through the same strict parser without replacing the file."""
        if not isinstance(text, str):
            raise ConfigError("config text is required")
        fd, tmp = tempfile.mkstemp(prefix=".admin-", suffix=".yaml", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text)
            os.chmod(tmp, 0o600)
            return AdminConfig.load(tmp)
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def save(self, text: str, *, actor: str) -> dict:
        """Validate, back up the current file and atomically replace it."""
        ok, _ = self.validate(text)
        if not ok:
            raise ConfigError("refusing to save invalid configuration")
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S") + "-" + str(int(time.time() * 1000) % 1000)
        backup_name = None
        if self.path.exists():
            backup = self.backup_dir / f"admin-{stamp}.yaml"
            shutil.copy2(self.path, backup)
            os.chmod(backup, 0o600)
            backup_name = backup.name
        tmp = self.path.with_name(self.path.name + ".tmp")
        descriptor = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, self.path)
        try:
            dir_fd = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0), 0o700)
        except OSError:
            dir_fd = None
        if dir_fd is not None:
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        self._audit(
            {
                "event": "CONFIG_SAVED",
                "actor": actor,
                "path": str(self.path),
                "backup": backup_name,
                "bytes": len(text.encode("utf-8")),
            }
        )
        return {"ok": True, "backup": backup_name}

    def _audit(self, record: dict) -> None:
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"time": time.time(), **record}
        with open(self.audit_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def list_backups(self, limit: int = 20) -> list[str]:
        if not self.backup_dir.is_dir():
            return []
        names = sorted(p.name for p in self.backup_dir.glob("admin-*.yaml"))
        return names[-limit:][::-1]
