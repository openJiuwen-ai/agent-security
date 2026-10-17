# Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
"""Server-managed workspace paths."""

from __future__ import annotations

import os
from pathlib import Path

# ``pwd`` is a POSIX-only module. The workspace home/mount paths are shared
# across runtimes (including the WindowsRuntime), so resolve the effective
# user's home without importing ``pwd`` at module top level on Windows.
try:  # pragma: no cover - exercised on POSIX only
    import pwd as _pwd  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - Windows
    _pwd = None


def _effective_user_home() -> Path:
    """Return the effective user's home directory without trusting $HOME.

    On POSIX this prefers the home recorded by ``getpwuid`` (accounts whose
    ``$HOME`` env points elsewhere are never trusted). On platforms without
    ``pwd`` (Windows) we fall back to ``Path.home()``.
    """
    if _pwd is not None:
        try:
            return Path(_pwd.getpwuid(os.geteuid()).pw_dir)
        except (KeyError, AttributeError, OSError):
            pass
    return Path.home()


# jiuwenbox 是独立可发布的服务, 数据根不依赖任何宿主产品 (jiuwenswarm /
# office-claw / agent-server). 统一用 ~/.jiuwenbox, Linux 与 Windows 一致.
# box-server 进程自己创建该目录, 天然是目录 owner, Windows 下改 DACL 不会
# WinError 5, 无需借助外部产品"同根"来保证权限.
JIUWENBOX_HOME = _effective_user_home() / ".jiuwenbox"
SANDBOX_WORKSPACE = JIUWENBOX_HOME / "workspace"
WIN_SANDBOX_WORKSPACE_ROOT = SANDBOX_WORKSPACE