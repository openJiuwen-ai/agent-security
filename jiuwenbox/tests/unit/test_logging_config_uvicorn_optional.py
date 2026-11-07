# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""patch_uvicorn_logging must no-op when uvicorn is missing.

Sandbox runners may use a bare system Python without uvicorn. configure_logging
calls patch_uvicorn_logging at import/setup time — a hard import would crash
the runner with ModuleNotFoundError.
"""

from __future__ import annotations

import builtins
import inspect
import sys

from jiuwenbox.logging_config import patch_uvicorn_logging


def test_patch_uvicorn_logging_guards_importerror() -> None:
    source = inspect.getsource(patch_uvicorn_logging)
    assert "except ImportError" in source


def test_patch_uvicorn_logging_noop_when_uvicorn_missing(monkeypatch) -> None:
    for key in list(sys.modules):
        if key == "uvicorn" or key.startswith("uvicorn."):
            monkeypatch.delitem(sys.modules, key, raising=False)

    real_import = builtins.__import__

    def block_uvicorn(name, *args, **kwargs):
        if name == "uvicorn" or name.startswith("uvicorn."):
            raise ImportError("No module named 'uvicorn'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", block_uvicorn)
    patch_uvicorn_logging()  # must not raise


def test_patch_uvicorn_logging_applies_when_uvicorn_present() -> None:
    import pytest

    pytest.importorskip("uvicorn")
    from uvicorn.config import LOGGING_CONFIG

    from jiuwenbox.logging_config import LOG_DATE_FORMAT, LOG_FORMAT

    previous = (
        LOGGING_CONFIG["formatters"]["default"].get("fmt"),
        LOGGING_CONFIG["formatters"]["default"].get("datefmt"),
    )
    try:
        patch_uvicorn_logging()
        assert LOGGING_CONFIG["formatters"]["default"]["fmt"] == LOG_FORMAT
        assert LOGGING_CONFIG["formatters"]["default"]["datefmt"] == LOG_DATE_FORMAT
    finally:
        fmt, datefmt = previous
        if fmt is not None:
            LOGGING_CONFIG["formatters"]["default"]["fmt"] = fmt
        if datefmt is not None:
            LOGGING_CONFIG["formatters"]["default"]["datefmt"] = datefmt
