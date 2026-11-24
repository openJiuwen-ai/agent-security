# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Trusted native access override; never populated from tool argument fields."""
from contextlib import contextmanager
from contextvars import ContextVar

_accesses = ContextVar("permission_native_accesses", default=None)


def native_accesses():
    return _accesses.get()


@contextmanager
def bind_native_accesses(accesses):
    token = _accesses.set(tuple(accesses))
    try:
        yield
    finally:
        _accesses.reset(token)
