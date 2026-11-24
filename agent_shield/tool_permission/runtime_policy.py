# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Opt-in native policy support, shared by process adapters and host callbacks.

Existing tool permission callers continue to use PermissionManager. This
namespace provides authenticated native resource and authorization helpers;
it does not export the underlying Guard components or replace old defaults.
"""

from .runtime import command_identity, confirmation, engine, grants, models, shell

__all__ = ["command_identity", "confirmation", "engine", "grants", "models", "shell"]
