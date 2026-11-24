# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Adapters for the SDK's existing path extraction and tool routing."""

import os
from urllib.parse import urlsplit

from ..netguard.component import extract_fetch_url
from ..routing import is_shell_tool as _is_shell_tool
from ..toolguard.shell_ast import split_shell_for_grants

__all__ = [
    "extract_fetch_url",
    "get_cwd",
    "is_shell_tool",
    "shell_tools_from_config",
    "split_shell_for_grants",
    "url_hostname",
]


def get_cwd():
    return os.getcwd()


def url_hostname(url):
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def shell_tools_from_config(config):
    return config.get("shell_tools", [])


def is_shell_tool(tool, custom=()):
    return _is_shell_tool(tool) or tool in custom
