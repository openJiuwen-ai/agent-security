# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Approval scope normalization; UI and transport parsing belong to the host."""

from dataclasses import replace

from .grants import scope_options

TOOL_NAME_ALIASES = {
    "free_search": "mcp_free_search",
    "paid_search": "mcp_paid_search",
    "fetch_webpage": "mcp_fetch_webpage",
    "web_fetch_webpage": "mcp_fetch_webpage",
    "exec_command": "mcp_exec_command",
}


def normalize_confirmation_scope(payload, subject):
    scope = payload.authorization_scope
    if scope is None:
        scope = (
            "exact"
            if payload.authorization_mode == "allow"
            or (subject["kind"] != "file" and not payload.auto_confirm)
            else next(
                (
                    option["value"]
                    for option in scope_options(subject)
                    if option["value"] != "exact"
                ),
                "exact",
            )
        )
    mode = payload.authorization_mode
    if mode is None:
        mode = "allow" if scope == "exact" else "allow_with_scope"
    return replace(payload, authorization_mode=mode, authorization_scope=scope)
