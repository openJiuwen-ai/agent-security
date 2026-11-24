# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Build the optional native runtime profile with existing SDK compilers.

Only the optional DLL runtime uses this profile. Existing PermissionEngine
callers retain their own caller-supplied sensitive paths and network defaults.
An effective host engine can instead be supplied through HostPolicyAdapter.
"""

import os
from copy import deepcopy
from importlib.resources import files
from ipaddress import ip_address
from pathlib import Path

import yaml

from ..netguard.builtin_rules import package_rules_enabled


def is_ip_literal(value):
    try:
        ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def network_pattern(value):
    if "://" in value or ":" not in value or is_ip_literal(value):
        return value
    return "https://" + value + "/"


def effective_runtime_config(config):
    result = deepcopy(dict(config))
    if not package_rules_enabled(result.get("package_builtin_rules")):
        return result
    defaults = yaml.safe_load(
        files(__package__).joinpath("defaults.yaml").read_text(encoding="utf-8")
    )
    # Explicit builtin sections are already host-composed policy, not a profile
    # overlay. Do not inject a second sensitive catalog into that composition.
    builtin = result.get("builtin")
    if not isinstance(builtin, dict):
        builtin = {}
        result["builtin"] = builtin
    if "sensitive_paths" not in builtin:
        paths = defaults["sensitive_paths"]
        if os.name == "nt":
            roots = {
                "%APPDATA%": Path(os.environ.get("APPDATA") or Path.home() / "AppData/Roaming"),
                "%LOCALAPPDATA%": Path(
                    os.environ.get("LOCALAPPDATA") or Path.home() / "AppData/Local"
                ),
                "~": Path.home(),
            }
            for entry in defaults["windows_sensitive_paths"]:
                variable, relative = entry["path"].split("/", 1)
                root = roots.get(variable)
                if root is None:
                    continue
                paths.append({**entry, "path": (root / relative).as_posix()})
            paths = [{**entry, "ignore_case": True} for entry in paths]
        builtin["sensitive_paths"] = paths
    net = result.get("net_guard")
    if not isinstance(net, dict):
        net = {}
        result["net_guard"] = net
    urls = net.get("urls")
    if not isinstance(urls, dict):
        urls = {}
        net["urls"] = urls
    for key, action in defaults["net_urls"].items():
        if action == "deny":
            urls[key] = action
        else:
            urls.setdefault(key, action)
    return result
