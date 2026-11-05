"""Packaged builtin catalogs and behavior rules."""

from __future__ import annotations

from agent_shield.policy_engine.builtin.catalog import DEFAULT_RISK, DISPLAY_NAME
from agent_shield.policy_engine.models.types import BehaviorRule
from agent_shield.policy_engine.core.ruleset import Ruleset, _check_catalog_refs
from agent_shield.policy_engine.core.behavior_schema import validate_behavior_clause
from agent_shield.policy_engine.builtin.policy import RISK_RANK

_ALLOWLIST = ["allowlist_hosts", "allowlist_cidrs"]
_SENSITIVE = [
    "**/.ssh/**",
    "**/.env",
    "**/.env.*",
    "**/*id_rsa*",
    "**/*id_ed25519*",
    "**/*.pem",
    "**/*.pfx",
    "**/.kube/config",
    "**/.aws/credentials",
    "**/.aws/config",
    "**/.npmrc",
    "**/authorized_keys",
]

# Higher-risk rules are listed first so a same-position tie keeps the stricter reason.
_WHENS: list[tuple[str, dict]] = [
    (
        "privilege.escalate",
        {
            "any": [
                {"effect": "privilege.escalate"},
                {"effect": "process.exec", "shell_meta.privilege": True},
            ]
        },
    ),
    ("fs.delete.protectedFiles", {"effect": "fs.delete", "path.in_catalog": "protectedFiles"}),
    ("fs.device.raw_write", {"effect": "fs.write", "path_kind": "device", "device_class": ["raw_disk", "volume"]}),
    (
        "net.egress.secret",
        {
            "effect": "net.egress",
            "any": [
                {"secret_like": True},
                {"local_file_attached": True, "local_files.glob_any": "sensitiveFiles"},
            ],
        },
    ),
    ("fs.write.protectedFiles", {"effect": "fs.write", "path.in_catalog": "protectedFiles", "exists": [True, None]}),
    ("fs.read.protectedReadFiles", {"effect": "fs.read", "path.in_catalog": "protectedReadFiles"}),
    ("fs.read.sensitiveFiles", {"effect": "fs.read", "path.glob_any": "sensitiveFiles"}),
    ("fs.write.sensitiveFiles", {"effect": "fs.write", "path.glob_any": "sensitiveFiles"}),
    ("fs.delete.sensitiveFiles", {"effect": "fs.delete", "path.glob_any": "sensitiveFiles"}),
    ("fs.delete.outside_force", {"effect": "fs.delete", "force": True, "path.scope": "outside"}),
    ("fs.device", {"effect": ["fs.read", "fs.write"], "path_kind": ["device", "named_pipe"]}),
    ("fs.delete.bulk", {"effect": "fs.delete", "bulk": True}),
    ("shell.obfuscated", {"effect": "process.exec", "shell_meta.obfuscated": True}),
    ("exec.remote_script", {"effect": "process.exec", "shell_meta.interpreter_sink": True}),
    ("fs.write.system_new", {"effect": "fs.write", "path.in_catalog": "systemPrefixes", "exists": False}),
    ("fs.write.outside", {"effect": "fs.write", "path.scope": "outside", "not": {"path.in_catalog": "protectedFiles"}}),
    ("fs.delete.outside", {"effect": "fs.delete", "path.scope": "outside", "force": False}),
    ("net.egress", {"effect": "net.egress", "not": {"endpoint.in_any_catalog": _ALLOWLIST}}),
    ("schedule.create", {"effect": "schedule.create"}),
    (
        "git.force_push",
        {
            "effect": "process.exec",
            "argv0": "git",
            "argv_contains": ["push"],
            "any": [
                {"argv_has_any": ["--force", "--force-with-lease", "-f"]},
                {"argv_has_any_prefix": ["--force-with-lease=", "+refs/"]},
            ],
        },
    ),
    ("fs.read.userFiles", {"effect": "fs.read", "path.in_catalog": "userFiles"}),
    ("fs.write.userFiles", {"effect": "fs.write", "path.in_catalog": "userFiles"}),
    ("fs.delete.userFiles", {"effect": "fs.delete", "path.in_catalog": "userFiles"}),
    (
        "net.fetch.get",
        {
            "effect": "net.fetch",
            "method": ["GET", "HEAD"],
            "not": {"endpoint.in_any_catalog": _ALLOWLIST},
        },
    ),
    ("net.connect.unlisted", {"effect": "net.connect", "not": {"endpoint.in_any_catalog": _ALLOWLIST}}),
    ("fs.read.nonsensitive_outside", {"effect": "fs.read", "path.scope": "outside"}),
    ("net.connect.allowlist", {"effect": "net.connect", "endpoint.in_any_catalog": _ALLOWLIST}),
    ("net.fetch.allowlist", {"effect": "net.fetch", "endpoint.in_any_catalog": _ALLOWLIST}),
    ("net.egress.allowlist", {"effect": "net.egress", "endpoint.in_any_catalog": _ALLOWLIST}),
]


def builtin_catalogs() -> dict:
    return {
        "protectedFiles": _os(
            "path",
            ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config", "/boot/**", "/etc/sudoers.d/**"],
            ["C:/Windows/System32/**", "C:/Windows/SysWOW64/**", "bootmgr"],
        ),
        "protectedReadFiles": _os(
            "path",
            ["/etc/shadow", "/etc/sudoers", "/etc/sudoers.d/**"],
            [
                "C:/Windows/System32/config/SAM",
                "C:/Windows/System32/config/SYSTEM",
                "C:/Windows/System32/config/SECURITY",
            ],
        ),
        "sensitiveFiles": {"kind": "glob", "entries": list(_SENSITIVE)},
        "userFiles": {"kind": "user", "entries": []},
        "systemPrefixes": _os(
            "prefix",
            ["/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt", "/boot", "/root", "/var"],
            ["C:/Windows", "C:/Program Files", "C:/Program Files (x86)"],
        ),
        "nativeToolsDenyList": _os(
            "program",
            ["sudo", "su", "pkexec", "doas"],
            ["sc", "reg", "regedt32", "regini", "schtasks", "netsh", "wmic", "diskpart", "bcdedit", "vssadmin"],
        ),
        "nativeToolsAskList": _os(
            "program",
            [],
            ["certutil", "bitsadmin", "mshta", "wscript", "cscript", "rundll32", "regsvr32"],
        ),
        "allowlist_hosts": {"kind": "host", "entries": []},
        "allowlist_cidrs": {"kind": "cidr", "entries": []},
        "privilege_argv0": {"kind": "program", "entries": ["sudo", "pkexec", "doas", "runas", "gsudo"]},
        "interpreter_sinks": {"kind": "program", "entries": ["bash", "sh", "zsh", "pwsh", "powershell", "cmd", "iex"]},
    }


def load_builtin_ruleset(*, unmatched: str = "none") -> Ruleset:
    catalogs = builtin_catalogs()
    behaviors: list[BehaviorRule] = []
    for rule_id, when in _WHENS:
        validate_behavior_clause(when)
        _check_catalog_refs(when, catalogs)
        risk = DEFAULT_RISK[rule_id]
        behaviors.append(BehaviorRule(rule_id, risk, "builtin", DISPLAY_NAME[rule_id], when, risk == "medium"))
    behaviors.sort(key=lambda rule: -RISK_RANK[rule.risk])
    return Ruleset(tuple(behaviors), (), catalogs, {}, unmatched)


def _os(kind: str, posix: list[str], windows: list[str]) -> dict:
    return {"kind": kind, "entries": [], "posix": list(posix), "windows": list(windows)}
