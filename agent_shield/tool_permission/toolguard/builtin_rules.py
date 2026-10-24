# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Package built-in command rules (R07, R12).

Pure data: every entry carries its default ``action``; ``severity`` is only a label.
Rules target concrete shell tool names (the former ``shell`` category is not used).
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

SHELL_TOOLS: tuple[str, ...] = (
    "bash", "powershell", "core.powershell", "mcp_exec_command", "create_terminal",
)

_RULES: tuple[dict[str, Any], ...] = (
    {
        "id": "shell_fs_recursive_or_forced_delete",
        "description": "递归、强制或批量删除，可能造成数据破坏",
        "tools": SHELL_TOOLS,
        "match_type": "command",
        "pattern": r"""re:(?i)(?:^|[\s;&|()])(?:(?:rm\s+(?=[^;&|]*(?:/[^;&|\s]*|\*|~[^;&|\s]*|\$HOME[^;&|\s]*|\.{1,2}(?:/[^;&|\s]*)?))(?=[^;&|]*(?:-[A-Za-z]*[rR][A-Za-z]*[fF]|-[A-Za-z]*[fF][A-Za-z]*[rR]|--recursive\b|--force\b|-[rR]\b[^;&|]*-[fF]\b|-[fF]\b[^;&|]*-[rR]\b))|(?:rm\s+(?:/\*|~/|\$HOME/|\.{1,2}/))|(?:find\s+[^;&|]*\s-delete\b)|(?:shred\b(?=[^;&|]*(?:/[^;&|\s]*|\*|~[^;&|\s]*|\$HOME[^;&|\s]*|(?:^|[\s])\.{1,2}(?:/[^;&|\s]*)?)))|(?:del\s+[^;&|]*/[fqs]+\b)|(?:(?:rd|rmdir)\s+[^;&|]*/[qf]*s[qf]*\b)))""",
        "severity": "HIGH",
        "action": "ask",
    },
    {
        "id": "shell_ps_recursive_or_forced_delete",
        "description": "PowerShell 递归或强制删除，可能造成数据破坏",
        "tools": SHELL_TOOLS,
        "match_type": "command",
        "pattern": r"""re:(?i)(^|[\s;&|()])(((Remove-Item|\bri\b|\berase\b|\brmdir\b|\bdel\b)\b[^\n\r;|&]*-(Recurse|Force|R|F)\b)|(\brm\b[^\n\r;|&]*-(Recurse|Force)\b))""",
        "severity": "HIGH",
        "action": "ask",
    },
    {
        "id": "shell_registry_delete",
        "description": "删除 Windows 注册表键（reg delete 或 Remove-Item 注册表驱动器）",
        "tools": SHELL_TOOLS,
        "match_type": "command",
        "pattern": r"""re:(?i)(?:^|[\s;&|()])(?:(?:reg\s+delete\b)|(?:(?:Remove-Item|Remove-ItemProperty|\bri\b)\b(?:\s[^\n\r;|&]*?)+?(?:HK(?:LM|CU|CR|U|CC):|Registry::)))""",
        "severity": "CRITICAL",
        "action": "deny",
    },
    {
        "id": "shell_disk_partition_or_raw_device_write",
        "description": "格式化、分区或直接写入块设备，可能破坏磁盘和文件系统",
        "tools": SHELL_TOOLS,
        "match_type": "command",
        "pattern": r"""re:(?i)(?:^|[\s;&|()])(?:(?:mkfs(?:\.[A-Za-z0-9_]+)?|mke2fs|diskpart|Format-Volume|Clear-Disk)\b|(?:fdisk\b(?!\s+(?:-l\b|--list\b)))|(?:parted\b(?!\s+(?:-l\b|--list\b)))|(?:format(?:\.com)?\s+(?:/[A-Za-z]+\s+)*[A-Za-z]:)|(?:dd\b[^;&|]*?(?:\bof\s*=\/dev\/|\\\\\.\\PhysicalDrive))|(?:>>?\s*\/dev\/(?:sd[a-z][0-9]*|vd[a-z][0-9]*|xvd[a-z][0-9]*|nvme[0-9]+n[0-9]+(?:p[0-9]+)?|disk[0-9]+)))""",
        "severity": "CRITICAL",
        "action": "deny",
    },
    {
        "id": "shell_download_and_execute",
        "description": "从网络下载内容后直接交给 shell、PowerShell 或动态执行器执行",
        "tools": SHELL_TOOLS,
        "match_type": "command",
        "pattern": r"""re:(?i)(^|[\s;&|()])(((curl|wget|fetch|ftp)\b[^;&]*\|\s*(?:(?:sudo|doas)\s+)?(bash|sh|zsh|dash|ash|source|pwsh|powershell)\b)|(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^;&|]*\|\s*(iex|Invoke-Expression)\b|((bash|sh|zsh|pwsh|powershell)\b[^;&|]*<\s*<\s*\(?\s*(curl|wget)\b))""",
        "severity": "HIGH",
        "action": "ask",
    },
    {
        "id": "shell_obfuscated_or_dynamic_execution",
        "description": "编码载荷、解码后执行、eval/iex 或内联解释器执行，命令难以审计",
        "tools": SHELL_TOOLS,
        "match_type": "command",
        "pattern": r"""re:(?i)(^|[\s;&|()])((base64\s+(-d|--decode)\b[^;&|]*\|\s*(bash|sh|zsh|dash|ash)\b)|(certutil\s+-decode\b)|((?:powershell|pwsh)\b[^;&|]*-(?:[Ee]nc(?:oded[Cc]ommand)?|[Ee]ncoded[Cc]ommand)\b)|(\[Convert\]::FromBase64String\()|(eval\s+[`$])|(\b(iex|Invoke-Expression)\b)|((python3?|perl|ruby|node)\s+(-c|-e)\b[^;&|]*(socket|subprocess|exec|eval|child_process)))""",
        "severity": "HIGH",
        "action": "ask",
    },
    {
        "id": "shell_reverse_shell_or_bind_shell",
        "description": "反向 shell、绑定 shell 或可疑网络执行通道",
        "tools": SHELL_TOOLS,
        "match_type": "command",
        "pattern": r"""re:(?i)(/dev/(tcp|udp)/|(^|[\s;&|()])(nc|ncat)\b[^;&|]*\s(-e|--exec)\s|\bsocat\b[^;&|]*(EXEC:|SYSTEM:|PTY)|\bbash\s+-i\b[^;&|]*/dev/tcp/|\bpython3?\s+-[ce]\b[^;&|]*(socket|pty\.spawn|subprocess)|\bperl\s+-[ce]\b[^;&|]*Socket)""",
        "severity": "CRITICAL",
        "action": "deny",
    },
    {
        "id": "shell_privilege_escalation",
        "description": "通过 sudo、su、doas、pkexec、runas 或管理员启动方式提升权限",
        "tools": SHELL_TOOLS,
        "match_type": "command",
        "pattern": r"""re:(?i)(^|[\s;&|()])((sudo|doas|pkexec)\s+|su\s+(-|root|\w)|runas\b|Start-Process\b[^;&|]*-Verb\s+RunAs\b|psexec\b|schtasks\b[^;&|]*/ru\s+SYSTEM\b)""",
        "severity": "HIGH",
        "action": "ask",
    },
    {
        "id": "shell_data_exfiltration",
        "description": "通过curl、wget、PowerShell等工具外发本地文件",
        "tools": SHELL_TOOLS,
        "match_type": "command",
        "pattern": r"""re:(?i)(?:^|[\s;&|\n()])(?:curl\b[^;&|\n]*?(?:--upload-file\b|(?:--data(?:-binary|-raw|-urlencode)?|-d)(?:\s+|=)?@|(?:-F|--form)(?:\s+|=)(?:@[^\s;&|\n]+|[^\s;&|\n]+=@)|-T\s+\S+)|wget\b[^;&|\n]*?--post-file\b|(?:Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b[^;&|\n]*?-InFile\b)""",
        "severity": "HIGH",
        "action": "ask",
    },
    {
        "id": "shell_remote_execution_or_lateral_movement",
        "description": "远程会话、远程进程创建或横向移动命令",
        "tools": SHELL_TOOLS,
        "match_type": "command",
        "pattern": r"""re:(?i)(^|[\s;&|()])((Invoke-Command|Enter-PSSession|New-PSSession)\b|winrs\b|wmic\b[^;&|]*process\s+call\s+create|psexec\b|ssh\b[^;&|]*\s\S+\s+["'][^"']+["'])""",
        "severity": "HIGH",
        "action": "ask",
    },
    {
        "id": "shell_fork_bomb_or_resource_abuse",
        "description": "fork bomb、解除进程限制或批量终止关键进程",
        "tools": SHELL_TOOLS,
        "match_type": "command",
        "pattern": r"""re:(?i)(:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:|(^|[\s;&|()])kill\s+-9\s+(-1|1)\b|(^|[\s;&|()])ulimit\s+-u\s+unlimited\b)""",
        "severity": "CRITICAL",
        "action": "deny",
    },
    {
        "id": "shell_system_shutdown_or_reboot",
        "description": "关机、重启或切换到关机/重启运行级别，属于明显破坏系统可用性的行为",
        "tools": SHELL_TOOLS,
        "match_type": "command",
        "pattern": r"""re:(?i)(?:^|&&|\|\||[;\n]|&)\s*(?:(?:(?:sudo|doas)\s+)?(?:shutdown|reboot|halt|poweroff)\b(?!\s+--help)|systemctl\s+(?:reboot|poweroff|halt)|(?:Stop-Computer|Restart-Computer)\b|(?:init|telinit)\s+(0|6)\b)""",
        "severity": "CRITICAL",
        "action": "deny",
    },
    {
        "id": "shell_chmod_world_writable",
        "description": "把文件或目录权限放宽为全局可写",
        "tools": SHELL_TOOLS,
        "match_type": "command",
        "pattern": r"""re:(?i)(?:^|[\s;&|()])chmod\s+(?:(?:-R|--recursive)\s+)?(?:0?[0-7]{2}[2367]\b|[0-7]{3}[2367]\b|a\+rwx\b|[ao]\+[a-z]*w[a-z]*)""",
        "severity": "HIGH",
        "action": "ask",
    },
    {
        "id": "shell_ld_preload_hijack",
        "description": "通过 LD_PRELOAD / DYLD_INSERT_LIBRARIES 劫持动态链接",
        "tools": SHELL_TOOLS,
        "match_type": "command",
        "pattern": r"""re:(?i)(^|[\s;&|()])((LD_PRELOAD|DYLD_INSERT_LIBRARIES)\s*=)""",
        "severity": "HIGH",
        "action": "ask",
    },
    {
        "id": "shell_clear_audit_history",
        "description": "清除 shell 历史或审计痕迹",
        "tools": SHELL_TOOLS,
        "match_type": "command",
        "pattern": r"""re:(?i)(^|[\s;&|()])((history\s+-c\b)|(HISTFILE\s*=\s*/dev/null)|((rm|shred)\b[^;&|]*\.(bash_history|zsh_history|python_history)\b)|Set-PSReadLineOption\b[^;&|]*HistorySaveStyle\b[^;&|]*SaveNothing)""",
        "severity": "HIGH",
        "action": "ask",
    },
    {
        "id": "shell_disable_firewall",
        "description": "关闭或清空防火墙规则",
        "tools": SHELL_TOOLS,
        "match_type": "command",
        "pattern": r"""re:(?i)(^|[\s;&|()])((ufw\b[^;&|]*\bdisable\b)|(iptables\s+(?:-t\s+\S+\s+)?(?:-F|--flush)\b)|(firewall-cmd\b[^;&|]*--set-default-zone=trusted)|(Set-NetFirewallProfile\b[^;&|]*-Enabled\s+False\b))""",
        "severity": "HIGH",
        "action": "ask",
    },
    {
        "id": "shell_docker_privileged",
        "description": "以过宽权限启动容器（privileged / SYS_ADMIN / pid=host）",
        "tools": SHELL_TOOLS,
        "match_type": "command",
        "pattern": r"""re:(?i)(^|[\s;&|()])docker\s+run\b[^;&|]*(--privileged\b|--cap-add(=|\s+)SYS_ADMIN\b|--pid(=|\s+)host\b)""",
        "severity": "HIGH",
        "action": "ask",
    },
    {
        "id": "shell_compound_chain",
        "description": "链式、管道或变量展开（; & | ${ 换行），命令可能串联多段",
        "tools": SHELL_TOOLS,
        "match_type": "command",
        # dev-stable ``_SHELL_OPERATORS_RE`` minus ``< > $( ` `` (command substitution is covered by structure_guard; redirection by the file guard).
        "pattern": r"re:[;&|]|\$\{|\r?\n",
        "severity": "HIGH",
        "action": "ask",
    },
)


def package_command_rules() -> list[dict[str, Any]]:
    """Return a fresh copy of the package rules, each tagged ``layer: builtin``."""
    return [{**deepcopy(rule), "layer": "builtin"} for rule in _RULES]


__all__ = ["SHELL_TOOLS", "package_command_rules"]
