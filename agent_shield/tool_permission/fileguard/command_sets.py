# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Single source of path-aware shell command names for FileGuard extraction.

Shell path analysis lives in ``path_extract`` (cmd0 whitelist + peer analyzers).
Legacy / read_deny_only call sites adapt that core; they must not redefine these
sets or reimplement segment extraction.
"""

from __future__ import annotations

PATH_AWARE_COMMANDS = frozenset({
    # POSIX / shared
    "cd", "rm", "cp", "mv", "mkdir", "touch", "chmod", "chown", "cat",
    "ls", "dir", "type", "head", "tail", "more", "less",
    "vim", "nano", "gedit", "notepad",
    "unlink", "ln", "link", "install", "rsync", "shred", "truncate",
    "rimraf", "deltree",
    # cmd.exe
    "del", "erase", "rd", "rmdir", "copy", "move", "md",
    "ren", "rename", "xcopy", "robocopy", "mklink", "replace",
    # PowerShell cmdlets + common aliases
    "get-content", "gc", "get-item", "gi", "get-childitem", "gci",
    "set-content", "add-content", "clear-content", "clc",
    "out-file", "tee", "tee-object", "sc",
    "remove-item", "ri", "new-item", "ni",
    "copy-item", "cpi", "move-item", "mi", "rename-item", "rni",
    "expand-archive", "compress-archive",
})

NT_CMD_SWITCH_COMMANDS = frozenset({
    "cd", "dir", "del", "erase", "copy", "move", "rd", "rmdir", "md",
    "type", "ren", "rename", "xcopy", "robocopy", "attrib", "cmd", "notepad",
    "mklink", "replace",
})

READ_CMDS = frozenset({
    "cat", "ls", "dir", "type", "head", "tail", "more", "less",
    "get-content", "gc", "get-item", "gi", "get-childitem", "gci",
})

WRITE_CMDS = frozenset({
    "mkdir", "touch", "chmod", "chown", "md",
    "set-content", "add-content", "clear-content", "clc",
    "out-file", "tee", "tee-object", "sc",
    "new-item", "ni", "mklink", "shred", "truncate",
    # Archive cmdlets: named -Path/-DestinationPath order varies; count all as write.
    "expand-archive", "compress-archive",
})

# Keep deletions on the existing SDK write axis.
DELETE_CMDS = frozenset({
    "rm", "del", "erase", "rd", "rmdir", "remove-item", "ri", "unlink",
    "rimraf", "deltree",
})

PS_PATH_FLAGS = frozenset({
    "-path", "-literalpath", "-filepath",
    "-destination", "-destinationpath", "-newname",
})

# Last path-shaped operand is the destination (cp/mv/ln style).
TRANSFER_CMDS = frozenset({
    "cp", "copy", "mv", "move", "install", "rsync", "replace", "ln", "link",
    "copy-item", "cpi", "move-item", "mi", "rename-item", "rni",
    "ren", "rename",
})

# Source is removed / renamed: also count write on each source.
MOVE_CMDS = frozenset({
    "mv", "move", "move-item", "mi", "rename-item", "rni", "ren", "rename",
})

# First operand source (read), second destination (write); later file masks ignored.
SYNC_CMDS = frozenset({"xcopy", "robocopy"})

PS_NAMED_PATH_CMDS = frozenset({
    "get-content", "gc", "get-item", "gi", "get-childitem", "gci",
    "set-content", "add-content", "clear-content", "clc",
    "out-file", "tee-object", "sc",
    "remove-item", "ri", "new-item", "ni",
    "copy-item", "cpi", "move-item", "mi", "rename-item", "rni",
    "expand-archive", "compress-archive",
})

# Tree wipers handled as delete/write (also listed for destructive analysis).
WIPE_CMDS = frozenset({"rimraf", "deltree"})

__all__ = [
    "PATH_AWARE_COMMANDS",
    "NT_CMD_SWITCH_COMMANDS",
    "READ_CMDS",
    "WRITE_CMDS",
    "DELETE_CMDS",
    "PS_PATH_FLAGS",
    "TRANSFER_CMDS",
    "MOVE_CMDS",
    "SYNC_CMDS",
    "PS_NAMED_PATH_CMDS",
    "WIPE_CMDS",
]
