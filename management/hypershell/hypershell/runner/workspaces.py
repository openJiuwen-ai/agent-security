"""Validate administrator-selected, independently owned workspaces."""

from pathlib import PurePosixPath
import re

from ..policy import AccessMode
from .client import RunnerError


def same_workspace_instance(before, after):
    """Check that evidence still refers to the same running workspace instance."""
    fields = ("sandbox_id", "generation", "engine_pid", "engine_start_ticks", "boot_id")
    return after.get("phase") == "RUNNING" and all(before.get(key) == after.get(key) for key in fields)


def workspace_state_path(raw, user_id, user_count):
    if not isinstance(user_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", user_id):
        raise RunnerError("workspace id must be a safe path component")
    if ("state_dir" in raw) == ("state_root" in raw):
        raise RunnerError("runtime must specify exactly one of state_dir or state_root")
    if "state_root" in raw:
        from ..config import _path

        return str(PurePosixPath(_path(raw["state_root"], "state_root")) / user_id)
    if user_count != 1:
        raise RunnerError("multiple users require state_root, not a shared state_dir")
    from ..config import _path

    return _path(raw["state_dir"], "state_dir")


def validate_live_profiles(config, resolve_user, resolve_group):
    """Reject UID aliases and private path sharing before starting any user."""
    identities, mounts = {}, []
    for name, profile in config.users.items():
        try:
            uid = resolve_user(profile.run_as_user).pw_uid
            gid = resolve_group(profile.run_as_group).gr_gid
        except KeyError as exc:
            raise RunnerError("workload account or group does not exist", user=name) from exc
        if uid == 0 or gid == 0:
            raise RunnerError("workload identity must not resolve to root", user=name)
        if any(uid == old_uid or gid == old_gid for old_uid, old_gid in identities.values()):
            raise RunnerError("workspaces must use distinct workload UIDs and GIDs", user=name)
        identities[name] = (uid, gid)
        for rid, mode in profile.grants.items():
            resource = config.catalog[rid]
            if mode == AccessMode.NONE or resource.kind not in ("directory", "file"):
                continue
            path = PurePosixPath(resource.backend_ref)
            for other, other_path, other_mode in mounts:
                overlaps = path == other_path or path in other_path.parents or other_path in path.parents
                if other != name and overlaps and max(mode, other_mode) == AccessMode.READ_WRITE:
                    raise RunnerError("workspaces cannot share writable resource trees", users=[other, name])
            mounts.append((name, path, mode))
    return identities
