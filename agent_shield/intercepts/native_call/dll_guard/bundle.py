"""Resolve and validate the Windows runtime DLL from installed resources."""

import hashlib
import json
import platform
import struct
import sys
from contextlib import ExitStack, contextmanager
from functools import lru_cache
from pathlib import Path

from .._binary_location import guard_binary_directory
from .errors import GuardBundleError, GuardBundleMissingError, GuardPlatformError


def require_guard_platform() -> None:
    if (
        sys.platform != "win32"
        or struct.calcsize("P") != 8
        or platform.machine().lower() not in {"amd64", "x86_64"}
    ):
        raise GuardPlatformError("DLL Guard requires Windows x64")


def locate_guard_dll() -> Path:
    """Resolve the optional native package, with a source-checkout fallback."""
    path = guard_binary_directory() / "jiuwen_runtime_guard.dll"
    if not path.is_file():
        raise GuardBundleMissingError(
            f"DLL Guard missing at {path}. Install agent-security-dll or provide an explicit DLL"
        )
    return path


def guard_manifest_path(dll: Path) -> Path:
    """Keep the integrity manifest specific to this DLL in the shared native directory."""
    return dll.with_suffix(".manifest.json")


def validate_guard_platform() -> Path:
    require_guard_platform()
    path = locate_guard_dll()
    return _validate_guard_cached(path, _bundle_identity(path))


def _bundle_identity(path: Path):
    try:
        return tuple(
            (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            for info in (path.stat(), guard_manifest_path(path).stat())
        )
    except FileNotFoundError as exc:
        raise GuardBundleMissingError(str(exc)) from exc
    except OSError as exc:
        raise GuardBundleError(f"DLL Guard bundle is unreadable: {path}") from exc


@lru_cache(maxsize=16)
def _validate_guard_cached(path: Path, identity) -> Path:
    validate_guard_bundle(path)
    if identity != _bundle_identity(path):
        raise GuardBundleError("DLL Guard bundle changed during validation")
    return path


def validate_guard_bundle(path: Path) -> Path:
    """Validate an explicit prebuilt artifact without importing the host or loading the DLL.

    Packaging and runtime share the protocol, architecture and checksum checks.
    This function never compiles the DLL or rewrites its manifest.
    """
    if not path.is_file():
        raise GuardBundleMissingError(f"DLL Guard is not installed: {path}")
    try:
        manifest = json.loads(guard_manifest_path(path).read_text(encoding="utf-8-sig"))
        binary = path.read_bytes()
        pe = struct.unpack_from("<I", binary, 0x3C)[0]
        valid = (
            manifest.get("protocol") == 4
            and manifest.get("architecture") == "x64"
            and manifest.get("sha256") == hashlib.sha256(binary).hexdigest()
            and binary[:2] == b"MZ"
            and binary[pe:pe + 4] == b"PE\0\0"
            and struct.unpack_from("<H", binary, pe + 4)[0] == 0x8664
        )
    except FileNotFoundError as exc:
        raise GuardBundleMissingError(str(exc)) from exc
    except (OSError, ValueError, TypeError, AttributeError, struct.error) as exc:
        raise GuardBundleError("DLL Guard bundle is incomplete or invalid") from exc
    if not valid:
        raise GuardBundleError("DLL Guard bundle protocol, architecture or checksum mismatch")
    return path


@contextmanager
def pin_guard_bundle(path: Path):
    """Keep the validated files and their resolved directory names in place until Job close."""
    import _winapi
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    attributes = kernel.GetFileInformationByHandleEx
    attributes.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    attributes.restype = wintypes.BOOL
    with ExitStack() as handles:
        # Acquire ancestors top down. Directory handles permit normal writes to
        # children, but exclude rename/delete of the directory we traversed.
        parents = list(reversed(path.parents))  # The volume/share root has no parent.
        for entry in [*parents[1:], path, guard_manifest_path(path)]:
            directory = entry in path.parents
            try:
                handle = _winapi.CreateFile(
                    str(entry),
                    0x80 if directory else 0x80000000,
                    3 if directory else 1,
                    0,
                    3,
                    0x00200000 | (0x02000000 if directory else 0),
                    0,
                )
                handles.callback(_winapi.CloseHandle, handle)
                info = (wintypes.DWORD * 2)()  # FILE_ATTRIBUTE_TAG_INFO
                if not attributes(handle, 9, info, ctypes.sizeof(info)):
                    raise ctypes.WinError(ctypes.get_last_error())
                if info[0] & 0x400:
                    raise GuardBundleError(f"Reparse point in resolved DLL Guard bundle: {entry}")
            except FileNotFoundError as exc:
                raise GuardBundleMissingError(str(exc)) from exc
            except OSError as exc:
                raise GuardBundleError(f"Cannot pin DLL Guard bundle entry {entry}: {exc}") from exc
        validate_guard_bundle(path)
        yield path
