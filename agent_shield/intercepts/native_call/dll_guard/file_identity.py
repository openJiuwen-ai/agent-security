"""Read file identities and all names of a Windows hard-linked object."""

from __future__ import annotations

import ctypes as ct
import ntpath
from contextlib import contextmanager
from ctypes import wintypes as wt
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


_INVALID_HANDLE = ct.c_void_p(-1).value
_PATH_CAPACITY = 32768
_ERROR_NO_MORE_FILES = 18
_ERROR_HANDLE_EOF = 38


class _FileIdInfo(ct.Structure):
    _fields_ = [("volume_serial", ct.c_ulonglong), ("file_id", ct.c_ubyte * 16)]


class _FileStandardInfo(ct.Structure):
    _fields_ = [
        ("allocation_size", ct.c_longlong), ("end_of_file", ct.c_longlong),
        ("links", wt.DWORD), ("delete_pending", ct.c_ubyte), ("directory", ct.c_ubyte),
    ]


@dataclass(frozen=True)
class WindowsFileIdentity:
    volume_serial: int
    file_id: str
    link_paths: tuple[Path, ...] = ()

    def approval_key(self) -> list:
        """Return the identity in the form stored in approval patterns."""
        return [self.volume_serial, self.file_id, [str(path) for path in self.link_paths]]


@lru_cache(maxsize=1)
def _kernel():
    kernel = ct.WinDLL("kernel32", use_last_error=True)
    signatures = {
        "CreateFileW": (wt.HANDLE, wt.LPCWSTR, wt.DWORD, wt.DWORD, ct.c_void_p, wt.DWORD, wt.DWORD, wt.HANDLE),
        "CloseHandle": (wt.BOOL, wt.HANDLE),
        "GetFileInformationByHandleEx": (wt.BOOL, wt.HANDLE, ct.c_int, ct.c_void_p, wt.DWORD),
        "GetVolumePathNameW": (wt.BOOL, wt.LPCWSTR, wt.LPWSTR, wt.DWORD),
        "FindFirstFileNameW": (wt.HANDLE, wt.LPCWSTR, wt.DWORD, ct.POINTER(wt.DWORD), wt.LPWSTR),
        "FindNextFileNameW": (wt.BOOL, wt.HANDLE, ct.POINTER(wt.DWORD), wt.LPWSTR),
        "FindClose": (wt.BOOL, wt.HANDLE),
    }
    for name, (result, *arguments) in signatures.items():
        function = getattr(kernel, name)
        function.restype = result
        function.argtypes = arguments
    return kernel


def _extended_path(path: Path) -> str:
    name = str(path)
    if name.startswith("\\\\?\\"):
        return name
    drive, tail = ntpath.splitdrive(name)
    if drive.startswith("\\\\"):
        # Join a complete UNC drive with its rooted tail across Python versions.
        return ntpath.join(f"\\\\?\\UNC\\{drive[2:]}", tail)
    return ntpath.join(f"\\\\?\\{drive}", tail)


@contextmanager
def _metadata_handle(kernel, path: Path):
    # A metadata-only, shared OPEN_EXISTING does not write or create a target.
    handle = kernel.CreateFileW(_extended_path(path), 0, 7, None, 3, 0x02000000, None)
    if handle == _INVALID_HANDLE:
        raise ct.WinError(ct.get_last_error())
    try:
        yield handle
    finally:
        kernel.CloseHandle(handle)


def _standard_info(kernel, handle):
    info = _FileStandardInfo()
    if not kernel.GetFileInformationByHandleEx(handle, 1, ct.byref(info), ct.sizeof(info)):
        raise ct.WinError(ct.get_last_error())
    return info


def _file_key(kernel, handle) -> tuple[int, str]:
    info = _FileIdInfo()
    if not kernel.GetFileInformationByHandleEx(handle, 18, ct.byref(info), ct.sizeof(info)):
        raise ct.WinError(ct.get_last_error())
    return info.volume_serial, bytes(info.file_id).hex()


def _policy_volume_mount(mount: str) -> str:
    # Match the normal drive/UNC paths used by FileGuard. A volume GUID with
    # no drive or mount folder still needs its extended-path prefix.
    if mount.lower().startswith("\\\\?\\unc\\"):
        drive, tail = ntpath.splitdrive(mount)
        return ntpath.join(f"\\\\{drive[8:]}", tail)
    if mount.startswith("\\\\?\\") and Path(mount[4:]).is_absolute():
        return mount[4:]
    return mount


def _link_paths(kernel, path: Path, key: tuple[int, str], count: int) -> tuple[Path, ...]:
    name = _extended_path(path)
    volume = ct.create_unicode_buffer(_PATH_CAPACITY)
    if not kernel.GetVolumePathNameW(name, volume, len(volume)):
        raise ct.WinError(ct.get_last_error())
    mount = _policy_volume_mount(volume.value)
    link = ct.create_unicode_buffer(_PATH_CAPACITY)
    size = wt.DWORD(len(link))
    finder = kernel.FindFirstFileNameW(name, 0, ct.byref(size), link)
    if finder == _INVALID_HANDLE:
        raise ct.WinError(ct.get_last_error())
    paths = set()
    try:
        while True:
            # FindFirstFileNameW returns names relative to the volume root.
            suffix = Path(link.value.lstrip("\\"))
            if suffix.anchor or not suffix.parts or ".." in suffix.parts:
                raise OSError("Invalid volume-relative hard link name")
            alias = (Path(mount) / suffix).resolve(strict=True)
            with _metadata_handle(kernel, alias) as handle:
                if _file_key(kernel, handle) != key:
                    raise OSError("Hard link no longer identifies the requested file")
            if alias in paths or len(paths) == count:
                raise OSError("Hard link enumeration did not match the file's link count")
            paths.add(alias)
            size.value = len(link)
            if not kernel.FindNextFileNameW(finder, ct.byref(size), link):
                error = ct.get_last_error()
                if error not in {_ERROR_HANDLE_EOF, _ERROR_NO_MORE_FILES}:
                    raise ct.WinError(error)
                break
    finally:
        kernel.FindClose(finder)
    if len(paths) != count or path not in paths:
        raise OSError("Incomplete hard link enumeration")
    return tuple(sorted(paths))


def read_file_identity(path: Path) -> WindowsFileIdentity | None:
    """Return None for a missing target and reject incomplete identity evidence."""
    kernel = _kernel()
    opened = False
    try:
        with _metadata_handle(kernel, path) as handle:
            opened = True
            key = _file_key(kernel, handle)
            info = _standard_info(kernel, handle)
            if info.delete_pending or not info.links:
                raise OSError("File identity is pending deletion")
            links = ()
            if not info.directory and info.links > 1:
                links = _link_paths(kernel, path, key, info.links)
                observed = _standard_info(kernel, handle)
                if observed.delete_pending or observed.links != info.links:
                    raise OSError("The file's link count changed during enumeration")
            return WindowsFileIdentity(*key, links)
    except FileNotFoundError:
        if opened:
            raise
        return None
