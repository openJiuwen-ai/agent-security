"""Windows x64 suspended-process import injection and Job ownership.

Optional SDK runtime; importing it does not initialize Windows APIs.
"""

from __future__ import annotations

import ctypes as ct
import struct
from ctypes import wintypes as wt
from pathlib import Path


def _validate_import_limits(descriptors: int, path_bytes: int) -> None:
    if descriptors >= 128:
        raise ct.WinError(214)  # ERROR_TOO_MANY_MODULES
    if not 0 < path_bytes <= 1200:
        raise ct.WinError(122)  # ERROR_INSUFFICIENT_BUFFER


def _validate_child_header(header: bytes) -> int:
    """Validate the AMD64 header before consulting optional-header fields."""
    if len(header) != 4096 or header[:2] != b"MZ":
        raise ct.WinError(193)  # ERROR_BAD_EXE_FORMAT
    pe = struct.unpack_from("<I", header, 0x3C)[0]
    if pe > 3000 or header[pe:pe + 4] != b"PE\0\0":
        raise ct.WinError(193)
    opt = pe + 24
    if (
        struct.unpack_from("<H", header, pe + 4)[0] != 0x8664
        or struct.unpack_from("<H", header, opt)[0] != 0x20B
    ):
        raise ct.WinError(216)  # ERROR_EXE_MACHINE_TYPE_MISMATCH
    return opt


class CacheRevocation:
    """One-shot manual-reset event shared by the injected process tree."""

    def __init__(self, job):
        self.job = job
        create = job.api("CreateEventW", wt.HANDLE, ct.c_void_p, wt.BOOL, wt.BOOL, wt.LPCWSTR)
        self.handle = job.check_result(create(None, True, False, None), "Create cache event")

    def duplicate_wait_handle(self, pid):
        # Grant SYNCHRONIZE only. A child must never be able to reset this event.
        job = self.job
        process = job.open_process(pid, 0x1040)  # QUERY_LIMITED_INFORMATION | DUP_HANDLE
        try:
            member = wt.BOOL()
            check = job.api("IsProcessInJob", wt.BOOL, wt.HANDLE, wt.HANDLE, ct.POINTER(wt.BOOL))
            if not check(process, job.handle, ct.byref(member)) or not member.value:
                return 0
            remote = wt.HANDLE()
            duplicate = job.api(
                "DuplicateHandle",
                wt.BOOL,
                wt.HANDLE,
                wt.HANDLE,
                wt.HANDLE,
                ct.POINTER(wt.HANDLE),
                wt.DWORD,
                wt.BOOL,
                wt.DWORD,
            )
            if duplicate(-1, self.handle, process, ct.byref(remote), 0x100000, False, 0):
                return remote.value  # Windows kernel handles use 32 significant bits.
            return 0
        finally:
            job.close_handle(process)

    def revoke(self):
        if self.handle:
            signal = self.job.api("SetEvent", wt.BOOL, wt.HANDLE)
            self.job.check_result(signal(self.handle), "Revoke DLL Guard cache")

    def close(self):
        self.revoke()
        self.job.close_handle(self.handle)
        self.handle = None


class WindowsJob:
    """Own a kill-on-close process tree and query kernel-enforced membership."""

    def __init__(self) -> None:
        self.kernel = ct.WinDLL("kernel32", use_last_error=True)
        self.ntdll = ct.WinDLL("ntdll", use_last_error=True)
        self.close_handle = self.api("CloseHandle", wt.BOOL, wt.HANDLE)
        create = self.api("CreateJobObjectW", wt.HANDLE, ct.c_void_p, wt.LPCWSTR)
        self.handle = create(None, None)
        self.check_result(self.handle, "CreateJobObjectW")
        # JOBOBJECT_EXTENDED_LIMIT_INFORMATION on Windows x64 (144 bytes).
        limits = ct.create_string_buffer(144)
        struct.pack_into("<I", limits, 16, 0x2000)  # KILL_ON_JOB_CLOSE
        set_info = self.api(
            "SetInformationJobObject", wt.BOOL, wt.HANDLE, ct.c_int, ct.c_void_p, wt.DWORD
        )
        try:
            self.check_result(
                set_info(self.handle, 9, limits, len(limits)), "SetInformationJobObject"
            )
        except BaseException:
            self.close()
            raise

    def api(self, name, result, *args, library=None):
        function = getattr(library or self.kernel, name)
        function.restype, function.argtypes = result, list(args)
        return function

    @staticmethod
    def check_result(value, operation):
        if not value:
            raise OSError(ct.get_last_error(), operation)
        return value

    def open_process(self, pid: int, access: int = 0x1000):
        return self.check_result(
            self.api("OpenProcess", wt.HANDLE, wt.DWORD, wt.BOOL, wt.DWORD)(access, False, pid),
            "OpenProcess",
        )

    def contains(self, pid: int) -> bool:
        if not self.handle:
            return False
        try:
            process = self.open_process(pid)
        except OSError:
            return False
        try:
            result = wt.BOOL()
            check = self.api("IsProcessInJob", wt.BOOL, wt.HANDLE, wt.HANDLE, ct.POINTER(wt.BOOL))
            return bool(check(process, self.handle, ct.byref(result)) and result.value)
        finally:
            self.close_handle(process)

    def inject_and_resume(self, pid: int, dll: Path, config: bytes) -> None:
        process = self.open_process(pid, 0x1FFFFF)
        try:
            self._inject_import(process, dll, config)
            resume = self.api("NtResumeProcess", ct.c_long, wt.HANDLE, library=self.ntdll)
            status = resume(process)
            if status != 0:
                raise OSError(f"NtResumeProcess failed (NTSTATUS {status & 0xFFFFFFFF:#010x})")
        finally:
            self.close_handle(process)

    def attach(self, pid: int) -> None:
        process = self.open_process(pid, 0x1FFFFF)
        try:
            assign = self.api("AssignProcessToJobObject", wt.BOOL, wt.HANDLE, wt.HANDLE)
            self.check_result(assign(self.handle, process), "AssignProcessToJobObject")
        finally:
            self.close_handle(process)

    def process_image(self, pid: int) -> str:
        process = self.open_process(pid)
        try:
            buffer, size = ct.create_unicode_buffer(32768), wt.DWORD(32768)
            query = self.api(
                "QueryFullProcessImageNameW",
                wt.BOOL,
                wt.HANDLE,
                wt.DWORD,
                wt.LPWSTR,
                ct.POINTER(wt.DWORD),
            )
            self.check_result(query(process, 0, buffer, ct.byref(size)), "Query process image")
            return buffer.value
        finally:
            self.close_handle(process)

    def _inject_import(self, process, dll: Path, config: bytes) -> None:
        if len(config) != 1028 or config[:4] != struct.pack("<I", 0x44474333):
            raise ValueError("Invalid DLL Guard bootstrap configuration")
        read = self.api(
            "ReadProcessMemory",
            wt.BOOL,
            wt.HANDLE,
            ct.c_void_p,
            ct.c_void_p,
            ct.c_size_t,
            ct.POINTER(ct.c_size_t),
        )
        write = self.api(
            "WriteProcessMemory",
            wt.BOOL,
            wt.HANDLE,
            ct.c_void_p,
            ct.c_void_p,
            ct.c_size_t,
            ct.POINTER(ct.c_size_t),
        )
        protect = self.api(
            "VirtualProtectEx",
            wt.BOOL,
            wt.HANDLE,
            ct.c_void_p,
            ct.c_size_t,
            wt.DWORD,
            ct.POINTER(wt.DWORD),
        )

        def read_bytes(address, size):
            buffer, count = ct.create_string_buffer(size), ct.c_size_t()
            self.check_result(
                read(process, address, buffer, size, ct.byref(count)), "ReadProcessMemory"
            )
            if count.value != size:
                raise OSError("Incomplete process memory read")
            return buffer.raw

        def write_bytes(address, data):
            count, buffer = ct.c_size_t(), ct.create_string_buffer(data)
            self.check_result(
                write(process, address, buffer, len(data), ct.byref(count)), "WriteProcessMemory"
            )
            if count.value != len(data):
                raise OSError("Incomplete process memory write")

        query = self.api(
            "NtQueryInformationProcess",
            ct.c_long,
            wt.HANDLE,
            wt.ULONG,
            ct.c_void_p,
            wt.ULONG,
            ct.c_void_p,
            library=self.ntdll,
        )
        info = (ct.c_void_p * 6)()
        status = query(process, 0, info, ct.sizeof(info), None)
        if status:
            raise OSError(f"Cannot query process image (NTSTATUS {status & 0xFFFFFFFF:#010x})")
        image = struct.unpack("<Q", read_bytes(info[1] + 0x10, 8))[0]
        header = read_bytes(image, 4096)
        opt = _validate_child_header(header)
        image_size = struct.unpack_from("<I", header, opt + 56)[0]
        import_rva = struct.unpack_from("<I", header, opt + 120)[0]
        entries = []
        if import_rva:
            for index in range(128):
                entry = read_bytes(image + import_rva + index * 20, 20)
                if entry == bytes(20):
                    break
                entries.append(entry)
        # A lossy ANSI conversion could identify a different file.
        try:
            encoded_name = str(dll).encode("mbcs", errors="strict")
        except UnicodeEncodeError as exc:
            raise ct.WinError(1113) from exc
        if encoded_name.decode("mbcs") != str(dll):
            raise ct.WinError(1113)  # ERROR_NO_UNICODE_TRANSLATION
        name = encoded_name + b"\0"
        _validate_import_limits(len(entries), len(name))
        if len(str(dll).encode("utf-16-le")) // 2 >= 1023:
            raise ValueError("DLL path exceeds the descendant loader's supported size")
        allocate = self.api(
            "VirtualAllocEx", ct.c_void_p, wt.HANDLE, ct.c_void_p, ct.c_size_t, wt.DWORD, wt.DWORD
        )
        start = (image + image_size + 65535) & ~65535
        remote = None
        for delta in range(0, 64 * 1024 * 1024, 65536):
            remote = allocate(process, start + delta, 8192, 0x3000, 4)
            if remote:
                break
        self.check_result(remote, "Allocate import table")
        rva = remote - image
        if not 0 < rva < 0xFFFFFFFF:
            raise ValueError("Import table address out of range")
        count = len(entries) + 2
        name_offset = (count * 20 + 7) & ~7
        ilt = (name_offset + len(name) + 7) & ~7
        iat, symbol = ilt + 16, ilt + 32
        label = b"\0\0GuardMarker\0"
        if symbol + 32 > 4096:
            raise ValueError("DLL import path exceeds supported size")
        # The second page carries per-process configuration. DllMain reads it
        # relative to the injected import directory; no sidecar or env mutation.
        payload = bytearray(8192)
        payload[4096:4096 + len(config)] = config
        # Install Guard outside the already installed soft-delete hook chain.
        # Only trust the exact module loaded by this host, never a basename
        # supplied by the target executable's import table.
        insertion = 0
        module = self.api("GetModuleHandleW", wt.HMODULE, wt.LPCWSTR)("jiuwen_softdelete.dll")
        if module and entries:
            loaded = ct.create_string_buffer(32768)
            get_name = self.api("GetModuleFileNameA", wt.DWORD, wt.HMODULE, ct.c_void_p, wt.DWORD)
            self.check_result(get_name(module, loaded, len(loaded)), "Query soft-delete module")
            entry_name = struct.unpack_from("<I", entries[0], 12)[0]
            imported = bytearray()
            for offset in range(32768):
                character = read_bytes(image + entry_name + offset, 1)
                if character == b"\0":
                    break
                imported.extend(character)
            if bytes(imported).lower() == loaded.value.lower():
                insertion = 1
        guard_entry = struct.pack("<IIIII", rva + ilt, 0, 0, rva + name_offset, rva + iat)
        entries.insert(insertion, guard_entry)
        for index, entry in enumerate(entries):
            payload[index * 20:(index + 1) * 20] = entry
        payload[name_offset:name_offset + len(name)] = name
        struct.pack_into("<Q", payload, ilt, rva + symbol)
        struct.pack_into("<Q", payload, iat, rva + symbol)
        payload[symbol:symbol + len(label)] = label
        write_bytes(remote, bytes(payload))
        old = wt.DWORD()
        self.check_result(protect(process, image, 4096, 4, ct.byref(old)), "Unprotect PE header")
        try:
            write_bytes(image + opt + 120, struct.pack("<II", rva, count * 20))
            write_bytes(image + opt + 200, bytes(8))
        finally:
            unused = wt.DWORD()
            self.check_result(
                protect(process, image, 4096, old.value, ct.byref(unused)), "Restore PE protection"
            )

    def close(self) -> None:
        if self.handle:
            self.close_handle(self.handle)
            self.handle = None

    def active_processes(self) -> int:
        """Count descendants as well as the original asyncio subprocess."""
        if not self.handle:
            return 0
        info = ct.create_string_buffer(48)
        query = self.api(
            "QueryInformationJobObject",
            wt.BOOL,
            wt.HANDLE,
            ct.c_int,
            ct.c_void_p,
            wt.DWORD,
            ct.c_void_p,
        )
        self.check_result(query(self.handle, 1, info, len(info), None), "Query Job process count")
        return struct.unpack_from("<I", info, 40)[0]


def windows_argv(command: str) -> list[str]:
    """Decode the actual Windows command line without invoking a shell."""
    shell = ct.WinDLL("shell32", use_last_error=True)
    kernel = ct.WinDLL("kernel32", use_last_error=True)
    shell.CommandLineToArgvW.restype = ct.POINTER(wt.LPWSTR)
    shell.CommandLineToArgvW.argtypes = [wt.LPCWSTR, ct.POINTER(ct.c_int)]
    kernel.LocalFree.argtypes = [ct.c_void_p]
    kernel.LocalFree.restype = ct.c_void_p
    count = ct.c_int()
    pointer = shell.CommandLineToArgvW(command, ct.byref(count))
    if not pointer:
        raise ValueError("Invalid Windows command line")
    try:
        return [pointer[index] for index in range(count.value)]
    finally:
        kernel.LocalFree(pointer)
