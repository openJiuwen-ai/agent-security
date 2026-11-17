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
        process = job.open_member(pid, 0x1040)  # QUERY_LIMITED_INFORMATION | DUP_HANDLE
        if process is None:
            return 0
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
        self._registered_members = {}
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

    def open_member(self, pid: int, access=0x1000):
        return self._open_member(pid, access)

    def contains(self, pid: int) -> bool:
        process = self._open_member(pid)
        if process is None:
            return False
        self.close_handle(process)
        return True

    def _open_member(self, pid: int, access=0x1000):
        if not self.handle:
            return None
        try:
            retained = self._registered_members.get(pid)
            if retained:
                process = wt.HANDLE()
                duplicate = self.api("DuplicateHandle", wt.BOOL, wt.HANDLE, wt.HANDLE,
                                     wt.HANDLE, ct.POINTER(wt.HANDLE), wt.DWORD, wt.BOOL, wt.DWORD)
                self.check_result(
                    duplicate(-1, retained, -1, ct.byref(process), 0, False, 2),
                    "Duplicate registered member",
                )
            else:
                process = self.open_process(pid, access)
        except OSError:
            return None
        result = wt.BOOL()
        check = self.api("IsProcessInJob", wt.BOOL, wt.HANDLE, wt.HANDLE, ct.POINTER(wt.BOOL))
        if check(process, self.handle, ct.byref(result)) and result.value:
            return process
        self.close_handle(process)
        return None

    def member_instance_id(self, pid: int) -> str | None:
        """Use the legacy PID:creation-FILETIME identity on a verified Job member."""
        process = self._open_member(pid)
        if process is None:
            return None
        try:
            times = [wt.FILETIME() for _ in range(4)]
            get_times = self.api("GetProcessTimes", wt.BOOL, wt.HANDLE, *([ct.POINTER(wt.FILETIME)] * 4))
            if not get_times(process, *(ct.byref(value) for value in times)):
                return None
            created = times[0]
            return f"{pid}:{(created.dwHighDateTime << 32) | created.dwLowDateTime}"
        finally:
            self.close_handle(process)

    def inject_and_resume(self, pid: int, dll: Path, config: bytes) -> None:
        process = self.open_process(pid, 0x1FFFFF)
        try:
            wow64 = wt.BOOL()
            query = self.api("IsWow64Process", wt.BOOL, wt.HANDLE, ct.POINTER(wt.BOOL))
            self.check_result(query(process, ct.byref(wow64)), "Query target architecture")
            if wow64.value:
                load = self.api("LoadLibraryW", wt.HMODULE, wt.LPCWSTR)
                module = self.check_result(load(str(dll)), "Load x86 Guard helper")
                try:
                    resolve = self.api("GetProcAddress", ct.c_void_p, wt.HMODULE, wt.LPCSTR)
                    address = self.check_result(
                        resolve(module, b"guard_prepare_session"),
                        "Resolve x86 session export",
                    )
                    prepare = ct.WINFUNCTYPE(wt.BOOL, wt.HANDLE, ct.c_void_p, wt.DWORD)(address)
                    binding = ct.create_string_buffer(config)
                    self.check_result(prepare(process, binding, len(config)), "Prepare x86 Guard session")
                finally:
                    self.api("FreeLibrary", wt.BOOL, wt.HMODULE)(module)
            else:
                self._inject_import(process, dll, config)
            resume = self.api("NtResumeProcess", ct.c_long, wt.HANDLE, library=self.ntdll)
            status = resume(process)
            if status != 0:
                raise OSError(f"NtResumeProcess failed (NTSTATUS {status & 0xFFFFFFFF:#010x})")
        finally:
            self.close_handle(process)

    def member_identity(self, pid: int) -> dict:
        """Read audit identity from a verified member, never from an IPC claim."""
        process = self._open_member(pid)
        if process is None:
            raise OSError("Process is no longer a Guard Job member")
        security = ct.WinDLL("advapi32", use_last_error=True)
        token = wt.HANDLE()
        security.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ct.POINTER(wt.HANDLE)]
        security.GetTokenInformation.argtypes = [wt.HANDLE, ct.c_int, ct.c_void_p, wt.DWORD, ct.POINTER(wt.DWORD)]
        security.ConvertSidToStringSidW.argtypes = [ct.c_void_p, ct.POINTER(ct.c_wchar_p)]
        free = self.api("LocalFree", ct.c_void_p, ct.c_void_p)
        try:
            self.check_result(security.OpenProcessToken(process, 8, ct.byref(token)), "Open audit token")

            def token_sid(kind):
                size = wt.DWORD()
                security.GetTokenInformation(token, kind, None, 0, ct.byref(size))
                buffer = ct.create_string_buffer(size.value)
                self.check_result(
                    security.GetTokenInformation(token, kind, buffer, size, ct.byref(size)),
                    "Read audit token",
                )
                text = ct.c_wchar_p()
                self.check_result(
                    security.ConvertSidToStringSidW(ct.c_void_p.from_buffer_copy(buffer), ct.byref(text)),
                    "Format audit SID",
                )
                try:
                    return text.value
                finally:
                    free(text)

            user_sid, integrity_sid = token_sid(1), token_sid(25)
            level = int(integrity_sid.rsplit("-", 1)[1])
            info = (ct.c_void_p * 6)()
            query = self.api(
                "NtQueryInformationProcess", ct.c_long, wt.HANDLE, wt.ULONG, ct.c_void_p,
                wt.ULONG, ct.c_void_p, library=self.ntdll,
            )
            if query(process, 0, info, ct.sizeof(info), None):
                raise OSError("Read audit process parent")
            return {
                "pid": pid, "parent_pid": info[5], "image": self.process_image(pid),
                "process_instance_id": self.member_instance_id(pid), "user_sid": user_sid,
                "integrity_level": "system" if level >= 16384 else "high" if level >= 12288
                else "medium" if level >= 8192 else "low" if level >= 4096 else "untrusted",
            }
        finally:
            if token.value:
                self.close_handle(token)
            self.close_handle(process)

    def attach(self, pid: int) -> None:
        process = self.open_process(pid, 0x1FFFFF)
        try:
            assign = self.api("AssignProcessToJobObject", wt.BOOL, wt.HANDLE, wt.HANDLE)
            self.check_result(assign(self.handle, process), "AssignProcessToJobObject")
        finally:
            self.close_handle(process)

    def register_child_handle(self, parent_pid: int, remote_handle: int, *, authorize=None) -> bool:
        """Accept only a real child handle held by an authenticated Job member."""
        if remote_handle <= 0 or remote_handle >= (1 << 64) - 16:
            return False
        # A registered cross-account parent may not be reopenable by PID.
        parent = self._open_member(parent_pid, 0x1040)
        if parent is None:
            return False
        child = wt.HANDLE()
        try:
            member = wt.BOOL()
            check = self.api("IsProcessInJob", wt.BOOL, wt.HANDLE, wt.HANDLE, ct.POINTER(wt.BOOL))
            if not check(parent, self.handle, ct.byref(member)) or not member.value:
                return False
            duplicate = self.api(
                "DuplicateHandle", wt.BOOL, wt.HANDLE, wt.HANDLE, wt.HANDLE,
                ct.POINTER(wt.HANDLE), wt.DWORD, wt.BOOL, wt.DWORD,
            )
            current = self.api("GetCurrentProcess", wt.HANDLE)()
            if not duplicate(parent, remote_handle, current, ct.byref(child), 0, False, 2):
                return False
            info = (ct.c_void_p * 6)()
            query = self.api(
                "NtQueryInformationProcess", ct.c_long, wt.HANDLE, wt.ULONG,
                ct.c_void_p, wt.ULONG, ct.c_void_p, library=self.ntdll,
            )
            if query(child, 0, info, ct.sizeof(info), None) or info[5] != parent_pid:
                return False
            if not (check(child, self.handle, ct.byref(member)) and member.value):
                assign = self.api("AssignProcessToJobObject", wt.BOOL, wt.HANDLE, wt.HANDLE)
                if not assign(self.handle, child):
                    return False
            get_pid = self.api("GetProcessId", wt.DWORD, wt.HANDLE)
            pid = get_pid(child)
            if not pid:
                return False
            previous = self._registered_members.get(pid)
            self._registered_members[pid] = child
            try:
                if authorize is not None:
                    authorize(self.member_identity(pid))
            except BaseException:
                if previous:
                    self._registered_members[pid] = previous
                else:
                    self._registered_members.pop(pid, None)
                raise
            if previous:
                self.close_handle(previous)
            child = wt.HANDLE()
            return True
        finally:
            if child.value:
                self.close_handle(child)
            self.close_handle(parent)

    def process_image(self, pid: int) -> str:
        process = self._open_member(pid)
        if process is None:
            raise OSError("Process is not a Guard Job member")
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

    def process_command_line(self, pid: int) -> str:
        process = self._open_member(pid)
        if process is None:
            raise OSError("Process is not a Guard Job member")

        class UnicodeString(ct.Structure):
            _fields_ = [("length", wt.USHORT), ("maximum", wt.USHORT), ("buffer", ct.c_void_p)]
        try:
            query = self.api("NtQueryInformationProcess", ct.c_long, wt.HANDLE, wt.ULONG,
                             ct.c_void_p, wt.ULONG, ct.POINTER(wt.ULONG), library=self.ntdll)
            required = wt.ULONG()
            query(process, 60, None, 0, ct.byref(required))
            if not ct.sizeof(UnicodeString) <= required.value <= 131072:
                raise OSError("Invalid process command line length")
            buffer = ct.create_string_buffer(required.value)
            status = query(process, 60, buffer, len(buffer), ct.byref(required))
            value = UnicodeString.from_buffer(buffer)
            start = ct.addressof(buffer)
            end = start + len(buffer)
            inside = bool(value.buffer) and start <= value.buffer <= value.buffer + value.length <= end
            invalid = status < 0 or value.length % 2
            if invalid or not inside:
                raise OSError("Cannot query process command line")
            return ct.wstring_at(value.buffer, value.length // 2)
        finally:
            self.close_handle(process)

    def _inject_import(self, process, dll: Path, config: bytes) -> None:
        if len(config) != 1032 or config[:4] != struct.pack("<I", 0x44474333):
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
        guard_entry = struct.pack("<IIIII", rva + ilt, 0, 0, rva + name_offset, rva + iat)
        entries.insert(0, guard_entry)
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
        for process in self._registered_members.values():
            self.close_handle(process)
        self._registered_members.clear()

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
