"""Execution-scoped security descriptor for the unified Windows pipe."""

import ctypes as ct
from ctypes import wintypes as wt

PIPE_REJECT_REMOTE_CLIENTS = 8
# Client I/O, excluding FILE_CREATE_PIPE_INSTANCE (0x4).
PIPE_CLIENT_ACCESS = 0x0012019b


class TokenUser(ct.Structure):
    _fields_ = [("Sid", ct.c_void_p), ("Attributes", wt.DWORD)]


class SecurityAttributes(ct.Structure):
    _fields_ = [
        ("nLength", wt.DWORD),
        ("lpSecurityDescriptor", ct.c_void_p),
        ("bInheritHandle", wt.BOOL),
    ]


class PipeSecurity:
    def __init__(self, additional_sids=(), *, client_access=PIPE_CLIENT_ACCESS):
        self.kernel = ct.WinDLL("kernel32", use_last_error=True)
        security = ct.WinDLL("advapi32", use_last_error=True)
        self.kernel.GetCurrentProcess.restype = wt.HANDLE
        self.kernel.CloseHandle.argtypes = [wt.HANDLE]
        self.kernel.LocalFree.argtypes = [ct.c_void_p]
        security.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ct.POINTER(wt.HANDLE)]
        security.GetTokenInformation.argtypes = [
            wt.HANDLE,
            ct.c_int,
            ct.c_void_p,
            wt.DWORD,
            ct.POINTER(wt.DWORD),
        ]
        security.ConvertSidToStringSidW.argtypes = [ct.c_void_p, ct.POINTER(ct.c_wchar_p)]
        security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wt.LPCWSTR,
            wt.DWORD,
            ct.POINTER(ct.c_void_p),
            ct.c_void_p,
        ]
        token, size = wt.HANDLE(), wt.DWORD()
        if not security.OpenProcessToken(self.kernel.GetCurrentProcess(), 8, ct.byref(token)):
            raise ct.WinError(ct.get_last_error())
        try:
            security.GetTokenInformation(token, 1, None, 0, ct.byref(size))
            user = ct.create_string_buffer(size.value)
            if not security.GetTokenInformation(token, 1, user, size, ct.byref(size)):
                raise ct.WinError(ct.get_last_error())
            sid = ct.c_wchar_p()
            if not security.ConvertSidToStringSidW(
                TokenUser.from_buffer_copy(user).Sid, ct.byref(sid)
            ):
                raise ct.WinError(ct.get_last_error())
            try:
                self.owner_sid = sid.value
                self.allowed_sids = frozenset(additional_sids) | {self.owner_sid}
                descriptor = f"D:P(A;;GA;;;{self.owner_sid})" + "".join(
                    f"(A;;0x{client_access:08x};;;{principal})"
                    for principal in sorted(self.allowed_sids - {self.owner_sid})
                )
            finally:
                self.kernel.LocalFree(sid)
        finally:
            self.kernel.CloseHandle(token)
        self.descriptor = ct.c_void_p()
        if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor,
            1,
            ct.byref(self.descriptor),
            None,
        ):
            raise ct.WinError(ct.get_last_error())
        self.attributes = SecurityAttributes(ct.sizeof(SecurityAttributes), self.descriptor, False)

    def apply(self, handle):
        security = ct.WinDLL("advapi32", use_last_error=True)
        update = security.SetKernelObjectSecurity
        update.argtypes, update.restype = [wt.HANDLE, wt.DWORD, ct.c_void_p], wt.BOOL
        if not update(handle, 4 | 0x80000000, self.descriptor):  # protected DACL only
            raise ct.WinError(ct.get_last_error())

    def pointer(self):
        return ct.cast(ct.pointer(self.attributes), ct.c_void_p)

    def close(self):
        if self.descriptor:
            self.kernel.LocalFree(self.descriptor)
            self.descriptor = None
