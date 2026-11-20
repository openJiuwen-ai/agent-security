/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 *
 * Windows soft delete shares the native disposition with the Shield runtime.
 * Ordinary children use suspended import preparation. Standalone MSYS shells
 * run under a debug loop; at CREATE_PROCESS_DEBUG_EVENT their delete tools
 * receive the same import preparation and immutable recovery payload before
 * loader startup. Preparation or DLL initialization failure prevents execution.
 * MSYS unlink/rmdir entry points report disposition synchronously through the
 * runtime's own errno, rather than deferring failures to an ignored NtClose.
 * Log paths copied through MSYS (/c/...) are turned back into drive paths so
 * short-lived Git tools can append the existing full.log. Every line is
 * marked [soft_delete].
 * Console hosts (conhost.exe) are left alone: injecting them crashes
 * the host and the parent exits with STATUS_DLL_INIT_FAILED.
 * MinGW images (libwinpthread-1.dll beside the exe, including git.exe)
 * and explorer.exe are not injected either. They live outside the
 * install directory and would keep this file locked across an upgrade.
 * A Git `rm` that holds this DLL is short-lived; overwrite-install still
 * finds it with Restart Manager on this file, same as other holders.
 *
 * Delete calls are turned into a recycle-bin move, or a same-volume rename
 * into the archive directory. A sandbox process turns a relative name into a
 * full path first, then asks box-server to recycle it as the logged-in user.
 * Recover mode returns a failure when the selected backend cannot confirm recovery.
 */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <winternl.h>
#include "recovery.h"
#include "softdelete.h"
#include "guard_lifecycle.h"
#include "file_hooks.h"
#include <shellapi.h>
#include <objbase.h>
#include <detours.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if !defined(_MSC_VER)
static void soft_wcopy(wchar_t *dst, size_t cap, const wchar_t *src) {
    size_t i = 0;
    if (dst == NULL || cap == 0) {
        return;
    }
    if (src == NULL) {
        dst[0] = L'\0';
        return;
    }
    while (i + 1 < cap && src[i] != L'\0') {
        dst[i] = src[i];
        i++;
    }
    dst[i] = L'\0';
}

static void soft_wcat(wchar_t *dst, size_t cap, const wchar_t *src) {
    size_t used = 0;
    if (dst == NULL || cap == 0) {
        return;
    }
    while (used < cap && dst[used] != L'\0') {
        used++;
    }
    if (used >= cap) {
        dst[cap - 1] = L'\0';
        return;
    }
    soft_wcopy(dst + used, cap - used, src);
}

static void format_unsigned(wchar_t *tmp, int *n, unsigned long value, int width) {
    int i = 0;
    wchar_t rev[32];
    if (value == 0) {
        rev[i++] = L'0';
    }
    while (value > 0 && i < 31) {
        rev[i++] = (wchar_t)(L'0' + (value % 10));
        value /= 10;
    }
    while (i < width && i < 31) {
        rev[i++] = L'0';
    }
    *n = i;
    while (i > 0) {
        tmp[(*n) - i] = rev[i - 1];
        i--;
    }
}

static int append_text(wchar_t *dst, size_t cap, size_t *used, const wchar_t *src) {
    if (src == NULL) {
        src = L"";
    }
    while (*src != L'\0') {
        if (*used + 1 >= cap) {
            if (cap > 0) {
                dst[cap - 1] = L'\0';
            }
            return -1;
        }
        dst[(*used)++] = *src++;
    }
    return 0;
}

/* %s, %d/%ld, %u/%lu, and zero-padded %04u only. No C runtime formatter. */
static int soft_vswprintf(wchar_t *dst, size_t cap, const wchar_t *fmt, va_list args) {
    size_t used = 0;
    if (dst == NULL || cap == 0) {
        return -1;
    }
    dst[0] = L'\0';
    if (fmt == NULL) {
        return -1;
    }
    while (*fmt != L'\0') {
        if (*fmt != L'%') {
            wchar_t one[2];
            one[0] = *fmt;
            one[1] = L'\0';
            if (append_text(dst, cap, &used, one) < 0) {
                return -1;
            }
            fmt++;
            continue;
        }
        fmt++;
        if (*fmt == L'%') {
            if (append_text(dst, cap, &used, L"%") < 0) {
                return -1;
            }
            fmt++;
            continue;
        }
        {
            int width = 0;
            wchar_t num[32];
            int n = 0;
            if (*fmt == L'0') {
                fmt++;
            }
            while (*fmt >= L'0' && *fmt <= L'9') {
                width = width * 10 + (int)(*fmt - L'0');
                fmt++;
            }
            if (*fmt == L'l') {
                fmt++;
            }
            if (*fmt == L's') {
                if (append_text(dst, cap, &used, va_arg(args, const wchar_t *)) < 0) {
                    return -1;
                }
            } else if (*fmt == L'd') {
                long value = va_arg(args, long);
                unsigned long mag;
                if (value < 0) {
                    if (append_text(dst, cap, &used, L"-") < 0) {
                        return -1;
                    }
                    mag = (unsigned long)(-(value + 1)) + 1;
                } else {
                    mag = (unsigned long)value;
                }
                format_unsigned(num, &n, mag, width);
                num[n] = L'\0';
                if (append_text(dst, cap, &used, num) < 0) {
                    return -1;
                }
            } else if (*fmt == L'u') {
                format_unsigned(num, &n, va_arg(args, unsigned long), width);
                num[n] = L'\0';
                if (append_text(dst, cap, &used, num) < 0) {
                    return -1;
                }
            } else {
                dst[0] = L'\0';
                return -1;
            }
            if (*fmt != L'\0') {
                fmt++;
            }
        }
    }
    if (used >= cap) {
        dst[cap - 1] = L'\0';
        return -1;
    }
    dst[used] = L'\0';
    return (int)used;
}

static int soft_swprintf(wchar_t *dst, size_t cap, const wchar_t *fmt, ...) {
    va_list args;
    int wrote;
    va_start(args, fmt);
    wrote = soft_vswprintf(dst, cap, fmt, args);
    va_end(args);
    return wrote;
}

static int soft_sprintf(char *dst, size_t cap, const char *fmt, ...) {
    wchar_t wide_fmt[256];
    wchar_t wide_out[256];
    size_t i;
    int wrote;
    va_list args;
    if (dst == NULL || cap == 0 || fmt == NULL) {
        return -1;
    }
    for (i = 0; fmt[i] != '\0' && i + 1 < 256; i++) {
        wide_fmt[i] = (wchar_t)(unsigned char)fmt[i];
    }
    wide_fmt[i] = L'\0';
    va_start(args, fmt);
    wrote = soft_vswprintf(wide_out, 256, wide_fmt, args);
    va_end(args);
    if (wrote < 0) {
        dst[0] = '\0';
        return -1;
    }
    for (i = 0; wide_out[i] != L'\0' && i + 1 < cap; i++) {
        dst[i] = (char)wide_out[i];
    }
    dst[i] = '\0';
    return (int)i;
}

#define wcscpy_s(dst, cap, src) soft_wcopy((dst), (cap), (src))
#define wcsncpy_s(dst, cap, src, trunc) soft_wcopy((dst), (cap), (src))
#define wcscat_s(dst, cap, src) soft_wcat((dst), (cap), (src))
#define swprintf_s soft_swprintf
#define sprintf_s soft_sprintf
#endif

static int memory_ok(const void *ptr, size_t bytes, int writable) {
    const uint8_t *cursor = (const uint8_t *)ptr;
    const uint8_t *end;
    if (ptr == NULL || bytes == 0) {
        return 0;
    }
    end = cursor + bytes;
    while (cursor < end) {
        MEMORY_BASIC_INFORMATION info;
        DWORD protect;
        uintptr_t region_end;
        if (VirtualQuery(cursor, &info, sizeof info) == 0 || info.State != MEM_COMMIT) {
            return 0;
        }
        if ((info.Protect & PAGE_GUARD) != 0) {
            return 0;
        }
        protect = info.Protect & 0xFF;
        if (writable) {
            if (protect != PAGE_READWRITE && protect != PAGE_WRITECOPY
                && protect != PAGE_EXECUTE_READWRITE && protect != PAGE_EXECUTE_WRITECOPY) {
                return 0;
            }
        } else if (protect != PAGE_READONLY && protect != PAGE_READWRITE && protect != PAGE_WRITECOPY
                   && protect != PAGE_EXECUTE_READ && protect != PAGE_EXECUTE_READWRITE
                   && protect != PAGE_EXECUTE_WRITECOPY) {
            return 0;
        }
        region_end = (uintptr_t)info.BaseAddress + info.RegionSize;
        if (region_end <= (uintptr_t)cursor) {
            return 0;
        }
        cursor = (const uint8_t *)region_end;
    }
    return 1;
}

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034L)
#define FILE_DISPOSITION_INFORMATION 13UL
#define FILE_DISPOSITION_INFORMATION_EX 64UL
#define FILE_RENAME_INFORMATION 10UL
#define FILE_RENAME_INFORMATION_EX 65UL
#define FILE_RENAME_REPLACE_IF_EXISTS 0x00000001UL
/* NtCreateFile option. Windows SDK puts this in winternl.h only. */
#ifndef FILE_DELETE_ON_CLOSE
#define FILE_DELETE_ON_CLOSE 0x00001000UL
#endif

#define ENV_ENABLED L"JIUWENBOX_SOFT_DELETE"
#define ENV_ARCHIVE L"JIUWENBOX_SOFT_DELETE_ARCHIVE"
#define ENV_DLL L"JIUWENBOX_SOFT_DELETE_DLL"
#define ENV_RECYCLE_PORT L"JIUWENBOX_SOFT_DELETE_RECYCLE_PORT"
#define ENV_RECYCLE_TOKEN L"JIUWENBOX_SOFT_DELETE_RECYCLE_TOKEN"
#define ENV_TRACE L"JIUWENBOX_SOFT_DELETE_TRACE"
#define ENV_RESULTS L"JIUWENBOX_SOFT_DELETE_RESULTS"
#define RECYCLE_TOKEN_MAX 256u
#define RECYCLE_PATH_MAX (48u * 1024u)
#define PENDING_MAX 1024
#define PATH_CAP 32768
#define INFO_COPY_MAX (20u + (PATH_CAP * (ULONG)sizeof(wchar_t)))

typedef LONG NTSTATUS;
typedef ULONG ACCESS_MASK;

typedef struct _UNICODE_STRING_ {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING_;

typedef struct _OBJECT_ATTRIBUTES_ {
    ULONG Length;
    HANDLE RootDirectory;
    UNICODE_STRING_ *ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES_;

typedef struct _IO_STATUS_BLOCK_ {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } StatusUnion;
    ULONG_PTR Information;
} IO_STATUS_BLOCK_;

typedef NTSTATUS(NTAPI *FnNtClose)(HANDLE);
typedef NTSTATUS(NTAPI *FnNtDeleteFile)(OBJECT_ATTRIBUTES_ *);
typedef NTSTATUS(NTAPI *FnNtSetInformationFile)(
    HANDLE, IO_STATUS_BLOCK_ *, PVOID, ULONG, ULONG);
typedef NTSTATUS(NTAPI *FnNtCreateFile)(
    HANDLE *, ACCESS_MASK, OBJECT_ATTRIBUTES_ *, IO_STATUS_BLOCK_ *,
    LARGE_INTEGER *, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI *FnNtOpenFile)(
    HANDLE *, ACCESS_MASK, OBJECT_ATTRIBUTES_ *, IO_STATUS_BLOCK_ *,
    ULONG, ULONG);
typedef BOOL(WINAPI *FnCreateProcessInternalW)(
    HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION,
    HANDLE *);

static HMODULE g_module;
static wchar_t g_self_path[PATH_CAP];
static CRITICAL_SECTION g_lock;
static int g_lock_ready;
/* DllMain holds the loader lock. Do not call msys getenv from that window. */
static int g_in_dllmain;
#if defined(__GNUC__)
#define SOFT_EXPORT __attribute__((dllexport))
#else
#define SOFT_EXPORT __declspec(dllexport)
#endif

static __declspec(thread) int t_bypass;
static __declspec(thread) int t_worker_creating;

static int g_detours;
static FnNtClose g_nt_close;
static FnNtDeleteFile g_nt_delete_file;
static FnNtSetInformationFile g_nt_set_info;
static FnNtCreateFile g_nt_create_file;
static FnNtOpenFile g_nt_open_file;
static FnCreateProcessInternalW g_create_process;
static BOOL(WINAPI *g_delete_file)(LPCWSTR);
static BOOL(WINAPI *g_remove_directory)(LPCWSTR);

static HANDLE g_pending_handle[PENDING_MAX];
typedef struct {
    HANDLE handle;
    HANDLE reference;
    BY_HANDLE_FILE_INFORMATION identity;
    BOOL recycled;
} DeleteProxy;
static DeleteProxy g_delete_proxy[PENDING_MAX];
static NTSTATUS (NTAPI *query_handle_object)(HANDLE, ULONG, PVOID, ULONG, ULONG *);
static BOOL (WINAPI *compare_object_handles)(HANDLE, HANDLE);
static int directory_is_empty(const wchar_t *path);
static BOOL g_pending_reserved[PENDING_MAX];
static wchar_t *g_pending_path[PENDING_MAX];
static GUID g_pending_operation[PENDING_MAX];
static wchar_t *g_pending_policy_path[PENDING_MAX];

static void log_line(const wchar_t *text);

/* -------------------------------------------------------------------------- */
/* Paths and the actual move.                                                 */
/* -------------------------------------------------------------------------- */

static wchar_t *heap_wcs_dup(const wchar_t *text) {
    size_t n;
    wchar_t *copy;
    if (text == NULL) {
        return NULL;
    }
    n = wcslen(text);
    copy = (wchar_t *)HeapAlloc(GetProcessHeap(), 0, (n + 1) * sizeof(wchar_t));
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, text, (n + 1) * sizeof(wchar_t));
    return copy;
}

static void to_dos_path(const wchar_t *in, wchar_t *out, size_t cch) {
    const wchar_t *src = in;
    if (in == NULL || cch == 0) {
        return;
    }
    out[0] = L'\0';
    if (wcsncmp(in, L"\\\\?\\UNC\\", 8) == 0) {
        if (cch < 3) {
            return;
        }
        out[0] = L'\\';
        out[1] = L'\\';
        src = in + 8;
        wcsncpy_s(out + 2, cch - 2, src, _TRUNCATE);
        return;
    }
    if (wcsncmp(in, L"\\??\\UNC\\", 8) == 0) {
        if (cch < 3) {
            return;
        }
        out[0] = L'\\';
        out[1] = L'\\';
        wcsncpy_s(out + 2, cch - 2, in + 8, _TRUNCATE);
        return;
    }
    if (wcsncmp(in, L"\\\\?\\", 4) == 0) {
        src = in + 4;
    } else if (wcsncmp(in, L"\\??\\", 4) == 0) {
        src = in + 4;
    } else if (wcsncmp(in, L"\\DosDevices\\", 12) == 0) {
        src = in + 12;
    }
    wcsncpy_s(out, cch, src, _TRUNCATE);
}

/* NtQueryObject name is \Device\HarddiskVolumeN\... . Map it back to C:\... */
static int device_path_to_dos(const wchar_t *nt_path, wchar_t *out, size_t cch) {
    wchar_t drive[3];
    wchar_t target[512];
    wchar_t letter;
    size_t prefix;
    size_t rest;
    drive[1] = L':';
    drive[2] = L'\0';
    for (letter = L'C'; letter <= L'Z'; letter++) {
        drive[0] = letter;
        if (QueryDosDeviceW(drive, target, 512) == 0) {
            continue;
        }
        prefix = wcslen(target);
        if (prefix == 0 || _wcsnicmp(nt_path, target, prefix) != 0) {
            continue;
        }
        if (nt_path[prefix] != L'\\' && nt_path[prefix] != L'\0') {
            continue;
        }
        rest = wcslen(nt_path + prefix);
        if (2 + rest + 1 > cch) {
            return 0;
        }
        out[0] = letter;
        out[1] = L':';
        wcsncpy_s(out + 2, cch - 2, nt_path + prefix, _TRUNCATE);
        return 1;
    }
    for (letter = L'A'; letter <= L'B'; letter++) {
        drive[0] = letter;
        if (QueryDosDeviceW(drive, target, 512) == 0) {
            continue;
        }
        prefix = wcslen(target);
        if (prefix == 0 || _wcsnicmp(nt_path, target, prefix) != 0) {
            continue;
        }
        if (nt_path[prefix] != L'\\' && nt_path[prefix] != L'\0') {
            continue;
        }
        rest = wcslen(nt_path + prefix);
        if (2 + rest + 1 > cch) {
            return 0;
        }
        out[0] = letter;
        out[1] = L':';
        wcsncpy_s(out + 2, cch - 2, nt_path + prefix, _TRUNCATE);
        return 1;
    }
    return 0;
}

/* PowerShell opens the file with DELETE access only. GetFinalPathNameByHandle
 * then fails, and a delete would be refused before the recycle broker is asked. */
static int path_from_object_name(HANDLE handle, wchar_t *out, size_t cch) {
    typedef struct {
        USHORT Length;
        USHORT MaximumLength;
        wchar_t *Buffer;
    } SoftUnicodeString;
    typedef struct {
        SoftUnicodeString Name;
    } SoftObjectName;
    typedef NTSTATUS(NTAPI *FnNtQueryObject)(HANDLE, ULONG, PVOID, ULONG, ULONG *);
    static FnNtQueryObject query;
    uint8_t *buf;
    ULONG needed = 0;
    NTSTATUS status;
    SoftObjectName *info;
    wchar_t *name;
    size_t chars;
    int ok = 0;
    if (query == NULL) {
        query = (FnNtQueryObject)(void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject");
        if (query == NULL) {
            return 0;
        }
    }
    buf = (uint8_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 65536);
    if (buf == NULL) {
        return 0;
    }
    status = query(handle, 1, buf, 65536, &needed);
    if (status < 0) {
        HeapFree(GetProcessHeap(), 0, buf);
        return 0;
    }
    info = (SoftObjectName *)buf;
    name = info->Name.Buffer;
    chars = (size_t)info->Name.Length / sizeof(wchar_t);
    if (name == NULL || chars == 0 || chars >= PATH_CAP
        || (uint8_t *)name < buf
        || (uint8_t *)(name + chars) > buf + 65536) {
        HeapFree(GetProcessHeap(), 0, buf);
        return 0;
    }
    {
        wchar_t *text = (wchar_t *)HeapAlloc(
            GetProcessHeap(), 0, (chars + 1) * sizeof(wchar_t));
        if (text == NULL) {
            HeapFree(GetProcessHeap(), 0, buf);
            return 0;
        }
        memcpy(text, name, chars * sizeof(wchar_t));
        text[chars] = L'\0';
        if (wcsncmp(text, L"\\??\\", 4) == 0 || wcsncmp(text, L"\\\\?\\", 4) == 0
            || wcsncmp(text, L"\\DosDevices\\", 12) == 0) {
            to_dos_path(text, out, cch);
            ok = out[0] != L'\0';
        } else if (wcsncmp(text, L"\\Device\\", 8) == 0) {
            ok = device_path_to_dos(text, out, cch);
        }
        HeapFree(GetProcessHeap(), 0, text);
    }
    HeapFree(GetProcessHeap(), 0, buf);
    return ok;
}

static void path_from_handle(HANDLE handle, wchar_t *out, size_t cch) {
    DWORD n;
    wchar_t *raw;
    out[0] = L'\0';
    raw = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PATH_CAP * sizeof(wchar_t));
    if (raw == NULL) {
        return;
    }
    n = GetFinalPathNameByHandleW(handle, raw, PATH_CAP, 0);
    if (n > 0 && n < PATH_CAP) {
        to_dos_path(raw, out, cch);
    }
    HeapFree(GetProcessHeap(), 0, raw);
    if (out[0] == L'\0') {
        path_from_object_name(handle, out, cch);
    }
}

static int join_root_name(HANDLE root, const wchar_t *name, wchar_t *out, size_t cch) {
    wchar_t root_path[PATH_CAP];
    size_t n;
    out[0] = L'\0';
    if (name == NULL || name[0] == L'\0') {
        return 0;
    }
    if (name[0] == L'\\' || (name[0] != L'\0' && name[1] == L':')) {
        to_dos_path(name, out, cch);
        return out[0] != L'\0';
    }
    if (root == NULL || root == INVALID_HANDLE_VALUE) {
        to_dos_path(name, out, cch);
        return out[0] != L'\0';
    }
    path_from_handle(root, root_path, PATH_CAP);
    if (root_path[0] == L'\0') {
        return 0;
    }
    n = wcslen(root_path);
    if (n + 1 + wcslen(name) + 1 >= cch) {
        return 0;
    }
    wcscpy_s(out, cch, root_path);
    if (n > 0 && out[n - 1] != L'\\' && out[n - 1] != L'/') {
        wcscat_s(out, cch, L"\\");
    }
    wcscat_s(out, cch, name);
    return 1;
}

static int path_from_object(OBJECT_ATTRIBUTES_ *oa, wchar_t *out, size_t cch) {
    wchar_t *name = NULL;
    int ok = 0;
    USHORT nbytes;
    out[0] = L'\0';
    if (oa == NULL || !memory_ok(oa, sizeof(*oa), 0)) {
        return 0;
    }
    if (oa->ObjectName == NULL || oa->ObjectName->Buffer == NULL || oa->ObjectName->Length == 0) {
        if (oa->RootDirectory != NULL) {
            path_from_handle(oa->RootDirectory, out, cch);
            ok = out[0] != L'\0';
        }
    } else if (!memory_ok(oa->ObjectName, sizeof(*oa->ObjectName), 0)) {
        ok = 0;
    } else {
        nbytes = oa->ObjectName->Length;
        if (nbytes > 0 && (nbytes % sizeof(wchar_t)) == 0 && (size_t)nbytes < PATH_CAP * sizeof(wchar_t)
            && memory_ok(oa->ObjectName->Buffer, nbytes, 0)) {
            name = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)nbytes + sizeof(wchar_t));
            if (name != NULL) {
                memcpy(name, oa->ObjectName->Buffer, nbytes);
                name[nbytes / sizeof(wchar_t)] = L'\0';
                ok = join_root_name(oa->RootDirectory, name, out, cch);
            }
        }
    }
    if (name != NULL) {
        HeapFree(GetProcessHeap(), 0, name);
    }
    return ok;
}

/* Keep DOS names for comparisons and IPC; extend only filesystem API inputs.
 * A process without longPathAware must work even when LongPathsEnabled is 0. */
static wchar_t *filesystem_path(const wchar_t *path) {
    wchar_t *full;
    wchar_t *extended;
    DWORD n;
    size_t prefix;
    int unc;
    if (path == NULL) {
        return NULL;
    }
    if (wcslen(path) < MAX_PATH || wcsncmp(path, L"\\\\?\\", 4) == 0) {
        return heap_wcs_dup(path);
    }
    full = (wchar_t *)HeapAlloc(GetProcessHeap(), 0, PATH_CAP * sizeof(wchar_t));
    if (full == NULL) {
        return NULL;
    }
    n = GetFullPathNameW(path, PATH_CAP, full, NULL);
    if (n == 0 || n >= PATH_CAP) {
        HeapFree(GetProcessHeap(), 0, full);
        return NULL;
    }
    unc = n > 1 && full[0] == L'\\' && full[1] == L'\\';
    prefix = unc ? 6 : 4;
    if (n + prefix >= PATH_CAP) {
        HeapFree(GetProcessHeap(), 0, full);
        return NULL;
    }
    extended = (wchar_t *)HeapAlloc(GetProcessHeap(), 0, (n + prefix + 1) * sizeof(wchar_t));
    if (extended != NULL) {
        wcscpy_s(extended, n + prefix + 1, unc ? L"\\\\?\\UNC\\" : L"\\\\?\\");
        wcscat_s(extended, n + prefix + 1, full + (unc ? 2 : 0));
    }
    HeapFree(GetProcessHeap(), 0, full);
    return extended;
}

static DWORD path_attributes(const wchar_t *path) {
    wchar_t *api_path = filesystem_path(path);
    DWORD attr = api_path == NULL ? INVALID_FILE_ATTRIBUTES : GetFileAttributesW(api_path);
    HeapFree(GetProcessHeap(), 0, api_path);
    return attr;
}

static int path_exists(const wchar_t *path) {
    DWORD attr = path_attributes(path);
    return attr != INVALID_FILE_ATTRIBUTES;
}

typedef char *(*FnMsGetenv)(const char *);

static void normalize_log_env_path(wchar_t *path, size_t cch);

/* Copy one POSIX environ value into out. Matches GetEnvironmentVariableW:
 * success returns the length without the terminator; a short buffer returns
 * the required length including the terminator and leaves no usable string. */
static DWORD copy_posix_env(FnMsGetenv getenv_fn, const char *key, wchar_t *out, DWORD cch) {
    const char *value;
    size_t value_len;
    int wide_n;
    value = getenv_fn(key);
    if (value == NULL || value[0] == '\0') {
        return 0;
    }
    value_len = strlen(value);
    if (value_len == 0 || value_len > 32768) {
        return 0;
    }
    wide_n = MultiByteToWideChar(CP_UTF8, 0, value, (int)value_len, NULL, 0);
    if (wide_n <= 0) {
        return 0;
    }
    if ((DWORD)wide_n + 1 > cch) {
        return (DWORD)wide_n + 1;
    }
    if (MultiByteToWideChar(CP_UTF8, 0, value, (int)value_len, out, (int)(cch - 1)) != wide_n) {
        out[0] = L'\0';
        return 0;
    }
    out[wide_n] = L'\0';
    return (DWORD)wide_n;
}

/* Win32 environment first. Git Bash keeps JIUWENBOX_* in the MSYS environ of
 * rm.exe and drops them from the Windows block, so GetEnvironmentVariableW
 * alone cannot see the recycle port. Fall back to msys/cygwin getenv only
 * after that miss. A failure here is "unset": the caller keeps its old path
 * and must not abort the process. */
static DWORD read_env_w(const wchar_t *key, wchar_t *out, DWORD cch) {
    DWORD n;
    HMODULE posix;
    FnMsGetenv getenv_fn;
    char key_utf[160];
    DWORD got = 0;
    if (out == NULL || cch == 0 || key == NULL || key[0] == L'\0') {
        return 0;
    }
    n = GetEnvironmentVariableW(key, out, cch);
    if (n > 0) {
        return n;
    }
    out[0] = L'\0';
    if (g_in_dllmain) {
        return 0;
    }
    posix = GetModuleHandleW(L"msys-2.0.dll");
    if (posix == NULL) {
        posix = GetModuleHandleW(L"cygwin1.dll");
    }
    if (posix == NULL) {
        return 0;
    }
    getenv_fn = (FnMsGetenv)(void *)GetProcAddress(posix, "getenv");
    if (getenv_fn == NULL) {
        return 0;
    }
    if (WideCharToMultiByte(CP_UTF8, 0, key, -1, key_utf, (int)sizeof key_utf, NULL, NULL) <= 0) {
        return 0;
    }
#if defined(_MSC_VER)
    __try {
        got = copy_posix_env(getenv_fn, key_utf, out, cch);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (cch > 0) {
            out[0] = L'\0';
        }
        got = 0;
    }
#else
    got = copy_posix_env(getenv_fn, key_utf, out, cch);
#endif
    return got;
}

/* Capture recovery settings before application code runs. */
static struct {
    int bound;
    wchar_t enabled[2];
    wchar_t archive[PATH_CAP];
    wchar_t port[16];
    wchar_t token[RECYCLE_TOKEN_MAX];
    wchar_t results[PATH_CAP];
} recovery_config;

int bind_recovery_config(void) {
    if (recovery_config.bound) return 1;
    if (read_env_w(ENV_ENABLED, recovery_config.enabled, 2) >= 2
        || read_env_w(ENV_ARCHIVE, recovery_config.archive, PATH_CAP) >= PATH_CAP
        || read_env_w(ENV_RECYCLE_PORT, recovery_config.port, 16) >= 16
        || read_env_w(ENV_RECYCLE_TOKEN, recovery_config.token, RECYCLE_TOKEN_MAX) >= RECYCLE_TOKEN_MAX
        || read_env_w(ENV_RESULTS,recovery_config.results,PATH_CAP)>=PATH_CAP)
        return 0;
    recovery_config.bound = 1;
    return 1;
}

int configure_recovery_config(LPCWSTR archive, LPCWSTR port, LPCWSTR token, LPCWSTR results) {
    BOOL bound = recovery_config.bound;
    if (!bind_recovery_config()) return 0;
    LPCWSTR inputs[] = {archive, port, token, results};
    LPWSTR outputs[] = {recovery_config.archive, recovery_config.port, recovery_config.token, recovery_config.results};
    const size_t sizes[] = {PATH_CAP, 16, RECYCLE_TOKEN_MAX, PATH_CAP};
    for (size_t i=0; i<4; ++i) {
        if (!inputs[i]) continue;
        if (wcslen(inputs[i]) >= sizes[i] || (bound && wcscmp(inputs[i],outputs[i]))) {
            SetLastError(ERROR_INVALID_PARAMETER); return 0;
        }
    }
    for (size_t i=0; i<4; ++i)
        if (inputs[i]) wcscpy_s(outputs[i],sizes[i],inputs[i]);
    return 1;
}

static void read_archive_dir(wchar_t *out, size_t cch) {
    DWORD n;
    if (recovery_config.bound) {
        n = (DWORD)wcslen(recovery_config.archive);
        if (n < cch) wcscpy_s(out, cch, recovery_config.archive);
    } else {
        n = read_env_w(ENV_ARCHIVE, out, (DWORD)cch);
    }
    if (n == 0 || n >= cch) {
        /* No cwd fallback. A missing setting must not create .trash beside the command. */
        out[0] = L'\0';
        return;
    }
    if (out[0] == L'/') {
        normalize_log_env_path(out, cch);
    }
}

static int normalize_dos_path(const wchar_t *in, wchar_t *out, size_t cch) {
    DWORD n;
    if (in == NULL || in[0] == L'\0' || out == NULL || cch == 0) {
        return 0;
    }
    n = GetFullPathNameW(in, (DWORD)cch, out, NULL);
    return n > 0 && n < cch;
}

/* X:\$Recycle.Bin only. A workspace folder with the same name stays soft-deleted. */
static int is_volume_recycle_bin(const wchar_t *full) {
    const wchar_t *cursor = full;
    if (cursor == NULL) {
        return 0;
    }
    if (wcsncmp(cursor, L"\\\\?\\", 4) == 0) {
        cursor += 4;
    }
    if (cursor[0] == L'\0' || cursor[1] != L':' || (cursor[2] != L'\\' && cursor[2] != L'/')) {
        return 0;
    }
    cursor += 3;
    if (_wcsnicmp(cursor, L"$Recycle.Bin", 12) != 0) {
        return 0;
    }
    return cursor[12] == L'\0' || cursor[12] == L'\\' || cursor[12] == L'/';
}

static int is_under_dir(const wchar_t *path, const wchar_t *dir) {
    size_t n;
    if (path == NULL || dir == NULL || dir[0] == L'\0') {
        return 0;
    }
    n = wcslen(dir);
    while (n > 0 && (dir[n - 1] == L'\\' || dir[n - 1] == L'/')) {
        n--;
    }
    if (n == 0 || _wcsnicmp(path, dir, n) != 0) {
        return 0;
    }
    return path[n] == L'\0' || path[n] == L'\\' || path[n] == L'/';
}

int softdelete_exempt(const wchar_t *dos_path) {
    wchar_t *full;
    wchar_t *archive;
    int under;
    if (dos_path == NULL || dos_path[0] == L'\0') {
        return 1;
    }
    full = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PATH_CAP * sizeof(wchar_t));
    if (full == NULL || !normalize_dos_path(dos_path, full, PATH_CAP)) {
        HeapFree(GetProcessHeap(), 0, full);
        return 0;
    }
    if (is_volume_recycle_bin(full)) {
        HeapFree(GetProcessHeap(), 0, full);
        return 1;
    }
    archive = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PATH_CAP * sizeof(wchar_t));
    if (archive == NULL) {
        HeapFree(GetProcessHeap(), 0, full);
        return 0;
    }
    read_archive_dir(archive, PATH_CAP);
    under = is_under_dir(full, archive);
    HeapFree(GetProcessHeap(), 0, archive);
    HeapFree(GetProcessHeap(), 0, full);
    return under;
}

static int mkdir_p(const wchar_t *path) {
    wchar_t buf[PATH_CAP];
    size_t i;
    size_t n;
    if (path == NULL || path[0] == L'\0') {
        return 0;
    }
    wcsncpy_s(buf, PATH_CAP, path, _TRUNCATE);
    n = wcslen(buf);
    if (n >= 2 && buf[1] == L':') {
        i = 2;
    } else {
        i = 0;
    }
    for (; i < n; i++) {
        if (buf[i] != L'\\' && buf[i] != L'/') {
            continue;
        }
        if (i == 0) {
            continue;
        }
        buf[i] = L'\0';
        if (buf[0] != L'\0' && !path_exists(buf)) {
            if (!CreateDirectoryW(buf, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
                return 0;
            }
        }
        buf[i] = L'\\';
    }
    if (!path_exists(buf)) {
        if (!CreateDirectoryW(buf, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
            return 0;
        }
    }
    return 1;
}

typedef struct DirNode_ {
    struct DirNode_ *next;
    wchar_t *path;
} DirNode_;

static void free_dir_list(DirNode_ *node) {
    while (node != NULL) {
        DirNode_ *next = node->next;
        HeapFree(GetProcessHeap(), 0, node->path);
        HeapFree(GetProcessHeap(), 0, node);
        node = next;
    }
}

static DirNode_ *dir_node(const wchar_t *path) {
    DirNode_ *node = (DirNode_ *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DirNode_));
    if (node == NULL) {
        return NULL;
    }
    node->path = heap_wcs_dup(path);
    if (node->path == NULL) {
        HeapFree(GetProcessHeap(), 0, node);
        return NULL;
    }
    return node;
}

static void sanitize_name(const wchar_t *path, wchar_t *out, size_t cch) {
    const wchar_t *base = path;
    const wchar_t *scan;
    size_t i = 0;
    for (scan = path; *scan != L'\0'; scan++) {
        if (*scan == L'\\' || *scan == L'/') {
            base = scan + 1;
        }
    }
    for (; *base != L'\0' && i + 1 < cch && i < 80; base++) {
        wchar_t ch = *base;
        if (ch == L'\\' || ch == L'/' || ch == L':' || ch == L'*' || ch == L'?' || ch == L'"'
            || ch == L'<' || ch == L'>' || ch == L'|' || ch < 32) {
            ch = L'_';
        }
        out[i++] = ch;
    }
    if (i == 0) {
        wcscpy_s(out, cch, L"file");
        return;
    }
    out[i] = L'\0';
}

static int same_volume(const wchar_t *left, const wchar_t *right) {
    wchar_t a[MAX_PATH];
    wchar_t b[MAX_PATH];
    wchar_t dos_a[MAX_PATH];
    wchar_t dos_b[MAX_PATH];
    wchar_t *api_left = filesystem_path(left);
    wchar_t *api_right = filesystem_path(right);
    int ok = api_left != NULL && api_right != NULL
        && GetVolumePathNameW(api_left, a, MAX_PATH)
        && GetVolumePathNameW(api_right, b, MAX_PATH);
    HeapFree(GetProcessHeap(), 0, api_left);
    HeapFree(GetProcessHeap(), 0, api_right);
    if (!ok) {
        return 0;
    }
    to_dos_path(a, dos_a, MAX_PATH);
    to_dos_path(b, dos_b, MAX_PATH);
    return _wcsicmp(dos_a, dos_b) == 0;
}

static int move_to_archive(const wchar_t *dos_path) {
    wchar_t archive[PATH_CAP];
    wchar_t name[96];
    wchar_t dest[PATH_CAP];
    SYSTEMTIME st;
    int i;
    read_archive_dir(archive, PATH_CAP);
    if (archive[0] == L'\0') {
        return 0;
    }
    if (!same_volume(dos_path, archive)) {
        log_line(L"archive skipped: different volume");
        return 0;
    }
    if (!mkdir_p(archive)) {
        return 0;
    }
    sanitize_name(dos_path, name, 96);
    GetLocalTime(&st);
    /* Outer name only. A directory rename leaves names inside it unchanged. */
    for (i = 0; i < 1000; i++) {
        int wrote;
        if (i == 0) {
            wrote = swprintf_s(
                dest, PATH_CAP, L"%s\\%s_%04u%02u%02u_%02u%02u%02u",
                archive, name, st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond);
        } else {
            wrote = swprintf_s(
                dest, PATH_CAP, L"%s\\%s_%04u%02u%02u_%02u%02u%02u_%d",
                archive, name, st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond, i);
        }
        if (wrote < 0) {
            return 0;
        }
        if (!path_exists(dest)) {
            break;
        }
    }
    if (path_exists(dest)) {
        return 0;
    }
    /* No MOVEFILE_COPY_ALLOWED: a cross-volume copy would delete the source. */
    {
        wchar_t *api_source = filesystem_path(dos_path);
        wchar_t *api_dest = filesystem_path(dest);
        int moved = api_source != NULL && api_dest != NULL
            && MoveFileExW(api_source, api_dest, MOVEFILE_WRITE_THROUGH);
        HeapFree(GetProcessHeap(), 0, api_source);
        HeapFree(GetProcessHeap(), 0, api_dest);
        if (!moved) {
            return 0;
        }
    }
    {
        wchar_t msg[1024];
        swprintf_s(msg, 1024, L"archive %s -> %s", dos_path, dest);
        log_line(msg);
    }
    return 1;
}

typedef int (WINAPI *FnWsaStartup)(WORD, void *);
typedef uintptr_t (WINAPI *FnSock)(int, int, int);
typedef int (WINAPI *FnSockOp)(uintptr_t, const void *, int);
typedef int (WINAPI *FnSendRecv)(uintptr_t, char *, int, int);
typedef int (WINAPI *FnCloseSock)(uintptr_t);
typedef int (WINAPI *FnSetOpt)(uintptr_t, int, int, const char *, int);
typedef unsigned short (WINAPI *FnHtons)(unsigned short);

static int g_wsa_ok;
static HMODULE g_ws2;
static FnSock g_sock_fn;
static FnSockOp g_connect_fn;
static FnSendRecv g_send_fn;
static FnSendRecv g_recv_fn;
static FnCloseSock g_close_fn;
static FnSetOpt g_setopt_fn;
static FnHtons g_htons_fn;

/* Set means the sandbox must ask box-server. A bad value still must not fall through. */
static int recycle_delegation_configured(void) {
    wchar_t buf[2];
    if (recovery_config.bound) return recovery_config.port[0] != 0;
    DWORD n = read_env_w(ENV_RECYCLE_PORT, buf, 2);
    return n > 0;
}

static int parse_port(const wchar_t *text) {
    int port = 0;
    if (text == NULL || text[0] == L'\0') {
        return 0;
    }
    for (; *text != L'\0'; text++) {
        if (*text < L'0' || *text > L'9') {
            return 0;
        }
        port = port * 10 + (int)(*text - L'0');
        if (port > 65535) {
            return 0;
        }
    }
    return port;
}

static int wsa_ready(void) {
    FnWsaStartup startup;
    unsigned char data[512];
    if (g_wsa_ok) {
        return 1;
    }
    if (g_ws2 == NULL) {
        g_ws2 = LoadLibraryW(L"ws2_32.dll");
    }
    if (g_ws2 == NULL) {
        return 0;
    }
    startup = (FnWsaStartup)(void *)GetProcAddress(g_ws2, "WSAStartup");
    g_sock_fn = (FnSock)(void *)GetProcAddress(g_ws2, "socket");
    g_connect_fn = (FnSockOp)(void *)GetProcAddress(g_ws2, "connect");
    g_send_fn = (FnSendRecv)(void *)GetProcAddress(g_ws2, "send");
    g_recv_fn = (FnSendRecv)(void *)GetProcAddress(g_ws2, "recv");
    g_close_fn = (FnCloseSock)(void *)GetProcAddress(g_ws2, "closesocket");
    g_setopt_fn = (FnSetOpt)(void *)GetProcAddress(g_ws2, "setsockopt");
    g_htons_fn = (FnHtons)(void *)GetProcAddress(g_ws2, "htons");
    if (startup == NULL || g_sock_fn == NULL || g_connect_fn == NULL || g_send_fn == NULL
        || g_recv_fn == NULL || g_close_fn == NULL || g_setopt_fn == NULL || g_htons_fn == NULL) {
        return 0;
    }
    if (startup(0x0202, data) != 0) {
        g_sock_fn = NULL;
        return 0;
    }
    g_wsa_ok = 1;
    return 1;
}

static void store_be32(unsigned char *dest, unsigned long value) {
    dest[0] = (unsigned char)((value >> 24) & 0xffu);
    dest[1] = (unsigned char)((value >> 16) & 0xffu);
    dest[2] = (unsigned char)((value >> 8) & 0xffu);
    dest[3] = (unsigned char)(value & 0xffu);
}

static unsigned long load_be32(const unsigned char *src) {
    return ((unsigned long)src[0] << 24) | ((unsigned long)src[1] << 16)
        | ((unsigned long)src[2] << 8) | (unsigned long)src[3];
}

static int sock_send_all(uintptr_t sock, const char *buf, int len) {
    int sent = 0;
    while (sent < len) {
        int n = g_send_fn(sock, (char *)(buf + sent), len - sent, 0);
        if (n <= 0) {
            return 0;
        }
        sent += n;
    }
    return 1;
}

static int sock_recv_all(uintptr_t sock, char *buf, int len) {
    int got = 0;
    while (got < len) {
        int n = g_recv_fn(sock, buf + got, len - got, 0);
        if (n <= 0) {
            return 0;
        }
        got += n;
    }
    return 1;
}

static char *utf8_of(const wchar_t *text, int *out_len) {
    int bytes;
    char *buf;
    *out_len = 0;
    bytes = WideCharToMultiByte(CP_UTF8, 0, text, -1, NULL, 0, NULL, NULL);
    if (bytes <= 1) {
        return NULL;
    }
    buf = (char *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)bytes);
    if (buf == NULL) {
        return NULL;
    }
    if (WideCharToMultiByte(CP_UTF8, 0, text, -1, buf, bytes, NULL, NULL) != bytes) {
        HeapFree(GetProcessHeap(), 0, buf);
        return NULL;
    }
    *out_len = bytes - 1;
    return buf;
}

/* Ask box-server, which runs as the logged-in user, to recycle this path.
 * Any failure leaves the file where it is. This function never deletes it. */
static int broker_request(const wchar_t *dos_path, const GUID *operation, int query) {
    wchar_t port_text[16];
    wchar_t token_w[RECYCLE_TOKEN_MAX];
    DWORD port_n;
    DWORD token_n;
    int port;
    int token_len = 0;
    int path_len = 0;
    char *token_utf = NULL;
    char *path_utf = NULL;
    unsigned char *frame = NULL;
    unsigned body_len;
    uintptr_t sock = (uintptr_t)-1;
    unsigned char addr[16];
    unsigned char len_buf[4];
    char resp[2];
    DWORD timeout_ms = 15000;
    unsigned short net_port;
    int ok = query ? -1 : 0;

    if (recovery_config.bound) {
        wcscpy_s(port_text, 16, recovery_config.port);
        wcscpy_s(token_w, RECYCLE_TOKEN_MAX, recovery_config.token);
        port_n = (DWORD)wcslen(port_text);
        token_n = (DWORD)wcslen(token_w);
    } else {
        port_n = read_env_w(ENV_RECYCLE_PORT, port_text, 16);
        token_n = read_env_w(ENV_RECYCLE_TOKEN, token_w, RECYCLE_TOKEN_MAX);
    }
    if (port_n == 0 || port_n >= 16) {
        return query ? -1 : 0;
    }
    port = parse_port(port_text);
    if (port == 0 || !wsa_ready()) {
        return query ? -1 : 0;
    }
    if (token_n == 0 || token_n >= RECYCLE_TOKEN_MAX) {
        return query ? -1 : 0;
    }
    token_utf = utf8_of(token_w, &token_len);
    path_utf = utf8_of(dos_path, &path_len);
    if (token_utf == NULL || path_utf == NULL || token_len <= 0 || path_len <= 0
        || (unsigned)token_len > RECYCLE_TOKEN_MAX || (unsigned)path_len > RECYCLE_PATH_MAX) {
        goto done;
    }
    body_len = 17u + 4u + (unsigned)token_len + 4u + (unsigned)path_len;
    frame = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, 4u + body_len);
    if (frame == NULL) {
        goto done;
    }
    store_be32(frame, body_len);
    frame[4] = query ? 2 : 1;
    memcpy(frame + 5, operation, 16);
    store_be32(frame + 21, (unsigned long)token_len);
    memcpy(frame + 25, token_utf, (size_t)token_len);
    store_be32(frame + 25 + token_len, (unsigned long)path_len);
    memcpy(frame + 29 + token_len, path_utf, (size_t)path_len);

    sock = g_sock_fn(2, 1, 6);
    if (sock == (uintptr_t)-1) {
        goto done;
    }
    g_setopt_fn(sock, 0xffff, 0x1005, (const char *)&timeout_ms, (int)sizeof(timeout_ms));
    g_setopt_fn(sock, 0xffff, 0x1006, (const char *)&timeout_ms, (int)sizeof(timeout_ms));
    memset(addr, 0, sizeof(addr));
    addr[0] = 2;
    net_port = g_htons_fn((unsigned short)port);
    memcpy(addr + 2, &net_port, sizeof(net_port));
    addr[4] = 127;
    addr[7] = 1;
    if (g_connect_fn(sock, addr, 16) != 0) {
        goto done;
    }
    ok = -1; /* A lost reply may follow a committed recovery. */
    if (!sock_send_all(sock, (const char *)frame, (int)(4u + body_len))) {
        goto done;
    }
    if (!sock_recv_all(sock, (char *)len_buf, 4)) {
        goto done;
    }
    if (load_be32(len_buf) != 2 || !sock_recv_all(sock, resp, 2)) {
        goto done;
    }
    if (!memcmp(resp, "ok", 2)) ok = 1;
    else if (!memcmp(resp, "no", 2)) ok = 0;
done:
    if (sock != (uintptr_t)-1 && g_close_fn != NULL) {
        g_close_fn(sock);
    }
    if (frame != NULL) {
        HeapFree(GetProcessHeap(), 0, frame);
    }
    if (token_utf != NULL) {
        HeapFree(GetProcessHeap(), 0, token_utf);
    }
    if (path_utf != NULL) {
        HeapFree(GetProcessHeap(), 0, path_utf);
    }
    return ok;
}

static int file_identity(const wchar_t *path, BY_HANDLE_FILE_INFORMATION *info) {
    wchar_t *api = filesystem_path(path);
    if (!api) return 0;
    HANDLE h = CreateFileW(api, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    HeapFree(GetProcessHeap(), 0, api);
    if (h == INVALID_HANDLE_VALUE) return 0;
    int ok = GetFileInformationByHandle(h, info);
    CloseHandle(h);
    return ok;
}

static int same_file(const wchar_t *path, const BY_HANDLE_FILE_INFORMATION *expected) {
    BY_HANDLE_FILE_INFORMATION now;
    return file_identity(path, &now) && now.dwVolumeSerialNumber == expected->dwVolumeSerialNumber
        && now.nFileIndexHigh == expected->nFileIndexHigh && now.nFileIndexLow == expected->nFileIndexLow;
}

static GuardAuthorizeDelete authorize_delete;
static GuardReportDelete report_delete;
static GuardReportStage report_stage;
static GuardAuthorizeReplace authorize_replace;
static BOOL recovery_mode = TRUE;
struct GuardDeleteScope {
    GUID operation;
    wchar_t *target;
    BY_HANDLE_FILE_INFORMATION identity;
    BOOL identified;
    int disposition;
    DWORD error;
    DWORD stage;
    struct GuardDeleteScope *previous;
};
static __declspec(thread) GuardDeleteScope *current_scope;
static int pending_has_operation(const GUID *operation);

static BOOL same_path(LPCWSTR first, LPCWSTR second) {
    if (!_wcsnicmp(first,L"\\\\?\\",4) || !_wcsnicmp(first,L"\\??\\",4)) first += 4;
    if (!_wcsnicmp(second,L"\\\\?\\",4) || !_wcsnicmp(second,L"\\??\\",4)) second += 4;
    return !_wcsicmp(first,second);
}
BOOL guard_replace_active(LPCWSTR target) {
    return current_scope && (same_path(current_scope->target,target) ||
        (current_scope->identified && same_file(target,&current_scope->identity)));
}
void softdelete_set_mode(BOOL recover) { recovery_mode = recover; }

void softdelete_set_policy(GuardAuthorizeDelete authorize, GuardReportDelete report, GuardReportStage stage, GuardAuthorizeReplace replace) {
    authorize_delete = authorize;
    report_delete = report;
    report_stage = stage;
    authorize_replace = replace;
}

#include "result_stream.c"

static void finish_recovery(const GUID *id, int disposition, DWORD error, LPCWSTR path) {
    if (current_scope && IsEqualGUID(id,&current_scope->operation)) {
        current_scope->disposition=disposition;
        current_scope->error=error;
    } else emit_delete_result(id,path,disposition,error);
}

GuardDeleteScope *guard_begin_replace(LPCWSTR source, LPCWSTR target, LPCWSTR backup, DWORD stage) {
    GuardDeleteScope *scope=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(*scope));
    if (!scope) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; }
    scope->target=heap_wcs_dup(target);
    if (!scope->target || FAILED(CoCreateGuid(&scope->operation))) {
        HeapFree(GetProcessHeap(),0,scope->target);
        HeapFree(GetProcessHeap(),0,scope);
        return NULL;
    }
    scope->stage=stage;
    DWORD attributes=path_attributes(target);
    DWORD identity_error=GetLastError();
    scope->identified=attributes!=INVALID_FILE_ATTRIBUTES && file_identity(target,&scope->identity);
    if ((attributes!=INVALID_FILE_ATTRIBUTES && !scope->identified) ||
        (attributes==INVALID_FILE_ATTRIBUTES && identity_error!=ERROR_FILE_NOT_FOUND && identity_error!=ERROR_PATH_NOT_FOUND)) {
        HeapFree(GetProcessHeap(),0,scope->target);
        HeapFree(GetProcessHeap(),0,scope);
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    }
    BOOL allowed=authorize_replace ? authorize_replace(&scope->operation,source,target,backup,stage|(scope->identified?256:0))
        : !authorize_delete || authorize_delete(&scope->operation,target,FALSE);
    if (!allowed) {
        HeapFree(GetProcessHeap(),0,scope->target);
        HeapFree(GetProcessHeap(),0,scope);
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    }
    scope->previous=current_scope;
    current_scope=scope;
    return scope;
}

BOOL guard_finish_replace(GuardDeleteScope *scope, LPCWSTR backup, LONG status, DWORD error) {
    current_scope=scope->previous;
    int disposition=scope->disposition;
    if (disposition==0 && backup && scope->identified && same_file(backup,&scope->identity))
        disposition=5; /* The original target is preserved in the requested backup. */
    if (scope->identified && disposition==0 && status>=0 && !pending_has_operation(&scope->operation))
        disposition=recovery_mode ? -1 : 4;
    if (scope->identified && !pending_has_operation(&scope->operation))
        emit_delete_result(&scope->operation,scope->target,disposition,disposition>0?0:scope->error?scope->error:error);
    emit_stage_result(&scope->operation,scope->target,scope->stage,status,error);
    HeapFree(GetProcessHeap(),0,scope->target);
    HeapFree(GetProcessHeap(),0,scope);
    if (status>=0 && disposition<0) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
    SetLastError(error);
    return status>=0;
}

static int recover_path(const wchar_t *dos_path, int delegate, const GUID *operation) {
    DWORD attr;
    if (dos_path == NULL || dos_path[0] == L'\0') {
        return 0;
    }
    if (t_bypass || (!delegate && recycle_delegation_configured())) return 0;
    t_bypass = 1;
    attr = path_attributes(dos_path);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        t_bypass = 0;
        return 0;
    }
    if (softdelete_exempt(dos_path)) {
        t_bypass = 0;
        return 0;
    }
    {
        wchar_t msg[1200];
        swprintf_s(
            msg, 1200, L"posix-debug: delete candidate recycle=%d path=%s",
            recycle_delegation_configured(), dos_path);
        log_line(msg);
    }
    /* Sandbox deletes are recycled by box-server. Failure keeps the file.
     * Expand here: box-server's current directory is not this command's. */
    if (delegate && recycle_delegation_configured()) {
        wchar_t *full;
        DWORD full_n;
        int delegated;
        full = (wchar_t *)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, PATH_CAP * sizeof(wchar_t));
        if (full == NULL) {
            t_bypass = 0;
            return 0;
        }
        full_n = GetFullPathNameW(dos_path, PATH_CAP, full, NULL);
        if (full_n == 0 || full_n >= PATH_CAP) {
            HeapFree(GetProcessHeap(), 0, full);
            t_bypass = 0;
            log_line(L"recycle broker refused; path could not be made absolute");
            return 0;
        }
        delegated = broker_request(full, operation, 0);
        if (delegated < 0) delegated = broker_request(full, operation, 1);
        t_bypass = 0;
        if (delegated == 1) {
            wchar_t msg[1024];
            swprintf_s(msg, 1024, L"recycle-delegated %s", full);
            log_line(msg);
            HeapFree(GetProcessHeap(), 0, full);
            return 3;
        }
        HeapFree(GetProcessHeap(), 0, full);
        log_line(L"broker recovery was not confirmed");
        return delegated;
    }
    {
        BY_HANDLE_FILE_INFORMATION identity;
        if (!file_identity(dos_path, &identity)) {
            t_bypass = 0;
            return 0;
        }
        if ((attr & FILE_ATTRIBUTE_REPARSE_POINT) == 0) {
            RecoveryStatus status = recycle_item(dos_path);
            if (status == RECOVERY_UNKNOWN) {
                t_bypass = 0;
                return -1;
            }
            if (status == RECOVERY_RECYCLED) {
                wchar_t msg[1024];
                swprintf_s(msg, 1024, L"recycle %s", dos_path);
                log_line(msg);
                t_bypass = 0;
                return 1;
            }
        }
        if (same_file(dos_path, &identity) && move_to_archive(dos_path)) {
            t_bypass = 0;
            return 2;
        }
        log_line(L"soft-delete failed; source left in place");
        t_bypass = 0;
        return 0;
    }
}

static int recover_operation(const wchar_t *path, const GUID *id, BOOL recheck, LPCWSTR bound_path) {
    BY_HANDLE_FILE_INFORMATION before;
    int identified = !authorize_delete || file_identity(path, &before);
    LPCWSTR policy_path=bound_path ? bound_path :
        current_scope && IsEqualGUID(id,&current_scope->operation) ? current_scope->target : path;
    if (authorize_delete && !authorize_delete(id, policy_path, recheck)) return 0;
    int result=0;
    DWORD error=ERROR_ACCESS_DENIED;
    BOOL original_target=!current_scope || !IsEqualGUID(id,&current_scope->operation) ||
        (current_scope->identified && same_file(path,&current_scope->identity));
    if (!original_target) error=ERROR_FILE_INVALID;
    if (identified && original_target && (!authorize_delete || same_file(path,&before))) {
        if (recovery_mode) result=recover_path(path,1,id);
        else {
            DWORD attributes=path_attributes(path);
            t_bypass=1;
            BOOL removed=attributes!=INVALID_FILE_ATTRIBUTES &&
                ((attributes&FILE_ATTRIBUTE_DIRECTORY) ? g_remove_directory(path) : g_delete_file(path));
            error=removed?ERROR_SUCCESS:GetLastError();
            t_bypass=0;
            result=removed?4:0;
        }
    }
    if (result>0) error=ERROR_SUCCESS;
    finish_recovery(id,result,error,policy_path);
    SetLastError(error);
    return result>0;
}

int guard_recover_path(const wchar_t *path) {
    GUID id;
    BOOL reused=guard_replace_active(path);
    if (reused) id=current_scope->operation;
    else if (FAILED(CoCreateGuid(&id))) return 0;
    return recover_operation(path,&id,reused,NULL);
}

#include "posix_delete.c"

SOFT_EXPORT int guard_recover_local(const wchar_t *path) {
    if (authorize_delete) return 0;
    return recover_path(path, 0, NULL);
}

static int ensure_dir(const wchar_t *dir) {
    wchar_t buf[1024];
    wchar_t *cursor;
    if (dir == NULL || dir[0] == L'\0') {
        return 0;
    }
    if (swprintf_s(buf, 1024, L"%s", dir) < 0) {
        return 0;
    }
    for (cursor = buf + 3; *cursor != L'\0'; cursor++) {
        if (*cursor != L'\\' && *cursor != L'/') {
            continue;
        }
        *cursor = L'\0';
        if (GetFileAttributesW(buf) == INVALID_FILE_ATTRIBUTES) {
            if (!CreateDirectoryW(buf, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
                return 0;
            }
        }
        *cursor = L'\\';
    }
    if (GetFileAttributesW(buf) == INVALID_FILE_ATTRIBUTES) {
        if (!CreateDirectoryW(buf, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
            return 0;
        }
    }
    return 1;
}

/* MSYS/Git Bash stores Windows paths as /c/Users/... or /cygdrive/c/Users/...
 * inside its own processes. CreateFileW cannot open those. */
static int env_drive_letter(wchar_t ch) {
    return (ch >= L'a' && ch <= L'z') || (ch >= L'A' && ch <= L'Z');
}

static void slashes_to_backslashes(wchar_t *text) {
    wchar_t *cursor;
    for (cursor = text; cursor != NULL && *cursor != L'\0'; cursor++) {
        if (*cursor == L'/') {
            *cursor = L'\\';
        }
    }
}

static void normalize_log_env_path(wchar_t *path, size_t cch) {
    wchar_t tmp[1024];
    if (path == NULL || path[0] == L'\0' || cch < 4) {
        return;
    }
    if (_wcsnicmp(path, L"/cygdrive/", 10) == 0 && env_drive_letter(path[10]) && path[11] == L'/') {
        if (swprintf_s(tmp, 1024, L"%c:%s", path[10], path + 11) > 0) {
            slashes_to_backslashes(tmp);
            wcscpy_s(path, cch, tmp);
        }
        return;
    }
    if (path[0] == L'/' && env_drive_letter(path[1]) && path[2] == L'/') {
        if (swprintf_s(tmp, 1024, L"%c:%s", path[1], path + 2) > 0) {
            slashes_to_backslashes(tmp);
            wcscpy_s(path, cch, tmp);
        }
        return;
    }
    slashes_to_backslashes(path);
}

/* Same file as the Python aggregate log. JIUWENSWARM_LOG_DIR, or the dated
 * layout when JIUWENSWARM_LOG_DATE_ROOT is set. */
static int resolve_soft_log_path(wchar_t *out, size_t cch) {
    wchar_t log_dir[1024];
    wchar_t date_root[1024];
    wchar_t data_dir[1024];
    wchar_t day[16];
    SYSTEMTIME st;
    DWORD n;
    DWORD root_n;
    size_t root_len;
    const wchar_t *rel;
    GetLocalTime(&st);
    if (swprintf_s(day, 16, L"%04u-%02u-%02u", st.wYear, st.wMonth, st.wDay) < 0) {
        return 0;
    }
    n = GetEnvironmentVariableW(L"JIUWENSWARM_LOG_DIR", log_dir, 1024);
    if (n > 0 && n < 1024) {
        normalize_log_env_path(log_dir, 1024);
    }
    if (n == 0 || n >= 1024) {
        DWORD data_n = GetEnvironmentVariableW(L"JIUWENSWARM_DATA_DIR", data_dir, 1024);
        if (data_n > 0 && data_n < 1024) {
            normalize_log_env_path(data_dir, 1024);
        }
        if (data_n == 0 || data_n >= 1024) {
            DWORD home_n = GetEnvironmentVariableW(L"USERPROFILE", data_dir, 1024);
            if (home_n == 0 || home_n >= 900) {
                return 0;
            }
            normalize_log_env_path(data_dir, 1024);
            if (swprintf_s(log_dir, 1024, L"%s\\.jiuwenswarm\\logs", data_dir) < 0) {
                return 0;
            }
        } else if (swprintf_s(log_dir, 1024, L"%s\\logs", data_dir) < 0) {
            return 0;
        }
    }
    root_n = GetEnvironmentVariableW(L"JIUWENSWARM_LOG_DATE_ROOT", date_root, 1024);
    if (root_n > 0 && root_n < 1024) {
        normalize_log_env_path(date_root, 1024);
    }
    root_len = (root_n > 0 && root_n < 1024) ? wcslen(date_root) : 0;
    while (root_len > 0 && (date_root[root_len - 1] == L'\\' || date_root[root_len - 1] == L'/')) {
        date_root[--root_len] = L'\0';
    }
    if (root_len > 0 && _wcsnicmp(log_dir, date_root, root_len) == 0
        && (log_dir[root_len] == L'\\' || log_dir[root_len] == L'/' || log_dir[root_len] == L'\0')) {
        rel = log_dir + root_len;
        while (*rel == L'\\' || *rel == L'/') {
            rel++;
        }
        if (*rel == L'\0') {
            return swprintf_s(out, cch, L"%s\\%s\\full.log", date_root, day) > 0;
        }
        return swprintf_s(out, cch, L"%s\\%s\\%s\\full.log", date_root, day, rel) > 0;
    }
    return swprintf_s(out, cch, L"%s\\%s\\full.log", log_dir, day) > 0;
}

static void append_utf8_file(const wchar_t *path, const char *prefix, const char *body) {
    wchar_t parent[1024];
    wchar_t *slash;
    HANDLE file;
    DWORD written = 0;
    int saved_bypass;
    if (path == NULL || path[0] == L'\0') {
        return;
    }
    if (swprintf_s(parent, 1024, L"%s", path) < 0) {
        return;
    }
    slash = wcsrchr(parent, L'\\');
    if (slash == NULL) {
        return;
    }
    *slash = L'\0';
    saved_bypass = t_bypass;
    t_bypass = 1;
    if (!ensure_dir(parent)) {
        t_bypass = saved_bypass;
        return;
    }
    file = CreateFileW(
        path, FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    t_bypass = saved_bypass;
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }
    if (prefix != NULL && prefix[0] != '\0') {
        WriteFile(file, prefix, (DWORD)strlen(prefix), &written, NULL);
    }
    if (body != NULL && body[0] != '\0') {
        WriteFile(file, body, (DWORD)strlen(body), &written, NULL);
    }
    WriteFile(file, "\r\n", 2, &written, NULL);
    FlushFileBuffers(file);
    CloseHandle(file);
}

static void append_trace(const char *prefix, const char *body) {
    wchar_t path[1024];
    DWORD n = read_env_w(ENV_TRACE, path, 1024);
    if (n == 0 || n >= 1024) {
        return;
    }
    /* rm.exe 里 msys-2.0.dll 会先把 C:\... 改成 /c/...。不转回来则路径里没有
     * 反斜杠，append_utf8_file 直接返回，hooks installed 进不了跟踪文件。 */
    normalize_log_env_path(path, 1024);
    append_utf8_file(path, prefix, body);
}

static void log_line(const wchar_t *text) {
    wchar_t path[1024];
    char utf8[2048];
    char prefix[160];
    int n;
    int wrote_host = 0;
    SYSTEMTIME st;
    if (text == NULL) {
        return;
    }
    OutputDebugStringW(L"[soft_delete] ");
    OutputDebugStringW(text);
    OutputDebugStringW(L"\n");
    GetLocalTime(&st);
    n = sprintf_s(
        prefix, sizeof prefix,
        "%04u-%02u-%02u %02u:%02u:%02u.%03u INFO soft_delete softdelete.c:0: [soft_delete] pid=%lu ",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
        st.wMilliseconds, GetCurrentProcessId());
    if (n < 0) {
        prefix[0] = '\0';
    }
    n = WideCharToMultiByte(CP_UTF8, 0, text, -1, utf8, (int)sizeof utf8, NULL, NULL);
    if (n <= 1) {
        utf8[0] = '\0';
    }
    if (resolve_soft_log_path(path, 1024)) {
        wchar_t parent[1024];
        wchar_t *slash;
        HANDLE file;
        DWORD written = 0;
        int saved_bypass;
        if (swprintf_s(parent, 1024, L"%s", path) >= 0) {
            slash = wcsrchr(parent, L'\\');
            if (slash != NULL) {
                *slash = L'\0';
                saved_bypass = t_bypass;
                t_bypass = 1;
                if (ensure_dir(parent)) {
                    file = CreateFileW(
                        path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                    t_bypass = saved_bypass;
                    if (file != INVALID_HANDLE_VALUE) {
                        if (prefix[0] != '\0') {
                            WriteFile(file, prefix, (DWORD)strlen(prefix), &written, NULL);
                        }
                        if (utf8[0] != '\0') {
                            WriteFile(file, utf8, (DWORD)strlen(utf8), &written, NULL);
                        }
                        WriteFile(file, "\r\n", 2, &written, NULL);
                        FlushFileBuffers(file);
                        CloseHandle(file);
                        wrote_host = 1;
                    }
                } else {
                    t_bypass = saved_bypass;
                }
            }
        }
    }
    /* 沙箱用户经常写不了宿主 full.log. 跟踪文件由 runner 转发进 full.log. */
    append_trace(prefix, utf8);
    if (!wrote_host) {
        static LONG host_log_failed = 0;
        if (InterlockedCompareExchange(&host_log_failed, 1, 0) == 0) {
            char note[1600];
            sprintf_s(
                note, sizeof note,
                "posix-debug: host full.log not writable pid=%lu",
                GetCurrentProcessId());
            append_trace("", note);
        }
    }
}

static void log_win(const wchar_t *api, DWORD err, DWORD pid, const wchar_t *detail) {
    wchar_t msg[1024];
    swprintf_s(
        msg, 1024, L"%s failed winerror=%lu target_pid=%lu %s",
        api != NULL ? api : L"api", err, pid, detail != NULL ? detail : L"");
    log_line(msg);
}

/* -------------------------------------------------------------------------- */
/* Pending deletes: disposition is recorded while the handle is still open.  */
/* -------------------------------------------------------------------------- */

static void pending_clear(HANDLE handle);
static int pending_record(HANDLE handle, const wchar_t *path, const GUID *restored, LPCWSTR bound_path) {
    if (!handle || handle==INVALID_HANDLE_VALUE || !path || !*path) return 0;
    wchar_t *copy=heap_wcs_dup(path);
    if (!copy) return 0;
    GUID operation;
    BOOL recheck=FALSE;
    if (restored) operation=*restored;
    else if (guard_replace_active(path)) { operation=current_scope->operation; recheck=TRUE; }
    else if (FAILED(CoCreateGuid(&operation))) { HeapFree(GetProcessHeap(),0,copy); return 0; }
    LPCWSTR policy_path=bound_path ? bound_path :
        current_scope && IsEqualGUID(&operation,&current_scope->operation) ? current_scope->target : path;
    wchar_t *policy_copy=heap_wcs_dup(policy_path);
    if (!policy_copy) { HeapFree(GetProcessHeap(),0,copy); return 0; }
    EnterCriticalSection(&g_lock);
    int slot=-1;
    for (int i=0;i<PENDING_MAX;i++) {
        if (g_pending_handle[i] && g_pending_handle[i]==handle) {
            slot=i; operation=g_pending_operation[i]; recheck=TRUE;
            HeapFree(GetProcessHeap(),0,policy_copy);
            policy_copy=heap_wcs_dup(g_pending_policy_path[i]);
            if (!policy_copy) { LeaveCriticalSection(&g_lock); HeapFree(GetProcessHeap(),0,copy); return 0; }
            break;
        }
        if (slot<0 && !g_pending_handle[i] && !g_pending_reserved[i]) slot=i;
    }
    if (slot<0) {
        LeaveCriticalSection(&g_lock); HeapFree(GetProcessHeap(),0,copy); HeapFree(GetProcessHeap(),0,policy_copy); return 0;
    }
    HeapFree(GetProcessHeap(),0,g_pending_path[slot]);
    g_pending_handle[slot]=handle;
    HeapFree(GetProcessHeap(),0,g_pending_policy_path[slot]);
    g_pending_policy_path[slot]=policy_copy;
    g_pending_path[slot]=copy;
    g_pending_operation[slot]=operation;
    LeaveCriticalSection(&g_lock);
    if (!restored && authorize_delete && !authorize_delete(&operation,policy_copy,recheck)) {
        pending_clear(handle);
        return 0;
    }
    return 1;
}
static void pending_open_end(int slot, HANDLE handle, DWORD error) {
    if (slot<0) return;
    EnterCriticalSection(&g_lock);
    GUID operation=g_pending_operation[slot];
    wchar_t *path=NULL,*policy=NULL;
    g_pending_reserved[slot]=FALSE;
    if(handle && handle!=INVALID_HANDLE_VALUE) g_pending_handle[slot]=handle;
    else {
        path=g_pending_path[slot]; policy=g_pending_policy_path[slot];
        g_pending_handle[slot]=NULL; g_pending_path[slot]=g_pending_policy_path[slot]=NULL;
    }
    LeaveCriticalSection(&g_lock);
    if(path) {
        finish_recovery(&operation,0,error,policy);
        HeapFree(GetProcessHeap(),0,path); HeapFree(GetProcessHeap(),0,policy);
    }
}
static int pending_open_begin(LPCWSTR path) {
    GUID operation;
    BOOL recheck=guard_replace_active(path);
    if(recheck) operation=current_scope->operation;
    else if(FAILED(CoCreateGuid(&operation)))return -1;
    wchar_t *copy=heap_wcs_dup(path);
    wchar_t *policy=heap_wcs_dup(recheck?current_scope->target:path);
    if(!copy||!policy) { HeapFree(GetProcessHeap(),0,copy); HeapFree(GetProcessHeap(),0,policy); return -1; }
    int slot=-1;
    EnterCriticalSection(&g_lock);
    for(int i=0;i<PENDING_MAX;++i)if(!g_pending_handle[i] && !g_pending_reserved[i]) { slot=i; break; }
    if(slot>=0) {
        g_pending_reserved[slot]=TRUE;
        g_pending_path[slot]=copy; g_pending_policy_path[slot]=policy; g_pending_operation[slot]=operation;
    }
    LeaveCriticalSection(&g_lock);
    if(slot<0) { HeapFree(GetProcessHeap(),0,copy); HeapFree(GetProcessHeap(),0,policy); return -1; }
    if(authorize_delete && !authorize_delete(&operation,policy,recheck)) {
        pending_open_end(slot,NULL,ERROR_OPERATION_ABORTED); return -1;
    }
    return slot;
}
static int pending_put(HANDLE handle, const wchar_t *path) {
    return pending_record(handle,path,NULL,NULL);
}
static void pending_clear(HANDLE handle) {
    GUID operation={0};
    wchar_t *policy=NULL;
    BOOL found=FALSE;
    EnterCriticalSection(&g_lock);
    for (int i=0;i<PENDING_MAX;i++) {
        if (g_pending_handle[i] && g_pending_handle[i]==handle) {
            operation=g_pending_operation[i]; found=TRUE;
            HeapFree(GetProcessHeap(),0,g_pending_path[i]);
            policy=g_pending_policy_path[i]; g_pending_policy_path[i]=NULL;
            g_pending_path[i]=NULL; g_pending_handle[i]=NULL;
            break;
        }
    }
    LeaveCriticalSection(&g_lock);
    if (found) finish_recovery(&operation,0,ERROR_OPERATION_ABORTED,policy);
    HeapFree(GetProcessHeap(),0,policy);
}
static wchar_t *pending_take(HANDLE handle, GUID *operation, wchar_t **policy_path) {
    wchar_t *path=NULL;
    EnterCriticalSection(&g_lock);
    for (int i=0;i<PENDING_MAX;i++) {
        if (g_pending_handle[i] && g_pending_handle[i]==handle) {
            path=g_pending_path[i]; *operation=g_pending_operation[i];
            *policy_path=g_pending_policy_path[i]; g_pending_policy_path[i]=NULL;
            g_pending_path[i]=NULL; g_pending_handle[i]=NULL; break;
        }
    }
    LeaveCriticalSection(&g_lock);
    return path;
}
static int pending_has_operation(const GUID *operation) {
    if (!g_lock_ready) return 0;
    int found=0;
    EnterCriticalSection(&g_lock);
    for (int i=0;i<PENDING_MAX;i++) {
        if ((g_pending_handle[i] || g_pending_reserved[i]) && IsEqualGUID(&g_pending_operation[i],operation)) { found=1; break; }
    }
    LeaveCriticalSection(&g_lock);
    return found;
}

static BOOL handle_has_delete(HANDLE handle) {
    /* PUBLIC_OBJECT_BASIC_INFORMATION begins with Attributes and GrantedAccess. */
    ULONG basic[14] = {0};
    return query_handle_object && query_handle_object(handle, 0, basic, sizeof basic, NULL) >= 0
        && (basic[1] & DELETE) != 0;
}

static DeleteProxy *find_delete_proxy(HANDLE handle) {
    /* Caller holds g_lock. */
    for (int i = 0; i < PENDING_MAX; ++i) {
        if (g_delete_proxy[i].handle == handle) return &g_delete_proxy[i];
    }
    return NULL;
}

static BOOL remember_delete_proxy(HANDLE handle) {
    BY_HANDLE_FILE_INFORMATION identity;
    if (GetFileType(handle) != FILE_TYPE_DISK || !GetFileInformationByHandle(handle, &identity)
        || (identity.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) return FALSE;
    HANDLE self = GetCurrentProcess(), reference = NULL;
    if (!DuplicateHandle(self, handle, self, &reference, 0, FALSE, DUPLICATE_SAME_ACCESS)) return FALSE;
    EnterCriticalSection(&g_lock);
    DeleteProxy *slot = find_delete_proxy(handle);
    if (slot) {
        g_nt_close(slot->reference);
        pending_clear(handle);
    } else {
        slot = find_delete_proxy(NULL);
    }
    if (slot) *slot = (DeleteProxy){.handle = handle, .reference = reference, .identity = identity};
    LeaveCriticalSection(&g_lock);
    if (!slot) g_nt_close(reference);
    return slot != NULL;
}

static BOOL get_delete_proxy(HANDLE handle, DeleteProxy *proxy) {
    if (!handle) return FALSE;
    EnterCriticalSection(&g_lock);
    DeleteProxy *slot = find_delete_proxy(handle);
    if (slot && !compare_object_handles(handle, slot->reference)) {
        /* A close outside NtClose can leave a stale numeric handle in the table. */
        HANDLE reference = slot->reference;
        ZeroMemory(slot, sizeof *slot);
        g_nt_close(reference);
        pending_clear(handle);
        slot = NULL;
    }
    if (slot) *proxy = *slot;
    LeaveCriticalSection(&g_lock);
    return slot != NULL;
}

static BOOL delete_proxy_eligible(ACCESS_MASK access, OBJECT_ATTRIBUTES_ *oa, ULONG share, ULONG options) {
    /* Only JiuwenBox recovery with a bound broker can issue virtual delete rights. */
    if (!recovery_mode || authorize_delete || !recovery_config.bound
        || !compare_object_handles
        || !parse_port(recovery_config.port) || !recovery_config.token[0]
        || !(access & DELETE) || (access & (MAXIMUM_ALLOWED | GENERIC_ALL))
        || !(share & FILE_SHARE_DELETE) || (options & (FILE_OPEN_BY_FILE_ID | FILE_OPEN_REPARSE_POINT))
        || !memory_ok(oa, sizeof *oa, 0) || (oa->Attributes & OBJ_INHERIT)) return FALSE;
    wchar_t *path = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PATH_CAP * sizeof *path);
    if (!path) return FALSE;
    BOOL eligible = path_from_object(oa, path, PATH_CAP) && !softdelete_exempt(path);
    HeapFree(GetProcessHeap(), 0, path);
    return eligible;
}

static NTSTATUS recycle_delete_proxy(const DeleteProxy *proxy, LPCWSTR path, const GUID *operation) {
    BY_HANDLE_FILE_INFORMATION identity;
    if (!compare_object_handles(proxy->handle, proxy->reference)
        || !GetFileInformationByHandle(proxy->handle, &identity)
        || identity.dwVolumeSerialNumber != proxy->identity.dwVolumeSerialNumber
        || identity.nFileIndexHigh != proxy->identity.nFileIndexHigh
        || identity.nFileIndexLow != proxy->identity.nFileIndexLow) return STATUS_ACCESS_DENIED;
    if (proxy->recycled) return STATUS_SUCCESS;
    if (!recycle_delegation_configured() || !path[0] || !same_file(path, &identity))
        return STATUS_ACCESS_DENIED;
    if ((identity.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !directory_is_empty(path))
        return (NTSTATUS)0xC0000101L; /* STATUS_DIRECTORY_NOT_EMPTY */

    /* Bound broker configuration makes recover_path broker-only for this operation. */
    int disposition = recover_path(path, 1, operation);
    if (disposition != 3) return STATUS_ACCESS_DENIED;
    EnterCriticalSection(&g_lock);
    DeleteProxy *slot = find_delete_proxy(proxy->handle);
    if (slot && slot->reference == proxy->reference) slot->recycled = TRUE;
    LeaveCriticalSection(&g_lock);
    return STATUS_SUCCESS;
}

static NTSTATUS close_delete_proxy(HANDLE handle) {
    EnterCriticalSection(&g_lock);
    NTSTATUS status = g_nt_close(handle);
    if (status >= 0) {
        DeleteProxy *slot = find_delete_proxy(handle);
        if (slot) {
            g_nt_close(slot->reference);
            ZeroMemory(slot, sizeof *slot);
        }
    }
    LeaveCriticalSection(&g_lock);
    return status;
}

static void set_iosb(IO_STATUS_BLOCK_ *iosb, NTSTATUS status) {
    if (iosb == NULL || !memory_ok(iosb, sizeof(*iosb), 1)) {
        return;
    }
    iosb->StatusUnion.Status = status;
    iosb->Information = 0;
}

static int disposition_wants_delete(ULONG cls, const uint8_t *info, ULONG length) {
    if (cls == FILE_DISPOSITION_INFORMATION) {
        return length >= 1 && info[0] != 0;
    }
    if (cls == FILE_DISPOSITION_INFORMATION_EX && length >= sizeof(ULONG)) {
        ULONG flags = 0;
        memcpy(&flags, info, sizeof flags);
        return (flags & 1UL) != 0;
    }
    return 0;
}

static int disposition_clears_delete(ULONG cls, const uint8_t *info, ULONG length) {
    if (cls == FILE_DISPOSITION_INFORMATION) {
        return length >= 1 && info[0] == 0;
    }
    if (cls == FILE_DISPOSITION_INFORMATION_EX && length >= sizeof(ULONG)) {
        ULONG flags = 0;
        memcpy(&flags, info, sizeof flags);
        return (flags & 1UL) == 0;
    }
    return 0;
}

static int rename_replaces(ULONG cls, const uint8_t *info, ULONG length) {
    ULONG flags = 0;
    if (cls == FILE_RENAME_INFORMATION) {
        return length >= 1 && info[0] != 0;
    }
    if (cls == FILE_RENAME_INFORMATION_EX && length >= sizeof(ULONG)) {
        memcpy(&flags, info, sizeof flags);
        return (flags & FILE_RENAME_REPLACE_IF_EXISTS) != 0;
    }
    return 0;
}

static int rename_replace_dest(ULONG cls, const uint8_t *info, ULONG length, wchar_t *dest, size_t cch) {
    HANDLE root = NULL;
    ULONG name_bytes = 0;
    wchar_t *name = NULL;
    int ok = 0;
    dest[0] = L'\0';
    const ULONG header = FIELD_OFFSET(FILE_RENAME_INFO, FileName);
    if (length < header || !memory_ok(info, length, 0)) {
        return 0;
    }
    memcpy(&root, info + FIELD_OFFSET(FILE_RENAME_INFO, RootDirectory), sizeof root);
    memcpy(&name_bytes, info + FIELD_OFFSET(FILE_RENAME_INFO, FileNameLength), sizeof name_bytes);
    if (!rename_replaces(cls, info, length) || name_bytes == 0 || (name_bytes % 2) != 0
        || name_bytes > length - header) {
        return 0;
    }
    name = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)name_bytes + sizeof(wchar_t));
    if (name == NULL) {
        return 0;
    }
    memcpy(name, info + header, name_bytes);
    name[name_bytes / sizeof(wchar_t)] = L'\0';
    ok = join_root_name(root, name, dest, cch);
    HeapFree(GetProcessHeap(), 0, name);
    return ok;
}

/* -------------------------------------------------------------------------- */
/* Hooks.                                                                     */
/* -------------------------------------------------------------------------- */

static int path_has_file_id(
    const wchar_t *path, int have_id, DWORD volume, DWORD index_high, DWORD index_low) {
    BY_HANDLE_FILE_INFORMATION info;
    HANDLE opened;
    int same;
    /* A path alone cannot identify the object once its handle is closed. */
    if (!have_id) {
        return 0;
    }
    {
        wchar_t *api_path = filesystem_path(path);
        if (api_path == NULL) {
            return 0;
        }
        opened = CreateFileW(
            api_path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        HeapFree(GetProcessHeap(), 0, api_path);
    }
    if (opened == INVALID_HANDLE_VALUE) {
        return 0;
    }
    same = GetFileInformationByHandle(opened, &info)
        && info.dwVolumeSerialNumber == volume
        && info.nFileIndexHigh == index_high
        && info.nFileIndexLow == index_low;
    CloseHandle(opened);
    return same;
}

static DWORD status_error(NTSTATUS status) {
    typedef ULONG (WINAPI *ConvertStatus)(NTSTATUS);
    ConvertStatus convert=(ConvertStatus)(void*)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"RtlNtStatusToDosError");
    return status>=0 ? ERROR_SUCCESS : convert?convert(status):ERROR_GEN_FAILURE;
}

static NTSTATUS NTAPI hook_NtClose(HANDLE handle) {
    DWORD saved;
    wchar_t *path;
    NTSTATUS status;
    int pending;
    int have_id = 0;
    DWORD volume = 0;
    DWORD index_high = 0;
    DWORD index_low = 0;
    BY_HANDLE_FILE_INFORMATION before;
    if (t_bypass) {
        return g_nt_close(handle);
    }
    /* Save before any Win32 call. CreateSymbolicLink reads this slot after
     * the cleanup close and ignores the NTSTATUS we return. */
    saved = GetLastError();
    GUID operation;
    wchar_t *policy_path=NULL;
    DeleteProxy proxy;
    BOOL virtual_delete = get_delete_proxy(handle, &proxy);
    path = pending_take(handle, &operation, &policy_path);
    pending = path != NULL;
    if (virtual_delete) {
        status = pending ? recycle_delete_proxy(&proxy, path, &operation) : STATUS_SUCCESS;
        if (status < 0) {
            /* Keep the handle and pending intent alive when close is refused. */
            pending_record(handle, path, &operation, policy_path);
        } else {
            if (pending) finish_recovery(&operation, 3, ERROR_SUCCESS, policy_path);
            status = close_delete_proxy(handle);
        }
        HeapFree(GetProcessHeap(), 0, policy_path);
        HeapFree(GetProcessHeap(), 0, path);
        SetLastError(saved);
        return status;
    }
    if (!pending) {
        SetLastError(saved);
        return g_nt_close(handle);
    }
    BOOL identified = GetFileInformationByHandle(handle, &before);
    if (!identified) {
        /* DELETE-only MSYS handles may lack metadata rights. Reopen the same
         * file object while it is still held, independent of its path. */
        HANDLE metadata = ReOpenFile(handle, FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
        if (metadata != INVALID_HANDLE_VALUE) {
            identified = GetFileInformationByHandle(metadata, &before);
            g_nt_close(metadata);
        }
    }
    if (identified) {
        have_id = 1;
        volume = before.dwVolumeSerialNumber;
        index_high = before.nFileIndexHigh;
        index_low = before.nFileIndexLow;
    }
    SetLastError(saved);
    status = g_nt_close(handle);
    DWORD close_error = status_error(status);
    emit_stage_result(&operation,policy_path,1,status,close_error);
    if (!pending || status < 0) {
        if (status < 0 && pending) {
            pending_record(handle, path, &operation, policy_path);
        }
        HeapFree(GetProcessHeap(), 0, policy_path);
        HeapFree(GetProcessHeap(), 0, path);
        SetLastError(close_error);
        return status;
    }
    if (!path_has_file_id(path, have_id, volume, index_high, index_low)) {
        log_line(L"deferred recovery refused: file identity unavailable or changed");
        finish_recovery(&operation,0,ERROR_FILE_INVALID,policy_path);
        HeapFree(GetProcessHeap(), 0, policy_path);
        HeapFree(GetProcessHeap(), 0, path);
        SetLastError(saved);
        return STATUS_ACCESS_DENIED;
    }
    if (softdelete_exempt(path)) {
        finish_recovery(&operation,0,ERROR_OPERATION_ABORTED,policy_path);
        HeapFree(GetProcessHeap(), 0, policy_path);
        HeapFree(GetProcessHeap(), 0, path);
        SetLastError(saved);
        return status;
    }
    if (!recover_operation(path,&operation,TRUE,policy_path)) {
        HeapFree(GetProcessHeap(), 0, policy_path);
        HeapFree(GetProcessHeap(), 0, path);
        SetLastError(saved);
        return STATUS_ACCESS_DENIED;
    }
    HeapFree(GetProcessHeap(), 0, policy_path);
    HeapFree(GetProcessHeap(), 0, path);
    SetLastError(saved);
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI hook_NtDeleteFile(OBJECT_ATTRIBUTES_ *oa) {
    DWORD saved;
    wchar_t *path;
    int ok;
    if (t_bypass) {
        return g_nt_delete_file(oa);
    }
    saved = GetLastError();
    path = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PATH_CAP * sizeof(wchar_t));
    if (path == NULL) {
        SetLastError(saved);
        return STATUS_ACCESS_DENIED;
    }
    if (!path_from_object(oa, path, PATH_CAP)) {
        HeapFree(GetProcessHeap(), 0, path);
        SetLastError(saved);
        return STATUS_ACCESS_DENIED;
    }
    if (softdelete_exempt(path)) {
        HeapFree(GetProcessHeap(), 0, path);
        return g_nt_delete_file(oa);
    }
    if (!path_exists(path)) {
        HeapFree(GetProcessHeap(), 0, path);
        SetLastError(ERROR_FILE_NOT_FOUND);
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    ok = guard_recover_path(path);
    HeapFree(GetProcessHeap(), 0, path);
    if (!ok) {
        SetLastError(saved);
        return STATUS_ACCESS_DENIED;
    }
    SetLastError(saved);
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI hook_NtSetInformationFile(
    HANDLE file, IO_STATUS_BLOCK_ *iosb, PVOID info, ULONG length, ULONG cls) {
    DWORD saved;
    uint8_t *bytes = NULL;
    wchar_t *path = NULL;
    wchar_t *dest = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    int handled = 0;
    GuardDeleteScope *replacement=NULL;
    if (t_bypass) {
        return g_nt_set_info(file, iosb, info, length, cls);
    }
    if (cls != FILE_DISPOSITION_INFORMATION && cls != FILE_DISPOSITION_INFORMATION_EX
        && cls != FILE_RENAME_INFORMATION && cls != FILE_RENAME_INFORMATION_EX) {
        return g_nt_set_info(file, iosb, info, length, cls);
    }
    saved = GetLastError();
    const ULONG header = FIELD_OFFSET(FILE_RENAME_INFO, FileName);
    DeleteProxy proxy;
    BOOL virtual_delete = get_delete_proxy(file, &proxy);
    if ((virtual_delete && (cls == FILE_RENAME_INFORMATION || cls == FILE_RENAME_INFORMATION_EX))
        || (!virtual_delete && !handle_has_delete(file))) {
        set_iosb(iosb, STATUS_ACCESS_DENIED);
        SetLastError(saved);
        return STATUS_ACCESS_DENIED;
    }
    if (info == NULL || length == 0 || !memory_ok(info, length < header ? length : header, 0)) {
        SetLastError(saved);
        return STATUS_ACCESS_DENIED;
    }
    if (length > INFO_COPY_MAX) {
        /* A normal rename still has to work. Only a delete or replace that we cannot inspect is refused. */
        if (cls == FILE_DISPOSITION_INFORMATION || cls == FILE_DISPOSITION_INFORMATION_EX) {
            if (disposition_wants_delete(cls, (const uint8_t *)info, length)) {
                SetLastError(saved);
                return STATUS_ACCESS_DENIED;
            }
        } else if (rename_replaces(cls, (const uint8_t *)info, length)) {
            SetLastError(saved);
            return STATUS_ACCESS_DENIED;
        }
        return g_nt_set_info(file, iosb, info, length, cls);
    }
    bytes = (uint8_t *)HeapAlloc(GetProcessHeap(), 0, length);
    path = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PATH_CAP * sizeof(wchar_t));
    dest = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PATH_CAP * sizeof(wchar_t));
    if (bytes == NULL || path == NULL || dest == NULL) {
        HeapFree(GetProcessHeap(), 0, bytes);
        HeapFree(GetProcessHeap(), 0, path);
        HeapFree(GetProcessHeap(), 0, dest);
        SetLastError(saved);
        return STATUS_ACCESS_DENIED;
    }
    if (!memory_ok(info, length, 0)) {
        HeapFree(GetProcessHeap(), 0, bytes);
        HeapFree(GetProcessHeap(), 0, path);
        HeapFree(GetProcessHeap(), 0, dest);
        SetLastError(saved);
        return STATUS_ACCESS_DENIED;
    }
    memcpy(bytes, info, length);
    if (virtual_delete) {
        ULONG flags = 0;
        if (cls == FILE_DISPOSITION_INFORMATION_EX && length >= sizeof flags)
            memcpy(&flags, bytes, sizeof flags);
        status = STATUS_ACCESS_DENIED;
        /* A proxy cannot perform the kernel's force-image-section check. */
        if (!(flags & (~0x1fUL | 4UL))) {
            if (disposition_clears_delete(cls, bytes, length)) {
                pending_clear(file);
                status = STATUS_SUCCESS;
            } else if (disposition_wants_delete(cls, bytes, length)) {
                path_from_handle(file, path, PATH_CAP);
                GUID operation;
                if ((flags & 8UL) && *path && !softdelete_exempt(path)) {
                    if (pending_put(file, path)) status = STATUS_SUCCESS;
                } else if (SUCCEEDED(CoCreateGuid(&operation))) {
                    status = recycle_delete_proxy(&proxy, path, &operation);
                    if (!proxy.recycled)
                        finish_recovery(&operation, status >= 0 ? 3 : 0, status_error(status), path);
                }
            }
        }
        set_iosb(iosb, status);
        handled = 1;
    } else if (cls == FILE_DISPOSITION_INFORMATION || cls == FILE_DISPOSITION_INFORMATION_EX) {
        if (disposition_clears_delete(cls, bytes, length)) {
            pending_clear(file);
        } else if (disposition_wants_delete(cls, bytes, length)) {
            path_from_handle(file, path, PATH_CAP);
            if (path[0] == L'\0') {
                status = STATUS_ACCESS_DENIED;
                handled = 1;
            } else if (softdelete_exempt(path)) {
                handled = 0;
            } else if (!pending_put(file, path)) {
                /* Handle stays open, so the move has to wait until NtClose. */
                status = STATUS_ACCESS_DENIED;
                handled = 1;
            } else {
                set_iosb(iosb, STATUS_SUCCESS);
                status = STATUS_SUCCESS;
                handled = 1;
            }
        }
    }
    if (!handled && (cls == FILE_RENAME_INFORMATION || cls == FILE_RENAME_INFORMATION_EX)
        && rename_replaces(cls, bytes, length)) {
        path_from_handle(file, path, PATH_CAP);
        if (!*path || !rename_replace_dest(cls, bytes, length, dest, PATH_CAP)) {
            status = STATUS_ACCESS_DENIED;
            handled = 1;
        } else if (_wcsicmp(path, dest) != 0 && !softdelete_exempt(dest)) {
            if(!guard_replace_active(dest)) replacement=guard_begin_replace(path,dest,NULL,2);
            if(!replacement && !guard_replace_active(dest)) handled=1;
            DWORD attrs=path_attributes(dest);
            if(!handled && attrs!=INVALID_FILE_ATTRIBUTES && recovery_mode)
                handled=!guard_recover_path(dest);
            if(attrs==INVALID_FILE_ATTRIBUTES) {
                DWORD err=GetLastError();
                if(err!=ERROR_FILE_NOT_FOUND && err!=ERROR_PATH_NOT_FOUND)handled=1;
            }
            if (handled) status = STATUS_ACCESS_DENIED;
            /* A racing replacement must not be overwritten after the check. */
            if (recovery_mode || attrs==INVALID_FILE_ATTRIBUTES) {
                if (cls == FILE_RENAME_INFORMATION) bytes[0] = 0;
                else bytes[0] &= (uint8_t)~FILE_RENAME_REPLACE_IF_EXISTS;
            }
        }
        if (handled) set_iosb(iosb, status);
    }
    if (!handled) {
        status = g_nt_set_info(file, iosb, bytes, length, cls);
        saved = GetLastError();
    }
    if(replacement && !guard_finish_replace(replacement,NULL,status,status_error(status))) {
        if(status>=0)status=STATUS_ACCESS_DENIED;
        set_iosb(iosb,status);
    }
    HeapFree(GetProcessHeap(), 0, bytes);
    HeapFree(GetProcessHeap(), 0, path);
    HeapFree(GetProcessHeap(), 0, dest);
    SetLastError(saved);
    return status;
}

static NTSTATUS NTAPI hook_NtCreateFile(
    HANDLE *file_handle, ACCESS_MASK access, OBJECT_ATTRIBUTES_ *oa, IO_STATUS_BLOCK_ *iosb,
    LARGE_INTEGER *alloc_size, ULONG attributes, ULONG share, ULONG disposition,
    ULONG options, PVOID ea, ULONG ea_length) {
    DWORD saved;
    ULONG cleaned = options;
    wchar_t *path = NULL;
    NTSTATUS status;
    DWORD after;
    int strip, slot=-1;
    if (t_bypass) {
        return g_nt_create_file(
            file_handle, access, oa, iosb, alloc_size, attributes, share, disposition,
            options, ea, ea_length);
    }
    saved = GetLastError();
    strip = (options & FILE_DELETE_ON_CLOSE) != 0;
    if (strip) {
        path = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PATH_CAP * sizeof(wchar_t));
        if (path == NULL || !path_from_object(oa, path, PATH_CAP)) {
            HeapFree(GetProcessHeap(), 0, path);
            SetLastError(saved);
            return STATUS_ACCESS_DENIED;
        }
        if (!softdelete_exempt(path)) {
            cleaned = options & ~FILE_DELETE_ON_CLOSE;
            slot=pending_open_begin(path);
            if(slot<0) {
                HeapFree(GetProcessHeap(),0,path);
                set_iosb(iosb,STATUS_ACCESS_DENIED); SetLastError(saved); return STATUS_ACCESS_DENIED;
            }
        } else {
            strip = 0;
        }
    }
    status = g_nt_create_file(
        file_handle, access, oa, iosb, alloc_size, attributes, share, disposition,
        cleaned, ea, ea_length);
    if (status == STATUS_ACCESS_DENIED && disposition == 1 /* FILE_OPEN */
        && memory_ok(file_handle, sizeof *file_handle, 1) && memory_ok(iosb, sizeof *iosb, 1)
        && delete_proxy_eligible(access, oa, share, options)) {
        HANDLE opened = NULL;
        IO_STATUS_BLOCK_ proxy_io = {0};
        NTSTATUS retry = g_nt_create_file(&opened, (access & ~DELETE) | FILE_READ_ATTRIBUTES,
            oa, &proxy_io, alloc_size, attributes, share, disposition, cleaned, ea, ea_length);
        if (retry >= 0) {
            if (remember_delete_proxy(opened)) {
                *file_handle = opened;
                *iosb = proxy_io;
                status = retry;
            } else g_nt_close(opened);
        }
    }
    if(slot>=0) {
        HANDLE opened=status>=0 && file_handle && memory_ok(file_handle,sizeof(*file_handle),0) ? *file_handle : NULL;
        pending_open_end(slot,opened,status_error(status));
    }
    after = GetLastError();
    HeapFree(GetProcessHeap(), 0, path);
    SetLastError(after);
    return status;
}

static NTSTATUS NTAPI hook_NtOpenFile(
    HANDLE *file_handle, ACCESS_MASK access, OBJECT_ATTRIBUTES_ *oa, IO_STATUS_BLOCK_ *iosb,
    ULONG share, ULONG options) {
    DWORD saved;
    ULONG cleaned = options;
    wchar_t *path = NULL;
    NTSTATUS status;
    DWORD after;
    int strip, slot=-1;
    if (t_bypass) {
        return g_nt_open_file(file_handle, access, oa, iosb, share, options);
    }
    saved = GetLastError();
    strip = (options & FILE_DELETE_ON_CLOSE) != 0;
    if (strip) {
        path = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PATH_CAP * sizeof(wchar_t));
        if (path == NULL || !path_from_object(oa, path, PATH_CAP)) {
            HeapFree(GetProcessHeap(), 0, path);
            SetLastError(saved);
            return STATUS_ACCESS_DENIED;
        }
        if (!softdelete_exempt(path)) {
            cleaned = options & ~FILE_DELETE_ON_CLOSE;
            slot=pending_open_begin(path);
            if(slot<0) {
                HeapFree(GetProcessHeap(),0,path);
                set_iosb(iosb,STATUS_ACCESS_DENIED); SetLastError(saved); return STATUS_ACCESS_DENIED;
            }
        } else {
            strip = 0;
        }
    }
    status = g_nt_open_file(file_handle, access, oa, iosb, share, cleaned);
    if (status == STATUS_ACCESS_DENIED
        && memory_ok(file_handle, sizeof *file_handle, 1) && memory_ok(iosb, sizeof *iosb, 1)
        && delete_proxy_eligible(access, oa, share, options)) {
        HANDLE opened = NULL;
        IO_STATUS_BLOCK_ proxy_io = {0};
        NTSTATUS retry = g_nt_open_file(&opened, (access & ~DELETE) | FILE_READ_ATTRIBUTES,
            oa, &proxy_io, share, cleaned);
        if (retry >= 0) {
            if (remember_delete_proxy(opened)) {
                *file_handle = opened;
                *iosb = proxy_io;
                status = retry;
            } else g_nt_close(opened);
        }
    }
    if(slot>=0) {
        HANDLE opened=status>=0 && file_handle && memory_ok(file_handle,sizeof(*file_handle),0) ? *file_handle : NULL;
        pending_open_end(slot,opened,status_error(status));
    }
    after = GetLastError();
    HeapFree(GetProcessHeap(), 0, path);
    SetLastError(after);
    return status;
}

static int env_block_has(const wchar_t *block, const wchar_t *key) {
    size_t key_len = wcslen(key);
    const wchar_t *cursor;
    if (block == NULL) {
        return 0;
    }
    for (cursor = block; *cursor != L'\0'; cursor += wcslen(cursor) + 1) {
        if (_wcsnicmp(cursor, key, key_len) == 0 && cursor[key_len] == L'=') {
            return 1;
        }
    }
    return 0;
}

static wchar_t *parent_env_value(const wchar_t *key) {
    DWORD n = GetEnvironmentVariableW(key, NULL, 0);
    wchar_t *value;
    if (n <= 1) {
        return NULL;
    }
    value = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n * sizeof(wchar_t));
    if (value == NULL || GetEnvironmentVariableW(key, value, n) == 0) {
        HeapFree(GetProcessHeap(), 0, value);
        return NULL;
    }
    return value;
}

/* CreateProcess without CREATE_UNICODE_ENVIRONMENT passes an ANSI block. */
static wchar_t *ansi_env_to_wide(const char *block) {
    const char *cursor = block;
    size_t bytes;
    int chars;
    wchar_t *wide;
    if (block == NULL) {
        return NULL;
    }
    if (*cursor == '\0') {
        bytes = 1;
    } else {
        while (*cursor != '\0') {
            cursor += strlen(cursor) + 1;
        }
        bytes = (size_t)(cursor - block) + 1;
    }
    if (bytes == 0 || bytes > 0x7fffffff) {
        return NULL;
    }
    chars = MultiByteToWideChar(CP_ACP, 0, block, (int)bytes, NULL, 0);
    if (chars <= 0) {
        return NULL;
    }
    wide = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (size_t)chars * sizeof(wchar_t));
    if (wide == NULL) {
        return NULL;
    }
    if (MultiByteToWideChar(CP_ACP, 0, block, (int)bytes, wide, chars) != chars) {
        HeapFree(GetProcessHeap(), 0, wide);
        return NULL;
    }
    return wide;
}

/* Keep the immutable recovery binding across both inherited and custom environments. */
int recovery_child_environment(LPVOID env, DWORD flags, wchar_t **merged) {
    const wchar_t *keys[] = {ENV_ENABLED, ENV_ARCHIVE, ENV_DLL, ENV_RECYCLE_PORT, ENV_RECYCLE_TOKEN, ENV_RESULTS};
    const wchar_t *values[] = {recovery_config.enabled, recovery_config.archive, g_self_path,
                               recovery_config.port, recovery_config.token, recovery_config.results};
    const wchar_t *optional[] = {L"SystemRoot", ENV_TRACE, L"JIUWENSWARM_LOG_DIR",
                                 L"JIUWENSWARM_LOG_DATE_ROOT", L"JIUWENSWARM_DATA_DIR"};
    wchar_t *extras[ARRAYSIZE(optional)] = {0};
    LPWCH inherited = env ? NULL : GetEnvironmentStringsW();
    wchar_t *converted = env && !(flags & CREATE_UNICODE_ENVIRONMENT) ? ansi_env_to_wide(env) : NULL;
    const wchar_t *block = !env ? inherited : (flags & CREATE_UNICODE_ENVIRONMENT) ? (LPCWSTR)env : converted;
    *merged = NULL;
    if (!block) return 0;
    size_t total = 2;
    for (const wchar_t *p = block; *p; p += wcslen(p) + 1) total += wcslen(p) + 1;
    for (size_t i = 0; i < ARRAYSIZE(keys); ++i) total += wcslen(keys[i]) + wcslen(values[i]) + 2;
    for (size_t i = 0; i < ARRAYSIZE(optional); ++i) {
        if (!env_block_has(block, optional[i])) extras[i] = parent_env_value(optional[i]);
        if (extras[i]) total += wcslen(optional[i]) + wcslen(extras[i]) + 2;
    }
    wchar_t *out = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, total * sizeof(wchar_t));
    if (out) {
        wchar_t *dest = out;
        for (const wchar_t *p = block; *p; p += wcslen(p) + 1) {
            int bound = 0;
            for (size_t i = 0; i < ARRAYSIZE(keys); ++i) {
                size_t len = wcslen(keys[i]);
                if (!_wcsnicmp(keys[i], p, len) && p[len] == L'=') { bound = 1; break; }
            }
            if (!bound) {
                size_t count = wcslen(p) + 1;
                memcpy(dest, p, count * sizeof(wchar_t));
                dest += count;
            }
        }
        for (size_t i = 0; i < ARRAYSIZE(keys); ++i) {
            if (*values[i]) dest += swprintf_s(dest, total - (dest-out), L"%s=%s", keys[i], values[i]) + 1;
        }
        for (size_t i = 0; i < ARRAYSIZE(optional); ++i) {
            if (extras[i]) dest += swprintf_s(dest, total - (dest-out), L"%s=%s", optional[i], extras[i]) + 1;
        }
        *dest = L'\0';
    }
    if (inherited) FreeEnvironmentStringsW(inherited);
    if (converted) HeapFree(GetProcessHeap(), 0, converted);
    for (size_t i = 0; i < ARRAYSIZE(optional); ++i)
        if (extras[i]) HeapFree(GetProcessHeap(), 0, extras[i]);
    *merged = out;
    return out != NULL;
}

/* Use the same fixed-package architecture selection as Shield. */
static BOOL prepare_recovery_child(HANDLE process) {
    int previous = t_worker_creating;
    t_worker_creating = 1;
    BOOL ok = prepare_packaged_guard(process);
    DWORD error = GetLastError();
    t_worker_creating = previous;
    SetLastError(error);
    return ok;
}

/* Any DLL mapped into Git Bash breaks its fork, so this process must not
 * inject into an image that ships next to msys-2.0.dll or cygwin1.dll.
 * The check is the file on disk: the caller itself is usually not MSYS. */
static int directory_has_leaf(const wchar_t *exe, const wchar_t *leaf) {
    wchar_t path[1024];
    const wchar_t *slash;
    size_t dir_chars;
    size_t leaf_chars;
    if (exe == NULL || leaf == NULL) {
        return 0;
    }
    slash = wcsrchr(exe, L'\\');
    if (slash == NULL) {
        return 0;
    }
    dir_chars = (size_t)(slash - exe);
    leaf_chars = wcslen(leaf);
    if (dir_chars + 1 + leaf_chars + 1 >= 1024) {
        return 0;
    }
    memcpy(path, exe, dir_chars * sizeof(wchar_t));
    path[dir_chars] = L'\\';
    memcpy(path + dir_chars + 1, leaf, (leaf_chars + 1) * sizeof(wchar_t));
    return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES;
}

static int image_is_posix(const wchar_t *exe) {
    const wchar_t *name = exe != NULL ? wcsrchr(exe, L'\\') : NULL;
    /* Git's bin\bash.exe is a native launcher for usr\bin\bash.exe.
     * Keep its debug tree in the caller: injecting the launcher would
     * make it own a debugger that dies as soon as the shell exits. */
    if (name != NULL && _wcsicmp(name + 1, L"bash.exe") == 0
        && directory_has_leaf(exe, L"..\\usr\\bin\\bash.exe")
        && directory_has_leaf(exe, L"..\\usr\\bin\\msys-2.0.dll")) {
        return 1;
    }
    return directory_has_leaf(exe, L"msys-2.0.dll")
        || directory_has_leaf(exe, L"cygwin1.dll");
}

/* conhost is created for every console process, including Git Bash.
 * A remote LoadLibrary at its initial breakpoint access-violates it,
 * and the parent then fails to start (0xC0000142). */
static int image_is_console_host(const wchar_t *exe) {
    const wchar_t *slash;
    const wchar_t *name;
    if (exe == NULL) {
        return 0;
    }
    slash = wcsrchr(exe, L'\\');
    name = (slash != NULL) ? slash + 1 : exe;
    return _wcsicmp(name, L"conhost.exe") == 0 || _wcsicmp(name, L"openconsole.exe") == 0;
}

static int parent_is_posix_runtime(void) {
    return GetModuleHandleW(L"msys-2.0.dll") != NULL
        || GetModuleHandleW(L"cygwin1.dll") != NULL;
}

static int first_command_token(const wchar_t *cmd, wchar_t *out, size_t cap) {
    size_t i = 0;
    size_t n = 0;
    if (cmd == NULL || out == NULL || cap < 2) {
        return 0;
    }
    while (cmd[i] == L' ' || cmd[i] == L'\t') {
        i++;
    }
    if (cmd[i] == L'"') {
        i++;
        while (cmd[i] != L'\0' && cmd[i] != L'"' && n + 1 < cap) {
            out[n++] = cmd[i++];
        }
    } else {
        while (cmd[i] != L'\0' && cmd[i] != L' ' && cmd[i] != L'\t' && n + 1 < cap) {
            out[n++] = cmd[i++];
        }
    }
    out[n] = L'\0';
    return n > 0;
}

static int resolve_child_image(LPCWSTR app, LPCWSTR cmd, wchar_t *full, DWORD cap) {
    wchar_t token[1024];
    const wchar_t *raw = app;
    DWORD n;
    if (full == NULL || cap < 2) {
        return 0;
    }
    full[0] = L'\0';
    if (raw == NULL || raw[0] == L'\0') {
        if (!first_command_token(cmd, token, 1024)) {
            return 0;
        }
        raw = token;
    }
    if (wcschr(raw, L'\\') == NULL && wcschr(raw, L'/') == NULL) {
        n = SearchPathW(NULL, raw, L".exe", cap, full, NULL);
        return n > 0 && n < cap;
    }
    n = GetFullPathNameW(raw, cap, full, NULL);
    return n > 0 && n < cap;
}

static int image_leaf_is(const wchar_t *exe, const wchar_t *leaf) {
    const wchar_t *slash;
    const wchar_t *name;
    if (exe == NULL || leaf == NULL) {
        return 0;
    }
    slash = wcsrchr(exe, L'\\');
    name = (slash != NULL) ? slash + 1 : exe;
    return _wcsicmp(name, leaf) == 0;
}

/* POSIX delete helpers spawned by Git Bash. Do not add bash/sh/find:
 * those fork, and an extra DLL makes the fork wait forever. */
static int image_is_posix_delete_tool(const wchar_t *exe) {
    return image_leaf_is(exe, L"rm.exe")
        || image_leaf_is(exe, L"rmdir.exe")
        || image_leaf_is(exe, L"unlink.exe")
        || image_leaf_is(exe, L"shred.exe");
}

/* These images are not injected. MinGW keeps the DLL mapped from outside
 * the install tree (git.exe). Explorer must keep running after uninstall. */
static int image_skip_inject(const wchar_t *exe) {
    return image_is_console_host(exe)
        || image_leaf_is(exe, L"explorer.exe")
        || directory_has_leaf(exe, L"libwinpthread-1.dll");
}

static int child_is_posix_image(LPCWSTR app, LPCWSTR cmd) {
    wchar_t full[1024];
    if (!resolve_child_image(app, cmd, full, 1024)) {
        return 0;
    }
    return image_is_posix(full);
}

/* Returns 1 only after the process has actually exited. A failed kill must
 * not be followed by a second CreateProcess: that would run the command twice. */
static int retire_suspended_process(LPPROCESS_INFORMATION pi) {
    DWORD waited;
    if (pi == NULL || pi->hProcess == NULL) {
        return 0;
    }
    TerminateProcess(pi->hProcess, 1);
    waited = WaitForSingleObject(pi->hProcess, 3000);
    if (waited != WAIT_OBJECT_0) {
        return 0;
    }
    CloseHandle(pi->hProcess);
    pi->hProcess = NULL;
    if (pi->hThread != NULL) {
        CloseHandle(pi->hThread);
        pi->hThread = NULL;
    }
    pi->dwProcessId = 0;
    pi->dwThreadId = 0;
    return 1;
}

/* A debug event has to be continued before the next one can be read.
 * Loading raises LOAD_DLL events, and this loop continues them. */
/* One Git Bash and the processes it starts. Owned by the thread that
 * created that Bash, so one stuck tree cannot block the next command. */
typedef struct DebugTree {
    DWORD root_pid;
    HANDLE root_process;
    int root_exited;
    int live;
} DebugTree;

static int debug_continue_status(const DEBUG_EVENT *ev) {
    DWORD code;
    if (ev->dwDebugEventCode != EXCEPTION_DEBUG_EVENT) {
        return DBG_CONTINUE;
    }
    code = ev->u.Exception.ExceptionRecord.ExceptionCode;
    if (code == EXCEPTION_BREAKPOINT || code == EXCEPTION_SINGLE_STEP) {
        return DBG_CONTINUE;
    }
    return DBG_EXCEPTION_NOT_HANDLED;
}

static void close_create_handles(CREATE_PROCESS_DEBUG_INFO *info) {
    if (info->hFile != NULL) {
        CloseHandle(info->hFile);
        info->hFile = NULL;
    }
    /* ContinueDebugEvent closes the process/thread handles on their exit
     * events. Closing them here lets that later close hit a reused handle. */
}

/* 1 means do not inject: MSYS/Cygwin shells, a console host, MinGW, or
 * an unreadable image. POSIX delete tools are injected so Git Bash rm
 * still hits the ntdll delete hooks. */
static int created_image_skip_inject(HANDLE process, HANDLE file) {
    wchar_t path[1024];
    DWORD cap = 1024;
    DWORD n;
    const wchar_t *bare;
    path[0] = L'\0';
    if (file != NULL) {
        n = GetFinalPathNameByHandleW(file, path, 1024, 0);
        if (n == 0 || n >= 1024) {
            path[0] = L'\0';
        }
    }
    if (path[0] == L'\0' && process != NULL) {
        if (!QueryFullProcessImageNameW(process, 0, path, &cap)) {
            path[0] = L'\0';
        }
    }
    bare = path;
    if (wcsncmp(path, L"\\\\?\\", 4) == 0) {
        bare = path + 4;
    }
    if (bare[0] == L'\0') {
        log_line(L"softdelete: debug image path unavailable; refusing unprotected execution");
        return -1;
    }
    if (image_skip_inject(bare)) {
        return 1;
    }
    if (image_is_posix_delete_tool(bare)) {
        return 0;
    }
    return image_is_posix(bare);
}

static void debug_process_image_path(HANDLE process, HANDLE file, wchar_t *path, DWORD cap) {
    DWORD n;
    if (path == NULL || cap < 2) {
        return;
    }
    path[0] = L'\0';
    if (file != NULL) {
        n = GetFinalPathNameByHandleW(file, path, cap, 0);
        if (n == 0 || n >= cap) {
            path[0] = L'\0';
        }
    }
    if (path[0] == L'\0' && process != NULL) {
        DWORD name_cap = cap;
        if (!QueryFullProcessImageNameW(process, 0, path, &name_cap)) {
            path[0] = L'\0';
        }
    }
    if (wcsncmp(path, L"\\\\?\\", 4) == 0 && path[4] != L'\0') {
        wcscpy_s(path, cap, path + 4);
    }
}

static void on_debug_create(DebugTree *tree, DEBUG_EVENT *ev) {
    CREATE_PROCESS_DEBUG_INFO *info = &ev->u.CreateProcessInfo;
    wchar_t image[1024];
    wchar_t msg[1200];
    int skip;
    debug_process_image_path(info->hProcess, info->hFile, image, 1024);
    skip = created_image_skip_inject(info->hProcess, info->hFile);
    swprintf_s(
        msg, 1200, L"posix-debug: CREATE pid=%lu skip_inject=%d live_after=%d image=%s",
        ev->dwProcessId, skip, tree->live + 1, image[0] != L'\0' ? image : L"(unknown)");
    log_line(msg);
    tree->live += 1;
    if (skip<0) { TerminateProcess(info->hProcess,125); close_create_handles(info); return; }
    if (!skip) {
        GuardRecoveryBootstrap *bootstrap=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(*bootstrap));
        BOOL prepared=FALSE;
        if (bootstrap) {
            bootstrap->magic=GUARD_RECOVERY_BOOTSTRAP;
            wcscpy_s(bootstrap->archive,32768,recovery_config.archive);
            wcscpy_s(bootstrap->port,16,recovery_config.port);
            wcscpy_s(bootstrap->token,256,recovery_config.token);
            wcscpy_s(bootstrap->result_file,32768,recovery_config.results);
            prepared=DetourCopyPayloadToProcess(info->hProcess,&guard_recovery_bootstrap_guid,bootstrap,sizeof(*bootstrap))
                && prepare_recovery_child(info->hProcess);
            HeapFree(GetProcessHeap(),0,bootstrap);
        }
        if (!prepared) {
            log_line(L"softdelete: import preparation failed; terminating unprotected child");
            TerminateProcess(info->hProcess,125);
        } else log_line(L"softdelete: child import prepared before loader startup");
    }
    close_create_handles(info);
}

static int dispatch_debug_event(DebugTree *tree, DEBUG_EVENT *ev) {
    if (ev->dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT) on_debug_create(tree,ev);
    else if (ev->dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT) {
        if (tree->live>0) --tree->live;
        if (ev->dwProcessId==tree->root_pid) tree->root_exited=1;
    } else if (ev->dwDebugEventCode==LOAD_DLL_DEBUG_EVENT && ev->u.LoadDll.hFile) {
        CloseHandle(ev->u.LoadDll.hFile); ev->u.LoadDll.hFile=NULL;
    }
    return 0;
}

/* The root can be killed while still suspended, before it reports any
 * debug event. The process handle is then the only sign that it is gone. */
static int debug_tree_finished(DebugTree *tree) {
    if (tree->live > 0) {
        return 0;
    }
    if (tree->root_exited) {
        return 1;
    }
    return tree->root_process != NULL
        && WaitForSingleObject(tree->root_process, 0) == WAIT_OBJECT_0;
}

/* CreateProcessW is what actually attaches the debugger. Setting
 * DEBUG_PROCESS only inside CreateProcessInternalW does not, and it
 * leaves Git Bash stuck. Each Bash is created on its own thread, so the
 * debug port belongs to that thread and one tree cannot block the next. */

typedef struct PosixStart {
    HANDLE token;
    LPCWSTR app;
    LPWSTR cmd;
    LPSECURITY_ATTRIBUTES process_attr;
    LPSECURITY_ATTRIBUTES thread_attr;
    BOOL inherit;
    DWORD flags;
    LPVOID env;
    LPCWSTR cwd;
    LPSTARTUPINFOW startup;
    LPPROCESS_INFORMATION pi_out;
    BOOL ok;
    DWORD error;
    HANDLE created;
} PosixStart;

static void log_posix_recycle_env(void) {
    wchar_t port[32];
    wchar_t msg[160];
    DWORD n = GetEnvironmentVariableW(ENV_RECYCLE_PORT, port, 32);
    swprintf_s(
        msg, 160, L"posix-debug: debugger thread RECYCLE_PORT=%s",
        (n > 0 && n < 32) ? port : L"(unset)");
    log_line(msg);
}

static DWORD WINAPI posix_debug_thread(LPVOID arg) {
    PosixStart *req = (PosixStart *)arg;
    DebugTree tree;
    PROCESS_INFORMATION *pi;
    DWORD used;
    wchar_t msg[1200];
    memset(&tree, 0, sizeof tree);
    log_posix_recycle_env();
    used = req->flags | DEBUG_PROCESS;
    t_worker_creating = 1;
    if (req->token == NULL) {
        req->ok = CreateProcessW(
            req->app, req->cmd, req->process_attr, req->thread_attr, req->inherit, used,
            req->env, req->cwd, req->startup, req->pi_out);
    } else {
        req->ok = CreateProcessAsUserW(
            req->token, req->app, req->cmd, req->process_attr, req->thread_attr,
            req->inherit, used, req->env, req->cwd, req->startup, req->pi_out);
    }
    req->error = GetLastError();
    t_worker_creating = 0;
    pi = req->pi_out;
    if (!req->ok || pi == NULL || pi->hProcess == NULL) {
        req->ok = FALSE;
        if (req->error == 0) {
            req->error = ERROR_INVALID_PARAMETER;
        }
        swprintf_s(
            msg, 1200,
            L"posix-debug: CreateProcess(DEBUG) failed winerror=%lu as_user=%d",
            req->error, req->token != NULL);
        log_line(msg);
        SetEvent(req->created);
        return 0;
    }
    /* This call requires a debugging connection, established above. */
    DebugSetProcessKillOnExit(FALSE);
    tree.root_pid = pi->dwProcessId;
    swprintf_s(
        msg, 1200, L"posix-debug: bash root started pid=%lu flags=0x%lx",
        pi->dwProcessId, (unsigned long)used);
    log_line(msg);
    if (!DuplicateHandle(
            GetCurrentProcess(), pi->hProcess, GetCurrentProcess(), &tree.root_process,
            0, FALSE, DUPLICATE_SAME_ACCESS)) {
        /* Never release a shell whose protected debug tree cannot be owned. */
        log_win(
            L"DuplicateHandle", GetLastError(), pi->dwProcessId,
            L"terminating bash without a protected debug tree");
        log_line(L"posix-debug: DuplicateHandle(root) failed, debug tree aborted");
        TerminateProcess(pi->hProcess,125);
        DebugActiveProcessStop(pi->dwProcessId);
        req->ok = FALSE;
        req->error = ERROR_DLL_INIT_FAILED;
        SetEvent(req->created);
        return 0;
    }
    SetEvent(req->created);
    while (!debug_tree_finished(&tree)) {
        DEBUG_EVENT ev;
        if (!WaitForDebugEvent(&ev, 50)) {
            continue;
        }
        if (!dispatch_debug_event(&tree, &ev)) {
            ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, debug_continue_status(&ev));
        }
    }
    swprintf_s(
        msg, 1200, L"posix-debug: debug tree finished root_pid=%lu", tree.root_pid);
    log_line(msg);
    CloseHandle(tree.root_process);
    return 0;
}

static BOOL submit_posix_create(
    HANDLE token, LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES process_attr,
    LPSECURITY_ATTRIBUTES thread_attr, BOOL inherit, DWORD flags, LPVOID env, LPCWSTR cwd,
    LPSTARTUPINFOW startup, LPPROCESS_INFORMATION pi) {
    PosixStart req;
    HANDLE thread;
    HANDLE waits[2];
    DWORD which;
    if (pi == NULL) {
        return FALSE;
    }
    memset(&req, 0, sizeof req);
    req.token = token;
    req.app = app;
    req.cmd = cmd;
    req.process_attr = process_attr;
    req.thread_attr = thread_attr;
    req.inherit = inherit;
    req.flags = flags;
    req.env = env;
    req.cwd = cwd;
    req.startup = startup;
    req.pi_out = pi;
    req.created = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (req.created == NULL) {
        log_line(L"posix-debug: submit_posix_create CreateEvent failed");
        return FALSE;
    }
    thread = CreateThread(NULL, 0, posix_debug_thread, &req, 0, NULL);
    if (thread == NULL) {
        log_win(L"CreateThread", GetLastError(), 0, L"posix-debug: submit_posix_create");
        CloseHandle(req.created);
        return FALSE;
    }
    waits[0] = req.created;
    waits[1] = thread;
    which = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
    CloseHandle(thread);
    CloseHandle(req.created);
    if (which != WAIT_OBJECT_0) {
        log_line(L"posix-debug: submit_posix_create wait ended on debug thread exit, not bash ready");
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    if (!req.ok) {
        wchar_t msg[128];
        swprintf_s(msg, 128, L"posix-debug: submit_posix_create failed winerror=%lu", req.error);
        log_line(msg);
        SetLastError(req.error);
    }
    return req.ok;
}

static void log_create_route(const wchar_t *decision, LPCWSTR app, LPCWSTR cmd) {
    wchar_t image[1024];
    wchar_t msg[1400];
    if (!resolve_child_image(app, cmd, image, 1024)) {
        image[0] = L'\0';
    }
    swprintf_s(
        msg, 1400, L"posix-debug: route %s pid=%lu image=%s",
        decision != NULL ? decision : L"?",
        GetCurrentProcessId(),
        image[0] != L'\0' ? image : L"(unresolved)");
    log_line(msg);
}

static BOOL WINAPI hook_CreateProcessInternalW(
    HANDLE token, LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES process_attr,
    LPSECURITY_ATTRIBUTES thread_attr, BOOL inherit, DWORD flags, LPVOID env,
    LPCWSTR cwd, LPSTARTUPINFOW startup, LPPROCESS_INFORMATION pi, HANDLE *new_token) {
    DWORD used = flags;
    int added_suspend = 0;
    BOOL ok;
    wchar_t *owned_env = NULL;
    if (!recovery_child_environment(env, flags, &owned_env)) {
        SetLastError(ERROR_BAD_ENVIRONMENT);
        return FALSE;
    }
    LPVOID use_env = owned_env;
    used |= CREATE_UNICODE_ENVIRONMENT;
    if (t_worker_creating || parent_is_posix_runtime()) {
        ok = g_create_process(token, app, cmd, process_attr, thread_attr, inherit, used, use_env,
                              cwd, startup, pi, new_token);
        DWORD error = GetLastError();
        HeapFree(GetProcessHeap(), 0, owned_env);
        SetLastError(error);
        return ok;
    }
    if (child_is_posix_image(app, cmd)) {
        wchar_t posix_image[1024];
        wchar_t posix_msg[1100];
        if (resolve_child_image(app, cmd, posix_image, 1024)) {
            swprintf_s(
                posix_msg, 1100, L"posix-debug: hook routing bash image=%s", posix_image);
            log_line(posix_msg);
        } else {
            log_line(L"posix-debug: hook routing bash image=(unresolved)");
        }
        ok = submit_posix_create(
            token, app, cmd, process_attr, thread_attr, inherit, used, use_env, cwd, startup, pi);
        if (ok && pi != NULL && pi->dwProcessId != 0) {
            swprintf_s(
                posix_msg, 1100, L"posix-debug: submit_posix_create ok bash_pid=%lu",
                pi->dwProcessId);
            log_line(posix_msg);
        }
        if (!ok && pi && pi->hProcess) retire_suspended_process(pi);
        HeapFree(GetProcessHeap(), 0, owned_env);
        return ok;
    }
    {
        wchar_t image[1024];
        if (resolve_child_image(app, cmd, image, 1024) && image_skip_inject(image)) {
            log_create_route(L"skip-inject", app, cmd);
            ok = g_create_process(
                token, app, cmd, process_attr, thread_attr, inherit, used, use_env, cwd, startup, pi,
                new_token);
            HeapFree(GetProcessHeap(), 0, owned_env);
            return ok;
        }
    }
    if ((used & CREATE_SUSPENDED) == 0) {
        used |= CREATE_SUSPENDED;
        added_suspend = 1;
    }
    log_create_route(L"suspend-inject", app, cmd);
    ok = g_create_process(
        token, app, cmd, process_attr, thread_attr, inherit, used, use_env, cwd, startup, pi,
        new_token);
    HeapFree(GetProcessHeap(), 0, owned_env);
    if (!ok || pi == NULL || pi->hProcess == NULL) {
        wchar_t msg[256];
        swprintf_s(
            msg, 256, L"posix-debug: create failed winerror=%lu pid=%lu",
            GetLastError(), GetCurrentProcessId());
        log_line(msg);
        return ok;
    }
    if (!prepare_recovery_child(pi->hProcess)
        || (added_suspend && ResumeThread(pi->hThread) == (DWORD)-1)) {
        DWORD error = GetLastError();
        retire_suspended_process(pi);
        SetLastError(error ? error : ERROR_DLL_INIT_FAILED);
        return FALSE;
    }
    return TRUE;
}

static int directory_is_empty(const wchar_t *path) {
    wchar_t *pattern;
    HANDLE find;
    WIN32_FIND_DATAW data;
    int empty = 1;
    size_t need = wcslen(path) + 3;
    pattern = (wchar_t *)HeapAlloc(GetProcessHeap(), 0, need * sizeof(wchar_t));
    if (pattern == NULL || swprintf_s(pattern, need, L"%s\\*", path) < 0) {
        HeapFree(GetProcessHeap(), 0, pattern);
        return 0;
    }
    find = FindFirstFileExW(
        pattern, FindExInfoBasic, &data, FindExSearchNameMatch, NULL, FIND_FIRST_EX_LARGE_FETCH);
    HeapFree(GetProcessHeap(), 0, pattern);
    if (find == INVALID_HANDLE_VALUE) {
        return 0;
    }
    do {
        if (wcscmp(data.cFileName, L".") != 0 && wcscmp(data.cFileName, L"..") != 0) {
            empty = 0;
            break;
        }
    } while (FindNextFileW(find, &data));
    FindClose(find);
    return empty;
}

static BOOL WINAPI hook_DeleteFileW(LPCWSTR path) {
    DWORD saved;
    DWORD attr;
    if (t_bypass) {
        return g_delete_file(path);
    }
    if (path == NULL || path[0] == L'\0') {
        return g_delete_file(path);
    }
    saved = GetLastError();
    attr = GetFileAttributesW(path);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return FALSE;
    }
    /* DeleteFileW does not remove directories. Leave that to RemoveDirectoryW. */
    if ((attr & FILE_ATTRIBUTE_DIRECTORY) != 0 && (attr & FILE_ATTRIBUTE_REPARSE_POINT) == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    if (softdelete_exempt(path)) {
        return g_delete_file(path);
    }
    if (!guard_recover_path(path)) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    SetLastError(saved);
    return TRUE;
}

static BOOL WINAPI hook_RemoveDirectoryW(LPCWSTR path) {
    DWORD saved;
    DWORD attr;
    if (t_bypass) {
        return g_remove_directory(path);
    }
    if (path == NULL || path[0] == L'\0') {
        return g_remove_directory(path);
    }
    saved = GetLastError();
    attr = GetFileAttributesW(path);
    if (attr == INVALID_FILE_ATTRIBUTES) return FALSE;
    if ((attr & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        SetLastError(ERROR_DIRECTORY);
        return FALSE;
    }
    if (softdelete_exempt(path)) {
        return g_remove_directory(path);
    }
    if ((attr & FILE_ATTRIBUTE_REPARSE_POINT) == 0 && !directory_is_empty(path)) {
        SetLastError(ERROR_DIR_NOT_EMPTY);
        return FALSE;
    }
    if (!guard_recover_path(path)) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    SetLastError(saved);
    return TRUE;
}

static void write_load_error(const wchar_t *text) {
    wchar_t dir[MAX_PATH];
    wchar_t path[MAX_PATH];
    HANDLE file;
    DWORD written = 0;
    char utf8[1024];
    int n;
    int saved_bypass;
    log_line(text);
    if (GetTempPathW(MAX_PATH, dir) == 0) {
        return;
    }
    normalize_log_env_path(dir, MAX_PATH);
    if (swprintf_s(path, MAX_PATH, L"%sjiuwen-softdelete-error.txt", dir) < 0) {
        return;
    }
    saved_bypass = t_bypass;
    t_bypass = 1;
    file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    t_bypass = saved_bypass;
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }
    n = WideCharToMultiByte(CP_UTF8, 0, text, -1, utf8, (int)sizeof utf8, NULL, NULL);
    if (n > 1) {
        WriteFile(file, utf8, (DWORD)(n - 1), &written, NULL);
    }
    CloseHandle(file);
}

void softdelete_bind(const GuardFileCalls *api, GuardFileCalls *handlers) {
    query_handle_object = (void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject");
    if (!g_lock_ready) InitializeCriticalSection(&g_lock);
    g_lock_ready = 1;
    g_nt_create_file = (FnNtCreateFile)api->create;
    g_nt_open_file = (FnNtOpenFile)api->open;
    g_nt_delete_file = (FnNtDeleteFile)api->remove;
    g_nt_set_info = (FnNtSetInformationFile)api->set;
    g_nt_close = api->close;
    g_delete_file = api->delete_file;
    g_remove_directory = api->remove_dir;
    handlers->create = (void*)hook_NtCreateFile;
    handlers->open = (void*)hook_NtOpenFile;
    handlers->remove = (void*)hook_NtDeleteFile;
    handlers->set = (void*)hook_NtSetInformationFile;
    handlers->close = hook_NtClose;
    handlers->delete_file = hook_DeleteFileW;
    handlers->remove_dir = hook_RemoveDirectoryW;
}

void softdelete_release(void) {
    for (int i = 0; i < PENDING_MAX; ++i) {
        if (g_delete_proxy[i].reference) g_nt_close(g_delete_proxy[i].reference);
    }
    ZeroMemory(g_delete_proxy, sizeof g_delete_proxy);
    if (g_lock_ready) {
        for (int i=0; i<PENDING_MAX; ++i) {
            if (g_pending_path[i]) {
                finish_recovery(&g_pending_operation[i],0,ERROR_OPERATION_ABORTED,g_pending_policy_path[i]);
                HeapFree(GetProcessHeap(),0,g_pending_path[i]);
                HeapFree(GetProcessHeap(),0,g_pending_policy_path[i]);
                g_pending_policy_path[i]=NULL;
                g_pending_path[i]=NULL;
                g_pending_handle[i]=NULL;
                g_pending_reserved[i]=FALSE;
            }
        }
        DeleteCriticalSection(&g_lock);
        g_lock_ready=0;
    }
    softdelete_set_policy(NULL,NULL,NULL,NULL);
    softdelete_set_context(NULL);
    posix_attached=FALSE;
    recovery_mode=TRUE;
    ZeroMemory(&recovery_config,sizeof(recovery_config));
}

static const GuardHookBinding file_bindings[GuardFileHookCount] = {
    [GuardHookNtCreateFile] = {(PVOID *)&g_nt_create_file, (PVOID)hook_NtCreateFile},
    [GuardHookNtOpenFile] = {(PVOID *)&g_nt_open_file, (PVOID)hook_NtOpenFile},
    [GuardHookNtDeleteFile] = {(PVOID *)&g_nt_delete_file, (PVOID)hook_NtDeleteFile},
    [GuardHookNtSetInformationFile] = {(PVOID *)&g_nt_set_info, (PVOID)hook_NtSetInformationFile},
    [GuardHookNtClose] = {(PVOID *)&g_nt_close, (PVOID)hook_NtClose},
    [GuardHookDeleteFileW] = {(PVOID *)&g_delete_file, (PVOID)hook_DeleteFileW},
    [GuardHookRemoveDirectoryW] = {(PVOID *)&g_remove_directory, (PVOID)hook_RemoveDirectoryW},
};

static BOOL remove_hooks(void) {
    if (!g_detours) return TRUE;
    LONG status=DetourTransactionBegin();
    if (status) { SetLastError(status); return FALSE; }
    status=DetourUpdateThread(GetCurrentThread());
    if (!status) status=softdelete_posix_hooks(FALSE);
    if (!status) status=configure_file_hooks(file_bindings,FALSE);
    if (!status) status=DetourDetach((PVOID *)&g_create_process,(PVOID)hook_CreateProcessInternalW);
    if (!status) status=DetourTransactionCommit();
    else DetourTransactionAbort();
    if (status) { SetLastError(status); return FALSE; }
    g_detours=0;
    return TRUE;
}

static int install_detours(void) {
    query_handle_object = (void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject");
    compare_object_handles = (void *)GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "CompareObjectHandles");
    g_create_process = (FnCreateProcessInternalW)GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "CreateProcessInternalW");
    if (!g_create_process) {
        return 0;
    }
    t_bypass = 1;
    if (DetourTransactionBegin() != NO_ERROR) {
        write_load_error(L"DetourTransactionBegin failed");
        t_bypass = 0;
        return 0;
    }
    if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR) {
        DetourTransactionAbort();
        write_load_error(L"DetourUpdateThread failed");
        t_bypass = 0;
        return 0;
    }
    if (configure_file_hooks(file_bindings, TRUE) != NO_ERROR ||
        softdelete_posix_hooks(TRUE) != NO_ERROR || DetourAttach((PVOID *)&g_create_process, (PVOID)hook_CreateProcessInternalW) != NO_ERROR) {
        DetourTransactionAbort();
        t_bypass = 0;
        return 0;
    }
    if (DetourTransactionCommit() != NO_ERROR) {
        DetourTransactionAbort();
        write_load_error(L"DetourTransactionCommit failed");
        t_bypass = 0;
        return 0;
    }
    g_detours = 1;
    t_bypass = 0;
    return 1;
}

static int install_all(void) {
    return install_detours();
}

/* The authenticated host uses the same disposition without delegating back to itself. */

/* Parent-side import-table patch. Does not resume or terminate the child. */
SOFT_EXPORT int guard_prepare_process(HANDLE process) {
    HMODULE module;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCWSTR)(void*)guard_prepare_process, &module)
        || !GetModuleFileNameW(module, g_self_path, PATH_CAP)) return 0;
    g_module = module;
    return prepare_recovery_child(process);
}

BOOL WINAPI softdelete_main(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_in_dllmain = 1;
        g_module = instance;
        {
            DWORD n = GetModuleFileNameW(g_module, g_self_path, PATH_CAP);
            if (n == 0 || n >= PATH_CAP) {
                g_self_path[0] = L'\0';
            }
        }
        if (!bind_recovery_config()) return FALSE;
        wcscpy_s(recovery_config.enabled,2,L"1");
        InitializeCriticalSection(&g_lock);
        g_lock_ready = 1;
        {
            int installed = 0;
#if defined(_MSC_VER)
            __try {
                installed = install_all();
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                installed = 0;
                t_bypass = 0;
                __try {
                    DetourTransactionAbort();
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                }
                log_line(L"softdelete: hook installation failed");
            }
#else
            installed = install_all();
#endif
            if (!installed) {
                DeleteCriticalSection(&g_lock);
                g_lock_ready = 0;
                g_in_dllmain = 0;
                return FALSE;
            } else {
                wchar_t exe[1024];
                wchar_t msg[1400];
                if (GetModuleFileNameW(NULL, exe, 1024) == 0) {
                    exe[0] = L'\0';
                }
                swprintf_s(
                    msg, 1400, L"posix-debug: hooks installed pid=%lu exe=%s",
                    GetCurrentProcessId(), exe[0] != L'\0' ? exe : L"(unknown)");
                log_line(msg);
            }
        }
        g_in_dllmain = 0;
    } else if (reason == DLL_PROCESS_DETACH && reserved == NULL) {
        if (!remove_hooks()) return FALSE;
        softdelete_release();

    }
    return TRUE;
}
