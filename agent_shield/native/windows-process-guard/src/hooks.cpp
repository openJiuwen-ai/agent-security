#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winternl.h>
#include <shellapi.h>
#include <detours.h>

#include "operation_mapping.h"
#include "path_classification.h"
#include "pipe_io.h"
#include "record_json.h"
#include "process_guard_startup.h"

#include <stdio.h>
#include <string.h>

#pragma warning(disable : 4191)

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wininet.lib")

extern "C" __declspec(dllexport) DWORD WINAPI ProcessGuardAttach(LPVOID param);

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    char name[96];
    HANDLE mapping;
    void* view;
    DWORD status;
    (void)reserved;
    if (reason != DLL_PROCESS_ATTACH) {
        return TRUE;
    }
    DisableThreadLibraryCalls(instance);
    sprintf_s(name, sizeof(name), "Local\\agent-security-%lu", GetCurrentProcessId());
    mapping = OpenFileMappingA(FILE_MAP_READ, FALSE, name);
    if (mapping == nullptr) {
        return FALSE;
    }
    view = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, sizeof(ProcessGuardStartup));
    status = view == nullptr ? 1 : ProcessGuardAttach(view);
    if (view != nullptr) {
        UnmapViewOfFile(view);
    }
    CloseHandle(mapping);
    return status == 0;
}



constexpr NTSTATUS kStatusAccessDenied = (NTSTATUS)0xC0000022L;
constexpr DWORD kFileDisposition = 4;
constexpr DWORD kFileDispositionEx = 21;
constexpr DWORD kFileRename = 3;
constexpr DWORD kFileRenameEx = 22;
constexpr ULONG kNtRename = 10;
constexpr ULONG kNtDisposition = 13;
constexpr ULONG kNtDispositionEx = 64;
constexpr ULONG kNtRenameEx = 65;
constexpr ULONG kFileDirectory = 0x00000001u;
constexpr DWORD kDeleteFlag = 0x00000001u;

struct HookGuard {
    HookGuard() { ++g_depth; }
    ~HookGuard() { --g_depth; }
    static __declspec(thread) int g_depth;
};

__declspec(thread) int HookGuard::g_depth = 0;

ProcessGuardStartup g_startup = {};
CRITICAL_SECTION g_decide_lock;
CRITICAL_SECTION g_broker_lock;
volatile LONG g_serial = 0;
int g_ready = 0;
CRITICAL_SECTION g_hook_lock;
__declspec(thread) int t_attaching = 0;

using CreateFileW_t = HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
using CreateFileA_t = HANDLE(WINAPI*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
using GetFileAttributesW_t = DWORD(WINAPI*)(LPCWSTR);
using GetFileAttributesA_t = DWORD(WINAPI*)(LPCSTR);
using FindFirstFileW_t = HANDLE(WINAPI*)(LPCWSTR, LPWIN32_FIND_DATAW);
using FindFirstFileA_t = HANDLE(WINAPI*)(LPCSTR, LPWIN32_FIND_DATAA);
using CreateDirectoryW_t = BOOL(WINAPI*)(LPCWSTR, LPSECURITY_ATTRIBUTES);
using CreateDirectoryA_t = BOOL(WINAPI*)(LPCSTR, LPSECURITY_ATTRIBUTES);
using DeleteFileW_t = BOOL(WINAPI*)(LPCWSTR);
using DeleteFileA_t = BOOL(WINAPI*)(LPCSTR);
using RemoveDirectoryW_t = BOOL(WINAPI*)(LPCWSTR);
using RemoveDirectoryA_t = BOOL(WINAPI*)(LPCSTR);
using MoveFileW_t = BOOL(WINAPI*)(LPCWSTR, LPCWSTR);
using MoveFileA_t = BOOL(WINAPI*)(LPCSTR, LPCSTR);
using MoveFileExW_t = BOOL(WINAPI*)(LPCWSTR, LPCWSTR, DWORD);
using MoveFileExA_t = BOOL(WINAPI*)(LPCSTR, LPCSTR, DWORD);
using CopyFileW_t = BOOL(WINAPI*)(LPCWSTR, LPCWSTR, BOOL);
using CopyFileA_t = BOOL(WINAPI*)(LPCSTR, LPCSTR, BOOL);
using CopyFileExW_t = BOOL(WINAPI*)(LPCWSTR, LPCWSTR, LPPROGRESS_ROUTINE, LPVOID, LPBOOL, DWORD);
using CopyFileExA_t = BOOL(WINAPI*)(LPCSTR, LPCSTR, LPPROGRESS_ROUTINE, LPVOID, LPBOOL, DWORD);
using ReplaceFileW_t = BOOL(WINAPI*)(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, LPVOID, LPVOID);
using ReplaceFileA_t = BOOL(WINAPI*)(LPCSTR, LPCSTR, LPCSTR, DWORD, LPVOID, LPVOID);
using CreateHardLinkW_t = BOOL(WINAPI*)(LPCWSTR, LPCWSTR, LPSECURITY_ATTRIBUTES);
using CreateHardLinkA_t = BOOL(WINAPI*)(LPCSTR, LPCSTR, LPSECURITY_ATTRIBUTES);
using CreateSymbolicLinkW_t = BOOLEAN(WINAPI*)(LPCWSTR, LPCWSTR, DWORD);
using CreateSymbolicLinkA_t = BOOLEAN(WINAPI*)(LPCSTR, LPCSTR, DWORD);
using SetFileAttributesW_t = BOOL(WINAPI*)(LPCWSTR, DWORD);
using SetFileAttributesA_t = BOOL(WINAPI*)(LPCSTR, DWORD);
using SetFileInformationByHandle_t = BOOL(WINAPI*)(HANDLE, FILE_INFO_BY_HANDLE_CLASS, LPVOID, DWORD);
using CreateProcessW_t = BOOL(WINAPI*)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
using CreateProcessA_t = BOOL(WINAPI*)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
using CreateProcessAsUserW_t = BOOL(WINAPI*)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
using CreateProcessAsUserA_t = BOOL(WINAPI*)(HANDLE, LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
using CreateProcessWithTokenW_t = BOOL(WINAPI*)(HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
using CreateProcessWithLogonW_t = BOOL(WINAPI*)(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
using ShellExecuteW_t = HINSTANCE(WINAPI*)(HWND, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, INT);
using ShellExecuteA_t = HINSTANCE(WINAPI*)(HWND, LPCSTR, LPCSTR, LPCSTR, LPCSTR, INT);
using ShellExecuteExW_t = BOOL(WINAPI*)(SHELLEXECUTEINFOW*);
using ShellExecuteExA_t = BOOL(WINAPI*)(SHELLEXECUTEINFOA*);
using Connect_t = int(WSAAPI*)(SOCKET, const sockaddr*, int);
using WSAConnect_t = int(WSAAPI*)(SOCKET, const sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
using WinHttpConnect_t = void*(WINAPI*)(void*, LPCWSTR, unsigned short, DWORD);
using InternetConnectW_t = void*(WINAPI*)(void*, LPCWSTR, unsigned short, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
using InternetConnectA_t = void*(WINAPI*)(void*, LPCSTR, unsigned short, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
using NtCreateFile_t = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
using NtSetInformationFile_t = NTSTATUS(NTAPI*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);
using NtDeleteFile_t = NTSTATUS(NTAPI*)(POBJECT_ATTRIBUTES);
using NtCreateUserProcess_t = NTSTATUS(NTAPI*)(PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK, PVOID, PVOID, ULONG, ULONG, PVOID, PVOID, PVOID);

CreateFileW_t Real_CreateFileW = nullptr;
CreateFileA_t Real_CreateFileA = nullptr;
GetFileAttributesW_t Real_GetFileAttributesW = nullptr;
GetFileAttributesA_t Real_GetFileAttributesA = nullptr;
FindFirstFileW_t Real_FindFirstFileW = nullptr;
FindFirstFileA_t Real_FindFirstFileA = nullptr;
CreateDirectoryW_t Real_CreateDirectoryW = nullptr;
CreateDirectoryA_t Real_CreateDirectoryA = nullptr;
DeleteFileW_t Real_DeleteFileW = nullptr;
DeleteFileA_t Real_DeleteFileA = nullptr;
RemoveDirectoryW_t Real_RemoveDirectoryW = nullptr;
RemoveDirectoryA_t Real_RemoveDirectoryA = nullptr;
MoveFileW_t Real_MoveFileW = nullptr;
MoveFileA_t Real_MoveFileA = nullptr;
MoveFileExW_t Real_MoveFileExW = nullptr;
MoveFileExA_t Real_MoveFileExA = nullptr;
CopyFileW_t Real_CopyFileW = nullptr;
CopyFileA_t Real_CopyFileA = nullptr;
CopyFileExW_t Real_CopyFileExW = nullptr;
CopyFileExA_t Real_CopyFileExA = nullptr;
ReplaceFileW_t Real_ReplaceFileW = nullptr;
ReplaceFileA_t Real_ReplaceFileA = nullptr;
CreateHardLinkW_t Real_CreateHardLinkW = nullptr;
CreateHardLinkA_t Real_CreateHardLinkA = nullptr;
CreateSymbolicLinkW_t Real_CreateSymbolicLinkW = nullptr;
CreateSymbolicLinkA_t Real_CreateSymbolicLinkA = nullptr;
SetFileAttributesW_t Real_SetFileAttributesW = nullptr;
SetFileAttributesA_t Real_SetFileAttributesA = nullptr;
SetFileInformationByHandle_t Real_SetFileInformationByHandle = nullptr;
CreateProcessW_t Real_CreateProcessW = nullptr;
CreateProcessA_t Real_CreateProcessA = nullptr;
CreateProcessAsUserW_t Real_CreateProcessAsUserW = nullptr;
CreateProcessAsUserA_t Real_CreateProcessAsUserA = nullptr;
CreateProcessAsUserA_t Real_CreateProcessAsUserA_Kernel = nullptr;
CreateProcessWithTokenW_t Real_CreateProcessWithTokenW = nullptr;
CreateProcessWithLogonW_t Real_CreateProcessWithLogonW = nullptr;
ShellExecuteW_t Real_ShellExecuteW = nullptr;
ShellExecuteA_t Real_ShellExecuteA = nullptr;
ShellExecuteExW_t Real_ShellExecuteExW = nullptr;
ShellExecuteExA_t Real_ShellExecuteExA = nullptr;
Connect_t Real_connect = nullptr;
WSAConnect_t Real_WSAConnect = nullptr;
WinHttpConnect_t Real_WinHttpConnect = nullptr;
InternetConnectW_t Real_InternetConnectW = nullptr;
InternetConnectA_t Real_InternetConnectA = nullptr;
NtCreateFile_t Real_NtCreateFile = nullptr;
NtSetInformationFile_t Real_NtSetInformationFile = nullptr;
NtDeleteFile_t Real_NtDeleteFile = nullptr;
NtCreateUserProcess_t Real_NtCreateUserProcess = nullptr;

struct WinRename {
    DWORD flags;
    HANDLE root;
    DWORD name_bytes;
    WCHAR name[1];
};

struct NtRename {
    BOOLEAN replace;
    HANDLE root;
    ULONG name_bytes;
    WCHAR name[1];
};

int depth() { return HookGuard::g_depth; }

HANDLE decide_pipe() { return (HANDLE)(uintptr_t)g_startup.decide_handle; }
HANDLE broker_pipe() { return (HANDLE)(uintptr_t)g_startup.broker_handle; }

void make_ids(char* request_id, size_t request_cap, char* operation_id, size_t operation_cap) {
    LONG serial = InterlockedIncrement(&g_serial);
    snprintf(request_id, request_cap, "req_%lu_%ld", (unsigned long)g_startup.pid, serial);
    snprintf(operation_id, operation_cap, "op_%lu_%ld", (unsigned long)g_startup.pid, serial);
}

int ask(const MappedOperation* operation, char* request_id, size_t request_cap, char* operation_id, size_t operation_cap) {
    SandboxIdentity identity = {};
    char when[40];
    char payload[65536];
    char response[8192];
    SYSTEMTIME stamp;
    make_ids(request_id, request_cap, operation_id, operation_cap);
    identity.pid = g_startup.pid;
    identity.parent_pid = g_startup.parent_pid;
    identity.tid = GetCurrentThreadId();
    snprintf(identity.instance_id, sizeof(identity.instance_id), "%s", g_startup.instance_id);
    snprintf(identity.image_utf8, sizeof(identity.image_utf8), "%s", g_startup.image_utf8);
    snprintf(identity.user_sid, sizeof(identity.user_sid), "%s", g_startup.user_sid);
    snprintf(identity.integrity, sizeof(identity.integrity), "%s", g_startup.integrity);
    GetSystemTime(&stamp);
    snprintf(when, sizeof(when), "%04u-%02u-%02uT%02u:%02u:%02uZ", stamp.wYear, stamp.wMonth, stamp.wDay, stamp.wHour, stamp.wMinute, stamp.wSecond);
    if (record_to_json(operation, &identity, request_id, operation_id, when, g_startup.tool_call_id, g_startup.tool_name, payload, sizeof(payload)) < 0) {
        return 0;
    }
    EnterCriticalSection(&g_decide_lock);
    int ok = pipe_transact(decide_pipe(), payload, response, sizeof(response), nullptr, g_startup.decision_timeout_ms);
    LeaveCriticalSection(&g_decide_lock);
    if (!ok) {
        return 0;
    }
    return decision_allows(response, request_id, operation_id);
}

void report_result(const char* request_id, const char* operation_id, int success, const char* disposition) {
    char payload[1024];
    if (operation_result_json(request_id, operation_id, success, disposition, payload, sizeof(payload)) < 0) {
        return;
    }
    EnterCriticalSection(&g_decide_lock);
    pipe_write_message(decide_pipe(), payload, nullptr, 5000);
    LeaveCriticalSection(&g_decide_lock);
}

int ansi_to_wide(const char* src, wchar_t* dest, size_t cap) {
    if (src == nullptr || cap > 0x7fffffffu) {
        return 0;
    }
    return MultiByteToWideChar(CP_ACP, 0, src, -1, dest, (int)cap) > 0;
}

int prepare_path(const wchar_t* path, wchar_t* dest, size_t cap) {
    DWORD length;
    if (path == nullptr || path[0] == L'\0' || cap > 0x7fffffffu) {
        return 0;
    }
    if (path[0] == L'\\' && path[1] == L'\\') {
        if (wcslen(path) + 1 > cap) {
            return 0;
        }
        wcscpy_s(dest, cap, path);
        return 1;
    }
    length = GetFullPathNameW(path, (DWORD)cap, dest, nullptr);
    return length > 0 && length < cap;
}

int path_missing(const wchar_t* path) {
    DWORD attributes;
    DWORD error;
    if (path == nullptr || wcschr(path, L'*') != nullptr || wcschr(path, L'?') != nullptr) {
        return 0;
    }
    attributes = Real_GetFileAttributesW(path);
    if (attributes != INVALID_FILE_ATTRIBUTES) {
        return 0;
    }
    error = GetLastError();
    return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}

int parent_directory(const wchar_t* path, wchar_t* dest, size_t cap) {
    wchar_t* slash;
    size_t length;
    if (wcscpy_s(dest, cap, path) != 0) {
        return 0;
    }
    length = wcslen(dest);
    while (length > 0 && (dest[length - 1] == L'\\' || dest[length - 1] == L'/')) {
        dest[--length] = L'\0';
    }
    slash = wcsrchr(dest, L'\\');
    if (slash == nullptr) {
        slash = wcsrchr(dest, L'/');
    }
    if (slash == nullptr) {
        return 0;
    }
    if ((slash - dest) == 2 && dest[1] == L':') {
        slash[1] = L'\0';
        return 1;
    }
    *slash = L'\0';
    return dest[0] != L'\0';
}

int parent_missing(const wchar_t* path) {
    wchar_t parent[SANDBOX_PATH_CAP];
    if (!parent_directory(path, parent, SANDBOX_PATH_CAP)) {
        return 0;
    }
    return path_missing(parent);
}

int trash_path(const wchar_t* path) {
    wchar_t from[SANDBOX_PATH_CAP + 2];
    SHFILEOPSTRUCTW operation = {};
    size_t length = wcslen(path);
    int result;
    if (length + 2 >= SANDBOX_PATH_CAP) {
        return 0;
    }
    memcpy(from, path, (length + 1) * sizeof(wchar_t));
    from[length + 1] = L'\0';
    operation.wFunc = FO_DELETE;
    operation.pFrom = from;
    operation.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI;
    result = SHFileOperationW(&operation);
    return result == 0 && !operation.fAnyOperationsAborted;
}

int handle_path(HANDLE file, wchar_t* dest, size_t cap) {
    DWORD length;
    if (cap > 0x7fffffffu) {
        return 0;
    }
    length = GetFinalPathNameByHandleW(file, dest, (DWORD)cap, 0);
    if (length == 0 || length >= cap) {
        return 0;
    }
    if (_wcsnicmp(dest, L"\\\\?\\UNC\\", 8) == 0) {
        size_t rest = wcslen(dest + 8);
        memmove(dest + 2, dest + 8, (rest + 1) * sizeof(wchar_t));
        return 1;
    }
    if (_wcsnicmp(dest, L"\\\\?\\", 4) == 0) {
        memmove(dest, dest + 4, (wcslen(dest + 4) + 1) * sizeof(wchar_t));
    }
    return dest[0] != L'\0';
}

int detect_arch(HANDLE process, char* dest, size_t cap) {
    USHORT process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    if (cap < 4 || !IsWow64Process2(process, &process_machine, &native_machine)) {
        return 0;
    }
    if (native_machine == IMAGE_FILE_MACHINE_ARM64 || process_machine == IMAGE_FILE_MACHINE_ARM64) {
        return 0;
    }
    if (process_machine == IMAGE_FILE_MACHINE_I386) {
        strcpy_s(dest, cap, "x86");
        return 1;
    }
    if (process_machine == IMAGE_FILE_MACHINE_UNKNOWN && native_machine == IMAGE_FILE_MACHINE_AMD64) {
        strcpy_s(dest, cap, "x64");
        return 1;
    }
    return 0;
}

int broker_provision(HANDLE process, DWORD pid, DWORD tid, DWORD original_flags) {
    char architecture[8];
    char request[2048];
    char response[512];
    char spec[64];
    int ok = 0;
    int sent;
    if (broker_pipe() == nullptr || !detect_arch(process, architecture, sizeof(architecture))) {
        return 0;
    }
    if (provision_request_json(pid, tid, architecture, original_flags, g_startup.tool_call_id, g_startup.tool_name, request, sizeof(request)) < 0) {
        return 0;
    }
    EnterCriticalSection(&g_broker_lock);
    sent = pipe_transact(broker_pipe(), request, response, sizeof(response), nullptr, g_startup.decision_timeout_ms);
    LeaveCriticalSection(&g_broker_lock);
    if (!sent || !json_copy_string(response, "spec", spec, sizeof(spec)) || strcmp(spec, "process-guard-broker/v1") != 0) {
        return 0;
    }
    return json_copy_bool(response, "ok", &ok) && ok;
}

int decide_file(const wchar_t* path, uint32_t access, uint32_t disposition, int directory, char* request_id, size_t request_cap, char* operation_id, size_t operation_cap) {
    wchar_t full[SANDBOX_PATH_CAP];
    MappedOperation operation = {};
    MapStatus status;
    int writing;
    if (path != nullptr && path_is_exempt(path)) {
        return 2;
    }
    if (!prepare_path(path, full, SANDBOX_PATH_CAP)) {
        return 0;
    }
    status = map_create_file(full, access, disposition, &operation);
    if (status == MAP_OK && directory) {
        snprintf(operation.kind, sizeof(operation.kind), "mkdir");
    }
    writing = status == MAP_OK && strcmp(operation.access, "write") == 0;
    if (status == MAP_EXEMPT) {
        return 2;
    }
    if (status != MAP_OK) {
        return 0;
    }
    if (classify_path(full) == PATH_NORMAL && ((!writing && path_missing(full)) || (writing && parent_missing(full)))) {
        return 2;
    }
    return ask(&operation, request_id, request_cap, operation_id, operation_cap);
}

int decide_delete(const wchar_t* path, int directory, wchar_t* full, size_t full_cap, char* request_id, size_t request_cap, char* operation_id, size_t operation_cap) {
    MappedOperation operation = {};
    MapStatus status;
    if (path != nullptr && path_is_exempt(path)) {
        return 2;
    }
    if (!prepare_path(path, full, full_cap)) {
        return 0;
    }
    if (classify_path(full) == PATH_NORMAL && path_missing(full)) {
        return 2;
    }
    status = map_delete_path(full, directory, &operation);
    if (status == MAP_EXEMPT) {
        return 2;
    }
    if (status != MAP_OK || !ask(&operation, request_id, request_cap, operation_id, operation_cap)) {
        return 0;
    }
    return 1;
}

BOOL finish_delete(const wchar_t* full, BOOL (WINAPI* real_delete)(LPCWSTR), const char* request_id, const char* operation_id) {
    int success = 0;
    const char* disposition = "failed";
    if (g_startup.delete_mode == SANDBOX_DELETE_PERMANENT) {
        success = real_delete(full) ? 1 : 0;
        disposition = success ? "permanent" : "failed";
    } else if (trash_path(full)) {
        success = 1;
        disposition = "trash";
    } else {
        SetLastError(ERROR_ACCESS_DENIED);
    }
    report_result(request_id, operation_id, success, disposition);
    return success ? TRUE : FALSE;
}

int decide_pair(const wchar_t* left, const wchar_t* right, int kind, const wchar_t* backup, char* request_id, size_t request_cap, char* operation_id, size_t operation_cap) {
    wchar_t full_left[SANDBOX_PATH_CAP];
    wchar_t full_right[SANDBOX_PATH_CAP];
    wchar_t full_backup[SANDBOX_PATH_CAP];
    MappedOperation operation = {};
    MapStatus status;
    if (!prepare_path(left, full_left, SANDBOX_PATH_CAP) || !prepare_path(right, full_right, SANDBOX_PATH_CAP)) {
        return 0;
    }
    if (kind == 0) {
        status = map_copy(full_left, full_right, &operation);
    } else if (kind == 1) {
        status = map_move(full_left, full_right, &operation);
    } else if (kind == 2) {
        const wchar_t* backup_path = nullptr;
        if (backup != nullptr && backup[0] != L'\0') {
            if (!prepare_path(backup, full_backup, SANDBOX_PATH_CAP)) {
                return 0;
            }
            backup_path = full_backup;
        }
        status = map_replace(full_left, full_right, backup_path, &operation);
    } else {
        status = map_link(full_left, full_right, kind == 4, &operation);
    }
    if (status != MAP_OK) {
        return 0;
    }
    if (classify_path(full_left) == PATH_NORMAL && classify_path(full_right) == PATH_NORMAL &&
        (path_missing(full_left) || parent_missing(full_right))) {
        return 2;
    }
    return ask(&operation, request_id, request_cap, operation_id, operation_cap);
}

template <typename RealCall>
BOOL spawn(const wchar_t* application, wchar_t* command, DWORD original_flags, PROCESS_INFORMATION* pi, RealCall real_call) {
    wchar_t image[SANDBOX_PATH_CAP];
    wchar_t recorded[SANDBOX_TEXT_CAP];
    wchar_t token[SANDBOX_PATH_CAP];
    MappedOperation operation = {};
    char request_id[64];
    char operation_id[64];
    PROCESS_INFORMATION local = {};
    const wchar_t* source = application;
    if (depth() > 0) {
        return real_call(original_flags, pi, application);
    }
    HookGuard guard;
    if (source == nullptr || source[0] == L'\0') {
        const wchar_t* cursor = command;
        size_t index = 0;
        if (cursor == nullptr) {
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
        while (*cursor == L' ' || *cursor == L'\t') {
            ++cursor;
        }
        if (*cursor == L'"') {
            ++cursor;
            while (*cursor != L'\0' && *cursor != L'"' && index + 1 < SANDBOX_PATH_CAP) {
                token[index++] = *cursor++;
            }
        } else {
            while (*cursor != L'\0' && *cursor != L' ' && *cursor != L'\t' && index + 1 < SANDBOX_PATH_CAP) {
                token[index++] = *cursor++;
            }
        }
        token[index] = L'\0';
        if (index == 0) {
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
        source = token;
    }
    if (wcschr(source, L'\\') != nullptr || wcschr(source, L'/') != nullptr) {
        if (wcscpy_s(image, SANDBOX_PATH_CAP, source) != 0) {
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
    } else if (SearchPathW(nullptr, source, L".exe", SANDBOX_PATH_CAP, image, nullptr) == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    if (command != nullptr && command[0] != L'\0') {
        if (wcscpy_s(recorded, SANDBOX_TEXT_CAP, command) != 0) {
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
    } else if (swprintf(recorded, SANDBOX_TEXT_CAP, L"\"%s\"", image) < 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    if (map_create_process(image, recorded, &operation) != MAP_OK ||
        !ask(&operation, request_id, sizeof(request_id), operation_id, sizeof(operation_id))) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    if (!real_call(original_flags | CREATE_SUSPENDED, &local, image)) {
        return FALSE;
    }
    if (!broker_provision(local.hProcess, local.dwProcessId, local.dwThreadId, original_flags)) {
        TerminateProcess(local.hProcess, 1);
        CloseHandle(local.hProcess);
        CloseHandle(local.hThread);
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    if ((original_flags & CREATE_SUSPENDED) == 0) {
        ResumeThread(local.hThread);
    }
    if (pi != nullptr) {
        *pi = local;
    } else {
        CloseHandle(local.hProcess);
        CloseHandle(local.hThread);
    }
    return TRUE;
}

int shell_command(const wchar_t* file, const wchar_t* parameters, wchar_t* command, size_t cap) {
    MappedOperation operation = {};
    if (map_shell_execute(file, parameters == nullptr ? L"" : parameters, &operation) != MAP_OK) {
        return 0;
    }
    return wcscpy_s(command, cap, operation.command_line) == 0;
}

int shell_verb_ok(const wchar_t* verb) {
    return verb == nullptr || verb[0] == L'\0' || _wcsicmp(verb, L"open") == 0;
}

BOOL run_shell(const wchar_t* file, const wchar_t* parameters, const wchar_t* directory, PROCESS_INFORMATION* pi) {
    wchar_t command[SANDBOX_TEXT_CAP];
    wchar_t mutable_command[SANDBOX_TEXT_CAP];
    if (!shell_command(file, parameters, command, SANDBOX_TEXT_CAP) || wcscpy_s(mutable_command, SANDBOX_TEXT_CAP, command) != 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return spawn(file, mutable_command, 0, pi, [&](DWORD flags, PROCESS_INFORMATION* out, const wchar_t* image) {
        STARTUPINFOW startup = {};
        startup.cb = sizeof(startup);
        return Real_CreateProcessW(image, mutable_command, nullptr, nullptr, FALSE, flags, nullptr, directory, &startup, out);
    });
}

int peer_from_sockaddr(const sockaddr* name, int length, char* ip, size_t ip_cap, int* port) {
    if (name == nullptr || ip_cap > 0x7fffffffu) {
        return 0;
    }
    if (name->sa_family == AF_INET && length >= (int)sizeof(sockaddr_in)) {
        const sockaddr_in* address = (const sockaddr_in*)name;
        if (inet_ntop(AF_INET, &address->sin_addr, ip, (DWORD)ip_cap) == nullptr) {
            return 0;
        }
        *port = ntohs(address->sin_port);
        return 1;
    }
    if (name->sa_family == AF_INET6 && length >= (int)sizeof(sockaddr_in6)) {
        const sockaddr_in6* address = (const sockaddr_in6*)name;
        if (inet_ntop(AF_INET6, &address->sin6_addr, ip, (DWORD)ip_cap) == nullptr) {
            return 0;
        }
        *port = ntohs(address->sin6_port);
        return 1;
    }
    return 0;
}

int authorize_connect(const char* ip, int port, const char* host) {
    MappedOperation operation = {};
    char request_id[64];
    char operation_id[64];
    if (map_connect(ip, port, host, &operation) != MAP_OK) {
        return 0;
    }
    return ask(&operation, request_id, sizeof(request_id), operation_id, sizeof(operation_id));
}

int copy_unicode(const UNICODE_STRING* name, wchar_t* dest, size_t cap) {
    size_t chars;
    if (name == nullptr || name->Buffer == nullptr || name->Length == 0) {
        return 0;
    }
    chars = name->Length / sizeof(wchar_t);
    if (chars + 1 > cap) {
        return 0;
    }
    memcpy(dest, name->Buffer, chars * sizeof(wchar_t));
    dest[chars] = L'\0';
    return 1;
}

int nt_is_afd(const wchar_t* path) {
    return path != nullptr && _wcsnicmp(path, L"\\Device\\Afd", 11) == 0 && (path[11] == L'\0' || path[11] == L'\\');
}

int nt_to_win32(const wchar_t* path, wchar_t* dest, size_t cap) {
    if (path == nullptr) {
        return 0;
    }
    if (_wcsnicmp(path, L"\\??\\UNC\\", 8) == 0) {
        return swprintf(dest, cap, L"\\\\%s", path + 8) > 0;
    }
    if (_wcsnicmp(path, L"\\??\\PIPE\\", 9) == 0) {
        return swprintf(dest, cap, L"\\\\.\\pipe\\%s", path + 9) > 0;
    }
    if (_wcsnicmp(path, L"\\??\\", 4) == 0) {
        return wcscpy_s(dest, cap, path + 4) == 0;
    }
    return 0;
}

uint32_t nt_disposition(ULONG disposition) {
    switch (disposition) {
        case 0:
            return CREATE_ALWAYS;
        case 1:
            return OPEN_EXISTING;
        case 2:
            return CREATE_NEW;
        case 3:
            return OPEN_ALWAYS;
        case 4:
            return TRUNCATE_EXISTING;
        case 5:
            return CREATE_ALWAYS;
        default:
            return 0;
    }
}

NTSTATUS nt_deny(IO_STATUS_BLOCK* io) {
    if (io != nullptr) {
        io->Status = kStatusAccessDenied;
        io->Information = 0;
    }
    return kStatusAccessDenied;
}

int rename_target(const wchar_t* old_path, const wchar_t* name, size_t chars, wchar_t* dest, size_t cap) {
    wchar_t leaf[SANDBOX_PATH_CAP];
    wchar_t parent[SANDBOX_PATH_CAP];
    if (chars == 0 || chars >= SANDBOX_PATH_CAP) {
        return 0;
    }
    memcpy(leaf, name, chars * sizeof(wchar_t));
    leaf[chars] = L'\0';
    if (leaf[0] == L'\\' || (leaf[0] != L'\0' && leaf[1] == L':')) {
        return prepare_path(leaf, dest, cap);
    }
    if (!parent_directory(old_path, parent, SANDBOX_PATH_CAP)) {
        return 0;
    }
    return swprintf(dest, cap, L"%s\\%s", parent, leaf) > 0;
}

HANDLE WINAPI Hook_CreateFileW(LPCWSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES security, DWORD disposition, DWORD flags, HANDLE template_file) {
    char request_id[64];
    char operation_id[64];
    int decision;
    if (depth() > 0) {
        return Real_CreateFileW(name, access, share, security, disposition, flags, template_file);
    }
    HookGuard guard;
    decision = decide_file(name, access, disposition, 0, request_id, sizeof(request_id), operation_id, sizeof(operation_id));
    if (decision == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return INVALID_HANDLE_VALUE;
    }
    return Real_CreateFileW(name, access, share, security, disposition, flags, template_file);
}

HANDLE WINAPI Hook_CreateFileA(LPCSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES security, DWORD disposition, DWORD flags, HANDLE template_file) {
    wchar_t wide[SANDBOX_PATH_CAP];
    char request_id[64];
    char operation_id[64];
    int decision;
    if (depth() > 0) {
        return Real_CreateFileA(name, access, share, security, disposition, flags, template_file);
    }
    HookGuard guard;
    if (!ansi_to_wide(name, wide, SANDBOX_PATH_CAP)) {
        SetLastError(ERROR_ACCESS_DENIED);
        return INVALID_HANDLE_VALUE;
    }
    decision = decide_file(wide, access, disposition, 0, request_id, sizeof(request_id), operation_id, sizeof(operation_id));
    if (decision == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return INVALID_HANDLE_VALUE;
    }
    return Real_CreateFileA(name, access, share, security, disposition, flags, template_file);
}

DWORD WINAPI Hook_GetFileAttributesW(LPCWSTR name) {
    char request_id[64];
    char operation_id[64];
    if (depth() > 0) {
        return Real_GetFileAttributesW(name);
    }
    HookGuard guard;
    if (decide_file(name, GENERIC_READ, OPEN_EXISTING, 0, request_id, sizeof(request_id), operation_id, sizeof(operation_id)) == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return INVALID_FILE_ATTRIBUTES;
    }
    return Real_GetFileAttributesW(name);
}

DWORD WINAPI Hook_GetFileAttributesA(LPCSTR name) {
    wchar_t wide[SANDBOX_PATH_CAP];
    char request_id[64];
    char operation_id[64];
    if (depth() > 0) {
        return Real_GetFileAttributesA(name);
    }
    HookGuard guard;
    if (!ansi_to_wide(name, wide, SANDBOX_PATH_CAP) ||
        decide_file(wide, GENERIC_READ, OPEN_EXISTING, 0, request_id, sizeof(request_id), operation_id, sizeof(operation_id)) == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return INVALID_FILE_ATTRIBUTES;
    }
    return Real_GetFileAttributesA(name);
}

HANDLE WINAPI Hook_FindFirstFileW(LPCWSTR name, LPWIN32_FIND_DATAW data) {
    char request_id[64];
    char operation_id[64];
    if (depth() > 0) {
        return Real_FindFirstFileW(name, data);
    }
    HookGuard guard;
    if (decide_file(name, GENERIC_READ, OPEN_EXISTING, 0, request_id, sizeof(request_id), operation_id, sizeof(operation_id)) == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return INVALID_HANDLE_VALUE;
    }
    return Real_FindFirstFileW(name, data);
}

HANDLE WINAPI Hook_FindFirstFileA(LPCSTR name, LPWIN32_FIND_DATAA data) {
    wchar_t wide[SANDBOX_PATH_CAP];
    char request_id[64];
    char operation_id[64];
    if (depth() > 0) {
        return Real_FindFirstFileA(name, data);
    }
    HookGuard guard;
    if (!ansi_to_wide(name, wide, SANDBOX_PATH_CAP) ||
        decide_file(wide, GENERIC_READ, OPEN_EXISTING, 0, request_id, sizeof(request_id), operation_id, sizeof(operation_id)) == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return INVALID_HANDLE_VALUE;
    }
    return Real_FindFirstFileA(name, data);
}

BOOL WINAPI Hook_CreateDirectoryW(LPCWSTR name, LPSECURITY_ATTRIBUTES security) {
    char request_id[64];
    char operation_id[64];
    if (depth() > 0) {
        return Real_CreateDirectoryW(name, security);
    }
    HookGuard guard;
    if (decide_file(name, GENERIC_WRITE, CREATE_NEW, 1, request_id, sizeof(request_id), operation_id, sizeof(operation_id)) == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return Real_CreateDirectoryW(name, security);
}

BOOL WINAPI Hook_CreateDirectoryA(LPCSTR name, LPSECURITY_ATTRIBUTES security) {
    wchar_t wide[SANDBOX_PATH_CAP];
    char request_id[64];
    char operation_id[64];
    if (depth() > 0) {
        return Real_CreateDirectoryA(name, security);
    }
    HookGuard guard;
    if (!ansi_to_wide(name, wide, SANDBOX_PATH_CAP) ||
        decide_file(wide, GENERIC_WRITE, CREATE_NEW, 1, request_id, sizeof(request_id), operation_id, sizeof(operation_id)) == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return Real_CreateDirectoryA(name, security);
}

BOOL WINAPI Hook_SetFileAttributesW(LPCWSTR name, DWORD attributes) {
    char request_id[64];
    char operation_id[64];
    if (depth() > 0) {
        return Real_SetFileAttributesW(name, attributes);
    }
    HookGuard guard;
    if (decide_file(name, GENERIC_WRITE, OPEN_EXISTING, 0, request_id, sizeof(request_id), operation_id, sizeof(operation_id)) == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return Real_SetFileAttributesW(name, attributes);
}

BOOL WINAPI Hook_SetFileAttributesA(LPCSTR name, DWORD attributes) {
    wchar_t wide[SANDBOX_PATH_CAP];
    char request_id[64];
    char operation_id[64];
    if (depth() > 0) {
        return Real_SetFileAttributesA(name, attributes);
    }
    HookGuard guard;
    if (!ansi_to_wide(name, wide, SANDBOX_PATH_CAP) ||
        decide_file(wide, GENERIC_WRITE, OPEN_EXISTING, 0, request_id, sizeof(request_id), operation_id, sizeof(operation_id)) == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return Real_SetFileAttributesA(name, attributes);
}

BOOL WINAPI Hook_DeleteFileW(LPCWSTR name) {
    wchar_t full[SANDBOX_PATH_CAP];
    char request_id[64];
    char operation_id[64];
    int decision;
    if (depth() > 0) {
        return Real_DeleteFileW(name);
    }
    HookGuard guard;
    decision = decide_delete(name, 0, full, SANDBOX_PATH_CAP, request_id, sizeof(request_id), operation_id, sizeof(operation_id));
    if (decision == 2) {
        return Real_DeleteFileW(name);
    }
    if (decision == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return finish_delete(full, Real_DeleteFileW, request_id, operation_id);
}

BOOL WINAPI Hook_DeleteFileA(LPCSTR name) {
    wchar_t wide[SANDBOX_PATH_CAP];
    wchar_t full[SANDBOX_PATH_CAP];
    char request_id[64];
    char operation_id[64];
    int decision;
    if (depth() > 0) {
        return Real_DeleteFileA(name);
    }
    HookGuard guard;
    if (!ansi_to_wide(name, wide, SANDBOX_PATH_CAP)) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    decision = decide_delete(wide, 0, full, SANDBOX_PATH_CAP, request_id, sizeof(request_id), operation_id, sizeof(operation_id));
    if (decision == 2) {
        return Real_DeleteFileA(name);
    }
    if (decision == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return finish_delete(full, Real_DeleteFileW, request_id, operation_id);
}

BOOL WINAPI Hook_RemoveDirectoryW(LPCWSTR name) {
    wchar_t full[SANDBOX_PATH_CAP];
    char request_id[64];
    char operation_id[64];
    int decision;
    if (depth() > 0) {
        return Real_RemoveDirectoryW(name);
    }
    HookGuard guard;
    decision = decide_delete(name, 1, full, SANDBOX_PATH_CAP, request_id, sizeof(request_id), operation_id, sizeof(operation_id));
    if (decision == 2) {
        return Real_RemoveDirectoryW(name);
    }
    if (decision == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return finish_delete(full, Real_RemoveDirectoryW, request_id, operation_id);
}

BOOL WINAPI Hook_RemoveDirectoryA(LPCSTR name) {
    wchar_t wide[SANDBOX_PATH_CAP];
    wchar_t full[SANDBOX_PATH_CAP];
    char request_id[64];
    char operation_id[64];
    int decision;
    if (depth() > 0) {
        return Real_RemoveDirectoryA(name);
    }
    HookGuard guard;
    if (!ansi_to_wide(name, wide, SANDBOX_PATH_CAP)) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    decision = decide_delete(wide, 1, full, SANDBOX_PATH_CAP, request_id, sizeof(request_id), operation_id, sizeof(operation_id));
    if (decision == 2) {
        return Real_RemoveDirectoryA(name);
    }
    if (decision == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return finish_delete(full, Real_RemoveDirectoryW, request_id, operation_id);
}

BOOL WINAPI Hook_CopyFileW(LPCWSTR from, LPCWSTR to, BOOL fail_if_exists) {
    char request_id[64];
    char operation_id[64];
    int decision;
    if (depth() > 0) {
        return Real_CopyFileW(from, to, fail_if_exists);
    }
    HookGuard guard;
    decision = decide_pair(from, to, 0, nullptr, request_id, sizeof(request_id), operation_id, sizeof(operation_id));
    if (decision == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return Real_CopyFileW(from, to, fail_if_exists);
}

BOOL WINAPI Hook_CopyFileA(LPCSTR from, LPCSTR to, BOOL fail_if_exists) {
    wchar_t wide_from[SANDBOX_PATH_CAP];
    wchar_t wide_to[SANDBOX_PATH_CAP];
    char request_id[64];
    char operation_id[64];
    if (depth() > 0) {
        return Real_CopyFileA(from, to, fail_if_exists);
    }
    HookGuard guard;
    if (!ansi_to_wide(from, wide_from, SANDBOX_PATH_CAP) || !ansi_to_wide(to, wide_to, SANDBOX_PATH_CAP) ||
        decide_pair(wide_from, wide_to, 0, nullptr, request_id, sizeof(request_id), operation_id, sizeof(operation_id)) == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return Real_CopyFileA(from, to, fail_if_exists);
}

BOOL WINAPI Hook_CopyFileExW(LPCWSTR from, LPCWSTR to, LPPROGRESS_ROUTINE progress, LPVOID data, LPBOOL cancel, DWORD flags) {
    char request_id[64];
    char operation_id[64];
    if (depth() > 0) {
        return Real_CopyFileExW(from, to, progress, data, cancel, flags);
    }
    HookGuard guard;
    if (decide_pair(from, to, 0, nullptr, request_id, sizeof(request_id), operation_id, sizeof(operation_id)) == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return Real_CopyFileExW(from, to, progress, data, cancel, flags);
}

BOOL WINAPI Hook_CopyFileExA(LPCSTR from, LPCSTR to, LPPROGRESS_ROUTINE progress, LPVOID data, LPBOOL cancel, DWORD flags) {
    wchar_t wide_from[SANDBOX_PATH_CAP];
    wchar_t wide_to[SANDBOX_PATH_CAP];
    char request_id[64];
    char operation_id[64];
    if (depth() > 0) {
        return Real_CopyFileExA(from, to, progress, data, cancel, flags);
    }
    HookGuard guard;
    if (!ansi_to_wide(from, wide_from, SANDBOX_PATH_CAP) || !ansi_to_wide(to, wide_to, SANDBOX_PATH_CAP) ||
        decide_pair(wide_from, wide_to, 0, nullptr, request_id, sizeof(request_id), operation_id, sizeof(operation_id)) == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return Real_CopyFileExA(from, to, progress, data, cancel, flags);
}

BOOL WINAPI Hook_MoveFileW(LPCWSTR from, LPCWSTR to) {
    char request_id[64];
    char operation_id[64];
    if (depth() > 0) {
        return Real_MoveFileW(from, to);
    }
    HookGuard guard;
    if (decide_pair(from, to, 1, nullptr, request_id, sizeof(request_id), operation_id, sizeof(operation_id)) == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return Real_MoveFileW(from, to);
}

BOOL WINAPI Hook_MoveFileA(LPCSTR from, LPCSTR to) {
    wchar_t wide_from[SANDBOX_PATH_CAP];
    wchar_t wide_to[SANDBOX_PATH_CAP];
    char request_id[64];
    char operation_id[64];
    if (depth() > 0) {
        return Real_MoveFileA(from, to);
    }
    HookGuard guard;
    if (!ansi_to_wide(from, wide_from, SANDBOX_PATH_CAP) || !ansi_to_wide(to, wide_to, SANDBOX_PATH_CAP) ||
        decide_pair(wide_from, wide_to, 1, nullptr, request_id, sizeof(request_id), operation_id, sizeof(operation_id)) == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return Real_MoveFileA(from, to);
}

BOOL WINAPI Hook_MoveFileExW(LPCWSTR from, LPCWSTR to, DWORD flags) {
    char request_id[64];
    char operation_id[64];
    if (depth() > 0) {
        return Real_MoveFileExW(from, to, flags);
    }
    HookGuard guard;
    if (decide_pair(from, to, 1, nullptr, request_id, sizeof(request_id), operation_id, sizeof(operation_id)) == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return Real_MoveFileExW(from, to, flags);
}

BOOL WINAPI Hook_MoveFileExA(LPCSTR from, LPCSTR to, DWORD flags) {
    wchar_t wide_from[SANDBOX_PATH_CAP];
    wchar_t wide_to[SANDBOX_PATH_CAP];
    char request_id[64];
    char operation_id[64];
    if (depth() > 0) {
        return Real_MoveFileExA(from, to, flags);
    }
    HookGuard guard;
    if (!ansi_to_wide(from, wide_from, SANDBOX_PATH_CAP) || !ansi_to_wide(to, wide_to, SANDBOX_PATH_CAP) ||
        decide_pair(wide_from, wide_to, 1, nullptr, request_id, sizeof(request_id), operation_id, sizeof(operation_id)) == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return Real_MoveFileExA(from, to, flags);
}

BOOL WINAPI Hook_ReplaceFileW(LPCWSTR replaced, LPCWSTR replacement, LPCWSTR backup, DWORD flags, LPVOID exclude, LPVOID reserved) {
    char request_id[64];
    char operation_id[64];
    if (depth() > 0) {
        return Real_ReplaceFileW(replaced, replacement, backup, flags, exclude, reserved);
    }
    HookGuard guard;
    if (decide_pair(replacement, replaced, 2, backup, request_id, sizeof(request_id), operation_id, sizeof(operation_id)) == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return Real_ReplaceFileW(replaced, replacement, backup, flags, exclude, reserved);
}

BOOL WINAPI Hook_ReplaceFileA(LPCSTR replaced, LPCSTR replacement, LPCSTR backup, DWORD flags, LPVOID exclude, LPVOID reserved) {
    wchar_t wide_replaced[SANDBOX_PATH_CAP];
    wchar_t wide_replacement[SANDBOX_PATH_CAP];
    wchar_t wide_backup[SANDBOX_PATH_CAP];
    char request_id[64];
    char operation_id[64];
    const wchar_t* backup_path = nullptr;
    if (depth() > 0) {
        return Real_ReplaceFileA(replaced, replacement, backup, flags, exclude, reserved);
    }
    HookGuard guard;
    if (!ansi_to_wide(replaced, wide_replaced, SANDBOX_PATH_CAP) || !ansi_to_wide(replacement, wide_replacement, SANDBOX_PATH_CAP)) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    if (backup != nullptr) {
        if (!ansi_to_wide(backup, wide_backup, SANDBOX_PATH_CAP)) {
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
        backup_path = wide_backup;
    }
    if (decide_pair(wide_replacement, wide_replaced, 2, backup_path, request_id, sizeof(request_id), operation_id, sizeof(operation_id)) == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return Real_ReplaceFileA(replaced, replacement, backup, flags, exclude, reserved);
}

BOOL WINAPI Hook_CreateHardLinkW(LPCWSTR link, LPCWSTR existing, LPSECURITY_ATTRIBUTES security) {
    char request_id[64];
    char operation_id[64];
    if (depth() > 0) {
        return Real_CreateHardLinkW(link, existing, security);
    }
    HookGuard guard;
    if (decide_pair(existing, link, 3, nullptr, request_id, sizeof(request_id), operation_id, sizeof(operation_id)) == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return Real_CreateHardLinkW(link, existing, security);
}

BOOL WINAPI Hook_CreateHardLinkA(LPCSTR link, LPCSTR existing, LPSECURITY_ATTRIBUTES security) {
    wchar_t wide_link[SANDBOX_PATH_CAP];
    wchar_t wide_existing[SANDBOX_PATH_CAP];
    char request_id[64];
    char operation_id[64];
    if (depth() > 0) {
        return Real_CreateHardLinkA(link, existing, security);
    }
    HookGuard guard;
    if (!ansi_to_wide(link, wide_link, SANDBOX_PATH_CAP) || !ansi_to_wide(existing, wide_existing, SANDBOX_PATH_CAP) ||
        decide_pair(wide_existing, wide_link, 3, nullptr, request_id, sizeof(request_id), operation_id, sizeof(operation_id)) == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return Real_CreateHardLinkA(link, existing, security);
}

BOOLEAN WINAPI Hook_CreateSymbolicLinkW(LPCWSTR link, LPCWSTR target, DWORD flags) {
    char request_id[64];
    char operation_id[64];
    if (depth() > 0) {
        return Real_CreateSymbolicLinkW(link, target, flags);
    }
    HookGuard guard;
    if (decide_pair(target, link, 4, nullptr, request_id, sizeof(request_id), operation_id, sizeof(operation_id)) == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return Real_CreateSymbolicLinkW(link, target, flags);
}

BOOLEAN WINAPI Hook_CreateSymbolicLinkA(LPCSTR link, LPCSTR target, DWORD flags) {
    wchar_t wide_link[SANDBOX_PATH_CAP];
    wchar_t wide_target[SANDBOX_PATH_CAP];
    char request_id[64];
    char operation_id[64];
    if (depth() > 0) {
        return Real_CreateSymbolicLinkA(link, target, flags);
    }
    HookGuard guard;
    if (!ansi_to_wide(link, wide_link, SANDBOX_PATH_CAP) || !ansi_to_wide(target, wide_target, SANDBOX_PATH_CAP) ||
        decide_pair(wide_target, wide_link, 4, nullptr, request_id, sizeof(request_id), operation_id, sizeof(operation_id)) == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return Real_CreateSymbolicLinkA(link, target, flags);
}

int decide_rename(const wchar_t* old_path, const wchar_t* name, size_t chars) {
    wchar_t target[SANDBOX_PATH_CAP];
    char request_id[64];
    char operation_id[64];
    if (!rename_target(old_path, name, chars, target, SANDBOX_PATH_CAP)) {
        return 0;
    }
    return decide_pair(old_path, target, 1, nullptr, request_id, sizeof(request_id), operation_id, sizeof(operation_id)) == 1;
}

BOOL WINAPI Hook_SetFileInformationByHandle(HANDLE file, FILE_INFO_BY_HANDLE_CLASS kind, LPVOID data, DWORD size) {
    wchar_t path[SANDBOX_PATH_CAP];
    char request_id[64];
    char operation_id[64];
    int decision;
    if (depth() > 0) {
        return Real_SetFileInformationByHandle(file, kind, data, size);
    }
    if (kind != FileDispositionInfo && kind != FileDispositionInfoEx && kind != FileRenameInfo && kind != FileRenameInfoEx) {
        return Real_SetFileInformationByHandle(file, kind, data, size);
    }
    HookGuard guard;
    if ((kind == FileDispositionInfo && (data == nullptr || size < sizeof(FILE_DISPOSITION_INFO) || !((FILE_DISPOSITION_INFO*)data)->DeleteFile)) ||
        (kind == FileDispositionInfoEx && (data == nullptr || size < sizeof(FILE_DISPOSITION_INFO_EX) || (((FILE_DISPOSITION_INFO_EX*)data)->Flags & kDeleteFlag) == 0))) {
        return Real_SetFileInformationByHandle(file, kind, data, size);
    }
    if (!handle_path(file, path, SANDBOX_PATH_CAP)) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    if (kind == FileRenameInfo || kind == FileRenameInfoEx) {
        WinRename* info = (WinRename*)data;
        if (data == nullptr || size < sizeof(DWORD) + sizeof(HANDLE) + sizeof(DWORD) || info->root != nullptr ||
            !decide_rename(path, info->name, info->name_bytes / sizeof(WCHAR))) {
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
        return Real_SetFileInformationByHandle(file, kind, data, size);
    }
    wchar_t full[SANDBOX_PATH_CAP];
    decision = decide_delete(path, 0, full, SANDBOX_PATH_CAP, request_id, sizeof(request_id), operation_id, sizeof(operation_id));
    if (decision == 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    if (decision == 2) {
        return Real_SetFileInformationByHandle(file, kind, data, size);
    }
    if (g_startup.delete_mode == SANDBOX_DELETE_PERMANENT) {
        BOOL deleted = Real_SetFileInformationByHandle(file, kind, data, size);
        report_result(request_id, operation_id, deleted ? 1 : 0, deleted ? "permanent" : "failed");
        return deleted;
    }
    if (!trash_path(full)) {
        report_result(request_id, operation_id, 0, "failed");
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    report_result(request_id, operation_id, 1, "trash");
    return TRUE;
}

NTSTATUS NTAPI Hook_NtCreateFile(PHANDLE file, ACCESS_MASK access, POBJECT_ATTRIBUTES attributes, PIO_STATUS_BLOCK io, PLARGE_INTEGER allocation, ULONG attributes_flags, ULONG share, ULONG disposition, ULONG options, PVOID ea, ULONG ea_length) {
    wchar_t nt_path[SANDBOX_PATH_CAP];
    wchar_t win32[SANDBOX_PATH_CAP];
    char request_id[64];
    char operation_id[64];
    uint32_t win32_disposition;
    if (depth() > 0) {
        return Real_NtCreateFile(file, access, attributes, io, allocation, attributes_flags, share, disposition, options, ea, ea_length);
    }
    HookGuard guard;
    if (attributes == nullptr || attributes->ObjectName == nullptr || !copy_unicode(attributes->ObjectName, nt_path, SANDBOX_PATH_CAP)) {
        return nt_deny(io);
    }
    /* Winsock opens \Device\Afd before connect. connect is the network decision. */
    if (attributes->RootDirectory == nullptr && nt_is_afd(nt_path)) {
        return Real_NtCreateFile(file, access, attributes, io, allocation, attributes_flags, share, disposition, options, ea, ea_length);
    }
    if (attributes->RootDirectory != nullptr || !nt_to_win32(nt_path, win32, SANDBOX_PATH_CAP)) {
        return nt_deny(io);
    }
    win32_disposition = nt_disposition(disposition);
    if (win32_disposition == 0 ||
        decide_file(win32, access, win32_disposition, (options & kFileDirectory) != 0, request_id, sizeof(request_id), operation_id, sizeof(operation_id)) == 0) {
        return nt_deny(io);
    }
    return Real_NtCreateFile(file, access, attributes, io, allocation, attributes_flags, share, disposition, options, ea, ea_length);
}

NTSTATUS NTAPI Hook_NtDeleteFile(POBJECT_ATTRIBUTES attributes) {
    wchar_t nt_path[SANDBOX_PATH_CAP];
    wchar_t win32[SANDBOX_PATH_CAP];
    wchar_t full[SANDBOX_PATH_CAP];
    char request_id[64];
    char operation_id[64];
    int decision;
    if (depth() > 0) {
        return Real_NtDeleteFile(attributes);
    }
    HookGuard guard;
    if (attributes == nullptr || attributes->RootDirectory != nullptr || !copy_unicode(attributes->ObjectName, nt_path, SANDBOX_PATH_CAP) ||
        !nt_to_win32(nt_path, win32, SANDBOX_PATH_CAP)) {
        return kStatusAccessDenied;
    }
    decision = decide_delete(win32, 0, full, SANDBOX_PATH_CAP, request_id, sizeof(request_id), operation_id, sizeof(operation_id));
    if (decision == 0) {
        return kStatusAccessDenied;
    }
    if (decision == 2 || g_startup.delete_mode == SANDBOX_DELETE_PERMANENT) {
        NTSTATUS status = Real_NtDeleteFile(attributes);
        if (decision == 1) {
            report_result(request_id, operation_id, status >= 0 ? 1 : 0, status >= 0 ? "permanent" : "failed");
        }
        return status;
    }
    if (!trash_path(full)) {
        report_result(request_id, operation_id, 0, "failed");
        return kStatusAccessDenied;
    }
    report_result(request_id, operation_id, 1, "trash");
    return 0;
}

NTSTATUS NTAPI Hook_NtSetInformationFile(HANDLE file, PIO_STATUS_BLOCK io, PVOID data, ULONG length, ULONG kind) {
    wchar_t path[SANDBOX_PATH_CAP];
    char request_id[64];
    char operation_id[64];
    int decision;
    if (depth() > 0 || (kind != kNtRename && kind != kNtRenameEx && kind != kNtDisposition && kind != kNtDispositionEx)) {
        return Real_NtSetInformationFile(file, io, data, length, kind);
    }
    HookGuard guard;
    if (!handle_path(file, path, SANDBOX_PATH_CAP)) {
        return nt_deny(io);
    }
    if (kind == kNtRename || kind == kNtRenameEx) {
        if (kind == kNtRename) {
            NtRename* info = (NtRename*)data;
            if (data == nullptr || info->root != nullptr || !decide_rename(path, info->name, info->name_bytes / sizeof(WCHAR))) {
                return nt_deny(io);
            }
        } else {
            WinRename* info = (WinRename*)data;
            if (data == nullptr || info->root != nullptr || !decide_rename(path, info->name, info->name_bytes / sizeof(WCHAR))) {
                return nt_deny(io);
            }
        }
        return Real_NtSetInformationFile(file, io, data, length, kind);
    }
    wchar_t full[SANDBOX_PATH_CAP];
    decision = decide_delete(path, 0, full, SANDBOX_PATH_CAP, request_id, sizeof(request_id), operation_id, sizeof(operation_id));
    if (decision == 0) {
        return nt_deny(io);
    }
    if (decision == 2 || g_startup.delete_mode == SANDBOX_DELETE_PERMANENT) {
        NTSTATUS status = Real_NtSetInformationFile(file, io, data, length, kind);
        if (decision == 1) {
            report_result(request_id, operation_id, status >= 0 ? 1 : 0, status >= 0 ? "permanent" : "failed");
        }
        return status;
    }
    if (!trash_path(full)) {
        report_result(request_id, operation_id, 0, "failed");
        return nt_deny(io);
    }
    report_result(request_id, operation_id, 1, "trash");
    if (io != nullptr) {
        io->Status = 0;
        io->Information = 0;
    }
    return 0;
}

NTSTATUS NTAPI Hook_NtCreateUserProcess(PHANDLE process, PHANDLE thread, ACCESS_MASK process_access, ACCESS_MASK thread_access, PVOID process_attributes, PVOID thread_attributes, ULONG process_flags, ULONG thread_flags, PVOID parameters, PVOID create_info, PVOID attributes) {
    if (depth() > 0) {
        return Real_NtCreateUserProcess(process, thread, process_access, thread_access, process_attributes, thread_attributes, process_flags, thread_flags, parameters, create_info, attributes);
    }
    return kStatusAccessDenied;
}

BOOL WINAPI Hook_CreateProcessW(LPCWSTR application, LPWSTR command, LPSECURITY_ATTRIBUTES process_attributes, LPSECURITY_ATTRIBUTES thread_attributes, BOOL inherit, DWORD flags, LPVOID environment, LPCWSTR directory, LPSTARTUPINFOW startup, LPPROCESS_INFORMATION information) {
    return spawn(application, command, flags, information, [&](DWORD next_flags, PROCESS_INFORMATION* out, const wchar_t* image) {
        return Real_CreateProcessW(image, command, process_attributes, thread_attributes, inherit, next_flags, environment, directory, startup, out);
    });
}

BOOL WINAPI Hook_CreateProcessA(LPCSTR application, LPSTR command, LPSECURITY_ATTRIBUTES process_attributes, LPSECURITY_ATTRIBUTES thread_attributes, BOOL inherit, DWORD flags, LPVOID environment, LPCSTR directory, LPSTARTUPINFOA startup, LPPROCESS_INFORMATION information) {
    wchar_t wide_application[SANDBOX_PATH_CAP];
    wchar_t wide_command[SANDBOX_TEXT_CAP];
    wchar_t wide_directory[SANDBOX_PATH_CAP];
    const wchar_t* app = nullptr;
    wchar_t* cmd = nullptr;
    const wchar_t* dir = nullptr;
    if (depth() > 0) {
        return Real_CreateProcessA(application, command, process_attributes, thread_attributes, inherit, flags, environment, directory, startup, information);
    }
    if (application != nullptr) {
        if (!ansi_to_wide(application, wide_application, SANDBOX_PATH_CAP)) {
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
        app = wide_application;
    }
    if (command != nullptr) {
        if (!ansi_to_wide(command, wide_command, SANDBOX_TEXT_CAP)) {
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
        cmd = wide_command;
    }
    if (directory != nullptr) {
        if (!ansi_to_wide(directory, wide_directory, SANDBOX_PATH_CAP)) {
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
        dir = wide_directory;
    }
    return spawn(app, cmd, flags, information, [&](DWORD next_flags, PROCESS_INFORMATION* out, const wchar_t* image) {
        STARTUPINFOW wide_startup = {};
        wide_startup.cb = sizeof(wide_startup);
        if (startup != nullptr) {
            wide_startup.dwFlags = startup->dwFlags;
            wide_startup.wShowWindow = startup->wShowWindow;
        }
        return Real_CreateProcessW(image, cmd, process_attributes, thread_attributes, inherit, next_flags, nullptr, dir, &wide_startup, out);
    });
}

BOOL WINAPI Hook_CreateProcessAsUserW(HANDLE token, LPCWSTR application, LPWSTR command, LPSECURITY_ATTRIBUTES process_attributes, LPSECURITY_ATTRIBUTES thread_attributes, BOOL inherit, DWORD flags, LPVOID environment, LPCWSTR directory, LPSTARTUPINFOW startup, LPPROCESS_INFORMATION information) {
    return spawn(application, command, flags, information, [&](DWORD next_flags, PROCESS_INFORMATION* out, const wchar_t* image) {
        return Real_CreateProcessAsUserW(token, image, command, process_attributes, thread_attributes, inherit, next_flags, environment, directory, startup, out);
    });
}

BOOL WINAPI Hook_CreateProcessAsUserA(HANDLE token, LPCSTR application, LPSTR command, LPSECURITY_ATTRIBUTES process_attributes, LPSECURITY_ATTRIBUTES thread_attributes, BOOL inherit, DWORD flags, LPVOID environment, LPCSTR directory, LPSTARTUPINFOA startup, LPPROCESS_INFORMATION information) {
    wchar_t wide_application[SANDBOX_PATH_CAP];
    wchar_t wide_command[SANDBOX_TEXT_CAP];
    wchar_t wide_directory[SANDBOX_PATH_CAP];
    const wchar_t* app = nullptr;
    wchar_t* cmd = nullptr;
    const wchar_t* dir = nullptr;
    if (depth() > 0) {
        CreateProcessAsUserA_t real = Real_CreateProcessAsUserA != nullptr ? Real_CreateProcessAsUserA : Real_CreateProcessAsUserA_Kernel;
        return real(token, application, command, process_attributes, thread_attributes, inherit, flags, environment, directory, startup, information);
    }
    if (application != nullptr) {
        if (!ansi_to_wide(application, wide_application, SANDBOX_PATH_CAP)) {
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
        app = wide_application;
    }
    if (command != nullptr) {
        if (!ansi_to_wide(command, wide_command, SANDBOX_TEXT_CAP)) {
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
        cmd = wide_command;
    }
    if (directory != nullptr) {
        if (!ansi_to_wide(directory, wide_directory, SANDBOX_PATH_CAP)) {
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
        dir = wide_directory;
    }
    if (Real_CreateProcessAsUserW == nullptr) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return spawn(app, cmd, flags, information, [&](DWORD next_flags, PROCESS_INFORMATION* out, const wchar_t* image) {
        STARTUPINFOW wide_startup = {};
        wide_startup.cb = sizeof(wide_startup);
        if (startup != nullptr) {
            wide_startup.dwFlags = startup->dwFlags;
            wide_startup.wShowWindow = startup->wShowWindow;
        }
        return Real_CreateProcessAsUserW(token, image, cmd, process_attributes, thread_attributes, inherit, next_flags, nullptr, dir, &wide_startup, out);
    });
}

BOOL WINAPI Hook_CreateProcessWithTokenW(HANDLE token, DWORD logon, LPCWSTR application, LPWSTR command, DWORD flags, LPVOID environment, LPCWSTR directory, LPSTARTUPINFOW startup, LPPROCESS_INFORMATION information) {
    return spawn(application, command, flags, information, [&](DWORD next_flags, PROCESS_INFORMATION* out, const wchar_t* image) {
        return Real_CreateProcessWithTokenW(token, logon, image, command, next_flags, environment, directory, startup, out);
    });
}

BOOL WINAPI Hook_CreateProcessWithLogonW(LPCWSTR user, LPCWSTR domain, LPCWSTR password, DWORD logon, LPCWSTR application, LPWSTR command, DWORD flags, LPVOID environment, LPCWSTR directory, LPSTARTUPINFOW startup, LPPROCESS_INFORMATION information) {
    return spawn(application, command, flags, information, [&](DWORD next_flags, PROCESS_INFORMATION* out, const wchar_t* image) {
        return Real_CreateProcessWithLogonW(user, domain, password, logon, image, command, next_flags, environment, directory, startup, out);
    });
}

HINSTANCE WINAPI Hook_ShellExecuteW(HWND window, LPCWSTR verb, LPCWSTR file, LPCWSTR parameters, LPCWSTR directory, INT show) {
    PROCESS_INFORMATION information = {};
    (void)window;
    (void)show;
    if (depth() > 0) {
        return Real_ShellExecuteW(window, verb, file, parameters, directory, show);
    }
    if (!shell_verb_ok(verb) || !run_shell(file, parameters, directory, &information)) {
        return (HINSTANCE)SE_ERR_ACCESSDENIED;
    }
    CloseHandle(information.hProcess);
    CloseHandle(information.hThread);
    return (HINSTANCE)33;
}

HINSTANCE WINAPI Hook_ShellExecuteA(HWND window, LPCSTR verb, LPCSTR file, LPCSTR parameters, LPCSTR directory, INT show) {
    wchar_t wide_verb[64];
    wchar_t wide_file[SANDBOX_PATH_CAP];
    wchar_t wide_parameters[SANDBOX_TEXT_CAP];
    wchar_t wide_directory[SANDBOX_PATH_CAP];
    const wchar_t* verb_w = nullptr;
    const wchar_t* parameters_w = nullptr;
    const wchar_t* directory_w = nullptr;
    PROCESS_INFORMATION information = {};
    (void)window;
    (void)show;
    if (depth() > 0) {
        return Real_ShellExecuteA(window, verb, file, parameters, directory, show);
    }
    if (verb != nullptr) {
        if (!ansi_to_wide(verb, wide_verb, 64)) {
            return (HINSTANCE)SE_ERR_ACCESSDENIED;
        }
        verb_w = wide_verb;
    }
    if (parameters != nullptr) {
        if (!ansi_to_wide(parameters, wide_parameters, SANDBOX_TEXT_CAP)) {
            return (HINSTANCE)SE_ERR_ACCESSDENIED;
        }
        parameters_w = wide_parameters;
    }
    if (directory != nullptr) {
        if (!ansi_to_wide(directory, wide_directory, SANDBOX_PATH_CAP)) {
            return (HINSTANCE)SE_ERR_ACCESSDENIED;
        }
        directory_w = wide_directory;
    }
    if (!ansi_to_wide(file, wide_file, SANDBOX_PATH_CAP) || !shell_verb_ok(verb_w) || !run_shell(wide_file, parameters_w, directory_w, &information)) {
        return (HINSTANCE)SE_ERR_ACCESSDENIED;
    }
    CloseHandle(information.hProcess);
    CloseHandle(information.hThread);
    return (HINSTANCE)33;
}

BOOL WINAPI Hook_ShellExecuteExW(SHELLEXECUTEINFOW* info) {
    PROCESS_INFORMATION information = {};
    if (depth() > 0) {
        return Real_ShellExecuteExW(info);
    }
    if (info == nullptr || info->lpIDList != nullptr || (info->fMask & (SEE_MASK_IDLIST | SEE_MASK_CLASSNAME)) != 0 || !shell_verb_ok(info->lpVerb)) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    if (!run_shell(info->lpFile, info->lpParameters, info->lpDirectory, &information)) {
        return FALSE;
    }
    if ((info->fMask & SEE_MASK_NOCLOSEPROCESS) != 0) {
        info->hProcess = information.hProcess;
    } else {
        CloseHandle(information.hProcess);
    }
    CloseHandle(information.hThread);
    info->hInstApp = (HINSTANCE)33;
    return TRUE;
}

BOOL WINAPI Hook_ShellExecuteExA(SHELLEXECUTEINFOA* info) {
    wchar_t wide_file[SANDBOX_PATH_CAP];
    wchar_t wide_parameters[SANDBOX_TEXT_CAP];
    wchar_t wide_directory[SANDBOX_PATH_CAP];
    wchar_t wide_verb[64];
    const wchar_t* parameters = nullptr;
    const wchar_t* directory = nullptr;
    const wchar_t* verb = nullptr;
    PROCESS_INFORMATION information = {};
    if (depth() > 0) {
        return Real_ShellExecuteExA(info);
    }
    if (info == nullptr || info->lpIDList != nullptr || (info->fMask & (SEE_MASK_IDLIST | SEE_MASK_CLASSNAME)) != 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    if (info->lpVerb != nullptr) {
        if (!ansi_to_wide(info->lpVerb, wide_verb, 64)) {
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
        verb = wide_verb;
    }
    if (!shell_verb_ok(verb) || info->lpFile == nullptr || !ansi_to_wide(info->lpFile, wide_file, SANDBOX_PATH_CAP)) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    if (info->lpParameters != nullptr) {
        if (!ansi_to_wide(info->lpParameters, wide_parameters, SANDBOX_TEXT_CAP)) {
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
        parameters = wide_parameters;
    }
    if (info->lpDirectory != nullptr) {
        if (!ansi_to_wide(info->lpDirectory, wide_directory, SANDBOX_PATH_CAP)) {
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
        directory = wide_directory;
    }
    if (!run_shell(wide_file, parameters, directory, &information)) {
        return FALSE;
    }
    if ((info->fMask & SEE_MASK_NOCLOSEPROCESS) != 0) {
        info->hProcess = information.hProcess;
    } else {
        CloseHandle(information.hProcess);
    }
    CloseHandle(information.hThread);
    info->hInstApp = (HINSTANCE)33;
    return TRUE;
}

int WSAAPI Hook_connect(SOCKET socket, const sockaddr* name, int length) {
    char ip[64];
    int port = 0;
    if (depth() > 0) {
        return Real_connect(socket, name, length);
    }
    HookGuard guard;
    if (!peer_from_sockaddr(name, length, ip, sizeof(ip), &port) || !authorize_connect(ip, port, nullptr)) {
        WSASetLastError(WSAEACCES);
        return SOCKET_ERROR;
    }
    return Real_connect(socket, name, length);
}

int WSAAPI Hook_WSAConnect(SOCKET socket, const sockaddr* name, int length, LPWSABUF caller, LPWSABUF callee, LPQOS in_qos, LPQOS out_qos) {
    char ip[64];
    int port = 0;
    if (depth() > 0) {
        return Real_WSAConnect(socket, name, length, caller, callee, in_qos, out_qos);
    }
    HookGuard guard;
    if (!peer_from_sockaddr(name, length, ip, sizeof(ip), &port) || !authorize_connect(ip, port, nullptr)) {
        WSASetLastError(WSAEACCES);
        return SOCKET_ERROR;
    }
    return Real_WSAConnect(socket, name, length, caller, callee, in_qos, out_qos);
}

void* WINAPI Hook_WinHttpConnect(void* session, LPCWSTR server, unsigned short port, DWORD reserved) {
    char host[256];
    if (depth() > 0) {
        return Real_WinHttpConnect(session, server, port, reserved);
    }
    HookGuard guard;
    if (!wide_to_utf8(server, host, sizeof(host)) || !authorize_connect(nullptr, (int)port, host)) {
        SetLastError(ERROR_ACCESS_DENIED);
        return nullptr;
    }
    return Real_WinHttpConnect(session, server, port, reserved);
}

void* WINAPI Hook_InternetConnectW(void* session, LPCWSTR server, unsigned short port, LPCWSTR user, LPCWSTR password, DWORD service, DWORD flags, DWORD_PTR context) {
    char host[256];
    if (depth() > 0) {
        return Real_InternetConnectW(session, server, port, user, password, service, flags, context);
    }
    HookGuard guard;
    if (!wide_to_utf8(server, host, sizeof(host)) || !authorize_connect(nullptr, (int)port, host)) {
        SetLastError(ERROR_ACCESS_DENIED);
        return nullptr;
    }
    return Real_InternetConnectW(session, server, port, user, password, service, flags, context);
}

void* WINAPI Hook_InternetConnectA(void* session, LPCSTR server, unsigned short port, LPCSTR user, LPCSTR password, DWORD service, DWORD flags, DWORD_PTR context) {
    if (depth() > 0) {
        return Real_InternetConnectA(session, server, port, user, password, service, flags, context);
    }
    HookGuard guard;
    if (server == nullptr || !authorize_connect(nullptr, (int)port, server)) {
        SetLastError(ERROR_ACCESS_DENIED);
        return nullptr;
    }
    return Real_InternetConnectA(session, server, port, user, password, service, flags, context);
}

PVOID module_proc(const wchar_t* module, const char* name) {
    HMODULE loaded = GetModuleHandleW(module);
    if (loaded == nullptr) {
        return nullptr;
    }
    return (PVOID)GetProcAddress(loaded, name);
}

static LONG g_hook_error = 0;

template <typename Fn>
int hook_fn(const wchar_t* module, const char* name, Fn hook, Fn* real) {
    PVOID target = module_proc(module, name);
    LONG err;
    if (target == nullptr) {
        g_hook_error = ERROR_PROC_NOT_FOUND;
        return 0;
    }
    *real = (Fn)target;
    err = DetourAttach((PVOID*)real, (PVOID)hook);
    if (err != NO_ERROR) {
        *real = nullptr;
        g_hook_error = err;
        return 0;
    }
    return 1;
}

template <typename Fn>
int hook_mod(const wchar_t* module, const char* name, Fn hook, Fn* real, int optional) {
    if (*real != nullptr) {
        return 1;
    }
    if (GetModuleHandleW(module) == nullptr) {
        if (optional) {
            return 1;
        }
        fprintf(stderr, "agent-security-process-guard: hook failed %ls!%s module missing\n", module, name);
        fflush(stderr);
        return 0;
    }
    if (hook_fn(module, name, hook, real)) {
        return 1;
    }
    fprintf(stderr, "agent-security-process-guard: hook failed %ls!%s error %ld\n", module, name, g_hook_error);
    fflush(stderr);
    return 0;
}

template <typename Fn>
int hook_kernel(const char* name, Fn hook, Fn* real) {
    if (hook_fn(L"kernelbase.dll", name, hook, real) || hook_fn(L"kernel32.dll", name, hook, real)) {
        return 1;
    }
    fprintf(stderr, "agent-security-process-guard: hook failed %s\n", name);
    fflush(stderr);
    return 0;
}

using LdrLoadDll_t = NTSTATUS(NTAPI*)(PWSTR, PULONG, PUNICODE_STRING, PHANDLE);
LdrLoadDll_t Real_LdrLoadDll = nullptr;

int attach_deferred() {
    return hook_mod(L"advapi32.dll", "CreateProcessAsUserW", Hook_CreateProcessAsUserW, &Real_CreateProcessAsUserW, 1) &&
           hook_mod(L"advapi32.dll", "CreateProcessAsUserA", Hook_CreateProcessAsUserA, &Real_CreateProcessAsUserA, 1) &&
           hook_mod(L"kernel32.dll", "CreateProcessAsUserA", Hook_CreateProcessAsUserA, &Real_CreateProcessAsUserA_Kernel, 1) &&
           hook_mod(L"advapi32.dll", "CreateProcessWithTokenW", Hook_CreateProcessWithTokenW, &Real_CreateProcessWithTokenW, 1) &&
           hook_mod(L"advapi32.dll", "CreateProcessWithLogonW", Hook_CreateProcessWithLogonW, &Real_CreateProcessWithLogonW, 1) &&
           hook_mod(L"shell32.dll", "ShellExecuteW", Hook_ShellExecuteW, &Real_ShellExecuteW, 1) &&
           hook_mod(L"shell32.dll", "ShellExecuteA", Hook_ShellExecuteA, &Real_ShellExecuteA, 1) &&
           hook_mod(L"shell32.dll", "ShellExecuteExW", Hook_ShellExecuteExW, &Real_ShellExecuteExW, 1) &&
           hook_mod(L"shell32.dll", "ShellExecuteExA", Hook_ShellExecuteExA, &Real_ShellExecuteExA, 1) &&
           hook_mod(L"ws2_32.dll", "connect", Hook_connect, &Real_connect, 1) &&
           hook_mod(L"ws2_32.dll", "WSAConnect", Hook_WSAConnect, &Real_WSAConnect, 1) &&
           hook_mod(L"winhttp.dll", "WinHttpConnect", Hook_WinHttpConnect, &Real_WinHttpConnect, 1) &&
           hook_mod(L"wininet.dll", "InternetConnectW", Hook_InternetConnectW, &Real_InternetConnectW, 1) &&
           hook_mod(L"wininet.dll", "InternetConnectA", Hook_InternetConnectA, &Real_InternetConnectA, 1);
}

int deferred_pending() {
    return (Real_CreateProcessAsUserW == nullptr && GetModuleHandleW(L"advapi32.dll") != nullptr) ||
           (Real_CreateProcessAsUserA == nullptr && GetModuleHandleW(L"advapi32.dll") != nullptr) ||
           (Real_CreateProcessAsUserA_Kernel == nullptr && GetModuleHandleW(L"kernel32.dll") != nullptr) ||
           (Real_CreateProcessWithTokenW == nullptr && GetModuleHandleW(L"advapi32.dll") != nullptr) ||
           (Real_CreateProcessWithLogonW == nullptr && GetModuleHandleW(L"advapi32.dll") != nullptr) ||
           (Real_ShellExecuteW == nullptr && GetModuleHandleW(L"shell32.dll") != nullptr) ||
           (Real_ShellExecuteA == nullptr && GetModuleHandleW(L"shell32.dll") != nullptr) ||
           (Real_ShellExecuteExW == nullptr && GetModuleHandleW(L"shell32.dll") != nullptr) ||
           (Real_ShellExecuteExA == nullptr && GetModuleHandleW(L"shell32.dll") != nullptr) ||
           (Real_connect == nullptr && GetModuleHandleW(L"ws2_32.dll") != nullptr) ||
           (Real_WSAConnect == nullptr && GetModuleHandleW(L"ws2_32.dll") != nullptr) ||
           (Real_WinHttpConnect == nullptr && GetModuleHandleW(L"winhttp.dll") != nullptr) ||
           (Real_InternetConnectW == nullptr && GetModuleHandleW(L"wininet.dll") != nullptr) ||
           (Real_InternetConnectA == nullptr && GetModuleHandleW(L"wininet.dll") != nullptr);
}

NTSTATUS NTAPI Hook_LdrLoadDll(PWSTR path, PULONG characteristics, PUNICODE_STRING module, PHANDLE handle) {
    NTSTATUS status = Real_LdrLoadDll(path, characteristics, module, handle);
    if (status < 0 || t_attaching || !deferred_pending()) {
        return status;
    }
    EnterCriticalSection(&g_hook_lock);
    t_attaching = 1;
    if (DetourTransactionBegin() != NO_ERROR || DetourUpdateThread(GetCurrentThread()) != NO_ERROR || !attach_deferred() ||
        DetourTransactionCommit() != NO_ERROR) {
        DetourTransactionAbort();
        t_attaching = 0;
        LeaveCriticalSection(&g_hook_lock);
        TerminateProcess(GetCurrentProcess(), SANDBOX_FAIL_EXIT);
    }
    t_attaching = 0;
    LeaveCriticalSection(&g_hook_lock);
    return status;
}

int install_hooks() {
    if (DetourTransactionBegin() != NO_ERROR || DetourUpdateThread(GetCurrentThread()) != NO_ERROR) {
        return 0;
    }
    int ok = hook_kernel("CreateFileW", Hook_CreateFileW, &Real_CreateFileW) &&
             hook_kernel("CreateFileA", Hook_CreateFileA, &Real_CreateFileA) &&
             hook_kernel("GetFileAttributesW", Hook_GetFileAttributesW, &Real_GetFileAttributesW) &&
             hook_kernel("GetFileAttributesA", Hook_GetFileAttributesA, &Real_GetFileAttributesA) &&
             hook_kernel("FindFirstFileW", Hook_FindFirstFileW, &Real_FindFirstFileW) &&
             hook_kernel("FindFirstFileA", Hook_FindFirstFileA, &Real_FindFirstFileA) &&
             hook_kernel("CreateDirectoryW", Hook_CreateDirectoryW, &Real_CreateDirectoryW) &&
             hook_kernel("CreateDirectoryA", Hook_CreateDirectoryA, &Real_CreateDirectoryA) &&
             hook_kernel("DeleteFileW", Hook_DeleteFileW, &Real_DeleteFileW) &&
             hook_kernel("DeleteFileA", Hook_DeleteFileA, &Real_DeleteFileA) &&
             hook_kernel("RemoveDirectoryW", Hook_RemoveDirectoryW, &Real_RemoveDirectoryW) &&
             hook_kernel("RemoveDirectoryA", Hook_RemoveDirectoryA, &Real_RemoveDirectoryA) &&
             hook_kernel("CopyFileW", Hook_CopyFileW, &Real_CopyFileW) &&
             hook_kernel("CopyFileA", Hook_CopyFileA, &Real_CopyFileA) &&
             hook_kernel("CopyFileExW", Hook_CopyFileExW, &Real_CopyFileExW) &&
             hook_kernel("CopyFileExA", Hook_CopyFileExA, &Real_CopyFileExA) &&
             hook_kernel("MoveFileW", Hook_MoveFileW, &Real_MoveFileW) &&
             hook_kernel("MoveFileA", Hook_MoveFileA, &Real_MoveFileA) &&
             hook_kernel("MoveFileExW", Hook_MoveFileExW, &Real_MoveFileExW) &&
             hook_kernel("MoveFileExA", Hook_MoveFileExA, &Real_MoveFileExA) &&
             hook_kernel("ReplaceFileW", Hook_ReplaceFileW, &Real_ReplaceFileW) &&
             hook_kernel("ReplaceFileA", Hook_ReplaceFileA, &Real_ReplaceFileA) &&
             hook_kernel("CreateHardLinkW", Hook_CreateHardLinkW, &Real_CreateHardLinkW) &&
             hook_kernel("CreateHardLinkA", Hook_CreateHardLinkA, &Real_CreateHardLinkA) &&
             hook_kernel("CreateSymbolicLinkW", Hook_CreateSymbolicLinkW, &Real_CreateSymbolicLinkW) &&
             hook_kernel("CreateSymbolicLinkA", Hook_CreateSymbolicLinkA, &Real_CreateSymbolicLinkA) &&
             hook_kernel("SetFileAttributesW", Hook_SetFileAttributesW, &Real_SetFileAttributesW) &&
             hook_kernel("SetFileAttributesA", Hook_SetFileAttributesA, &Real_SetFileAttributesA) &&
             hook_kernel("SetFileInformationByHandle", Hook_SetFileInformationByHandle, &Real_SetFileInformationByHandle) &&
             hook_kernel("CreateProcessW", Hook_CreateProcessW, &Real_CreateProcessW) &&
             hook_kernel("CreateProcessA", Hook_CreateProcessA, &Real_CreateProcessA) &&
             hook_mod(L"ntdll.dll", "LdrLoadDll", Hook_LdrLoadDll, &Real_LdrLoadDll, 0) &&
             attach_deferred() &&
             hook_mod(L"ntdll.dll", "NtCreateFile", Hook_NtCreateFile, &Real_NtCreateFile, 0) &&
             hook_mod(L"ntdll.dll", "NtSetInformationFile", Hook_NtSetInformationFile, &Real_NtSetInformationFile, 0) &&
             hook_mod(L"ntdll.dll", "NtDeleteFile", Hook_NtDeleteFile, &Real_NtDeleteFile, 0) &&
             hook_mod(L"ntdll.dll", "NtCreateUserProcess", Hook_NtCreateUserProcess, &Real_NtCreateUserProcess, 0);
    if (!ok || DetourTransactionCommit() != NO_ERROR) {
        DetourTransactionAbort();
        return 0;
    }
    return 1;
}

extern "C" __declspec(dllexport) DWORD WINAPI ProcessGuardAttach(LPVOID param) {
    ProcessGuardStartup* startup = (ProcessGuardStartup*)param;
    if (g_ready) {
        return 0;
    }
    if (startup == nullptr || startup->decide_handle == 0 || startup->broker_handle == 0 || startup->decision_timeout_ms == 0) {
        return 1;
    }
    g_startup = *startup;
    InitializeCriticalSection(&g_decide_lock);
    InitializeCriticalSection(&g_broker_lock);
    InitializeCriticalSection(&g_hook_lock);
    if (!install_hooks()) {
        return 2;
    }
    g_ready = 1;
    return 0;
}
