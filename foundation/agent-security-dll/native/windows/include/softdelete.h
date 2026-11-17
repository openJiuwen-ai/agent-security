#pragma once
#include <windows.h>
#include <winternl.h>

/* Originals belong to the single hook transaction installed for the process. */
typedef struct {
    NTSTATUS (NTAPI *create)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
    NTSTATUS (NTAPI *open)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
    NTSTATUS (NTAPI *remove)(POBJECT_ATTRIBUTES);
    NTSTATUS (NTAPI *set)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
    NTSTATUS (NTAPI *close)(HANDLE);
    BOOL (WINAPI *delete_file)(LPCWSTR);
    BOOL (WINAPI *remove_dir)(LPCWSTR);
} GuardFileCalls;

void softdelete_bind(const GuardFileCalls *originals, GuardFileCalls *handlers);
typedef BOOL (*GuardAuthorizeDelete)(const GUID *operation, LPCWSTR path, BOOL recheck);
typedef void (*GuardReportDelete)(const GUID *operation, int disposition, DWORD error);
typedef void (*GuardReportStage)(const GUID *operation, DWORD stage, LONG status, DWORD error);
typedef BOOL (*GuardAuthorizeReplace)(const GUID *operation, LPCWSTR source, LPCWSTR target, LPCWSTR backup, DWORD stage);
void softdelete_set_policy(GuardAuthorizeDelete authorize, GuardReportDelete report, GuardReportStage stage, GuardAuthorizeReplace replace);
void softdelete_set_mode(BOOL recover);
void softdelete_release(void);
int configure_recovery_config(LPCWSTR archive, LPCWSTR port, LPCWSTR token, LPCWSTR results);
int prepare_result_stream(void);
typedef struct GuardDeleteScope GuardDeleteScope;
GuardDeleteScope *guard_begin_replace(LPCWSTR source, LPCWSTR target, LPCWSTR backup, DWORD stage);
BOOL guard_finish_replace(GuardDeleteScope *scope, LPCWSTR backup, LONG status, DWORD error);
BOOL guard_replace_active(LPCWSTR target);
int softdelete_exempt(LPCWSTR path);
int recovery_child_environment(LPVOID env, DWORD flags, wchar_t **merged);

LONG softdelete_posix_hooks(BOOL attach);
void softdelete_set_context(void (*context)(int));

/* Select only the bundled Guard matching the target architecture. */
BOOL prepare_packaged_guard(HANDLE process);
