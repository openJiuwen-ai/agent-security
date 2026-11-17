#include "file_hooks.h"
#include "detours.h"

/* Both startup modes register the same file API set in the caller's transaction. */
LONG configure_file_hooks(const GuardHookBinding bindings[GuardFileHookCount], BOOL attach) {
    static const struct { LPCWSTR module; LPCSTR name; } targets[GuardFileHookCount] = {
        [GuardHookNtCreateFile] = {L"ntdll.dll", "NtCreateFile"},
        [GuardHookNtOpenFile] = {L"ntdll.dll", "NtOpenFile"},
        [GuardHookNtDeleteFile] = {L"ntdll.dll", "NtDeleteFile"},
        [GuardHookNtSetInformationFile] = {L"ntdll.dll", "NtSetInformationFile"},
        [GuardHookNtClose] = {L"ntdll.dll", "NtClose"},
        [GuardHookDeleteFileW] = {L"kernelbase.dll", "DeleteFileW"},
        [GuardHookRemoveDirectoryW] = {L"kernelbase.dll", "RemoveDirectoryW"},
    };
    for (size_t i = 0; i < GuardFileHookCount; ++i) {
        const GuardHookBinding *binding = &bindings[i];
        if (!binding->original || !binding->handler) return ERROR_INVALID_PARAMETER;
        if (attach) {
            HMODULE module = GetModuleHandleW(targets[i].module);
            if (!module) return ERROR_MOD_NOT_FOUND;
            *binding->original = (PVOID)GetProcAddress(module, targets[i].name);
            if (!*binding->original) return ERROR_PROC_NOT_FOUND;
        }
        LONG error = attach ? DetourAttach(binding->original, binding->handler)
                            : DetourDetach(binding->original, binding->handler);
        if (error != NO_ERROR) return error;
    }
    return NO_ERROR;
}
