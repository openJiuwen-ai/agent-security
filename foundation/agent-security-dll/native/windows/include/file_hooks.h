#pragma once
#include <windows.h>

typedef struct {
    PVOID *original;
    PVOID handler;
} GuardHookBinding;

typedef enum {
    GuardHookNtCreateFile,
    GuardHookNtOpenFile,
    GuardHookNtDeleteFile,
    GuardHookNtSetInformationFile,
    GuardHookNtClose,
    GuardHookDeleteFileW,
    GuardHookRemoveDirectoryW,
    GuardFileHookCount
} GuardFileHook;

LONG configure_file_hooks(const GuardHookBinding bindings[GuardFileHookCount], BOOL attach);
