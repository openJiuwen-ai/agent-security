#pragma once
#include <windows.h>
#include <string.h>

/* Use the process handle supplied by Windows, independent of any IPC claim. */
static inline int guard_process_architecture(HANDLE process, char *dest, size_t cap) {
    USHORT machine = IMAGE_FILE_MACHINE_UNKNOWN, native = IMAGE_FILE_MACHINE_UNKNOWN;
    typedef BOOL (WINAPI *QueryArchitecture)(HANDLE, USHORT *, USHORT *);
    QueryArchitecture query = (QueryArchitecture)(void*)GetProcAddress(
        GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2");
    if (cap < 4 || !query || !query(process, &machine, &native)) return 0;
    if (native == IMAGE_FILE_MACHINE_ARM64 || machine == IMAGE_FILE_MACHINE_ARM64) return 0;
    if (machine == IMAGE_FILE_MACHINE_I386) return strcpy_s(dest, cap, "x86") == 0;
    if (machine == IMAGE_FILE_MACHINE_UNKNOWN && native == IMAGE_FILE_MACHINE_AMD64)
        return strcpy_s(dest, cap, "x64") == 0;
    return 0;
}
