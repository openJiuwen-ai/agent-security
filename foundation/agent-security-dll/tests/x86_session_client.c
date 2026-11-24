/* Exercise the x86 Guard in this fixture's own process. No target is attached. */
#include "../native/windows/guard/guard.c"
#include <stdio.h>

int wmain(int argc, wchar_t **argv) {
    DWORD received;
    if (argc != 3 || !ReadFile(GetStdHandle(STD_INPUT_HANDLE), &config, sizeof(config), &received, NULL)
        || received != sizeof(config) || config.magic != 0x44474333) return 2;
    GuardOpenConfig options={sizeof(options),GUARD_CAP_SHIELD|(config.permanent?0:GUARD_CAP_RECOVERY),config.permanent,&config,NULL,NULL,NULL};
    HANDLE lease=guard_open(&options);
    if (!lease) return 2;
    HANDLE file = CreateFileW(argv[1], GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return 3;
    CloseHandle(file);
    file = CreateFileW(argv[2], GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file != INVALID_HANDLE_VALUE) {
        CloseHandle(file);
        return 4;
    }
    if (GetLastError() != ERROR_ACCESS_DENIED) return 5;
    FILETIME created, exited, kernel, user;
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) return 6;
    ULARGE_INTEGER stamp;
    stamp.LowPart = created.dwLowDateTime;
    stamp.HighPart = created.dwHighDateTime;
    printf("%u %lu %llu\n", (unsigned)(8 * sizeof(void*)), GetCurrentProcessId(), stamp.QuadPart);
    return guard_close(lease)?0:7;
}
