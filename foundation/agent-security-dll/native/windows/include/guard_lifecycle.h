#pragma once
#include <windows.h>

/* Shield startup and JiuwenBox debug-child import preparation both
 * acquire their automatic lease through guard_open. Dynamic broker mappings
 * carry no startup payload and remain inert. */
static const GUID guard_recovery_bootstrap_guid =
    {0x437ba331,0x95a4,0x4881,{0xa6,0x69,0xd7,0x90,0xca,0xfe,0x09,0x02}};
#define GUARD_RECOVERY_BOOTSTRAP 0x4752423au
typedef struct {
    DWORD magic;
    WCHAR archive[32768], port[16], token[256], result_file[32768];
} GuardRecoveryBootstrap;

enum { GUARD_CAP_SHIELD = 1, GUARD_CAP_RECOVERY = 2 };
enum { GUARD_DELETE_RECOVER = 0, GUARD_DELETE_PERMANENT = 1 };
typedef struct Config {
    DWORD magic;
    WCHAR pipe[256], ready[256];
    DWORD permanent;
} GuardSessionConfig;
typedef struct {
    DWORD size;
    DWORD capabilities;
    DWORD delete_mode;
    const GuardSessionConfig *session;
    LPCWSTR archive_directory;
    LPCWSTR broker_port;
    LPCWSTR broker_token;
    LPCWSTR result_file;
} GuardOpenConfig;

/* Each successful open owns one lease. Hook registration belongs to the
 * immutable execution binding and is released by its final close. */
#ifdef __cplusplus
extern "C" {
#endif
__declspec(dllexport) HANDLE guard_open(const GuardOpenConfig *config);
__declspec(dllexport) BOOL guard_close(HANDLE handle);
#ifdef __cplusplus
}
#endif
