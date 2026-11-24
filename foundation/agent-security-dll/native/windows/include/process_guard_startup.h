#ifndef AGENT_SECURITY_PROCESS_GUARD_STARTUP_H
#define AGENT_SECURITY_PROCESS_GUARD_STARTUP_H

#include <stdint.h>

/* Copied into a suspended child before its main thread runs.
   Layout is identical for x64 and WOW64 x86: no pointers, packed to 8. */

#define SANDBOX_FAIL_EXIT 83
#define SANDBOX_DELETE_TRASH 0u
#define SANDBOX_DELETE_PERMANENT 1u
#define SANDBOX_INSTANCE_CAP 128
#define SANDBOX_SID_CAP 256
#define SANDBOX_INTEGRITY_CAP 16
#define SANDBOX_IMAGE_UTF8_CAP 4096
#define SANDBOX_TOOL_CALL_ID_CAP 128
#define SANDBOX_TOOL_NAME_CAP 256

#pragma pack(push, 8)
typedef struct ProcessGuardStartup {
    uint64_t decide_handle;
    uint64_t broker_handle;
    uint32_t decision_timeout_ms;
    uint32_t delete_mode;
    uint32_t pid;
    uint32_t parent_pid;
    char instance_id[SANDBOX_INSTANCE_CAP];
    char user_sid[SANDBOX_SID_CAP];
    char integrity[SANDBOX_INTEGRITY_CAP];
    char image_utf8[SANDBOX_IMAGE_UTF8_CAP];
    char tool_call_id[SANDBOX_TOOL_CALL_ID_CAP];
    char tool_name[SANDBOX_TOOL_NAME_CAP];
} ProcessGuardStartup;
#pragma pack(pop)

#endif
