#ifndef AGENT_SECURITY_RECORD_JSON_H
#define AGENT_SECURITY_RECORD_JSON_H

#include "operation_mapping.h"
#include "process_guard_startup.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SandboxIdentity {
    uint32_t pid;
    uint32_t parent_pid;
    uint32_t tid;
    char instance_id[SANDBOX_INSTANCE_CAP];
    char image_utf8[SANDBOX_IMAGE_UTF8_CAP];
    char user_sid[SANDBOX_SID_CAP];
    char integrity[SANDBOX_INTEGRITY_CAP];
} SandboxIdentity;

int wide_to_utf8(const wchar_t* src, char* dest, size_t dest_cap);
int record_to_json(
    const MappedOperation* operation,
    const SandboxIdentity* identity,
    const char* request_id,
    const char* operation_id,
    const char* time_utc,
    const char* tool_call_id,
    const char* tool_name,
    char* dest,
    size_t dest_cap);
int provision_request_json(
    uint32_t pid,
    uint32_t tid,
    const char* architecture,
    uint32_t creation_flags,
    const char* tool_call_id,
    const char* tool_name,
    char* dest,
    size_t dest_cap);
int bind_to_json(const SandboxIdentity* identity, char* dest, size_t dest_cap);
int operation_result_json(
    const char* request_id,
    const char* operation_id,
    int success,
    const char* disposition,
    char* dest,
    size_t dest_cap);
int decision_allows(const char* json, const char* request_id, const char* operation_id);
int json_copy_string(const char* json, const char* key, char* dest, size_t dest_cap);
int json_copy_uint(const char* json, const char* key, uint32_t* dest);
int json_copy_bool(const char* json, const char* key, int* dest);

#ifdef __cplusplus
}
#endif

#endif
