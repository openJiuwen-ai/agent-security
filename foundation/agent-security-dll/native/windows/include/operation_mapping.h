#ifndef AGENT_SECURITY_OPERATION_MAPPING_H
#define AGENT_SECURITY_OPERATION_MAPPING_H

#include <stdint.h>
#include <wchar.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Map one Win32 call onto one native operation.
   Copy, move, replace, and links stay one record with several resources.
   MAP_EXEMPT means the call is an exact pseudo device and must not ask Decide.
   MAP_REJECT means this activation cannot be controlled, so the caller fails closed. */

#define SANDBOX_PATH_CAP 1024
#define SANDBOX_TEXT_CAP 2048

typedef enum MapStatus {
    MAP_OK = 0,
    MAP_EXEMPT = 1,
    MAP_REJECT = 2
} MapStatus;

typedef struct MappedResource {
    wchar_t path[SANDBOX_PATH_CAP];
    char role[16];
    char device_class[16];
} MappedResource;

typedef struct MappedOperation {
    char kind[32];
    char access[16];
    int resource_count;
    MappedResource resources[4];
    wchar_t image[SANDBOX_PATH_CAP];
    wchar_t command_line[SANDBOX_TEXT_CAP];
    char host[256];
    int has_host;
    char ip[64];
    int has_ip;
    int port;
} MappedOperation;

MapStatus map_create_file(const wchar_t* path, uint32_t desired_access, uint32_t disposition, MappedOperation* out);
MapStatus map_delete_path(const wchar_t* path, int directory, MappedOperation* out);
MapStatus map_copy(const wchar_t* source, const wchar_t* target, MappedOperation* out);
MapStatus map_move(const wchar_t* source, const wchar_t* target, MappedOperation* out);
MapStatus map_replace(const wchar_t* source, const wchar_t* target, const wchar_t* backup, MappedOperation* out);
MapStatus map_link(const wchar_t* source, const wchar_t* target, int symlink, MappedOperation* out);
MapStatus map_create_process(const wchar_t* image, const wchar_t* command_line, MappedOperation* out);
MapStatus map_shell_execute(const wchar_t* file, const wchar_t* parameters, MappedOperation* out);
MapStatus map_connect(const char* ip, int port, const char* host, MappedOperation* out);
int process_guard_target_supported(const char* architecture);

#ifdef __cplusplus
}
#endif

#endif
