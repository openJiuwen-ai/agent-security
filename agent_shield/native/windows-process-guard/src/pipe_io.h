#ifndef AGENT_SECURITY_PIPE_IO_H
#define AGENT_SECURITY_PIPE_IO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Overlapped, length-prefixed JSON. cancel is optional.
   A broken pipe, cancel, or timeout returns 0 so the caller fails closed. */

int pipe_write_message(void* pipe, const char* json, void* cancel, uint32_t timeout_ms);
int pipe_read_message(void* pipe, char* dest, size_t dest_cap, void* cancel, uint32_t timeout_ms);
int pipe_transact(
    void* pipe,
    const char* request,
    char* response,
    size_t response_cap,
    void* cancel,
    uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif

#endif
