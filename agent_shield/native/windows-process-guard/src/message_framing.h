#ifndef AGENT_SECURITY_MESSAGE_FRAMING_H
#define AGENT_SECURITY_MESSAGE_FRAMING_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Length-prefixed frames. A short buffer is incomplete, not a denial.
   An oversized or empty declared length is rejected. */

#define SANDBOX_FRAME_MAX (1024u * 1024u)

int frame_encode(uint8_t* dest, size_t dest_cap, const uint8_t* payload, uint32_t payload_len);
int frame_decode(const uint8_t* src, size_t src_len, uint32_t* payload_len);

int decision_ids_match(
    const char* expected_request,
    const char* expected_operation,
    const char* actual_request,
    const char* actual_operation);
int process_guard_spec_supported(const char* spec);

#ifdef __cplusplus
}
#endif

#endif
