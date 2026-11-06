#include "message_framing.h"

#include <string.h>

int frame_encode(uint8_t* dest, size_t dest_cap, const uint8_t* payload, uint32_t payload_len) {
    if (dest == NULL || payload == NULL || payload_len == 0 || payload_len > SANDBOX_FRAME_MAX) {
        return -1;
    }
    if (dest_cap < (size_t)payload_len + 4u) {
        return -1;
    }
    dest[0] = (uint8_t)(payload_len & 0xffu);
    dest[1] = (uint8_t)((payload_len >> 8) & 0xffu);
    dest[2] = (uint8_t)((payload_len >> 16) & 0xffu);
    dest[3] = (uint8_t)((payload_len >> 24) & 0xffu);
    memcpy(dest + 4, payload, payload_len);
    return (int)(payload_len + 4u);
}

int frame_decode(const uint8_t* src, size_t src_len, uint32_t* payload_len) {
    uint32_t length;
    if (src == NULL || payload_len == NULL) {
        return -1;
    }
    if (src_len < 4u) {
        return 0;
    }
    length = (uint32_t)src[0] | ((uint32_t)src[1] << 8) | ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
    if (length == 0 || length > SANDBOX_FRAME_MAX) {
        return -1;
    }
    if (src_len < (size_t)length + 4u) {
        return 0;
    }
    *payload_len = length;
    return 1;
}

int decision_ids_match(
    const char* expected_request,
    const char* expected_operation,
    const char* actual_request,
    const char* actual_operation) {
    if (expected_request == NULL || expected_operation == NULL || actual_request == NULL ||
        actual_operation == NULL) {
        return 0;
    }
    return strcmp(expected_request, actual_request) == 0 && strcmp(expected_operation, actual_operation) == 0;
}

int process_guard_spec_supported(const char* spec) {
    if (spec == NULL) {
        return 0;
    }
    return strcmp(spec, "native-record/v1") == 0 || strcmp(spec, "native-decision/v1") == 0 ||
           strcmp(spec, "native-operation-result/v1") == 0 || strcmp(spec, "process-guard-broker/v1") == 0;
}
