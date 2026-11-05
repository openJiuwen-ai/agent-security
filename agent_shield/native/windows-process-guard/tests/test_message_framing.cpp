#include "../src/message_framing.h"

#include <stdio.h>
#include <string.h>

static int g_failed = 0;

#define EXPECT(cond)                                                                                      \
    do {                                                                                                  \
        if (!(cond)) {                                                                                    \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #cond);                                    \
            g_failed += 1;                                                                                \
        }                                                                                                 \
    } while (0)

int main(void) {
    const char* payload = "{\"spec\":\"native-decision/v1\",\"request_id\":\"req\",\"operation_id\":\"op\"}";
    uint8_t buffer[256];
    uint32_t length = 0;
    int encoded = frame_encode(buffer, sizeof(buffer), (const uint8_t*)payload, (uint32_t)strlen(payload));
    EXPECT(encoded == (int)strlen(payload) + 4);
    EXPECT(frame_decode(buffer, 3, &length) == 0);
    EXPECT(frame_decode(buffer, (size_t)encoded, &length) == 1);
    EXPECT(length == (uint32_t)strlen(payload));
    EXPECT(memcmp(buffer + 4, payload, length) == 0);

    buffer[0] = 0;
    buffer[1] = 0;
    buffer[2] = 0;
    buffer[3] = 0;
    EXPECT(frame_decode(buffer, 4, &length) == -1);
    buffer[0] = 0xff;
    buffer[1] = 0xff;
    buffer[2] = 0xff;
    buffer[3] = 0x7f;
    EXPECT(frame_decode(buffer, 4, &length) == -1);
    EXPECT(frame_encode(buffer, sizeof(buffer), (const uint8_t*)payload, 0) == -1);

    EXPECT(decision_ids_match("req", "op", "req", "op") == 1);
    EXPECT(decision_ids_match("req", "op", "other", "op") == 0);
    EXPECT(decision_ids_match("req", "op", "req", "other") == 0);
    EXPECT(process_guard_spec_supported("native-record/v1") == 1);
    EXPECT(process_guard_spec_supported("native-decision/v1") == 1);
    EXPECT(process_guard_spec_supported("native-record/unknown") == 0);
    EXPECT(process_guard_spec_supported(NULL) == 0);

    if (g_failed != 0) {
        fprintf(stderr, "%d framing checks failed\n", g_failed);
        return 1;
    }
    return 0;
}
