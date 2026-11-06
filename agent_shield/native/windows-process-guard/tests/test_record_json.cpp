#include "../src/record_json.h"

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
    MappedOperation operation = {};
    SandboxIdentity identity = {};
    char json[4096];
    char request[2048];
    char tool_call_id[SANDBOX_TOOL_CALL_ID_CAP];
    char tool_name[SANDBOX_TOOL_NAME_CAP];
    strcpy_s(operation.kind, "open");
    strcpy_s(operation.access, "read");
    operation.resource_count = 1;
    wcscpy_s(operation.resources[0].path, L"C:\\Users\\me\\proj\\a.txt");
    strcpy_s(operation.resources[0].role, "subject");
    identity.pid = 10;
    identity.tid = 11;
    identity.parent_pid = 9;
    strcpy_s(identity.instance_id, "10:100");
    strcpy_s(identity.image_utf8, "C:/Windows/System32/cmd.exe");
    strcpy_s(identity.user_sid, "S-1-5-21-1");
    strcpy_s(identity.integrity, "medium");

    EXPECT(record_to_json(&operation, &identity, "req", "op", "2026-10-21T00:00:00Z", "", "", json, sizeof(json)) > 0);
    EXPECT(strstr(json, "\"cause\"") == nullptr);

    EXPECT(record_to_json(&operation, &identity, "req", "op", "2026-10-21T00:00:00Z", "call_7f3", "bash", json, sizeof(json)) > 0);
    EXPECT(strstr(json, "\"cause\":{\"tool_call_id\":\"call_7f3\",\"name\":\"bash\"}") != nullptr);

    EXPECT(provision_request_json(20, 21, "x64", 4, "call\"1", "ba\\sh", request, sizeof(request)) > 0);
    EXPECT(json_copy_string(request, "tool_call_id", tool_call_id, sizeof(tool_call_id)) == 1);
    EXPECT(strcmp(tool_call_id, "call\"1") == 0);
    EXPECT(json_copy_string(request, "tool_name", tool_name, sizeof(tool_name)) == 1);
    EXPECT(strcmp(tool_name, "ba\\sh") == 0);
    EXPECT(json_copy_string(request, "architecture", tool_name, sizeof(tool_name)) == 1);
    EXPECT(strcmp(tool_name, "x64") == 0);

    return g_failed == 0 ? 0 : 1;
}
