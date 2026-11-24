#include "record_json.h"

#include "message_framing.h"

#include <windows.h>

#include <stdio.h>
#include <string.h>

typedef struct JsonBuf {
    char* dest;
    size_t cap;
    size_t used;
    int overflow;
} JsonBuf;

static void jb_add(JsonBuf* buf, const char* text) {
    size_t length = strlen(text);
    if (buf->overflow || buf->used + length + 1 > buf->cap) {
        buf->overflow = 1;
        return;
    }
    memcpy(buf->dest + buf->used, text, length);
    buf->used += length;
    buf->dest[buf->used] = '\0';
}

static void jb_add_escaped(JsonBuf* buf, const char* text) {
    static const char* hex = "0123456789abcdef";
    jb_add(buf, "\"");
    if (text == NULL) {
        text = "";
    }
    for (; *text != '\0'; ++text) {
        unsigned char value = (unsigned char)*text;
        char tmp[8];
        if (value == '\\' || value == '"') {
            tmp[0] = '\\';
            tmp[1] = (char)value;
            tmp[2] = '\0';
            jb_add(buf, tmp);
        } else if (value < 0x20u) {
            tmp[0] = '\\';
            tmp[1] = 'u';
            tmp[2] = '0';
            tmp[3] = '0';
            tmp[4] = hex[value >> 4];
            tmp[5] = hex[value & 0x0fu];
            tmp[6] = '\0';
            jb_add(buf, tmp);
        } else {
            tmp[0] = (char)value;
            tmp[1] = '\0';
            jb_add(buf, tmp);
        }
    }
    jb_add(buf, "\"");
}

static void jb_add_uint(JsonBuf* buf, uint32_t value) {
    char tmp[16];
    snprintf(tmp, sizeof(tmp), "%lu", (unsigned long)value);
    jb_add(buf, tmp);
}

static const char* category_of(const char* kind) {
    if (strcmp(kind, "create_process") == 0) {
        return "process";
    }
    if (strcmp(kind, "connect") == 0) {
        return "network";
    }
    return "file";
}

int wide_to_utf8(const wchar_t* src, char* dest, size_t dest_cap) {
    int written;
    if (src == NULL || dest == NULL || dest_cap == 0 || dest_cap > 0x7fffffffu) {
        return 0;
    }
    written = WideCharToMultiByte(CP_UTF8, 0, src, -1, dest, (int)dest_cap, NULL, NULL);
    return written > 0;
}

static void add_file_resource(JsonBuf* buf, const MappedResource* resource) {
    char path[SANDBOX_PATH_CAP * 3];
    jb_add(buf, "{\"path\":");
    if (!wide_to_utf8(resource->path, path, sizeof(path))) {
        buf->overflow = 1;
        return;
    }
    jb_add_escaped(buf, path);
    jb_add(buf, ",\"role\":");
    jb_add_escaped(buf, resource->role);
    if (resource->device_class[0] != '\0') {
        jb_add(buf, ",\"device_class\":");
        jb_add_escaped(buf, resource->device_class);
    }
    jb_add(buf, "}");
}

static void add_process_resource(JsonBuf* buf, const MappedOperation* operation) {
    char image[SANDBOX_PATH_CAP * 3];
    char command[SANDBOX_TEXT_CAP * 3];
    if (!wide_to_utf8(operation->image, image, sizeof(image)) ||
        !wide_to_utf8(operation->command_line, command, sizeof(command))) {
        buf->overflow = 1;
        return;
    }
    jb_add(buf, "{\"role\":\"image\",\"path\":");
    jb_add_escaped(buf, image);
    jb_add(buf, ",\"image\":");
    jb_add_escaped(buf, image);
    jb_add(buf, ",\"command_line\":");
    jb_add_escaped(buf, command);
    jb_add(buf, "}");
}

static void add_connect_resource(JsonBuf* buf, const MappedOperation* operation) {
    char port[16];
    jb_add(buf, "{\"role\":\"peer\",\"host\":");
    if (operation->has_host) {
        jb_add_escaped(buf, operation->host);
    } else {
        jb_add(buf, "null");
    }
    jb_add(buf, ",\"ip\":");
    if (operation->has_ip) {
        jb_add_escaped(buf, operation->ip);
    } else {
        jb_add(buf, "null");
    }
    snprintf(port, sizeof(port), "%d", operation->port);
    jb_add(buf, ",\"port\":");
    jb_add(buf, port);
    jb_add(buf, "}");
}

static int cause_present(const char* tool_call_id, const char* tool_name) {
    return tool_call_id != NULL && tool_call_id[0] != '\0' && tool_name != NULL && tool_name[0] != '\0';
}

int record_to_json(
    const MappedOperation* operation,
    const SandboxIdentity* identity,
    const char* request_id,
    const char* operation_id,
    const char* time_utc,
    const char* tool_call_id,
    const char* tool_name,
    char* dest,
    size_t dest_cap) {
    JsonBuf buf;
    int index;
    if (operation == NULL || identity == NULL || request_id == NULL || operation_id == NULL || time_utc == NULL ||
        dest == NULL || dest_cap == 0) {
        return -1;
    }
    dest[0] = '\0';
    buf.dest = dest;
    buf.cap = dest_cap;
    buf.used = 0;
    buf.overflow = 0;
    jb_add(&buf, "{\"spec\":\"native-record/v1\",\"request_id\":");
    jb_add_escaped(&buf, request_id);
    jb_add(&buf, ",\"operation_id\":");
    jb_add_escaped(&buf, operation_id);
    jb_add(&buf, ",\"time\":");
    jb_add_escaped(&buf, time_utc);
    jb_add(&buf, ",\"process\":{\"pid\":");
    jb_add_uint(&buf, identity->pid);
    jb_add(&buf, ",\"tid\":");
    jb_add_uint(&buf, identity->tid);
    jb_add(&buf, ",\"parent_pid\":");
    jb_add_uint(&buf, identity->parent_pid);
    jb_add(&buf, ",\"process_instance_id\":");
    jb_add_escaped(&buf, identity->instance_id);
    jb_add(&buf, ",\"image\":");
    jb_add_escaped(&buf, identity->image_utf8);
    jb_add(&buf, ",\"identity\":{\"user_sid\":");
    jb_add_escaped(&buf, identity->user_sid);
    jb_add(&buf, ",\"integrity_level\":");
    jb_add_escaped(&buf, identity->integrity);
    jb_add(&buf, "}},\"operation\":{\"category\":");
    jb_add_escaped(&buf, category_of(operation->kind));
    jb_add(&buf, ",\"kind\":");
    jb_add_escaped(&buf, operation->kind);
    jb_add(&buf, ",\"access\":");
    jb_add_escaped(&buf, operation->access);
    jb_add(&buf, ",\"resources\":[");
    if (strcmp(operation->kind, "connect") == 0) {
        add_connect_resource(&buf, operation);
    } else if (strcmp(operation->kind, "create_process") == 0) {
        add_process_resource(&buf, operation);
    } else {
        for (index = 0; index < operation->resource_count; ++index) {
            if (index > 0) {
                jb_add(&buf, ",");
            }
            add_file_resource(&buf, &operation->resources[index]);
        }
    }
    jb_add(&buf, "]}");
    if (cause_present(tool_call_id, tool_name)) {
        jb_add(&buf, ",\"cause\":{\"tool_call_id\":");
        jb_add_escaped(&buf, tool_call_id);
        jb_add(&buf, ",\"name\":");
        jb_add_escaped(&buf, tool_name);
        jb_add(&buf, "}");
    }
    jb_add(&buf, "}");
    if (buf.overflow || buf.used == 0 || buf.used > SANDBOX_FRAME_MAX) {
        return -1;
    }
    return (int)buf.used;
}

int provision_request_json(
    uint32_t pid,
    uint32_t tid,
    const char* architecture,
    uint32_t creation_flags,
    const char* tool_call_id,
    const char* tool_name,
    char* dest,
    size_t dest_cap) {
    JsonBuf buf;
    if (architecture == NULL || dest == NULL || dest_cap == 0) {
        return -1;
    }
    dest[0] = '\0';
    buf.dest = dest;
    buf.cap = dest_cap;
    buf.used = 0;
    buf.overflow = 0;
    jb_add(&buf, "{\"spec\":\"process-guard-broker/v1\",\"action\":\"provision_child\",\"tool_call_id\":");
    jb_add_escaped(&buf, tool_call_id != NULL ? tool_call_id : "");
    jb_add(&buf, ",\"tool_name\":");
    jb_add_escaped(&buf, tool_name != NULL ? tool_name : "");
    jb_add(&buf, ",\"child\":{\"pid\":");
    jb_add_uint(&buf, pid);
    jb_add(&buf, ",\"tid\":");
    jb_add_uint(&buf, tid);
    jb_add(&buf, ",\"architecture\":");
    jb_add_escaped(&buf, architecture);
    jb_add(&buf, ",\"creation_flags\":");
    jb_add_uint(&buf, creation_flags);
    jb_add(&buf, "}}");
    if (buf.overflow || buf.used == 0) {
        return -1;
    }
    return (int)buf.used;
}

int bind_to_json(const SandboxIdentity* identity, char* dest, size_t dest_cap) {
    JsonBuf buf;
    if (identity == NULL || dest == NULL || dest_cap == 0) {
        return -1;
    }
    dest[0] = '\0';
    buf.dest = dest;
    buf.cap = dest_cap;
    buf.used = 0;
    buf.overflow = 0;
    jb_add(&buf, "{\"spec\":\"process-guard-bind/v1\",\"pid\":");
    jb_add_uint(&buf, identity->pid);
    jb_add(&buf, ",\"parent_pid\":");
    jb_add_uint(&buf, identity->parent_pid);
    jb_add(&buf, ",\"process_instance_id\":");
    jb_add_escaped(&buf, identity->instance_id);
    jb_add(&buf, ",\"image\":");
    jb_add_escaped(&buf, identity->image_utf8);
    jb_add(&buf, ",\"user_sid\":");
    jb_add_escaped(&buf, identity->user_sid);
    jb_add(&buf, ",\"integrity_level\":");
    jb_add_escaped(&buf, identity->integrity);
    jb_add(&buf, "}");
    if (buf.overflow || buf.used == 0) {
        return -1;
    }
    return (int)buf.used;
}

int operation_result_json(
    const char* request_id,
    const char* operation_id,
    int success,
    const char* disposition,
    char* dest,
    size_t dest_cap) {
    JsonBuf buf;
    if (request_id == NULL || operation_id == NULL || disposition == NULL || dest == NULL || dest_cap == 0) {
        return -1;
    }
    dest[0] = '\0';
    buf.dest = dest;
    buf.cap = dest_cap;
    buf.used = 0;
    buf.overflow = 0;
    jb_add(&buf, "{\"spec\":\"native-operation-result/v1\",\"request_id\":");
    jb_add_escaped(&buf, request_id);
    jb_add(&buf, ",\"operation_id\":");
    jb_add_escaped(&buf, operation_id);
    jb_add(&buf, success ? ",\"success\":true,\"disposition\":" : ",\"success\":false,\"disposition\":");
    jb_add_escaped(&buf, disposition);
    jb_add(&buf, "}");
    if (buf.overflow || buf.used == 0) {
        return -1;
    }
    return (int)buf.used;
}

static const char* value_after(const char* json, const char* key) {
    char pattern[80];
    const char* found;
    size_t key_len = strlen(key);
    if (json == NULL || key_len + 3 >= sizeof(pattern)) {
        return NULL;
    }
    pattern[0] = '"';
    memcpy(pattern + 1, key, key_len);
    pattern[key_len + 1] = '"';
    pattern[key_len + 2] = '\0';
    found = strstr(json, pattern);
    if (found == NULL) {
        return NULL;
    }
    found += key_len + 2;
    while (*found == ' ' || *found == '\t' || *found == '\r' || *found == '\n') {
        ++found;
    }
    if (*found != ':') {
        return NULL;
    }
    ++found;
    while (*found == ' ' || *found == '\t' || *found == '\r' || *found == '\n') {
        ++found;
    }
    return found;
}

int json_copy_string(const char* json, const char* key, char* dest, size_t dest_cap) {
    const char* value = value_after(json, key);
    size_t used = 0;
    if (value == NULL || dest == NULL || dest_cap == 0 || *value != '"') {
        return 0;
    }
    ++value;
    while (*value != '\0' && *value != '"') {
        char ch = *value++;
        if (ch == '\\') {
            if (*value == '\0') {
                return 0;
            }
            ch = *value++;
            if (ch == 'n') {
                ch = '\n';
            } else if (ch == 'r') {
                ch = '\r';
            } else if (ch == 't') {
                ch = '\t';
            }
        }
        if (used + 1 >= dest_cap) {
            return 0;
        }
        dest[used++] = ch;
    }
    if (*value != '"') {
        return 0;
    }
    dest[used] = '\0';
    return 1;
}

int json_copy_uint(const char* json, const char* key, uint32_t* dest) {
    const char* value = value_after(json, key);
    uint32_t number = 0;
    int digits = 0;
    if (value == NULL || dest == NULL) {
        return 0;
    }
    while (*value >= '0' && *value <= '9') {
        number = number * 10u + (uint32_t)(*value - '0');
        ++value;
        ++digits;
    }
    if (digits == 0) {
        return 0;
    }
    *dest = number;
    return 1;
}

int json_copy_bool(const char* json, const char* key, int* dest) {
    const char* value = value_after(json, key);
    if (value == NULL || dest == NULL) {
        return 0;
    }
    if (strncmp(value, "true", 4) == 0) {
        *dest = 1;
        return 1;
    }
    if (strncmp(value, "false", 5) == 0) {
        *dest = 0;
        return 1;
    }
    return 0;
}

int decision_allows(const char* json, const char* request_id, const char* operation_id) {
    char spec[64];
    char request[128];
    char operation[128];
    int allow = 0;
    if (!json_copy_string(json, "spec", spec, sizeof(spec)) || strcmp(spec, "native-decision/v1") != 0) {
        return 0;
    }
    if (!process_guard_spec_supported(spec)) {
        return 0;
    }
    if (!json_copy_string(json, "request_id", request, sizeof(request))) {
        return 0;
    }
    if (!json_copy_string(json, "operation_id", operation, sizeof(operation))) {
        return 0;
    }
    if (!json_copy_bool(json, "allow", &allow)) {
        return 0;
    }
    if (!decision_ids_match(request_id, operation_id, request, operation)) {
        return 0;
    }
    return allow ? 1 : 0;
}
