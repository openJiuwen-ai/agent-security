#include "operation_mapping.h"

#include "path_classification.h"

#include <stdio.h>
#include <string.h>
#include <wchar.h>

#define GENERIC_READ 0x80000000u
#define GENERIC_WRITE 0x40000000u
#define GENERIC_ALL 0x10000000u
#define FILE_WRITE_DATA 0x0002u
#define FILE_APPEND_DATA 0x0004u
#define FILE_WRITE_EA 0x0010u
#define FILE_WRITE_ATTRIBUTES 0x0100u
#define CREATE_NEW 1u
#define CREATE_ALWAYS 2u
#define OPEN_ALWAYS 4u
#define TRUNCATE_EXISTING 5u

static void clear_operation(MappedOperation* out) {
    memset(out, 0, sizeof(*out));
}

static int copy_wide(wchar_t* dest, size_t cap, const wchar_t* source) {
    size_t length;
    if (source == NULL) {
        return 0;
    }
    length = wcslen(source);
    if (length + 1 > cap) {
        return 0;
    }
    memcpy(dest, source, (length + 1) * sizeof(wchar_t));
    return 1;
}

static int copy_text(char* dest, size_t cap, const char* source) {
    size_t length = strlen(source);
    if (length + 1 > cap) {
        return 0;
    }
    memcpy(dest, source, length + 1);
    return 1;
}

static int add_resource(MappedOperation* out, const wchar_t* path, const char* role, const char* device_class) {
    MappedResource* resource;
    if (out->resource_count >= 4) {
        return 0;
    }
    resource = &out->resources[out->resource_count];
    if (!copy_wide(resource->path, SANDBOX_PATH_CAP, path)) {
        return 0;
    }
    snprintf(resource->role, sizeof(resource->role), "%s", role);
    snprintf(resource->device_class, sizeof(resource->device_class), "%s", device_class == NULL ? "" : device_class);
    out->resource_count += 1;
    return 1;
}

static int write_access(uint32_t desired_access, uint32_t disposition) {
    uint32_t write_bits = GENERIC_WRITE | GENERIC_ALL | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
                          FILE_WRITE_ATTRIBUTES;
    int creates = disposition == CREATE_NEW || disposition == CREATE_ALWAYS || disposition == TRUNCATE_EXISTING ||
                  disposition == OPEN_ALWAYS;
    return (desired_access & write_bits) != 0 || creates;
}

static MapStatus map_file_path(const wchar_t* path, const char* read_kind, const char* write_kind, int writing, MappedOperation* out) {
    PathClass kind;
    if (out == NULL || path == NULL || path[0] == L'\0') {
        return MAP_REJECT;
    }
    kind = classify_path(path);
    if (kind == PATH_PSEUDO_DEVICE) {
        return MAP_EXEMPT;
    }
    clear_operation(out);
    if (kind == PATH_NAMED_PIPE) {
        snprintf(out->kind, sizeof(out->kind), "pipe_open");
        snprintf(out->access, sizeof(out->access), "%s", writing ? "write" : "read");
        if (!add_resource(out, path, "subject", "named_pipe")) {
            return MAP_REJECT;
        }
        return MAP_OK;
    }
    if (kind == PATH_RAW_DISK || kind == PATH_VOLUME || kind == PATH_OTHER_DEVICE) {
        snprintf(out->kind, sizeof(out->kind), "device_open");
        snprintf(out->access, sizeof(out->access), "%s", writing ? "write" : "read");
        if (!add_resource(out, path, "subject", path_device_class(kind))) {
            return MAP_REJECT;
        }
        return MAP_OK;
    }
    snprintf(out->kind, sizeof(out->kind), "%s", writing ? write_kind : read_kind);
    snprintf(out->access, sizeof(out->access), "%s", writing ? "write" : "read");
    if (!add_resource(out, path, writing ? "target" : "subject", "")) {
        return MAP_REJECT;
    }
    return MAP_OK;
}

MapStatus map_create_file(const wchar_t* path, uint32_t desired_access, uint32_t disposition, MappedOperation* out) {
    int writing = write_access(desired_access, disposition);
    const char* write_kind = (disposition == CREATE_NEW || disposition == CREATE_ALWAYS || disposition == TRUNCATE_EXISTING)
                                 ? "create"
                                 : "write";
    return map_file_path(path, "open", write_kind, writing, out);
}

MapStatus map_delete_path(const wchar_t* path, int directory, MappedOperation* out) {
    PathClass kind;
    if (out == NULL || path == NULL || path[0] == L'\0') {
        return MAP_REJECT;
    }
    kind = classify_path(path);
    if (kind == PATH_PSEUDO_DEVICE) {
        return MAP_EXEMPT;
    }
    if (kind != PATH_NORMAL) {
        return MAP_REJECT;
    }
    clear_operation(out);
    snprintf(out->kind, sizeof(out->kind), "%s", directory ? "rmdir" : "delete");
    snprintf(out->access, sizeof(out->access), "delete");
    if (!add_resource(out, path, "target", "")) {
        return MAP_REJECT;
    }
    return MAP_OK;
}

static MapStatus map_two(const char* kind, const wchar_t* source, const wchar_t* target, const wchar_t* backup, MappedOperation* out) {
    if (out == NULL || source == NULL || target == NULL) {
        return MAP_REJECT;
    }
    if (path_is_exempt(source) || path_is_exempt(target) || (backup != NULL && path_is_exempt(backup))) {
        return MAP_REJECT;
    }
    clear_operation(out);
    snprintf(out->kind, sizeof(out->kind), "%s", kind);
    snprintf(out->access, sizeof(out->access), "write");
    if (!add_resource(out, source, "source", "") || !add_resource(out, target, "target", "")) {
        return MAP_REJECT;
    }
    if (backup != NULL && !add_resource(out, backup, "backup", "")) {
        return MAP_REJECT;
    }
    return MAP_OK;
}

MapStatus map_copy(const wchar_t* source, const wchar_t* target, MappedOperation* out) {
    return map_two("copy", source, target, NULL, out);
}

MapStatus map_move(const wchar_t* source, const wchar_t* target, MappedOperation* out) {
    return map_two("move", source, target, NULL, out);
}

MapStatus map_replace(const wchar_t* source, const wchar_t* target, const wchar_t* backup, MappedOperation* out) {
    return map_two("replace", source, target, backup, out);
}

MapStatus map_link(const wchar_t* source, const wchar_t* target, int symlink, MappedOperation* out) {
    return map_two(symlink ? "symlink" : "hardlink", source, target, NULL, out);
}

MapStatus map_create_process(const wchar_t* image, const wchar_t* command_line, MappedOperation* out) {
    if (out == NULL || image == NULL || image[0] == L'\0' || command_line == NULL) {
        return MAP_REJECT;
    }
    clear_operation(out);
    snprintf(out->kind, sizeof(out->kind), "create_process");
    snprintf(out->access, sizeof(out->access), "execute");
    if (!copy_wide(out->image, SANDBOX_PATH_CAP, image) || !copy_wide(out->command_line, SANDBOX_TEXT_CAP, command_line)) {
        return MAP_REJECT;
    }
    if (!add_resource(out, image, "image", "")) {
        return MAP_REJECT;
    }
    return MAP_OK;
}

static int ends_with_ci(const wchar_t* text, const wchar_t* suffix) {
    size_t text_len = wcslen(text);
    size_t suffix_len = wcslen(suffix);
    size_t index;
    if (suffix_len > text_len) {
        return 0;
    }
    for (index = 0; index < suffix_len; ++index) {
        wchar_t left = text[text_len - suffix_len + index];
        wchar_t right = suffix[index];
        if (left >= L'A' && left <= L'Z') {
            left = (wchar_t)(left - L'A' + L'a');
        }
        if (right >= L'A' && right <= L'Z') {
            right = (wchar_t)(right - L'A' + L'a');
        }
        if (left != right) {
            return 0;
        }
    }
    return 1;
}

MapStatus map_shell_execute(const wchar_t* file, const wchar_t* parameters, MappedOperation* out) {
    wchar_t command[SANDBOX_TEXT_CAP];
    if (file == NULL || file[0] == L'\0' || out == NULL) {
        return MAP_REJECT;
    }
    if (wcsstr(file, L"://") != NULL || !ends_with_ci(file, L".exe")) {
        return MAP_REJECT;
    }
    if (parameters == NULL || parameters[0] == L'\0') {
        swprintf(command, SANDBOX_TEXT_CAP, L"\"%s\"", file);
    } else {
        swprintf(command, SANDBOX_TEXT_CAP, L"\"%s\" %s", file, parameters);
    }
    return map_create_process(file, command, out);
}

MapStatus map_connect(const char* ip, int port, const char* host, MappedOperation* out) {
    if (out == NULL || port < 0 || port > 65535) {
        return MAP_REJECT;
    }
    if ((ip == NULL || ip[0] == '\0') && (host == NULL || host[0] == '\0')) {
        return MAP_REJECT;
    }
    clear_operation(out);
    snprintf(out->kind, sizeof(out->kind), "connect");
    snprintf(out->access, sizeof(out->access), "connect");
    out->port = port;
    if (ip != NULL && ip[0] != '\0') {
        if (!copy_text(out->ip, sizeof(out->ip), ip)) {
            return MAP_REJECT;
        }
        out->has_ip = 1;
    }
    if (host != NULL && host[0] != '\0') {
        if (!copy_text(out->host, sizeof(out->host), host)) {
            return MAP_REJECT;
        }
        out->has_host = 1;
    }
    return MAP_OK;
}

int process_guard_target_supported(const char* architecture) {
    if (architecture == NULL) {
        return 0;
    }
    return strcmp(architecture, "x64") == 0 || strcmp(architecture, "x86") == 0;
}
