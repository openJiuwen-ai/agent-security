#include "path_classification.h"

#include <wchar.h>
#include <wctype.h>

static wchar_t fold(wchar_t value) {
    if (value >= L'A' && value <= L'Z') {
        return (wchar_t)(value - L'A' + L'a');
    }
    return value;
}

static int equals_ci(const wchar_t* left, const wchar_t* right) {
    if (left == NULL || right == NULL) {
        return 0;
    }
    while (*left != L'\0' && *right != L'\0') {
        if (fold(*left) != fold(*right)) {
            return 0;
        }
        ++left;
        ++right;
    }
    return *left == L'\0' && *right == L'\0';
}

static int starts_ci(const wchar_t* text, const wchar_t* prefix) {
    if (text == NULL || prefix == NULL) {
        return 0;
    }
    while (*prefix != L'\0') {
        if (*text == L'\0' || fold(*text) != fold(*prefix)) {
            return 0;
        }
        ++text;
        ++prefix;
    }
    return 1;
}

static int contains_ci(const wchar_t* text, const wchar_t* needle) {
    size_t index;
    size_t needle_len;
    size_t text_len;
    if (text == NULL || needle == NULL) {
        return 0;
    }
    needle_len = wcslen(needle);
    text_len = wcslen(text);
    if (needle_len == 0 || needle_len > text_len) {
        return 0;
    }
    for (index = 0; index + needle_len <= text_len; ++index) {
        size_t offset;
        int match = 1;
        for (offset = 0; offset < needle_len; ++offset) {
            if (fold(text[index + offset]) != fold(needle[offset])) {
                match = 0;
                break;
            }
        }
        if (match) {
            return 1;
        }
    }
    return 0;
}

static int is_exact_pseudo(const wchar_t* path) {
    static const wchar_t* names[] = {L"nul", L"con", L"conin$", L"conout$"};
    size_t index;
    for (index = 0; index < 4; ++index) {
        wchar_t nt[16];
        wchar_t dos[16];
        if (equals_ci(path, names[index])) {
            return 1;
        }
        swprintf(nt, 16, L"\\\\.\\%s", names[index]);
        swprintf(dos, 16, L"\\\\?\\%s", names[index]);
        if (equals_ci(path, nt) || equals_ci(path, dos)) {
            return 1;
        }
    }
    return 0;
}

static int is_drive_device(const wchar_t* path) {
    /* \\.\C: or \\?\C: */
    return wcslen(path) == 6 && path[0] == L'\\' && path[1] == L'\\' &&
           (path[2] == L'.' || path[2] == L'?') && path[3] == L'\\' &&
           iswalpha(path[4]) && path[5] == L':';
}

PathClass classify_path(const wchar_t* path) {
    if (path == NULL || path[0] == L'\0') {
        return PATH_NORMAL;
    }
    if (is_exact_pseudo(path)) {
        return PATH_PSEUDO_DEVICE;
    }
    if (starts_ci(path, L"\\\\.\\pipe\\") || starts_ci(path, L"\\\\?\\pipe\\")) {
        return PATH_NAMED_PIPE;
    }
    if (contains_ci(path, L"physicaldrive") ||
        (starts_ci(path, L"\\\\.\\harddisk") && !contains_ci(path, L"volume")) ||
        (starts_ci(path, L"\\\\?\\harddisk") && !contains_ci(path, L"volume"))) {
        return PATH_RAW_DISK;
    }
    if (contains_ci(path, L"harddiskvolume") || is_drive_device(path)) {
        return PATH_VOLUME;
    }
    if (starts_ci(path, L"\\\\.\\") || starts_ci(path, L"\\\\?\\")) {
        return PATH_OTHER_DEVICE;
    }
    return PATH_NORMAL;
}

int path_is_exempt(const wchar_t* path) {
    return classify_path(path) == PATH_PSEUDO_DEVICE;
}

const char* path_device_class(PathClass kind) {
    switch (kind) {
        case PATH_PSEUDO_DEVICE:
            return "pseudo";
        case PATH_RAW_DISK:
            return "raw_disk";
        case PATH_VOLUME:
            return "volume";
        case PATH_NAMED_PIPE:
            return "named_pipe";
        case PATH_OTHER_DEVICE:
            return "other";
        default:
            return "";
    }
}
