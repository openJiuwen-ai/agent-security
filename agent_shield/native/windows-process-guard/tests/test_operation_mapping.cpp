#include "../src/operation_mapping.h"

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

static const uint32_t kGenericRead = 0x80000000u;
static const uint32_t kGenericWrite = 0x40000000u;
static const uint32_t kOpenExisting = 3u;
static const uint32_t kCreateAlways = 2u;

int main(void) {
    MappedOperation operation;

    EXPECT(map_create_file(L"C:\\Users\\me\\proj\\a.txt", kGenericRead, kOpenExisting, &operation) == MAP_OK);
    EXPECT(strcmp(operation.kind, "open") == 0);
    EXPECT(strcmp(operation.access, "read") == 0);
    EXPECT(operation.resource_count == 1);
    EXPECT(wcscmp(operation.resources[0].path, L"C:\\Users\\me\\proj\\a.txt") == 0);

    EXPECT(map_create_file(L"C:\\Users\\me\\proj\\a.txt", kGenericWrite, kCreateAlways, &operation) == MAP_OK);
    EXPECT(strcmp(operation.kind, "create") == 0);
    EXPECT(strcmp(operation.access, "write") == 0);

    EXPECT(map_create_file(L"NUL", kGenericRead, kOpenExisting, &operation) == MAP_EXEMPT);
    EXPECT(map_create_file(L"\\\\.\\PhysicalDrive0", kGenericWrite, kOpenExisting, &operation) == MAP_OK);
    EXPECT(strcmp(operation.kind, "device_open") == 0);
    EXPECT(strcmp(operation.access, "write") == 0);
    EXPECT(strcmp(operation.resources[0].device_class, "raw_disk") == 0);
    EXPECT(map_create_file(L"\\\\.\\COM1", kGenericRead, kOpenExisting, &operation) == MAP_OK);
    EXPECT(strcmp(operation.resources[0].device_class, "other") == 0);
    EXPECT(map_create_file(L"\\\\.\\pipe\\not-control", kGenericRead, kOpenExisting, &operation) == MAP_OK);
    EXPECT(strcmp(operation.kind, "pipe_open") == 0);

    EXPECT(map_delete_path(L"D:\\other\\a.txt", 0, &operation) == MAP_OK);
    EXPECT(strcmp(operation.kind, "delete") == 0);
    EXPECT(strcmp(operation.access, "delete") == 0);
    EXPECT(strcmp(operation.resources[0].role, "target") == 0);

    EXPECT(map_copy(L"C:\\src\\a.txt", L"D:\\dst\\b.txt", &operation) == MAP_OK);
    EXPECT(strcmp(operation.kind, "copy") == 0);
    EXPECT(operation.resource_count == 2);
    EXPECT(strcmp(operation.resources[0].role, "source") == 0);
    EXPECT(strcmp(operation.resources[1].role, "target") == 0);

    EXPECT(map_move(L"C:\\src\\a.txt", L"D:\\dst\\b.txt", &operation) == MAP_OK);
    EXPECT(strcmp(operation.kind, "move") == 0);
    EXPECT(map_replace(L"C:\\src\\a.txt", L"D:\\dst\\b.txt", L"D:\\dst\\b.bak", &operation) == MAP_OK);
    EXPECT(operation.resource_count == 3);
    EXPECT(strcmp(operation.resources[2].role, "backup") == 0);
    EXPECT(map_replace(L"C:\\src\\a.txt", L"D:\\dst\\b.txt", NULL, &operation) == MAP_OK);
    EXPECT(operation.resource_count == 2);
    EXPECT(map_link(L"C:\\src\\a.txt", L"D:\\dst\\link", 1, &operation) == MAP_OK);
    EXPECT(strcmp(operation.kind, "symlink") == 0);

    EXPECT(map_create_process(L"C:\\Program Files\\Git\\cmd\\git.exe", L"git push --force origin main", &operation) == MAP_OK);
    EXPECT(strcmp(operation.kind, "create_process") == 0);
    EXPECT(strcmp(operation.access, "execute") == 0);
    EXPECT(wcsstr(operation.command_line, L"--force") != NULL);

    EXPECT(map_shell_execute(L"C:\\Windows\\System32\\cmd.exe", L"/c echo hi", &operation) == MAP_OK);
    EXPECT(strcmp(operation.kind, "create_process") == 0);
    EXPECT(map_shell_execute(L"https://example.com", NULL, &operation) == MAP_REJECT);
    EXPECT(map_shell_execute(L"C:\\docs\\readme.txt", NULL, &operation) == MAP_REJECT);

    EXPECT(map_connect("169.254.169.254", 80, NULL, &operation) == MAP_OK);
    EXPECT(strcmp(operation.kind, "connect") == 0);
    EXPECT(operation.has_host == 0);
    EXPECT(operation.has_ip == 1);
    EXPECT(strcmp(operation.ip, "169.254.169.254") == 0);
    EXPECT(operation.port == 80);
    EXPECT(map_connect(NULL, 443, "pypi.org", &operation) == MAP_OK);
    EXPECT(operation.has_ip == 0);
    EXPECT(strcmp(operation.host, "pypi.org") == 0);
    EXPECT(map_connect(NULL, 1, NULL, &operation) == MAP_REJECT);

    EXPECT(process_guard_target_supported("x64") == 1);
    EXPECT(process_guard_target_supported("x86") == 1);
    EXPECT(process_guard_target_supported("arm64") == 0);
    EXPECT(process_guard_target_supported(NULL) == 0);

    if (g_failed != 0) {
        fprintf(stderr, "%d operation mapping checks failed\n", g_failed);
        return 1;
    }
    return 0;
}
