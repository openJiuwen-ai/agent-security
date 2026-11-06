#include "../src/path_classification.h"

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
    EXPECT(classify_path(L"NUL") == PATH_PSEUDO_DEVICE);
    EXPECT(classify_path(L"con") == PATH_PSEUDO_DEVICE);
    EXPECT(classify_path(L"CONIN$") == PATH_PSEUDO_DEVICE);
    EXPECT(classify_path(L"\\\\.\\NUL") == PATH_PSEUDO_DEVICE);
    EXPECT(classify_path(L"\\\\?\\CONOUT$") == PATH_PSEUDO_DEVICE);
    EXPECT(path_is_exempt(L"NUL") == 1);
    EXPECT(path_is_exempt(L"C:\\foo\\NUL") == 0);
    EXPECT(classify_path(L"C:\\foo\\NUL") == PATH_NORMAL);

    EXPECT(classify_path(L"\\\\.\\PhysicalDrive0") == PATH_RAW_DISK);
    EXPECT(strcmp(path_device_class(PATH_RAW_DISK), "raw_disk") == 0);
    EXPECT(classify_path(L"\\\\.\\Harddisk0\\DR0") == PATH_RAW_DISK);
    EXPECT(classify_path(L"\\\\.\\C:") == PATH_VOLUME);
    EXPECT(classify_path(L"\\\\.\\HarddiskVolume2") == PATH_VOLUME);
    EXPECT(classify_path(L"\\\\.\\COM1") == PATH_OTHER_DEVICE);
    EXPECT(classify_path(L"\\\\.\\pipe\\decide") == PATH_NAMED_PIPE);
    EXPECT(path_is_exempt(L"\\\\.\\pipe\\decide") == 0);
    EXPECT(path_is_exempt(L"\\\\.\\PhysicalDrive0") == 0);
    EXPECT(classify_path(L"C:\\Users\\me\\proj\\a.txt") == PATH_NORMAL);
    EXPECT(classify_path(L"") == PATH_NORMAL);
    EXPECT(classify_path(NULL) == PATH_NORMAL);

    if (g_failed != 0) {
        fprintf(stderr, "%d path classification checks failed\n", g_failed);
        return 1;
    }
    return 0;
}
