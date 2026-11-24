#include "pipe_io.h"

#include "message_framing.h"

#include <windows.h>

#include <string.h>

static DWORD time_left(DWORD start, DWORD timeout_ms) {
    DWORD used = GetTickCount() - start;
    if (used >= timeout_ms) {
        return 0;
    }
    return timeout_ms - used;
}

static int wait_io(HANDLE pipe, OVERLAPPED* overlapped, HANDLE cancel, DWORD timeout_ms, DWORD* transferred) {
    HANDLE waits[2];
    DWORD count = 1;
    DWORD result;
    waits[0] = overlapped->hEvent;
    if (cancel != NULL) {
        waits[1] = cancel;
        count = 2;
    }
    result = WaitForMultipleObjects(count, waits, FALSE, timeout_ms);
    if (result != WAIT_OBJECT_0) {
        CancelIoEx(pipe, overlapped);
        GetOverlappedResult(pipe, overlapped, transferred, TRUE);
        return 0;
    }
    if (!GetOverlappedResult(pipe, overlapped, transferred, FALSE)) {
        return 0;
    }
    return 1;
}

static int write_all(HANDLE pipe, const uint8_t* data, size_t size, HANDLE cancel, DWORD start, DWORD timeout_ms) {
    size_t done = 0;
    while (done < size) {
        OVERLAPPED overlapped;
        DWORD transferred = 0;
        DWORD left = time_left(start, timeout_ms);
        BOOL ok;
        if (left == 0) {
            return 0;
        }
        memset(&overlapped, 0, sizeof(overlapped));
        overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (overlapped.hEvent == NULL) {
            return 0;
        }
        ok = WriteFile(pipe, data + done, (DWORD)(size - done), &transferred, &overlapped);
        if (!ok && GetLastError() == ERROR_IO_PENDING) {
            ok = wait_io(pipe, &overlapped, cancel, left, &transferred);
        }
        CloseHandle(overlapped.hEvent);
        if (!ok || transferred == 0) {
            return 0;
        }
        done += transferred;
    }
    return 1;
}

static int read_exact(HANDLE pipe, uint8_t* dest, size_t size, HANDLE cancel, DWORD start, DWORD timeout_ms) {
    size_t done = 0;
    while (done < size) {
        OVERLAPPED overlapped;
        DWORD transferred = 0;
        DWORD left = time_left(start, timeout_ms);
        BOOL ok;
        if (left == 0) {
            return 0;
        }
        memset(&overlapped, 0, sizeof(overlapped));
        overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (overlapped.hEvent == NULL) {
            return 0;
        }
        ok = ReadFile(pipe, dest + done, (DWORD)(size - done), &transferred, &overlapped);
        if (!ok && GetLastError() == ERROR_IO_PENDING) {
            ok = wait_io(pipe, &overlapped, cancel, left, &transferred);
        }
        CloseHandle(overlapped.hEvent);
        if (!ok || transferred == 0) {
            return 0;
        }
        done += transferred;
    }
    return 1;
}

int pipe_write_message(void* pipe, const char* json, void* cancel, uint32_t timeout_ms) {
    uint8_t header[4];
    uint32_t length;
    DWORD start;
    if (pipe == NULL || json == NULL) {
        return 0;
    }
    length = (uint32_t)strlen(json);
    if (length == 0 || length > SANDBOX_FRAME_MAX) {
        return 0;
    }
    header[0] = (uint8_t)(length & 0xffu);
    header[1] = (uint8_t)((length >> 8) & 0xffu);
    header[2] = (uint8_t)((length >> 16) & 0xffu);
    header[3] = (uint8_t)((length >> 24) & 0xffu);
    start = GetTickCount();
    if (!write_all((HANDLE)pipe, header, 4, (HANDLE)cancel, start, timeout_ms)) {
        return 0;
    }
    return write_all((HANDLE)pipe, (const uint8_t*)json, length, (HANDLE)cancel, start, timeout_ms);
}

int pipe_read_message(void* pipe, char* dest, size_t dest_cap, void* cancel, uint32_t timeout_ms) {
    uint8_t header[4];
    uint32_t length;
    DWORD start;
    if (pipe == NULL || dest == NULL || dest_cap < 2) {
        return 0;
    }
    start = GetTickCount();
    if (!read_exact((HANDLE)pipe, header, 4, (HANDLE)cancel, start, timeout_ms)) {
        return 0;
    }
    length = (uint32_t)header[0] | ((uint32_t)header[1] << 8) | ((uint32_t)header[2] << 16) |
             ((uint32_t)header[3] << 24);
    if (length == 0 || length > SANDBOX_FRAME_MAX || (size_t)length + 1 > dest_cap) {
        return 0;
    }
    if (!read_exact((HANDLE)pipe, (uint8_t*)dest, length, (HANDLE)cancel, start, timeout_ms)) {
        return 0;
    }
    dest[length] = '\0';
    return 1;
}

int pipe_transact(
    void* pipe,
    const char* request,
    char* response,
    size_t response_cap,
    void* cancel,
    uint32_t timeout_ms) {
    if (!pipe_write_message(pipe, request, cancel, timeout_ms)) {
        return 0;
    }
    return pipe_read_message(pipe, response, response_cap, cancel, timeout_ms);
}
