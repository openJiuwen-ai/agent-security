/* WinHTTP and WinINet connection handles identify a server before any socket
 * or HTTP request exists. Keep credentials outside the policy message. */
__declspec(dllimport) HINTERNET WINAPI InternetConnectW(HINTERNET, LPCWSTR, INTERNET_PORT,
    LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
__declspec(dllimport) HINTERNET WINAPI InternetConnectA(HINTERNET, LPCSTR, INTERNET_PORT,
    LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
static HINTERNET (WINAPI *original_internet_connect_w)(HINTERNET, LPCWSTR, INTERNET_PORT,
    LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
static HINTERNET (WINAPI *original_internet_connect_a)(HINTERNET, LPCSTR, INTERNET_PORT,
    LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);

static int capture_server_w(WCHAR dest[256], LPCWSTR source) {
    if (!source) return 0;
    __try {
        size_t length = wcsnlen(source, 256);
        if (!length || length == 256) return 0;
        memcpy(dest, source, length * sizeof(WCHAR));
        dest[length] = 0;
        return !wmemchr(dest, 0, length);
    } __except(EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

static int capture_server_a(char dest[1024], LPCSTR source) {
    if (!source) return 0;
    __try {
        size_t length = strnlen(source, 1024);
        if (!length || length == 1024) return 0;
        memcpy(dest, source, length);
        dest[length] = 0;
        return !memchr(dest, 0, length);
    } __except(EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

static int approve_connection_handle(LPCWSTR server, INTERNET_PORT port) {
    WCHAR number[8];
    if (!server || !*server) return 0;
    wsprintfW(number, L"%u", (unsigned)port);
    guard(1);
    int allowed = decide_pair(44, server, number);
    guard(0);
    if (!allowed) SetLastError(ERROR_ACCESS_DENIED);
    return allowed;
}

static HINTERNET WINAPI hook_internet_connect_w(HINTERNET session, LPCWSTR server, INTERNET_PORT port,
    LPCWSTR user, LPCWSTR password, DWORD service, DWORD flags, DWORD_PTR context) {
    if (busy()) return original_internet_connect_w(session, server, port, user, password, service, flags, context);
    WCHAR host[256];
    if (!capture_server_w(host, server) || !approve_connection_handle(host, port)) {
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    }
    return original_internet_connect_w(session, host, port, user, password, service, flags, context);
}

static HINTERNET WINAPI hook_internet_connect_a(HINTERNET session, LPCSTR server, INTERNET_PORT port,
    LPCSTR user, LPCSTR password, DWORD service, DWORD flags, DWORD_PTR context) {
    if (busy()) return original_internet_connect_a(session, server, port, user, password, service, flags, context);
    char host[1024];
    WCHAR wide[256];
    if (!capture_server_a(host, server) ||
        !MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, host, -1, wide, ARRAYSIZE(wide)) ||
        !approve_connection_handle(wide, port)) {
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    }
    return original_internet_connect_a(session, host, port, user, password, service, flags, context);
}
