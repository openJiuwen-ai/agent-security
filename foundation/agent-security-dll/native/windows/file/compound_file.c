/* Included by guard.c. Keep the Win32 operation's roles through policy review.
 * Lower-level checks remain active during the real call, including recovery. */
static BOOL (WINAPI *original_copy)(LPCWSTR, LPCWSTR, BOOL);
static BOOL (WINAPI *original_copy_ex)(LPCWSTR, LPCWSTR, LPPROGRESS_ROUTINE, LPVOID, LPBOOL, DWORD);
static BOOL (WINAPI *original_move_ex)(LPCWSTR, LPCWSTR, DWORD);
static BOOL (WINAPI *original_replace)(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, LPVOID, LPVOID);
static BOOL (WINAPI *original_copy_a)(LPCSTR, LPCSTR, BOOL);
static BOOL (WINAPI *original_copy_ex_a)(LPCSTR, LPCSTR, LPPROGRESS_ROUTINE, LPVOID, LPBOOL, DWORD);
static BOOL (WINAPI *original_replace_a)(LPCSTR, LPCSTR, LPCSTR, DWORD, LPVOID, LPVOID);
static BOOLEAN (WINAPI *original_symlink_w)(LPCWSTR, LPCWSTR, DWORD);
static BOOLEAN (WINAPI *original_symlink_a)(LPCSTR, LPCSTR, DWORD);
static BOOL (WINAPI *original_hardlink_w)(LPCWSTR, LPCWSTR, LPSECURITY_ATTRIBUTES);
static BOOL (WINAPI *original_hardlink_a)(LPCSTR, LPCSTR, LPSECURITY_ATTRIBUTES);
static DWORD hardlink_source_slot = TLS_OUT_OF_INDEXES;

static BOOL hardlink_metadata_open(LPCWSTR path, ACCESS_MASK access, ULONG disp, ULONG options) {
    LPCWSTR source = TlsGetValue(hardlink_source_slot);
    if (!source || disp != 1 || (options & (FILE_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE)) ||
        !(access & FILE_WRITE_ATTRIBUTES) || (access & ~(FILE_WRITE_ATTRIBUTES | SYNCHRONIZE)))
        return FALSE;
    if (wcsncmp(path, L"\\??\\", 4)) return FALSE;
    path += 4;
    if (!wcsncmp(source, L"\\\\?\\", 4)) source += 4;
    else if (!wcsncmp(source, L"\\\\", 2) && !_wcsnicmp(path, L"UNC\\", 4))
        return !wcscmp(source + 2, path + 4);
    return !wcscmp(source, path);
}

static BOOL capture_absolute_path(LPCWSTR input, WCHAR output[GUARD_PATH_CHARS]) {
    WCHAR captured[GUARD_PATH_CHARS];
    __try {
        size_t length = wcsnlen(input, ARRAYSIZE(captured));
        if (!length || length >= ARRAYSIZE(captured)) return FALSE;
        memcpy(captured, input, length * sizeof(WCHAR));
        captured[length] = 0;
        if (wmemchr(captured, 0, length)) return FALSE;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    DWORD count = GetFullPathNameW(captured, GUARD_PATH_CHARS, output, NULL);
    return count > 0 && count < GUARD_PATH_CHARS;
}

static BOOL approve_compound(DWORD action_code, LPCWSTR source, LPCWSTR target, LPCWSTR backup,
                             WCHAR paths[3][GUARD_PATH_CHARS]) {
    LPCWSTR fields[] = {paths[0], paths[1], paths[2]};
    guard(1);
    BOOL ok = capture_absolute_path(source, paths[0]) && capture_absolute_path(target, paths[1])
        && (!backup || capture_absolute_path(backup, paths[2]))
        && decide_fields(action_code, fields, backup ? 3 : 2);
    guard(0);
    if (!ok) SetLastError(ERROR_ACCESS_DENIED);
    return ok;
}

static BOOL WINAPI hook_copy(LPCWSTR source, LPCWSTR target, BOOL exclusive) {
    if (busy()) return original_copy(source, target, exclusive);
    WCHAR paths[3][GUARD_PATH_CHARS];
    return approve_compound(18, source, target, NULL, paths) && original_copy(paths[0], paths[1], exclusive);
}

static BOOL WINAPI hook_copy_ex(LPCWSTR source, LPCWSTR target, LPPROGRESS_ROUTINE progress,
                                LPVOID context, LPBOOL cancel, DWORD flags) {
    if (busy()) return original_copy_ex(source, target, progress, context, cancel, flags);
    WCHAR paths[3][GUARD_PATH_CHARS];
    return approve_compound(18, source, target, NULL, paths)
        && original_copy_ex(paths[0], paths[1], progress, context, cancel, flags);
}

static BOOL WINAPI hook_move_ex(LPCWSTR source, LPCWSTR target, DWORD flags) {
    if (busy() || !source || !target || (flags & MOVEFILE_DELAY_UNTIL_REBOOT))
        return original_move_ex(source, target, flags);
    WCHAR from[GUARD_PATH_CHARS], to[GUARD_PATH_CHARS];
    GuardDeleteScope *scope = NULL;
    guard(1);
    BOOL allowed = capture_absolute_path(source, from) && capture_absolute_path(target, to);
    if (allowed) {
        if ((flags & MOVEFILE_REPLACE_EXISTING) && _wcsicmp(from, to) != 0) {
            scope = guard_begin_replace(from, to, NULL, 2);
            allowed = scope != NULL;
        } else {
            allowed = decide_pair(16, from, to);
        }
    }
    guard(0);
    if (!allowed) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }

    BOOL moved = original_move_ex(from, to, flags);
    if (!scope) return moved;
    DWORD error = moved ? ERROR_SUCCESS : GetLastError();
    guard(1);
    moved = guard_finish_replace(scope, NULL, moved ? 0 : -1, error);
    error = GetLastError();
    guard(0);
    SetLastError(error);
    return moved;
}

static BOOL WINAPI hook_replace(LPCWSTR target, LPCWSTR source, LPCWSTR backup, DWORD flags,
                                LPVOID exclude, LPVOID reserved) {
    if (busy()) return original_replace(target, source, backup, flags, exclude, reserved);
    WCHAR paths[3][GUARD_PATH_CHARS];
    guard(1);
    BOOL captured=capture_absolute_path(source,paths[0]) && capture_absolute_path(target,paths[1])
        && (!backup || capture_absolute_path(backup,paths[2]));
    GuardDeleteScope *scope=captured?guard_begin_replace(paths[0],paths[1],backup?paths[2]:NULL,3):NULL;
    guard(0);
    if(!scope) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
    BOOL ok=original_replace(paths[1],paths[0],backup?paths[2]:NULL,flags,exclude,reserved);
    DWORD error=ok?ERROR_SUCCESS:GetLastError();
    guard(1);
    ok=guard_finish_replace(scope,backup?paths[2]:NULL,ok?0:-1,error);
    DWORD final_error=GetLastError();
    guard(0);
    SetLastError(final_error);
    return ok;
}

static BOOL capture_ansi_path(UINT page, LPCSTR input, WCHAR output[GUARD_PATH_CHARS]) {
    __try {
        return MultiByteToWideChar(page, MB_ERR_INVALID_CHARS, input, -1, output, GUARD_PATH_CHARS) != 0;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
}

static BOOL WINAPI hook_copy_a(LPCSTR source, LPCSTR target, BOOL exclusive) {
    if (busy()) return original_copy_a(source, target, exclusive);
    WCHAR wide_source[GUARD_PATH_CHARS], wide_target[GUARD_PATH_CHARS];
    UINT page = AreFileApisANSI() ? CP_ACP : CP_OEMCP;
    return capture_ansi_path(page, source, wide_source) && capture_ansi_path(page, target, wide_target)
        && hook_copy(wide_source, wide_target, exclusive);
}

static BOOL WINAPI hook_copy_ex_a(LPCSTR source, LPCSTR target, LPPROGRESS_ROUTINE progress,
                                  LPVOID context, LPBOOL cancel, DWORD flags) {
    if (busy()) return original_copy_ex_a(source, target, progress, context, cancel, flags);
    WCHAR wide_source[GUARD_PATH_CHARS], wide_target[GUARD_PATH_CHARS];
    UINT page = AreFileApisANSI() ? CP_ACP : CP_OEMCP;
    return capture_ansi_path(page, source, wide_source) && capture_ansi_path(page, target, wide_target)
        && hook_copy_ex(wide_source, wide_target, progress, context, cancel, flags);
}

static BOOL WINAPI hook_replace_a(LPCSTR target, LPCSTR source, LPCSTR backup, DWORD flags,
                                  LPVOID exclude, LPVOID reserved) {
    if (busy()) return original_replace_a(target, source, backup, flags, exclude, reserved);
    WCHAR wide_source[GUARD_PATH_CHARS], wide_target[GUARD_PATH_CHARS], wide_backup[GUARD_PATH_CHARS];
    UINT page = AreFileApisANSI() ? CP_ACP : CP_OEMCP;
    return capture_ansi_path(page, source, wide_source) && capture_ansi_path(page, target, wide_target)
        && (!backup || capture_ansi_path(page, backup, wide_backup))
        && hook_replace(wide_target, wide_source, backup ? wide_backup : NULL, flags, exclude, reserved);
}

static BOOLEAN WINAPI hook_symlink_w(LPCWSTR link, LPCWSTR target, DWORD flags) {
    if (busy()) return original_symlink_w(link, target, flags);
    WCHAR link_path[GUARD_PATH_CHARS], target_text[GUARD_PATH_CHARS], source[GUARD_PATH_CHARS];
    size_t length = 0;
    __try {
        if (target) length = wcsnlen(target, ARRAYSIZE(target_text));
        if (length && length < ARRAYSIZE(target_text)) {
            memcpy(target_text, target, length * sizeof(WCHAR));
            target_text[length] = 0;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) { length = 0; }
    if (!length || length >= ARRAYSIZE(target_text) || !capture_absolute_path(link, link_path)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    LPCWSTR stored = target_text;
    if (target_text[0] == L'\\' || target_text[0] == L'/' || target_text[1] == L':') {
        if (!capture_absolute_path(target_text, source)) return FALSE;
        stored = source;
    } else {
        /* Windows resolves a relative target from the directory containing the link. */
        wcscpy_s(source, ARRAYSIZE(source), link_path);
        WCHAR *slash = wcsrchr(source, L'\\');
        if (!slash || (size_t)(slash + 1 - source) + length >= ARRAYSIZE(source)) {
            SetLastError(ERROR_FILENAME_EXCED_RANGE);
            return FALSE;
        }
        wcscpy_s(slash + 1, ARRAYSIZE(source) - (size_t)(slash + 1 - source), target_text);
    }
    guard(1);
    int allowed = decide_pair(19, source, link_path);
    guard(0);
    if (!allowed) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
    return original_symlink_w(link_path, stored, flags);
}

static BOOLEAN WINAPI hook_symlink_a(LPCSTR link, LPCSTR target, DWORD flags) {
    if (busy()) return original_symlink_a(link, target, flags);
    WCHAR wide_link[GUARD_PATH_CHARS], wide_target[GUARD_PATH_CHARS];
    UINT page = AreFileApisANSI() ? CP_ACP : CP_OEMCP;
    return capture_ansi_path(page, link, wide_link) && capture_ansi_path(page, target, wide_target)
        && hook_symlink_w(wide_link, wide_target, flags);
}

static BOOL WINAPI hook_hardlink_w(LPCWSTR link, LPCWSTR source, LPSECURITY_ATTRIBUTES security) {
    if (busy()) return original_hardlink_w(link, source, security);
    WCHAR full_source[GUARD_PATH_CHARS], full_link[GUARD_PATH_CHARS];
    if (!capture_absolute_path(source, full_source) || !capture_absolute_path(link, full_link)) {
        SetLastError(ERROR_INVALID_NAME);
        return FALSE;
    }
    void *previous = TlsGetValue(hardlink_source_slot);
    if (!TlsSetValue(hardlink_source_slot, full_source)) return FALSE;
    BOOL ok = FALSE;
    __try {
        ok = original_hardlink_w(full_link, full_source, security);
    } __finally {
        DWORD error = GetLastError();
        TlsSetValue(hardlink_source_slot, previous);
        SetLastError(error);
    }
    return ok;
}

static BOOL WINAPI hook_hardlink_a(LPCSTR link, LPCSTR source, LPSECURITY_ATTRIBUTES security) {
    if (busy()) return original_hardlink_a(link, source, security);
    WCHAR wide_link[GUARD_PATH_CHARS], wide_source[GUARD_PATH_CHARS];
    UINT page = AreFileApisANSI() ? CP_ACP : CP_OEMCP;
    return capture_ansi_path(page, link, wide_link) && capture_ansi_path(page, source, wide_source)
        && hook_hardlink_w(wide_link, wide_source, security);
}

static LONG install_compound_file_hooks(HMODULE kernel) {
    LONG status = guard_attach(GetProcAddress(kernel, "CopyFileW"), hook_copy, (PVOID *)&original_copy);
    if (!status) status = guard_attach(GetProcAddress(kernel, "CopyFileExW"), hook_copy_ex, (PVOID *)&original_copy_ex);
    if (!status) status = guard_attach(GetProcAddress(kernel, "MoveFileExW"), hook_move_ex, (PVOID *)&original_move_ex);
    if (!status) status = guard_attach(GetProcAddress(kernel, "ReplaceFileW"), hook_replace, (PVOID *)&original_replace);
    if (!status) status = guard_attach(GetProcAddress(kernel, "CopyFileA"), hook_copy_a, (PVOID *)&original_copy_a);
    if (!status) status = guard_attach(GetProcAddress(kernel, "CopyFileExA"), hook_copy_ex_a, (PVOID *)&original_copy_ex_a);
    if (!status) status = guard_attach(GetProcAddress(kernel, "ReplaceFileA"), hook_replace_a, (PVOID *)&original_replace_a);
    if (!status) status = guard_attach(GetProcAddress(kernel, "CreateSymbolicLinkW"), hook_symlink_w, (PVOID *)&original_symlink_w);
    if (!status) status = guard_attach(GetProcAddress(kernel, "CreateSymbolicLinkA"), hook_symlink_a, (PVOID *)&original_symlink_a);
    if (!status) status = guard_attach(GetProcAddress(kernel, "CreateHardLinkW"), hook_hardlink_w, (PVOID *)&original_hardlink_w);
    if (!status) status = guard_attach(GetProcAddress(kernel, "CreateHardLinkA"), hook_hardlink_a, (PVOID *)&original_hardlink_a);
    return status;
}
