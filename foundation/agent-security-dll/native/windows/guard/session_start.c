/* Detours' helper runs the import update at the target architecture. The
 * target stays suspended until its owning Guard resumes it. */
static const GUID session_config_guid =
    {0x94b454e7,0x31e6,0x44d5,{0x91,0xfa,0x41,0x9f,0x8f,0x22,0x59,0x01}};

BOOL prepare_packaged_guard(HANDLE process) {
    char architecture[8], current[8], dll[4096];
    wchar_t path[1024], *separator;
    if (!guard_process_architecture(process, architecture, sizeof(architecture)) ||
        !guard_process_architecture(GetCurrentProcess(), current, sizeof(current))) {
        SetLastError(ERROR_EXE_MACHINE_TYPE_MISMATCH);
        return FALSE;
    }
    wcscpy_s(path, 1024, self_path);
    separator = wcsrchr(path, L'\\');
    if (!separator) { SetLastError(ERROR_BAD_PATHNAME); return FALSE; }
    *separator = 0;
    separator = wcsrchr(path, L'\\');
    if (!separator) { SetLastError(ERROR_BAD_PATHNAME); return FALSE; }
    *separator = 0;
    if (wcscat_s(path, 1024, !strcmp(architecture,"x86")
            ? L"\\x86\\agent_security_guard.dll" : L"\\x64\\agent_security_guard.dll")) return FALSE;
    BOOL substituted = FALSE;
    UINT page = GetACP();
    DWORD flags = page == CP_UTF8 ? WC_ERR_INVALID_CHARS : WC_NO_BEST_FIT_CHARS;
    BOOL *used_default = page == CP_UTF8 ? NULL : &substituted;
    if (!WideCharToMultiByte(page, flags, path, -1, dll, sizeof(dll), NULL, used_default)) return FALSE;
    if (substituted) {
        /* Preserve recovery under install paths outside the system code page. */
        wchar_t short_path[1024];
        DWORD length = GetShortPathNameW(path, short_path, ARRAYSIZE(short_path));
        substituted = FALSE;
        if (!length || length >= ARRAYSIZE(short_path) ||
            !WideCharToMultiByte(page, flags, short_path, -1, dll, sizeof(dll), NULL, used_default) || substituted) {
            SetLastError(ERROR_NO_UNICODE_TRANSLATION);
            return FALSE;
        }
    }
    LPCSTR libraries[] = {dll};
    if (!strcmp(current, architecture))
        return DetourUpdateProcessWithDll(process, libraries, 1);
    /* The helper belongs to this launch, so the native process floor must
     * allow its creation while application code remains blocked. */
    void *previous = query_process ? TlsGetValue(managed_launch_slot) : NULL;
    if (query_process && !TlsSetValue(managed_launch_slot, (void *)1)) return FALSE;
    BOOL result = DetourProcessViaHelperW(GetProcessId(process), dll, CreateProcessW);
    DWORD error = GetLastError();
    if (query_process) TlsSetValue(managed_launch_slot, previous);
    SetLastError(error);
    return result;
}

static BOOL prepare_session_process(HANDLE process, const struct Config *binding) {
    if (!DetourCopyPayloadToProcess(process, &session_config_guid, (PVOID)binding, sizeof(*binding)))
        return FALSE;
    return prepare_packaged_guard(process);
}

__declspec(dllexport) BOOL guard_prepare_session(HANDLE process, const void *binding, DWORD size) {
    if (!binding || size != sizeof(struct Config)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    struct Config copy;
    memcpy(&copy, binding, sizeof(copy));
    if (copy.magic != 0x44474333 || copy.permanent > 1 ||
        !copy.pipe[0] || !copy.ready[0] || copy.pipe[255] || copy.ready[255]) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    return prepare_session_process(process, &copy);
}
