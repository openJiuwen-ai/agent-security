/* Keep shell launch within the same process tree and reject delegated verbs. */
static HINSTANCE (WINAPI *original_shell_w)(HWND,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,INT);
static HINSTANCE (WINAPI *original_shell_a)(HWND,LPCSTR,LPCSTR,LPCSTR,LPCSTR,INT);
static BOOL (WINAPI *original_shell_ex_w)(SHELLEXECUTEINFOW *);
static BOOL (WINAPI *original_shell_ex_a)(SHELLEXECUTEINFOA *);

static BOOL shell_launch(LPCWSTR verb, LPCWSTR file, LPCWSTR args, LPCWSTR directory,
                         PROCESS_INFORMATION *process) {
    if (!file || !*file || (verb && *verb && _wcsicmp(verb,L"open"))) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    size_t count = wcslen(file) + (args ? wcslen(args) : 0) + 5;
    if (count > 32768 || wcschr(file,L'"')) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    WCHAR *command = HeapAlloc(GetProcessHeap(), 0, count * sizeof(WCHAR));
    if (!command) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    swprintf_s(command,count,L"\"%s\" %s",file,args ? args : L"");
    STARTUPINFOW startup = {.cb=sizeof(startup)};
    BOOL ok = CreateProcessW(file,command,NULL,NULL,FALSE,0,NULL,directory,&startup,process);
    DWORD error = GetLastError();
    HeapFree(GetProcessHeap(),0,command);
    SetLastError(error);
    return ok;
}

static BOOL WINAPI hook_shell_ex_w(SHELLEXECUTEINFOW *info) {
    if (busy()) return original_shell_ex_w(info);
    if (!info || info->cbSize != sizeof(*info) || info->lpIDList ||
        (info->fMask & (SEE_MASK_IDLIST | SEE_MASK_CLASSNAME))) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    PROCESS_INFORMATION process = {0};
    if (!shell_launch(info->lpVerb,info->lpFile,info->lpParameters,info->lpDirectory,&process))
        return FALSE;
    if (info->fMask & SEE_MASK_NOCLOSEPROCESS) info->hProcess = process.hProcess;
    else CloseHandle(process.hProcess);
    CloseHandle(process.hThread);
    info->hInstApp = (HINSTANCE)(ULONG_PTR)33;
    return TRUE;
}

static WCHAR *shell_wide(LPCSTR text) {
    if (!text) return NULL;
    int count = MultiByteToWideChar(CP_ACP,MB_ERR_INVALID_CHARS,text,-1,NULL,0);
    if (!count) return NULL;
    WCHAR *wide = HeapAlloc(GetProcessHeap(),0,(size_t)count*sizeof(WCHAR));
    if (wide && !MultiByteToWideChar(CP_ACP,MB_ERR_INVALID_CHARS,text,-1,wide,count)) {
        HeapFree(GetProcessHeap(),0,wide);
        return NULL;
    }
    return wide;
}

static BOOL WINAPI hook_shell_ex_a(SHELLEXECUTEINFOA *info) {
    if (busy()) return original_shell_ex_a(info);
    if (!info || info->cbSize != sizeof(*info) || info->lpIDList ||
        (info->fMask & (SEE_MASK_IDLIST | SEE_MASK_CLASSNAME))) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    WCHAR *verb=shell_wide(info->lpVerb), *file=shell_wide(info->lpFile);
    WCHAR *args=shell_wide(info->lpParameters), *directory=shell_wide(info->lpDirectory);
    BOOL valid=file && (!info->lpVerb || verb) && (!info->lpParameters || args)
        && (!info->lpDirectory || directory);
    SHELLEXECUTEINFOW wide={.cbSize=sizeof(wide),.fMask=info->fMask,
        .lpVerb=verb,.lpFile=file,.lpParameters=args,.lpDirectory=directory};
    BOOL ok=valid && hook_shell_ex_w(&wide);
    DWORD error=GetLastError();
    HeapFree(GetProcessHeap(),0,verb); HeapFree(GetProcessHeap(),0,file);
    HeapFree(GetProcessHeap(),0,args); HeapFree(GetProcessHeap(),0,directory);
    info->hProcess=wide.hProcess; info->hInstApp=wide.hInstApp;
    SetLastError(ok ? error : ERROR_ACCESS_DENIED);
    return ok;
}

static HINSTANCE WINAPI hook_shell_w(HWND window,LPCWSTR verb,LPCWSTR file,LPCWSTR args,LPCWSTR directory,INT show) {
    if (busy()) return original_shell_w(window,verb,file,args,directory,show);
    SHELLEXECUTEINFOW info={.cbSize=sizeof(info),.lpVerb=verb,.lpFile=file,
        .lpParameters=args,.lpDirectory=directory};
    return hook_shell_ex_w(&info) ? info.hInstApp : (HINSTANCE)(ULONG_PTR)SE_ERR_ACCESSDENIED;
}
static HINSTANCE WINAPI hook_shell_a(HWND window,LPCSTR verb,LPCSTR file,LPCSTR args,LPCSTR directory,INT show) {
    if (busy()) return original_shell_a(window,verb,file,args,directory,show);
    SHELLEXECUTEINFOA info={.cbSize=sizeof(info),.lpVerb=verb,.lpFile=file,
        .lpParameters=args,.lpDirectory=directory};
    return hook_shell_ex_a(&info) ? info.hInstApp : (HINSTANCE)(ULONG_PTR)SE_ERR_ACCESSDENIED;
}
static LONG install_shell_hooks(void) {
    HMODULE module=GetModuleHandleW(L"shell32.dll");
    LONG status=guard_attach(GetProcAddress(module,"ShellExecuteW"),hook_shell_w,(PVOID*)&original_shell_w);
    if(!status)status=guard_attach(GetProcAddress(module,"ShellExecuteA"),hook_shell_a,(PVOID*)&original_shell_a);
    if(!status)status=guard_attach(GetProcAddress(module,"ShellExecuteExW"),hook_shell_ex_w,(PVOID*)&original_shell_ex_w);
    if(!status)status=guard_attach(GetProcAddress(module,"ShellExecuteExA"),hook_shell_ex_a,(PVOID*)&original_shell_ex_a);
    return status;
}
