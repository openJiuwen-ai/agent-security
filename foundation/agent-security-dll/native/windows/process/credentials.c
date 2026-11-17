/* Credential-based Win32 creation may be delegated to a Windows service.
 * Keep the returned child suspended until it joins the owning Guard Job. */
static BOOL (WINAPI *original_token_process)(HANDLE,DWORD,LPCWSTR,LPWSTR,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);
static BOOL (WINAPI *original_logon_process)(LPCWSTR,LPCWSTR,LPCWSTR,DWORD,LPCWSTR,LPWSTR,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);

typedef struct ServiceLaunch {
    WCHAR directory[GUARD_PATH_CHARS];
    WCHAR *environment;
} ServiceLaunch;

static BOOL begin_service_launch(ServiceLaunch *launch,LPVOID environment,DWORD flags,LPCWSTR directory) {
    launch->environment=NULL;
    if(directory) {
        if(!capture_absolute_path(directory,launch->directory))return FALSE;
    } else {
        DWORD count=GetCurrentDirectoryW(ARRAYSIZE(launch->directory),launch->directory);
        if(!count || count>=ARRAYSIZE(launch->directory))return FALSE;
    }
    guard(1);
    if(recover_enabled && !recovery_child_environment(environment,flags,&launch->environment)) {
        guard(0);SetLastError(ERROR_BAD_ENVIRONMENT);return FALSE;
    }
    if(!TlsSetValue(managed_launch_slot,(void*)1)) {
        HeapFree(GetProcessHeap(),0,launch->environment);guard(0);return FALSE;
    }
    return TRUE;
}

static BOOL finish_service_launch(ServiceLaunch *launch,BOOL ok,LPPROCESS_INFORMATION process,DWORD flags) {
    DWORD error=GetLastError();
    TlsSetValue(managed_launch_slot,NULL);
    HeapFree(GetProcessHeap(),0,launch->environment);
    if(ok) {
        ok=finish_child(process,launch->directory,flags);
        error=GetLastError();
    }
    guard(0);SetLastError(error);
    return ok;
}

static BOOL WINAPI hook_token_process(HANDLE token,DWORD logon,LPCWSTR app,LPWSTR command,DWORD flags,
                                     LPVOID environment,LPCWSTR directory,LPSTARTUPINFOW startup,LPPROCESS_INFORMATION process) {
    if(busy())return original_token_process(token,logon,app,command,flags,environment,directory,startup,process);
    ServiceLaunch launch;
    if(!begin_service_launch(&launch,environment,flags,directory))return FALSE;
    BOOL ok=original_token_process(token,logon,app,command,
        flags|CREATE_SUSPENDED|(launch.environment?CREATE_UNICODE_ENVIRONMENT:0),
        launch.environment?launch.environment:environment,launch.directory,startup,process);
    return finish_service_launch(&launch,ok,process,flags);
}
static BOOL WINAPI hook_logon_process(LPCWSTR user,LPCWSTR domain,LPCWSTR password,DWORD logon,
                                     LPCWSTR app,LPWSTR command,DWORD flags,LPVOID environment,LPCWSTR directory,
                                     LPSTARTUPINFOW startup,LPPROCESS_INFORMATION process) {
    if(busy())return original_logon_process(user,domain,password,logon,app,command,flags,environment,directory,startup,process);
    ServiceLaunch launch;
    if(!begin_service_launch(&launch,environment,flags,directory))return FALSE;
    BOOL ok=original_logon_process(user,domain,password,logon,app,command,
        flags|CREATE_SUSPENDED|(launch.environment?CREATE_UNICODE_ENVIRONMENT:0),
        launch.environment?launch.environment:environment,launch.directory,startup,process);
    return finish_service_launch(&launch,ok,process,flags);
}
static LONG install_credential_hooks(void) {
    HMODULE module=GetModuleHandleW(L"advapi32.dll");
    LONG status=guard_attach(GetProcAddress(module,"CreateProcessWithTokenW"),
        hook_token_process,(PVOID*)&original_token_process);
    if(!status)status=guard_attach(GetProcAddress(module,"CreateProcessWithLogonW"),
        hook_logon_process,(PVOID*)&original_logon_process);
    return status;
}
