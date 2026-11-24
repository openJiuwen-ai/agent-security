/* One immutable execution binding owns the hooks; opens own independent leases. */
BOOL WINAPI process_guard_main(HINSTANCE module, DWORD reason, LPVOID reserved);
BOOL WINAPI softdelete_main(HINSTANCE module, DWORD reason, LPVOID reserved);
typedef struct GuardLease { struct GuardLease *next; } GuardLease;
static GuardLease *leases;
static DWORD active_capabilities, active_delete_mode;
static HINSTANCE guard_module;
static SRWLOCK lifecycle_lock = SRWLOCK_INIT;
static HANDLE automatic_lease;

static BOOL stop_shield(void) {
    if (hooks_installed) {
        guard(1);
        LONG status=DetourTransactionBegin();
        if (status) { guard(0); SetLastError(status); return FALSE; }
        status=DetourUpdateThread(GetCurrentThread());
        if (!status) status=softdelete_posix_hooks(FALSE);
        if (!status) status=configure_file_hooks(file_bindings,FALSE);
        for (size_t i=registered_hook_count; !status && i; --i)
            status=DetourDetach(registered_hooks[i-1].original,registered_hooks[i-1].handler);
        if (!status) status=DetourTransactionCommit();
        else DetourTransactionAbort();
        guard(0);
        if (status) { SetLastError(status); return FALSE; }
        hooks_installed=FALSE;
    }
    registered_hook_count=0;
    softdelete_release();
    if (cache_revoked) { CloseHandle(cache_revoked); cache_revoked=NULL; }
    ZeroMemory(allow_entries,sizeof(allow_entries));
    if (tls_slot!=TLS_OUT_OF_INDEXES) TlsFree(tls_slot);
    if (mount_query_slot!=TLS_OUT_OF_INDEXES) TlsFree(mount_query_slot);
    if (hardlink_source_slot!=TLS_OUT_OF_INDEXES) TlsFree(hardlink_source_slot);
    hardlink_source_slot=TLS_OUT_OF_INDEXES;
    if (managed_launch_slot!=TLS_OUT_OF_INDEXES) TlsFree(managed_launch_slot);
    tls_slot=mount_query_slot=managed_launch_slot=TLS_OUT_OF_INDEXES;
    query_process=NULL; query_object=NULL; query_attributes=NULL;
    ZeroMemory(&config,sizeof(config));
    return TRUE;
}

__declspec(dllexport) HANDLE guard_open(const GuardOpenConfig *options) {
    if (!options || options->size!=sizeof(*options) || !options->capabilities ||
        (options->capabilities & ~(GUARD_CAP_SHIELD|GUARD_CAP_RECOVERY)) || options->delete_mode>1 ||
        ((options->capabilities & GUARD_CAP_RECOVERY) && options->delete_mode!=GUARD_DELETE_RECOVER)) {
        SetLastError(ERROR_INVALID_PARAMETER); return NULL;
    }
    if ((options->capabilities & GUARD_CAP_SHIELD) && (!options->session ||
        options->session->magic!=0x44474333 || options->session->permanent!=options->delete_mode ||
        !options->session->pipe[0] || options->session->pipe[255] ||
        !options->session->ready[0] || options->session->ready[255])) {
        SetLastError(ERROR_INVALID_PARAMETER); return NULL;
    }
    GuardLease *lease=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(*lease));
    if (!lease) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; }
    AcquireSRWLockExclusive(&lifecycle_lock);
    BOOL ok=TRUE;
    if (leases && (options->delete_mode!=active_delete_mode ||
        (options->capabilities & ~active_capabilities) ||
        ((options->capabilities & GUARD_CAP_SHIELD) && memcmp(options->session,&config,sizeof(config))))) {
        SetLastError(ERROR_INVALID_STATE); ok=FALSE;
    }
    if (ok) {
        ok=configure_recovery_config(options->archive_directory,options->broker_port,options->broker_token,options->result_file);
        if (ok && !leases) ok=prepare_result_stream();
        if (!ok && !leases) softdelete_release();
    }
    if (ok && !leases) {
        if (options->capabilities & GUARD_CAP_SHIELD) {
            config=*options->session;
            ok=install();
            if (!ok) { DWORD error=GetLastError(); stop_shield(); SetLastError(error); }
        }
        else ok=softdelete_main(guard_module,DLL_PROCESS_ATTACH,NULL);
        if (ok) { active_capabilities=options->capabilities; active_delete_mode=options->delete_mode; }
        else softdelete_release();
    }
    DWORD error=GetLastError();
    if (ok) { lease->next=leases; leases=lease; }
    ReleaseSRWLockExclusive(&lifecycle_lock);
    if (!ok) { HeapFree(GetProcessHeap(),0,lease); SetLastError(error?error:ERROR_DLL_INIT_FAILED); return NULL; }
    return lease;
}

__declspec(dllexport) BOOL guard_close(HANDLE handle) {
    AcquireSRWLockExclusive(&lifecycle_lock);
    GuardLease **slot=&leases;
    while (*slot && *slot!=handle) slot=&(*slot)->next;
    if (!*slot) { ReleaseSRWLockExclusive(&lifecycle_lock); SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    BOOL ok=TRUE;
    if (leases==*slot && !leases->next) {
        if (active_capabilities & GUARD_CAP_SHIELD) ok=stop_shield();
        else ok=softdelete_main(guard_module,DLL_PROCESS_DETACH,NULL);
        if (ok) active_capabilities=active_delete_mode=0;
    }
    if (ok) { GuardLease *lease=*slot; *slot=lease->next; HeapFree(GetProcessHeap(),0,lease); }
    DWORD error=GetLastError();
    ReleaseSRWLockExclusive(&lifecycle_lock);
    SetLastError(error);
    return ok;
}

BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID reserved) {
    if (reason==DLL_PROCESS_ATTACH) {
        if (DetourIsHelperProcess()) return TRUE;
        DetourRestoreAfterWith();
        guard_module=module;
        if (!GetModuleFileNameW(module,self_path,1024) || lstrlenW(self_path)>=1023) return FALSE;
        GuardOpenConfig options={sizeof(options),0,GUARD_DELETE_RECOVER,NULL,NULL,NULL,NULL};
        if (runtime_config_present()) {
            options.capabilities=GUARD_CAP_SHIELD|(config.permanent?0:GUARD_CAP_RECOVERY);
            options.delete_mode=config.permanent;
            options.session=&config;
        } else {
            /* Recovery import preparation carries its immutable binding.
               Ordinary broker/installer LoadLibrary mappings remain inert. */
            DWORD size=0;
            const GuardRecoveryBootstrap *bootstrap=DetourFindPayloadEx(&guard_recovery_bootstrap_guid,&size);
            if (!bootstrap) {
                WCHAR mapping[96];
                swprintf_s(mapping, ARRAYSIZE(mapping), L"Local\\agent-security-%lu", GetCurrentProcessId());
                HANDLE startup=OpenFileMappingW(FILE_MAP_READ,FALSE,mapping);
                if (startup) {
                    CloseHandle(startup);
                    return process_guard_main(module,reason,reserved);
                }
            }
            if (!reserved && (!bootstrap || size!=sizeof(*bootstrap) || bootstrap->magic!=GUARD_RECOVERY_BOOTSTRAP))
                return TRUE;
            WCHAR enabled[2];
            if (bootstrap && size==sizeof(*bootstrap) && bootstrap->magic==GUARD_RECOVERY_BOOTSTRAP &&
                !bootstrap->archive[32767] && !bootstrap->port[15] && !bootstrap->token[255] && !bootstrap->result_file[32767]) {
                options.archive_directory=bootstrap->archive;
                options.broker_port=bootstrap->port;
                options.broker_token=bootstrap->token;
                options.result_file=bootstrap->result_file;
            } else if (GetEnvironmentVariableW(L"JIUWENBOX_SOFT_DELETE",enabled,2)!=1 || enabled[0]!=L'1') return FALSE;
            options.capabilities=GUARD_CAP_RECOVERY;
        }
        automatic_lease=guard_open(&options);
        return automatic_lease!=NULL;
    }
    if (reason==DLL_PROCESS_DETACH && !reserved) {
        /* Explicit owners must close before FreeLibrary. The import owner is automatic. */
        if (automatic_lease) { guard_close(automatic_lease); automatic_lease=NULL; }
    }
    return TRUE;
}
