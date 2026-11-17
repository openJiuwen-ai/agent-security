/* MSYS/Cygwin reports unlink errors before closing its internal NT handle.
 * Use the same native disposition here, while failure can still become errno.
 * ABI: cygwin_conv_path CCP_POSIX_TO_WIN_W=1, CCP_RELATIVE=0x100;
 * Cygwin AT_FDCWD=-2, AT_REMOVEDIR=8. errno belongs to the POSIX runtime. */
static SSIZE_T (__cdecl *posix_convert)(unsigned,const void*,void*,size_t);
static intptr_t (__cdecl *posix_handle)(int);
static int *(__cdecl *posix_errno)(void);
static int (__cdecl *posix_unlink)(const char*);
static int (__cdecl *posix_rmdir)(const char*);
static int (__cdecl *posix_remove)(const char*);
static int (__cdecl *posix_unlinkat)(int,const char*,int);
static void (*posix_context)(int);
static BOOL posix_attached;
static int directory_is_empty(const wchar_t *path);
void softdelete_set_context(void (*context)(int)) { posix_context=context; }
static int posix_fail(int error) { *posix_errno()=error; return -1; }

static int posix_delete(int fd,const char *path,int directory,int choose_type) {
    wchar_t *wide=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,PATH_CAP*sizeof(wchar_t));
    if (!wide) return posix_fail(12);
    int error=0,result=-1;
    if (posix_context) posix_context(1);
    if (fd!=-2 && path && path[0]!='/') {
        HANDLE handle=(HANDLE)posix_handle(fd);
        path_from_handle(handle,wide,PATH_CAP);
        size_t length=wcslen(wide);
        if (!length || length+2>=PATH_CAP) error=9;
        else {
            wide[length++]=L'\\';
            if (posix_convert(1|0x100,path,wide+length,(PATH_CAP-length)*sizeof(wchar_t))) error=22;
        }
    } else if (posix_convert(1,path,wide,PATH_CAP*sizeof(wchar_t))) error=*posix_errno();
    if (!error) {
        DWORD attr=path_attributes(wide);
        BOOL is_directory=attr!=INVALID_FILE_ATTRIBUTES && (attr&FILE_ATTRIBUTE_DIRECTORY) && !(attr&FILE_ATTRIBUTE_REPARSE_POINT);
        if (choose_type) directory=is_directory;
        if (attr==INVALID_FILE_ATTRIBUTES) error=2;
        else if (is_directory && !directory) error=21;
        else if (!is_directory && directory) error=20;
        else if (directory && !directory_is_empty(wide)) error=90;
        else if (softdelete_exempt(wide)) result=2; /* Let the normal NT policy handle exclusions. */
        else { result=guard_recover_path(wide)?0:-1; if(result)error=13; }
    }
    DWORD last_error=GetLastError();
    if (posix_context) posix_context(0);
    HeapFree(GetProcessHeap(),0,wide);
    SetLastError(last_error);
    return error?posix_fail(error):result;
}
static int __cdecl hook_posix_unlink(const char *path) {
    if(t_bypass)return posix_unlink(path);
    int result=posix_delete(-2,path,0,0);
    return result==2?posix_unlink(path):result;
}
static int __cdecl hook_posix_rmdir(const char *path) {
    if(t_bypass)return posix_rmdir(path);
    int result=posix_delete(-2,path,1,0);
    return result==2?posix_rmdir(path):result;
}
static int __cdecl hook_posix_remove(const char *path) {
    if(t_bypass)return posix_remove(path);
    int result=posix_delete(-2,path,0,1);
    return result==2?posix_remove(path):result;
}
static int __cdecl hook_posix_unlinkat(int fd,const char *path,int flags) {
    if(t_bypass)return posix_unlinkat(fd,path,flags);
    if(flags&~8)return posix_fail(22);
    int result=posix_delete(fd,path,!!(flags&8),0);
    return result==2?posix_unlinkat(fd,path,flags):result;
}
LONG softdelete_posix_hooks(BOOL attach) {
    HMODULE module=GetModuleHandleW(L"msys-2.0.dll");
    if(!module)module=GetModuleHandleW(L"cygwin1.dll");
    if(attach) {
        if(!module)return NO_ERROR;
        posix_convert=(void*)GetProcAddress(module,"cygwin_conv_path");
        posix_handle=(void*)GetProcAddress(module,"_get_osfhandle");
        posix_errno=(void*)GetProcAddress(module,"__errno");
        posix_unlink=(void*)GetProcAddress(module,"unlink");
        posix_rmdir=(void*)GetProcAddress(module,"rmdir");
        posix_remove=(void*)GetProcAddress(module,"remove");
        posix_unlinkat=(void*)GetProcAddress(module,"unlinkat");
        if(!posix_convert||!posix_handle||!posix_errno||!posix_unlink||!posix_rmdir||!posix_remove||!posix_unlinkat)
            return ERROR_PROC_NOT_FOUND;
    } else if(!posix_attached)return NO_ERROR;
    PVOID *originals[]={(PVOID*)&posix_unlink,(PVOID*)&posix_rmdir,(PVOID*)&posix_remove,(PVOID*)&posix_unlinkat};
    PVOID hooks[]={(PVOID)hook_posix_unlink,(PVOID)hook_posix_rmdir,(PVOID)hook_posix_remove,(PVOID)hook_posix_unlinkat};
    for(size_t i=0;i<ARRAYSIZE(hooks);++i) {
        LONG status=attach?DetourAttach(originals[i],hooks[i]):DetourDetach(originals[i],hooks[i]);
        if(status)return status;
    }
    posix_attached=attach;
    return NO_ERROR;
}
