/* Windows x64 file, process and network runtime Guard.
 * Supported APIs and user-mode isolation limits are documented in README.md. */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0603
#endif
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
#include <winternl.h>
#include <winhttp.h>
#include <windns.h>
#include <wchar.h>
#include "detours.h"
#include "file_name_snapshot.c"

/* Import-table injection establishes the child runtime and IPC protocol.
 * Detours installs API hooks in a single transaction. */
/* Detours represents code addresses as PVOID on Windows. */
#define guard_attach(target, hook, original) attach_addresses((PVOID)(target), (PVOID)(hook), original)
static LONG attach_addresses(PVOID target, PVOID hook, PVOID *original) {
    if(!target) return ERROR_PROC_NOT_FOUND;
    *original=target;
    return DetourAttach(original,hook);
}

typedef NTSTATUS(NTAPI *CreateFn)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PIO_STATUS_BLOCK,PLARGE_INTEGER,ULONG,ULONG,ULONG,ULONG,PVOID,ULONG);
typedef NTSTATUS(NTAPI *OpenFn)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PIO_STATUS_BLOCK,ULONG,ULONG);
typedef BOOL(WINAPI *ProcFn)(HANDLE,LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION,PHANDLE);
static CreateFn original_create;
static OpenFn original_open;
static ProcFn original_process;
typedef NTSTATUS(NTAPI *QueryObjectFn)(HANDLE,ULONG,PVOID,ULONG,PULONG);
typedef NTSTATUS(NTAPI *QueryAttributesFn)(POBJECT_ATTRIBUTES,PVOID);
typedef NTSTATUS(NTAPI *QueryProcessFn)(HANDLE,ULONG,PVOID,ULONG,PULONG);
static QueryObjectFn query_object;
static QueryAttributesFn query_attributes;
static QueryProcessFn query_process;
static DWORD tls_slot;
static DWORD mount_query_slot;
static BOOL (WINAPI *original_mount_name)(LPCWSTR,LPWSTR,DWORD);
static wchar_t self_path[1024];
static LONG sequence;
static struct Config {DWORD magic; wchar_t pipe[256],ready[256];} config;
#include "allow_cache.c"
#define GUARD_MAX_REQUEST_BYTES (128u * 1024u)

static int busy(void) { return TlsGetValue(tls_slot)!=NULL; }
static void guard(int on) { TlsSetValue(tls_slot,(void*)(ULONG_PTR)on); }
static int transfer(HANDLE pipe, void *data, DWORD size, int writing) {
    char *cursor=(char*)data;
    while(size) {
        DWORD count=0;
        BOOL ok=writing?WriteFile(pipe,cursor,size,&count,NULL):ReadFile(pipe,cursor,size,&count,NULL);
        if(!ok || !count) return 0;
        size-=count; cursor+=count;
    }
    return 1;
}
static HANDLE connect_policy_pipe(void) {
    ULONGLONG deadline=GetTickCount64()+5000;
    for(;;) {
        HANDLE pipe=CreateFileW(config.pipe,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
        if(pipe!=INVALID_HANDLE_VALUE)return pipe;
        /* Another runtime thread can connect before the server posts its next
           listener. Retry only contention; all other errors remain closed. */
        if(GetLastError()!=ERROR_PIPE_BUSY)return INVALID_HANDLE_VALUE;
        ULONGLONG now=GetTickCount64();
        if(now>=deadline||!WaitNamedPipeW(config.pipe,(DWORD)(deadline-now)))return INVALID_HANDLE_VALUE;
    }
}
static DWORD decide_fields(DWORD action,LPCWSTR *fields,int count) {
    struct Request {DWORD magic,pid,seq,action,length;} request;
    struct Reply {DWORD magic,seq,allowed;} reply={0};
    /* A Windows command line can contain 32767 UTF-16 code units. UTF-8
       serialization plus exe/cwd must not turn a valid launch into DENY. */
    char local_text[8192]; DWORD total=0,offset=0;
    if(count<1||count>3)return 0;
    AllowEntry *slot=count==1?cache_slot(action,fields[0]):NULL;
    if(slot && cache_matches(slot,action,fields[0]))return 1;
    for(int i=0;i<count;i++) {
        int size=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,fields[i],-1,NULL,0,NULL,NULL);
        if(!size||(DWORD)size>GUARD_MAX_REQUEST_BYTES-total)return 0;
        total+=size;
    }
    char *text=total<=sizeof(local_text)?local_text:HeapAlloc(GetProcessHeap(),0,total);
    if(!text)return 0;
    HANDLE pipe=INVALID_HANDLE_VALUE;DWORD allowed=0;int ok=0;
    for(int i=0;i<count;i++) {
        int size=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,fields[i],-1,text+offset,total-offset,NULL,NULL);
        if(!size)goto cleanup;
        offset+=size;
    }
    request.magic=0x44475231; request.pid=GetCurrentProcessId(); request.seq=InterlockedIncrement(&sequence);
    request.action=slot?(action|0x80000000u):action; request.length=total-1;
    pipe=connect_policy_pipe();
    if(pipe==INVALID_HANDLE_VALUE)goto cleanup;
    ok=transfer(pipe,&request,sizeof(request),1)&&transfer(pipe,text,request.length,1)&&transfer(pipe,&reply,sizeof(reply),0);
    if(ok && reply.magic==0x44475031 && reply.seq==request.seq) {
        allowed=action==41?reply.allowed:(reply.allowed==1 || (slot && reply.allowed==2));
        if(slot && reply.allowed==2)cache_allow(slot,action,fields[0]);
    }
cleanup:
    if(pipe!=INVALID_HANDLE_VALUE)CloseHandle(pipe);
    if(text!=local_text)HeapFree(GetProcessHeap(),0,text);
    return allowed;
}
static int decide(DWORD action,LPCWSTR resource) {return decide_fields(action,&resource,1);}
static int decide_pair(DWORD action,LPCWSTR first,LPCWSTR second) {
    LPCWSTR fields[2]={first,second}; return decide_fields(action,fields,2);
}
static int object_path(POBJECT_ATTRIBUTES attrs,wchar_t *out,DWORD capacity) {
    if(!attrs) return 0;
    UNICODE_STRING empty={0};UNICODE_STRING *object_name=attrs->ObjectName?attrs->ObjectName:&empty;
    if(!object_name->Buffer&&object_name->Length)return 0;
    DWORD size=object_name->Length/sizeof(wchar_t),prefix=0;
    if(size>=capacity||(!size&&!attrs->RootDirectory)) return 0;
    if(object_name->Length%sizeof(wchar_t)||(size&&wmemchr(object_name->Buffer,L'\0',size)))return 0;
    if(attrs->RootDirectory && (!size||object_name->Buffer[0]!=L'\\')) {
        prefix=GetFinalPathNameByHandleW(attrs->RootDirectory,out,capacity,0);
        if(!prefix) {
            /* Pipe-directory handles have no Win32 final file name. Obtain
               their kernel object name without trusting caller-supplied cwd. */
            BYTE data[8192];ULONG used=0;
            if(query_object(attrs->RootDirectory,1,data,sizeof(data),&used)<0)return 0;
            UNICODE_STRING *name=(UNICODE_STRING*)data;
            prefix=name->Length/sizeof(wchar_t);
            if(!name->Buffer||prefix>=capacity)return 0;
            CopyMemory(out,name->Buffer,name->Length);out[prefix]=0;
        }
        if(!prefix||prefix+size+2>capacity) return 0;
        if(size&&out[prefix-1]!=L'\\')out[prefix++]=L'\\';
    }
    if(prefix+size>=capacity) return 0;
    if(size)CopyMemory(out+prefix,object_name->Buffer,size*sizeof(wchar_t));
    out[prefix+size]=0;
    return 1;
}
static int directory_object(POBJECT_ATTRIBUTES attrs,ULONG options) {
    if(options&1)return 1; /* FILE_DIRECTORY_FILE */
    if(options&0x40)return 0; /* FILE_NON_DIRECTORY_FILE */
    /* Call the metadata API directly: a directory handle need not have been
       opened with FILE_DIRECTORY_FILE (e.g. Bash chdir / backup semantics). */
    struct {LARGE_INTEGER times[4];ULONG attributes;} info;
    return query_attributes(attrs,&info)>=0&&(info.attributes&FILE_ATTRIBUTE_DIRECTORY);
}
static DWORD action(ACCESS_MASK access,ULONG disposition,ULONG options,int directory) {
    DWORD mask=0;
    /* The kernel chooses the granted rights after our policy check. */
    if(access&MAXIMUM_ALLOWED)access|=GENERIC_ALL;
    if(access&(GENERIC_READ|GENERIC_ALL|FILE_READ_DATA|FILE_READ_ATTRIBUTES|FILE_READ_EA)) mask|=1;
    if((access&(GENERIC_WRITE|GENERIC_ALL|FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_WRITE_ATTRIBUTES|FILE_WRITE_EA|WRITE_DAC|WRITE_OWNER))
       || disposition!=1) mask|=2;
    if((access&(DELETE|GENERIC_ALL)) || (directory&&(access&FILE_DELETE_CHILD)) || (options&0x1000)) mask|=8;
    /* FILE_TRAVERSE shares the FILE_EXECUTE bit. Traversing a directory is
       a read operation, not execution of code inside the protected root. */
    if(access&(GENERIC_EXECUTE|GENERIC_ALL|FILE_EXECUTE)) mask|=directory?1:4;
    return mask?mask:1;
}
static NTSTATUS denied(PHANDLE handle,PIO_STATUS_BLOCK io) {
    NTSTATUS status=(NTSTATUS)0xc0000022L;
    if(handle) *handle=NULL;
    if(io) { io->Status=status; io->Information=0; }
    return status;
}
static int runtime_device(LPCWSTR path) {
    /* Only these OS interfaces have non-file semantics. All other names
       require a FileGuard identity, including bare volumes and redirectors. */
    static const wchar_t *const objects[]={
        L"\\Device\\Null",L"\\Device\\KsecDD",L"\\Device\\Nsi",L"\\Device\\CNG",
        L"\\Device\\MountPointManager",L"\\??\\MountPointManager",
        L"\\??\\NUL",L"\\??\\CON",L"\\??\\CONIN$",L"\\??\\CONOUT$"
    };
    static const wchar_t *const namespaces[]={
        L"\\Device\\NamedPipe",L"\\Device\\Mailslot",L"\\Device\\ConDrv",L"\\Device\\Afd",
        L"\\??\\PIPE",L"\\??\\MAILSLOT"
    };
    if(!_wcsnicmp(path,L"\\??\\GLOBALROOT\\",15))path+=14;
    for(size_t i=0;i<ARRAYSIZE(objects);i++)
        if(!_wcsicmp(path,objects[i]))return 1;
    for(size_t i=0;i<ARRAYSIZE(namespaces);i++) {
        size_t length=wcslen(namespaces[i]);
        if(!_wcsnicmp(path,namespaces[i],length)&&(path[length]==0||path[length]==L'\\'))return 1;
    }
    return 0;
}

static BOOL WINAPI hook_mount_name(LPCWSTR mount,LPWSTR name,DWORD length) {
    /* The API closes its internal handle and returns only the volume name. */
    void *previous=TlsGetValue(mount_query_slot);
    if(!TlsSetValue(mount_query_slot,(void*)1))return FALSE;
    BOOL ok=original_mount_name(mount,name,length);
    DWORD error=GetLastError();
    TlsSetValue(mount_query_slot,previous);
    SetLastError(error);
    return ok;
}

static int approve_open(wchar_t *path,POBJECT_ATTRIBUTES attrs,ACCESS_MASK access,ULONG disp,ULONG options) {
    if(runtime_device(path))return 1;
    /* Mount-point queries open a drive for metadata. Only these limited
       rights can use the root's read policy. Raw data opens keep the NT name. */
    if(TlsGetValue(mount_query_slot)&&!(access&~(FILE_READ_ATTRIBUTES|SYNCHRONIZE))&&disp==1&&!(options&0x1000)
       &&!wcsncmp(path,L"\\??\\",4)
       &&((path[4]>=L'A'&&path[4]<=L'Z')||(path[4]>=L'a'&&path[4]<=L'z'))
       &&path[5]==L':'&&!path[6]) {
        path[6]=L'\\';path[7]=0;
        return decide(1,path);
    }
    return decide(action(access,disp,options,directory_object(attrs,options)),path);
}

static NTSTATUS NTAPI hook_create(PHANDLE h,ACCESS_MASK a,POBJECT_ATTRIBUTES o,PIO_STATUS_BLOCK io,
                                 PLARGE_INTEGER z,ULONG at,ULONG sh,ULONG disp,ULONG op,PVOID ea,ULONG el) {
    if(busy()) return original_create(h,a,o,io,z,at,sh,disp,op,ea,el);
    guard(1);
    ObjectNameSnapshot snapshot;
    OBJECT_ATTRIBUTES *attrs=&snapshot.attributes;
    wchar_t path[GUARD_PATH_CHARS];
    int allowed=capture_object_name(&snapshot,o) && object_path(attrs,path,ARRAYSIZE(path)) &&
        approve_open(path,attrs,a,disp,op);
    NTSTATUS status=allowed?original_create(h,a,attrs,io,z,at,sh,disp,op,ea,el):denied(h,io);
    guard(0); return status;
}
static NTSTATUS NTAPI hook_open(PHANDLE h,ACCESS_MASK a,POBJECT_ATTRIBUTES o,PIO_STATUS_BLOCK io,ULONG sh,ULONG op) {
    if(busy()) return original_open(h,a,o,io,sh,op);
    guard(1);
    ObjectNameSnapshot snapshot;
    OBJECT_ATTRIBUTES *attrs=&snapshot.attributes;
    wchar_t path[GUARD_PATH_CHARS];
    int allowed=0;
    if(capture_object_name(&snapshot,o)) {
        /* Reopening an already held anonymous pipe has no new destination. */
        int pipe_reopen=attrs->RootDirectory && (!attrs->ObjectName||!attrs->ObjectName->Length) &&
            GetFileType(attrs->RootDirectory)==FILE_TYPE_PIPE;
        allowed=pipe_reopen || (object_path(attrs,path,ARRAYSIZE(path)) && approve_open(path,attrs,a,1,op));
    }
    NTSTATUS status=allowed?original_open(h,a,attrs,io,sh,op):denied(h,io);
    guard(0); return status;
}

typedef NTSTATUS(NTAPI *SetInfoFn)(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG,FILE_INFORMATION_CLASS);
typedef NTSTATUS(NTAPI *DeleteFn)(POBJECT_ATTRIBUTES);
static SetInfoFn original_setinfo;
static DeleteFn original_delete;
static BOOL (WINAPI *original_deletefile)(LPCWSTR);
static BOOL (WINAPI *original_removedir)(LPCWSTR);
static BOOL checked_delete(LPCWSTR path,BOOL (WINAPI *original)(LPCWSTR)) {
    if(busy()) return original(path);
    guard(1);wchar_t absolute[2048];
    DWORD size=path?GetFullPathNameW(path,2048,absolute,NULL):0;
    int allowed=size>0&&size<2048&&decide(8,absolute);
    BOOL result=allowed?original(absolute):FALSE;
    DWORD error=allowed?GetLastError():ERROR_ACCESS_DENIED;
    guard(0);SetLastError(error);return result;
}
static BOOL WINAPI hook_deletefile(LPCWSTR path){return checked_delete(path,original_deletefile);}
static BOOL WINAPI hook_removedir(LPCWSTR path){return checked_delete(path,original_removedir);}
static NTSTATUS NTAPI hook_delete(POBJECT_ATTRIBUTES attrs) {
    if(busy()) return original_delete(attrs);
    guard(1);
    ObjectNameSnapshot snapshot;
    wchar_t path[GUARD_PATH_CHARS];
    int allowed=capture_object_name(&snapshot,attrs) && object_path(&snapshot.attributes,path,ARRAYSIZE(path)) &&
        decide(8,path);
    NTSTATUS status=allowed?original_delete(&snapshot.attributes):(NTSTATUS)0xc0000022L;
    guard(0); return status;
}
static NTSTATUS NTAPI hook_setinfo(HANDLE file,PIO_STATUS_BLOCK io,PVOID data,ULONG size,FILE_INFORMATION_CLASS kind) {
    if(busy()) return original_setinfo(file,io,data,size,kind);
    if(GetFileType(file)==FILE_TYPE_PIPE) return original_setinfo(file,io,data,size,kind);
    /* Rename/link: base and Ex variants. Disposition, EOF and allocation all
       mutate the existing file; approve before invoking the original syscall. */
    int pair=kind==10||kind==11||kind==65||kind==72;
    int write=pair||kind==13||kind==64||kind==19||kind==20||kind==4;
    if(!write) return original_setinfo(file,io,data,size,kind);
    guard(1); wchar_t source[2048],target[2048];
    DWORD length=GetFinalPathNameByHandleW(file,source,2048,0);
    int allowed=length>0&&length<2048;
    FileTargetSnapshot snapshot;
    if(allowed&&pair) {
        allowed=capture_file_target(&snapshot,data,size,&size);
        if(allowed) {
            USHORT bytes=(USHORT)snapshot.name_bytes;
            UNICODE_STRING name={.Length=bytes,.MaximumLength=bytes,.Buffer=snapshot.name};
            OBJECT_ATTRIBUTES attrs={.Length=sizeof(attrs),.RootDirectory=snapshot.root,.ObjectName=&name};
            allowed=object_path(&attrs,target,ARRAYSIZE(target))&&decide_pair((kind==10||kind==65)?16:17,source,target);
            data=&snapshot;
        }
    } else if(allowed) allowed=decide((kind==13||kind==64)?8:2,source);
    NTSTATUS status=allowed?original_setinfo(file,io,data,size,kind):denied(NULL,io);
    guard(0); return status;
}

/* Import-table injection for descendants is compiled from child_injection.c. */
#include "child_injection.c"
#include "network.c"

/* Query the suspended child's command line. The returned UNICODE_STRING
 * references the query buffer and is length-delimited. */
static WCHAR *child_command_line(HANDLE child) {
    const ULONG capacity=sizeof(UNICODE_STRING)+65536+sizeof(WCHAR);
    BYTE *buffer=HeapAlloc(GetProcessHeap(),0,capacity);
    if(!buffer)return NULL;
    ULONG used=0;
    if(query_process(child,60 /* ProcessCommandLineInformation */,buffer,capacity-sizeof(WCHAR),&used)>=0 &&
       used>=sizeof(UNICODE_STRING) && used<=capacity-sizeof(WCHAR)){
        UNICODE_STRING *line=(UNICODE_STRING*)buffer;
        ULONG_PTR start=(ULONG_PTR)line->Buffer-(ULONG_PTR)buffer;
        if(start>=sizeof(*line) && start<=used && line->Length<=used-start &&
           line->Length<=line->MaximumLength && line->Length%sizeof(WCHAR)==0){
            size_t chars=line->Length/sizeof(WCHAR);
            if(!wmemchr(line->Buffer,L'\0',chars)){
                memmove(buffer,line->Buffer,line->Length);
                ((WCHAR*)buffer)[chars]=0;
                return (WCHAR*)buffer;
            }
        }
    }
    HeapFree(GetProcessHeap(),0,buffer);
    return NULL;
}

static BOOL WINAPI hook_process(HANDLE tok,LPCWSTR app,LPWSTR cmd,LPSECURITY_ATTRIBUTES pa,
    LPSECURITY_ATTRIBUTES ta,BOOL inh,DWORD flags,LPVOID env,LPCWSTR cwd,LPSTARTUPINFOW si,
    LPPROCESS_INFORMATION pi,PHANDLE nt) {
    if(busy()) return original_process(tok,app,cmd,pa,ta,inh,flags,env,cwd,si,pi,nt);
    wchar_t directory[2048];
    if(cwd){
        size_t chars;
        __try {
            chars=wcsnlen(cwd,2048);
            if(chars<2048){memcpy(directory,cwd,chars*sizeof(WCHAR));directory[chars]=0;}
        } __except(EXCEPTION_EXECUTE_HANDLER){SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}
        if(chars>=2048){SetLastError(ERROR_FILENAME_EXCED_RANGE);return FALSE;}
    }else{
        DWORD size=GetCurrentDirectoryW(2048,directory);
        if(!size)return FALSE;
        if(size>=2048){SetLastError(ERROR_FILENAME_EXCED_RANGE);return FALSE;}
    }
    guard(1);
    BOOL ok=original_process(tok,app,cmd,pa,ta,inh,flags|CREATE_SUSPENDED,env,directory,si,pi,nt);
    if(ok && pi) {
        wchar_t executable[2048]; DWORD length=2048;
        int ready=QueryFullProcessImageNameW(pi->hProcess,0,executable,&length)&&length<2048;
        WCHAR *command=child_command_line(pi->hProcess);
        LPCWSTR fields[3]={executable,command,directory};
        DWORD failure=ERROR_SUCCESS;
        if(!ready || !command) failure=ERROR_INVALID_DATA;
        else if(!decide_fields(40,fields,3)) failure=ERROR_ACCESS_DENIED;
        else if(!inject_import_child(pi->hProcess) ||
                (!(flags&CREATE_SUSPENDED) && ResumeThread(pi->hThread)==(DWORD)-1)) {
            failure=GetLastError();
            if(!failure)failure=ERROR_DLL_INIT_FAILED;
        }
        if(command)HeapFree(GetProcessHeap(),0,command);
        if(failure) {
            TerminateProcess(pi->hProcess,125);
            CloseHandle(pi->hThread); CloseHandle(pi->hProcess);
            ZeroMemory(pi,sizeof(*pi)); guard(0); SetLastError(failure); return FALSE;
        }
    }
    guard(0); return ok;
}
static int install(void) {
    tls_slot=TlsAlloc(); if(tls_slot==TLS_OUT_OF_INDEXES) return 0;
    mount_query_slot=TlsAlloc(); if(mount_query_slot==TLS_OUT_OF_INDEXES)return 0;
    guard(1);
    /* The injector places configuration in the second page of its import
       allocation. Each process owns its copy, while all load one fixed DLL. */
    BYTE *image=(BYTE*)GetModuleHandleW(NULL);
    IMAGE_NT_HEADERS64 *nt=(IMAGE_NT_HEADERS64*)(image+((IMAGE_DOS_HEADER*)image)->e_lfanew);
    DWORD imports=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    SIZE_T got=0;
    if(!imports || !ReadProcessMemory(GetCurrentProcess(),image+imports+4096,&config,sizeof(config),&got)
        || got!=sizeof(config) || config.magic!=0x44474333
        || !config.pipe[0] || !config.ready[0] || config.pipe[255] || config.ready[255]) return 0;
    size_t ready_length=wcslen(config.ready);
    if(ready_length>=6 && !wcscmp(config.ready+ready_length-6,L"-cache")) {
        LPCWSTR field=L"cache";
        cache_revoked=(HANDLE)(ULONG_PTR)decide_fields(41,&field,1);
    }
    HMODULE ntdll=GetModuleHandleW(L"ntdll.dll"),kernel=GetModuleHandleW(L"kernelbase.dll");
    /* Resolve before installing hooks: GetProcAddress inside a file hook can
       re-enter the Windows appcompat loader while it holds its internal lock. */
    query_object=(QueryObjectFn)(void*)GetProcAddress(ntdll,"NtQueryObject");
    query_attributes=(QueryAttributesFn)(void*)GetProcAddress(ntdll,"NtQueryAttributesFile");
    query_process=(QueryProcessFn)(void*)GetProcAddress(ntdll,"NtQueryInformationProcess");
    if(!query_object||!query_attributes||!query_process)return 0;
    int status=DetourTransactionBegin();
    if(!status) status=DetourUpdateThread(GetCurrentThread());
    if(!status) status=guard_attach(GetProcAddress(ntdll,"NtCreateFile"),hook_create,(void**)&original_create);
    if(!status) status=guard_attach(GetProcAddress(ntdll,"NtOpenFile"),hook_open,(void**)&original_open);
    if(!status) status=guard_attach(GetProcAddress(ntdll,"NtDeleteFile"),hook_delete,(void**)&original_delete);
    if(!status) status=guard_attach(GetProcAddress(ntdll,"NtSetInformationFile"),hook_setinfo,(void**)&original_setinfo);
    if(!status) status=guard_attach(GetProcAddress(kernel,"DeleteFileW"),hook_deletefile,(void**)&original_deletefile);
    if(!status) status=guard_attach(GetProcAddress(kernel,"RemoveDirectoryW"),hook_removedir,(void**)&original_removedir);
    if(!status) status=guard_attach(GetProcAddress(kernel,"GetVolumeNameForVolumeMountPointW"),hook_mount_name,(void**)&original_mount_name);
    if(!status) status=guard_attach(GetProcAddress(kernel,"CreateProcessInternalW"),hook_process,(void**)&original_process);
    if(!status) status=install_network_hooks();
    if(!status) status=DetourTransactionCommit();
    else DetourTransactionAbort();
    if(status) return 0;
    HANDLE ready=OpenEventW(EVENT_MODIFY_STATE,FALSE,config.ready);
    if(!ready) return 0;
    int ok=SetEvent(ready); CloseHandle(ready);
    guard(0); return ok;
}
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID reserved) {
    (void)reserved;
    if(reason==DLL_PROCESS_ATTACH) {
        if(!GetModuleFileNameW(module,self_path,1024) || lstrlenW(self_path)>=1023) return FALSE;
        /* /MT links the static MSVC CRT, which needs thread notifications. */
        return install();
    }
    return TRUE;
}
__declspec(dllexport) int GuardMarker(void) { return 1; }
