#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0603
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <svcguid.h>
#include <windows.h>
#include <winternl.h>
#include <winhttp.h>
#include <windns.h>
#include <stdio.h>
#include <wchar.h>
#include <stdlib.h>
#include "../src/child_pe.c"
#include "../src/file_name_snapshot.c"
#include "../src/socket_address_snapshot.c"

typedef struct {
    struct sockaddr_in6 source;
    HANDLE captured;
    HANDLE updated;
    WCHAR filename[2];
} SnapshotFixture;

static DWORD WINAPI update_address(void *arg) {
    SnapshotFixture *fixture=arg;
    for(unsigned i=0;i<256;i++){
        if(WaitForSingleObject(fixture->captured,5000)!=WAIT_OBJECT_0)return 1;
        fixture->source.sin6_port=htons(2);
        fixture->filename[0]=L'b';
        SetEvent(fixture->updated);
    }
    return 0;
}

static int test_address_snapshots(void) {
    SnapshotFixture fixture={.source={.sin6_family=AF_INET6}};
    UNICODE_STRING name={sizeof(WCHAR),sizeof(fixture.filename),fixture.filename};
    OBJECT_ATTRIBUTES attrs={.Length=sizeof(attrs),.ObjectName=&name};
    fixture.captured=CreateEventW(NULL,FALSE,FALSE,NULL);
    fixture.updated=CreateEventW(NULL,FALSE,FALSE,NULL);
    HANDLE worker=CreateThread(NULL,0,update_address,&fixture,0,NULL);
    if(!worker||!fixture.captured||!fixture.updated)return 1;
    for(unsigned i=0;i<256;i++){
        fixture.source.sin6_port=htons(1);
        fixture.filename[0]=L'a';
        ObjectNameSnapshot object;
        if(!capture_object_name(&object,&attrs))return 2;
        const struct sockaddr *address=(const struct sockaddr*)&fixture.source;
        SOCKADDR_STORAGE copy;
        if(!capture_socket_address(&copy,&address,sizeof(fixture.source)))return 2;
        SetEvent(fixture.captured);
        if(WaitForSingleObject(fixture.updated,5000)!=WAIT_OBJECT_0 ||
           ((const struct sockaddr_in6*)address)->sin6_port!=htons(1) ||
           object.name.Buffer[0]!=L'a')return 3;
    }
    if(WaitForSingleObject(worker,5000)!=WAIT_OBJECT_0)return 4;
    CloseHandle(worker);CloseHandle(fixture.updated);CloseHandle(fixture.captured);
    return 0;
}

static int test_name_snapshots(void) {
    WCHAR text[] = L"alpha";
    UNICODE_STRING name = {sizeof(text) - sizeof(WCHAR), sizeof(text), text};
    OBJECT_ATTRIBUTES attrs = {.Length=sizeof(attrs), .RootDirectory=(HANDLE)1, .ObjectName=&name};
    ObjectNameSnapshot object;
    if (!capture_object_name(&object, &attrs)) return 1;
    text[0] = L'z';
    name.Length = 0;
    attrs.RootDirectory = NULL;
    if (object.attributes.RootDirectory != (HANDLE)1 || object.attributes.ObjectName != &object.name ||
        object.name.Length != sizeof(text) - sizeof(WCHAR) || wcscmp(object.name.Buffer, L"alpha")) return 2;
    name.Length = 1;
    if (capture_object_name(&object, &attrs)) return 3;
    name.Length = sizeof(text) - sizeof(WCHAR);
    name.MaximumLength = 0;
    if (!capture_object_name(&object, &attrs) || wcscmp(object.name.Buffer, L"zlpha")) return 4;
    attrs.ObjectName = NULL;
    if (!capture_object_name(&object, &attrs) || object.attributes.ObjectName) return 5;

    FileTargetSnapshot input = {.flags=3, .root=(HANDLE)2, .name_bytes=10, .name=L"alpha"};
    FileTargetSnapshot target;
    ULONG captured, size = FIELD_OFFSET(FileTargetSnapshot, name) + input.name_bytes;
    if (!capture_file_target(&target, &input, size, &captured) || captured != size) return 6;
    ZeroMemory(&input, sizeof(input));
    if (target.flags != 3 || target.root != (HANDLE)2 || target.name_bytes != 10 ||
        wmemcmp(target.name, L"alpha", 5)) return 7;
    input.name_bytes = 12;
    if (capture_file_target(&target, &input, size, &captured)) return 8;
    input.name_bytes = 9;
    if (capture_file_target(&target, &input, size, &captured)) return 9;
    return 0;
}

static unsigned redirect_callbacks;
static HANDLE resolved_event;
static volatile unsigned resolved_callbacks;
static volatile DWORD resolved_error;
static void CALLBACK resolved(DWORD error,DWORD bytes,LPWSAOVERLAPPED ov) {
    (void)bytes;(void)ov;
    resolved_error=error;InterlockedIncrement((LONG*)&resolved_callbacks);SetEvent(resolved_event);
}
static void WINAPI dns_resolved(PVOID context,PDNS_QUERY_RESULT result) {
    (void)context;
    resolved_error=result->QueryStatus;InterlockedIncrement((LONG*)&resolved_callbacks);SetEvent(resolved_event);
}
typedef struct {ULONG version;PCWSTR name;WORD type;ULONG64 options;PVOID servers;ULONG interface_index;
                PDNS_QUERY_COMPLETION_ROUTINE callback;PVOID context;} TestDnsRequest;

static int resolve_test(LPCWSTR name,LPCWSTR api) {
    WSADATA data;if(WSAStartup(MAKEWORD(2,2),&data))return 40;
    char ansi[1024];WideCharToMultiByte(CP_UTF8,0,name,-1,ansi,sizeof(ansi),NULL,NULL);
    int error=0;unsigned found=0;
    printf("RESOLVE_START PID=%lu TID=%lu\n",GetCurrentProcessId(),GetCurrentThreadId());fflush(stdout);
    resolved_event=CreateEventW(NULL,TRUE,FALSE,NULL);
    if(!wcscmp(api,L"gai_a")) {
        PADDRINFOA result=NULL;error=getaddrinfo(ansi,"80",NULL,&result);found=result!=NULL;if(result)freeaddrinfo(result);
    } else if(!wcscmp(api,L"gai_w")) {
        PADDRINFOW result=NULL;error=GetAddrInfoW(name,L"80",NULL,&result);found=result!=NULL;if(result)FreeAddrInfoW(result);
    } else if(!wcscmp(api,L"gai_exa")) {
        PADDRINFOEXA result=NULL;
        /* Exercise the deprecated ANSI entry point deliberately. */
#pragma warning(suppress:4996)
        error=GetAddrInfoExA(ansi,"80",NS_DNS,NULL,NULL,&result,NULL,NULL,NULL,NULL);
#pragma warning(suppress:4996)
        found=result!=NULL;if(result)FreeAddrInfoExA(result);
    } else if(!wcscmp(api,L"gai_exw")||!wcscmp(api,L"gai_async")) {
        int async=!wcscmp(api,L"gai_async");PADDRINFOEXW result=NULL;HANDLE cancel=NULL;OVERLAPPED ov={0};
        error=GetAddrInfoExW(name,L"80",NS_DNS,NULL,NULL,&result,NULL,async?&ov:NULL,async?resolved:NULL,async?&cancel:NULL);
        if(error==WSA_IO_PENDING){if(WaitForSingleObject(resolved_event,5000))return 41;error=resolved_error;}
        found=result!=NULL;if(result)FreeAddrInfoExW(result);
    } else if(!wcscmp(api,L"hostbyname")) {
#pragma warning(suppress:4996)
        struct hostent *result=gethostbyname(ansi);found=result!=NULL;if(!result)error=WSAGetLastError();
    } else if(!wcscmp(api,L"hostbyaddr")) {
        IN6_ADDR address;
        int family=wcschr(name,L':')?AF_INET6:AF_INET;
        if(InetPtonW(family,name,&address)!=1)return 40;
#pragma warning(suppress:4996)
        struct hostent *result=gethostbyaddr((const char*)&address,family==AF_INET?4:16,family);
        found=result!=NULL;if(!found)error=WSAGetLastError();
    } else if(!wcsncmp(api,L"lookup_",7)) {
        GUID service=SVCID_INET_HOSTADDRBYNAME;
        DWORD ns=wcsstr(api,L"_all")?NS_ALL:NS_DNS;
        DWORD flags=LUP_RETURN_ADDR;
        HANDLE handle=NULL;
        if(api[7]==L'a'){
            WSAQUERYSETA query={.dwSize=sizeof(query),.dwNameSpace=ns,
                .lpServiceClassId=&service,.lpszServiceInstanceName=ansi};
#pragma warning(suppress:4996)
            error=WSALookupServiceBeginA(&query,flags,&handle);
        }else{
            WSAQUERYSETW query={.dwSize=sizeof(query),.dwNameSpace=ns,
                .lpServiceClassId=&service,.lpszServiceInstanceName=(LPWSTR)name};
            error=WSALookupServiceBeginW(&query,flags,&handle);
        }
        if(error)error=WSAGetLastError();
        else{
            WSAQUERYSETW results[32];DWORD size=sizeof(results);
            if(WSALookupServiceNextW(handle,flags,&size,results))error=WSAGetLastError();
            else found=results[0].dwNumberOfCsAddrs!=0;
            WSALookupServiceEnd(handle);
        }
    } else if(!wcscmp(api,L"dns_ex")||!wcscmp(api,L"dns_async")) {
        int async=!wcscmp(api,L"dns_async");TestDnsRequest request={1,name,DNS_TYPE_A,0,NULL,0,async?dns_resolved:NULL,NULL};
        DNS_QUERY_RESULT result={DNS_QUERY_RESULTS_VERSION1};BYTE cancel[32]={0};
        typedef DNS_STATUS (WINAPI *QueryFn)(TestDnsRequest*,PDNS_QUERY_RESULT,PVOID);
        QueryFn query=(QueryFn)(void*)GetProcAddress(GetModuleHandleW(L"dnsapi.dll"),"DnsQueryEx");
        error=query(&request,&result,cancel);
        if(error==DNS_REQUEST_PENDING){if(WaitForSingleObject(resolved_event,5000))return 42;error=resolved_error;}
        found=result.pQueryRecords!=NULL;if(found)DnsRecordListFree(result.pQueryRecords,DnsFreeRecordList);
    } else {
        PDNS_RECORD result=NULL;
        if(!wcscmp(api,L"dns_w"))error=DnsQuery_W(name,DNS_TYPE_A,0,NULL,&result,NULL);
        else if(!wcscmp(api,L"dns_utf8"))error=DnsQuery_UTF8(ansi,DNS_TYPE_A,0,NULL,(PDNS_RECORDA*)&result,NULL);
        else error=DnsQuery_A(ansi,DNS_TYPE_A,0,NULL,&result,NULL);
        found=result!=NULL;if(result)DnsRecordListFree(result,DnsFreeRecordList);
    }
    printf("RESOLVE_ERROR=%d FOUND=%u CALLBACKS=%u PID=%lu TID=%lu\n",error,found,resolved_callbacks,
           GetCurrentProcessId(),GetCurrentThreadId());fflush(stdout);
    CloseHandle(resolved_event);WSACleanup();return error?43:0;
}
static HANDLE http_event;
static volatile DWORD http_phase;
static unsigned callback_socket_port;
static volatile LONG callback_socket_result=-1;
static volatile int callback_socket_error;
static void CALLBACK test_http_status(HINTERNET h,DWORD_PTR context,DWORD status,LPVOID info,DWORD length) {
    (void)h;(void)context;(void)info;(void)length;
    if(status==WINHTTP_CALLBACK_STATUS_REDIRECT)redirect_callbacks++;
    if(status==WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE&&callback_socket_port) {
        SOCKET socket=WSASocketW(AF_INET,SOCK_STREAM,0,NULL,0,0);
        struct sockaddr_in address={0};address.sin_family=AF_INET;
        address.sin_port=htons((u_short)callback_socket_port);address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        callback_socket_result=connect(socket,(struct sockaddr*)&address,sizeof(address))==0;
        callback_socket_error=WSAGetLastError();closesocket(socket);
    }
    if(http_event && (status==WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE
        ||status==WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE||status==WINHTTP_CALLBACK_STATUS_REQUEST_ERROR
        ||status==WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING)) {http_phase=status;SetEvent(http_event);}
}
static int http_wait(DWORD phase) {return WaitForSingleObject(http_event,5000)==WAIT_OBJECT_0&&http_phase==phase;}

int wmain(int argc,wchar_t **argv) {
    if(argc==4&&!wcscmp(argv[1],L"check-import-limits"))
        return (int)child_import_limits(wcstoul(argv[2],NULL,10),wcstoul(argv[3],NULL,10));
    if(argc==2&&!wcscmp(argv[1],L"check-name-snapshots"))return test_name_snapshots();
    if(argc==2&&!wcscmp(argv[1],L"check-address-snapshots"))return test_address_snapshots();
    if(argc==3&&!wcscmp(argv[1],L"check-child-pe")) {
        BYTE header[4096];
        FILE *file=NULL;
        if(_wfopen_s(&file,argv[2],L"rb"))return 2;
        size_t size=fread(header,1,sizeof(header),file);
        fclose(file);
        if(size!=sizeof(header))return 2;
        return child_pe_header(header)?0:(int)GetLastError();
    }
    if(argc<3) return 2;
    if(argc>3&&!wcscmp(argv[3],L"dir")) {
        HANDLE dir=CreateFileW(argv[1],wcstoul(argv[2],NULL,0),FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                              NULL,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS,NULL);
        if(dir==INVALID_HANDLE_VALUE){printf("DIR_ERROR=%lu\n",GetLastError());return 47;}
        CloseHandle(dir);printf("DIR_OK\n");return 0;
    }
    if(argc>5&&!wcscmp(argv[3],L"proxy")) {
        WSADATA data;WSAStartup(MAKEWORD(2,2),&data);SOCKET s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
        struct sockaddr_in address={0};address.sin_family=AF_INET;address.sin_port=htons((u_short)_wtoi(argv[2]));
        InetPtonW(AF_INET,argv[1],&address.sin_addr);
        if(connect(s,(struct sockaddr*)&address,sizeof(address)))return 48;
        char target[1024],request[1400];WideCharToMultiByte(CP_UTF8,0,argv[4],-1,target,sizeof(target),NULL,NULL);
        snprintf(request,sizeof(request),"CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n",target,target);
        int ok=1;DWORD sent=0;unsigned length=(unsigned)strlen(request);
        if(!wcscmp(argv[5],L"vector")||!wcscmp(argv[5],L"sendmsg")) {
            WSABUF parts[3]={{3,request},{8,request+3},{length-11,request+11}};
            WSAMSG msg={.lpBuffers=parts,.dwBufferCount=3};
            ok=(!wcscmp(argv[5],L"sendmsg")?WSASendMsg(s,&msg,0,&sent,NULL,NULL):
                WSASend(s,parts,3,&sent,0,NULL,NULL))==0;
        } else {
            ok=send(s,request,3,0)==3;
            if(ok)ok=send(s,request+3,8,0)==8;
            if(ok)ok=send(s,request+11,length-11,0)==(int)length-11;
        }
        int error=WSAGetLastError();closesocket(s);printf("PROXY=%d ERROR=%d\n",ok,error);return ok?0:49;
    }
    if(argc>3&&!wcscmp(argv[3],L"pipe")) {
        HANDLE pipe=CreateFileW(argv[1],GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
        if(pipe==INVALID_HANDLE_VALUE){printf("PIPE_ERROR=%lu\n",GetLastError());return 46;}
        CloseHandle(pipe);printf("PIPE_OK\n");return 0;
    }
    if(argc>3&&!wcscmp(argv[3],L"volume")) {
        wchar_t name[MAX_PATH];BOOL ok=GetVolumeNameForVolumeMountPointW(argv[1],name,MAX_PATH);
        printf("VOLUME=%d ERROR=%lu\n",ok,GetLastError());return ok?0:44;
    }
    if(argc>3&&!wcscmp(argv[3],L"volume_data")) {
        HANDLE file=CreateFileW(argv[1],GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
        if(file==INVALID_HANDLE_VALUE){printf("VOLUME_DATA_DENIED=%lu\n",GetLastError());return 45;}
        CloseHandle(file);return 0;
    }
    if(argc>3&&!wcscmp(argv[3],L"resolve"))return resolve_test(argv[1],argv[2]);
    if(argc>3 && (!wcscmp(argv[3],L"tcp") || !wcscmp(argv[3],L"udp") || !wcscmp(argv[3],L"sendmsg") || !wcscmp(argv[3],L"connectex"))) {
        WSADATA data; if(WSAStartup(MAKEWORD(2,2),&data)) return 10;
        int message=!wcscmp(argv[3],L"sendmsg");
        int udp=message||!wcscmp(argv[3],L"udp");
        int ipv6=wcschr(argv[1],L':')!=NULL;
        SOCKET socket=WSASocketW(ipv6?AF_INET6:AF_INET,udp?SOCK_DGRAM:SOCK_STREAM,0,NULL,0,WSA_FLAG_OVERLAPPED);
        if(socket==INVALID_SOCKET) {printf("SOCKET_ERROR=%d\n",WSAGetLastError());return 11;}
        struct sockaddr_in address={0};address.sin_family=AF_INET;address.sin_port=htons((u_short)_wtoi(argv[2]));
        InetPtonW(AF_INET,argv[1],&address.sin_addr);
        struct sockaddr_in6 address6={0};address6.sin6_family=AF_INET6;address6.sin6_port=address.sin_port;
        InetPtonW(AF_INET6,argv[1],&address6.sin6_addr);
        struct sockaddr *destination=ipv6?(struct sockaddr*)&address6:(struct sockaddr*)&address;
        int size=ipv6?sizeof(address6):sizeof(address);
        if(!wcscmp(argv[3],L"connectex")) {
            struct sockaddr_storage local={0};local.ss_family=ipv6?AF_INET6:AF_INET;
            LPFN_CONNECTEX fn=NULL;GUID guid=WSAID_CONNECTEX;DWORD bytes=0,flags=0;
            if(bind(socket,(struct sockaddr*)&local,size)||WSAIoctl(socket,SIO_GET_EXTENSION_FUNCTION_POINTER,
                &guid,sizeof(guid),&fn,sizeof(fn),&bytes,NULL,NULL))return 13;
            OVERLAPPED ov={0};ov.hEvent=CreateEventW(NULL,TRUE,FALSE,NULL);
            BOOL ok=fn(socket,destination,size,"HELLO",5,&bytes,&ov);
            if(!ok&&WSAGetLastError()==ERROR_IO_PENDING)ok=WSAGetOverlappedResult(socket,&ov,&bytes,TRUE,&flags);
            printf("CONNECTEX=%d ERROR=%d\n",ok,WSAGetLastError());CloseHandle(ov.hEvent);closesocket(socket);WSACleanup();return ok?0:12;
        }
        int result;
        if(message) {
            GUID guid=WSAID_WSASENDMSG;LPFN_WSASENDMSG extension=NULL;DWORD bytes=0;
            if(WSAIoctl(socket,SIO_GET_EXTENSION_FUNCTION_POINTER,&guid,sizeof(guid),
                        &extension,sizeof(extension),&bytes,NULL,NULL)||extension!=WSASendMsg)return 13;
            WSABUF payload={5,"HELLO"};
            WSAMSG msg={.name=destination,.namelen=size,.lpBuffers=&payload,.dwBufferCount=1};
            result=WSASendMsg(socket,&msg,0,&bytes,NULL,NULL);
        } else result=udp?sendto(socket,"HELLO",5,0,destination,size):connect(socket,destination,size);
        if(!udp && result==0) result=send(socket,"HELLO",5,0);
        printf("NETWORK=%d ERROR=%d\n",result,WSAGetLastError());closesocket(socket);WSACleanup();return result<0?12:0;
    }
    if(argc>4 && !wcscmp(argv[3],L"http")) {
        int async=argc>5&&!wcscmp(argv[5],L"async");
        int proxy=argc>6&&!wcscmp(argv[5],L"named_proxy");
        HINTERNET session=WinHttpOpen(L"GuardTests",proxy?WINHTTP_ACCESS_TYPE_NAMED_PROXY:WINHTTP_ACCESS_TYPE_NO_PROXY,
                                    proxy?argv[6]:NULL,NULL,async?WINHTTP_FLAG_ASYNC:0);
        if(!session) return 20;
        if(async) {
            if(argc>6){WSADATA data;WSAStartup(MAKEWORD(2,2),&data);callback_socket_port=_wtoi(argv[6]);}
            http_event=CreateEventW(NULL,FALSE,FALSE,NULL);
            WinHttpSetStatusCallback(session,test_http_status,WINHTTP_CALLBACK_FLAG_ALL_COMPLETIONS
                |WINHTTP_CALLBACK_FLAG_HANDLES|WINHTTP_CALLBACK_FLAG_REDIRECT,0);
        }
        if(argc>5&&(!wcscmp(argv[5],L"callback")||!wcscmp(argv[5],L"callback_clear"))) {
            WinHttpSetStatusCallback(session,test_http_status,WINHTTP_CALLBACK_FLAG_REDIRECT,0);
            if(!wcscmp(argv[5],L"callback_clear"))WinHttpSetStatusCallback(session,NULL,0,0);
        }
        HINTERNET connection=WinHttpConnect(session,argv[1],(INTERNET_PORT)_wtoi(argv[2]),0);
        int secure=argc>5&&!wcscmp(argv[5],L"https");
        HINTERNET request=connection?WinHttpOpenRequest(connection,L"GET",argv[4],NULL,NULL,NULL,secure?WINHTTP_FLAG_SECURE:0):NULL;
        if(request&&secure){DWORD flags=SECURITY_FLAG_IGNORE_UNKNOWN_CA|SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
            WinHttpSetOption(request,WINHTTP_OPTION_SECURITY_FLAGS,&flags,sizeof(flags));}
        BOOL ok=request&&WinHttpSendRequest(request,NULL,0,NULL,0,0,0);
        if(ok&&async)ok=http_wait(WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE);
        if(ok)ok=WinHttpReceiveResponse(request,NULL);
        if(ok&&async)ok=http_wait(WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE);
        printf("HTTP=%d ERROR=%lu CALLBACKS=%u SOCKET=%ld SOCKET_ERROR=%d\n",ok,GetLastError(),redirect_callbacks,
               callback_socket_result,callback_socket_error);
        if(request) WinHttpCloseHandle(request);if(connection) WinHttpCloseHandle(connection);WinHttpCloseHandle(session);
        if(http_event){CloseHandle(http_event);http_event=NULL;}
        return ok?0:21;
    }
    if(argc>3 && !wcscmp(argv[3],L"rename")) return MoveFileExW(argv[1],argv[2],MOVEFILE_REPLACE_EXISTING)?0:31;
    if(argc>3 && !wcscmp(argv[3],L"delete")) return DeleteFileW(argv[1])?0:32;
    if(argc>3 && !wcscmp(argv[3],L"truncate")) {
        HANDLE file=CreateFileW(argv[1],GENERIC_WRITE,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
        if(file==INVALID_HANDLE_VALUE) return 33;
        BOOL ok=SetEndOfFile(file);CloseHandle(file);return ok?0:34;
    }
    int depth=argc>3?_wtoi(argv[3]):0;
    if(depth>0) {
        wchar_t command[8192];
        swprintf(command,8192,L"\"%ls\" \"%ls\" \"%ls\" %d",argv[0],argv[1],argv[2],depth-1);
        STARTUPINFOW startup={0}; startup.cb=sizeof(startup);
        PROCESS_INFORMATION child={0};
        if(!CreateProcessW(argv[0],command,NULL,NULL,TRUE,0,NULL,NULL,&startup,&child)) return 7;
        CloseHandle(child.hThread);
        WaitForSingleObject(child.hProcess,INFINITE);
        DWORD code=0; GetExitCodeProcess(child.hProcess,&code); CloseHandle(child.hProcess);
        return (int)code;
    }
    HANDLE marker=CreateFileW(argv[2],FILE_APPEND_DATA,FILE_SHARE_READ,NULL,OPEN_ALWAYS,0,NULL);
    if(marker==INVALID_HANDLE_VALUE) return 3;
    DWORD count;
    WriteFile(marker,"START\n",6,&count,NULL); CloseHandle(marker);
    printf("START_PID=%lu TID=%lu\n",GetCurrentProcessId(),GetCurrentThreadId()); fflush(stdout);
    if(argc>3 && !wcscmp(argv[3],L"sleep")) Sleep(500);
    for(int i=0;i<2;i++) {
        HANDLE file=CreateFileW(argv[1],GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
        if(file==INVALID_HANDLE_VALUE) return 5;
        char data[256];
        if(!ReadFile(file,data,255,&count,NULL)) { CloseHandle(file); return 6; }
        CloseHandle(file); data[count]=0;
        printf("PID=%lu TID=%lu CONTENT=%s\n",GetCurrentProcessId(),GetCurrentThreadId(),data); fflush(stdout);
    }
    return 0;
}
