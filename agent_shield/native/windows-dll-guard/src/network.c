/* Domain lookups, full URLs and raw endpoints remain separate subjects.
 * A DNS approval never turns into a general permission for returned IPs. */
static int (WSAAPI *original_addrinfo)(PCSTR,PCSTR,const ADDRINFOA*,PADDRINFOA*);
static int (WSAAPI *original_addrinfow)(PCWSTR,PCWSTR,const ADDRINFOW*,PADDRINFOW*);
static int (WSAAPI *original_addrinfoexa)(PCSTR,PCSTR,DWORD,LPGUID,const ADDRINFOEXA*,PADDRINFOEXA*,PTIMEVAL,LPOVERLAPPED,LPLOOKUPSERVICE_COMPLETION_ROUTINE,LPHANDLE);
static int (WSAAPI *original_addrinfoexw)(PCWSTR,PCWSTR,DWORD,LPGUID,const ADDRINFOEXW*,PADDRINFOEXW*,PTIMEVAL,LPOVERLAPPED,LPLOOKUPSERVICE_COMPLETION_ROUTINE,LPHANDLE);
#include <svcguid.h>
#include "socket_address_snapshot.c"
static struct hostent* (WSAAPI *original_hostbyname)(const char*);
static struct hostent* (WSAAPI *original_hostbyaddr)(const char*,int,int);
static INT (WSAAPI *original_lookup_a)(LPWSAQUERYSETA,DWORD,LPHANDLE);
static INT (WSAAPI *original_lookup_w)(LPWSAQUERYSETW,DWORD,LPHANDLE);
static DNS_STATUS (WINAPI *original_dnsa)(PCSTR,WORD,DWORD,PIP4_ARRAY,PDNS_RECORD*,PVOID*);
static DNS_STATUS (WINAPI *original_dnsw)(PCWSTR,WORD,DWORD,PIP4_ARRAY,PDNS_RECORD*,PVOID*);
static DNS_STATUS (WINAPI *original_dnsutf8)(PCSTR,WORD,DWORD,PIP4_ARRAY,PDNS_RECORDA*,PVOID*);
/* MinGW's windns.h omits DnsQueryEx's request declaration. Only the stable
 * version/name prefix is inspected; the original receives the full request. */
typedef struct {ULONG version;PCWSTR name;} GuardDnsRequest;
static DNS_STATUS (WINAPI *original_dnsex)(GuardDnsRequest*,PDNS_QUERY_RESULT,PVOID);
/* Force an import dependency: dnsapi must already be loaded when DllMain
 * installs mandatory hooks, including in applications that use only Winsock. */
static void (WINAPI * volatile dns_dependency)(PVOID,DNS_FREE_TYPE)=DnsFree;
static DWORD http_application_tls=TLS_OUT_OF_INDEXES;
static volatile LONG active_http_requests;
static int http_transport(void) {
    /* WinHTTP requests are authorized as URLs, not a second anonymous socket.
       Application callbacks keep their own network operation permissions. */
    if(!InterlockedCompareExchange(&active_http_requests,0,0)||TlsGetValue(http_application_tls))return 0;
    HMODULE http=GetModuleHandleW(L"winhttp.dll"),webio=GetModuleHandleW(L"webio.dll");void *frames[64];
    USHORT count=CaptureStackBackTrace(0,64,frames,NULL);
    for(USHORT i=0;i<count;i++) {
        HMODULE module=NULL;
        if(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCWSTR)frames[i],&module)&&(module==http||(webio&&module==webio)))return 1;
    }
    return 0;
}

static int approve_domain_w(PCWSTR name,int numeric) {
    int transport=http_transport();
    if(!name || !*name) return 1; /* NULL/local-host and service-only lookups. */
    wchar_t copy[256];unsigned length=0;struct in_addr v4;struct in6_addr v6;
    while(length<256 && name[length]) {copy[length]=name[length];length++;}
    if(length>=256) return 0;
    copy[length]=0;
    /* Numeric lookups carry no domain identity; connect/send still check IP. */
    if(numeric&&(InetPtonW(AF_INET,copy,&v4)==1 || InetPtonW(AF_INET6,copy,&v6)==1)) return 1;
    int before=busy();guard(1);int allowed=decide(transport?36:35,copy);guard(before);return allowed;
}
static int approve_domain_a(PCSTR name,UINT encoding,int numeric) {
    if(!name || !*name) return 1;
    unsigned length=0;while(length<1024 && name[length])length++;
    if(length>=1024)return 0;
    wchar_t wide[256];int count=MultiByteToWideChar(encoding,MB_ERR_INVALID_CHARS,name,length,wide,255);
    if(!count)return 0;wide[count]=0;return approve_domain_w(wide,numeric);
}
static int WSAAPI hook_addrinfo(PCSTR name,PCSTR service,const ADDRINFOA *hints,PADDRINFOA *out) {
    if(!busy()&&!approve_domain_a(name,CP_ACP,1)) {if(out)*out=NULL;WSASetLastError(WSAEACCES);return WSAEACCES;}
    return original_addrinfo(name,service,hints,out);
}
static int WSAAPI hook_addrinfow(PCWSTR name,PCWSTR service,const ADDRINFOW *hints,PADDRINFOW *out) {
    if(!busy()&&!approve_domain_w(name,1)) {if(out)*out=NULL;WSASetLastError(WSAEACCES);return WSAEACCES;}
    return original_addrinfow(name,service,hints,out);
}
static int WSAAPI hook_addrinfoexa(PCSTR name,PCSTR service,DWORD ns,LPGUID id,const ADDRINFOEXA *hints,PADDRINFOEXA *out,
                                  PTIMEVAL timeout,LPOVERLAPPED ov,LPLOOKUPSERVICE_COMPLETION_ROUTINE cb,LPHANDLE cancel) {
    if(!busy()&&!approve_domain_a(name,CP_ACP,1)) {
        if(out)*out=NULL;if(cancel)*cancel=NULL;WSASetLastError(WSAEACCES);return WSAEACCES;
    }
    return original_addrinfoexa(name,service,ns,id,hints,out,timeout,ov,cb,cancel);
}
static int WSAAPI hook_addrinfoexw(PCWSTR name,PCWSTR service,DWORD ns,LPGUID id,const ADDRINFOEXW *hints,PADDRINFOEXW *out,
                                  PTIMEVAL timeout,LPOVERLAPPED ov,LPLOOKUPSERVICE_COMPLETION_ROUTINE cb,LPHANDLE cancel) {
    if(!busy()&&!approve_domain_w(name,1)) {
        if(out)*out=NULL;if(cancel)*cancel=NULL;WSASetLastError(WSAEACCES);return WSAEACCES;
    }
    return original_addrinfoexw(name,service,ns,id,hints,out,timeout,ov,cb,cancel);
}
static struct hostent* WSAAPI hook_hostbyname(const char *name) {
    if(!busy()&&!approve_domain_a(name,CP_ACP,1)){WSASetLastError(WSAEACCES);return NULL;}
    return original_hostbyname(name);
}
static struct hostent* WSAAPI hook_hostbyaddr(const char *address,int length,int family) {
    if(busy())return original_hostbyaddr(address,length,family);
    int size=family==AF_INET?sizeof(IN_ADDR):sizeof(IN6_ADDR);
    if(family!=AF_INET && family!=AF_INET6){WSASetLastError(WSAEAFNOSUPPORT);return NULL;}
    if(!address || length<size){WSASetLastError(WSAEFAULT);return NULL;}
    if(family==AF_INET6 && length!=size){WSASetLastError(WSAEINVAL);return NULL;}
    IN6_ADDR copy;
    wchar_t text[INET6_ADDRSTRLEN];
    __try { memcpy(&copy,address,size); }
    __except(EXCEPTION_EXECUTE_HANDLER){WSASetLastError(WSAEFAULT);return NULL;}
    if(!InetNtopW(family,&copy,text,INET6_ADDRSTRLEN))return NULL;
    if(!approve_domain_w(text,0)){WSASetLastError(WSAEACCES);return NULL;}
    return original_hostbyaddr((const char*)&copy,size,family);
}
static int dns_service_query(DWORD ns,const GUID *type) {
    static const GUID hostname=SVCID_HOSTNAME, by_name=SVCID_INET_HOSTADDRBYNAME,
                      by_address=SVCID_INET_HOSTADDRBYINETSTRING;
    return ns==NS_DNS || (ns==NS_ALL && type && (IS_SVCID_TCP(type) || IS_SVCID_UDP(type) ||
        IsEqualGUID(type,&hostname) || IsEqualGUID(type,&by_name) || IsEqualGUID(type,&by_address)));
}
static INT WSAAPI hook_lookup_a(LPWSAQUERYSETA query,DWORD flags,LPHANDLE handle) {
    if(query && query->dwSize<sizeof(*query)){WSASetLastError(WSAEFAULT);return SOCKET_ERROR;}
    if(!busy() && query && dns_service_query(query->dwNameSpace,query->lpServiceClassId) &&
       !approve_domain_a(query->lpszServiceInstanceName,CP_ACP,0)){
        if(handle)*handle=NULL;
        WSASetLastError(WSAEACCES);return SOCKET_ERROR;
    }
    return original_lookup_a(query,flags,handle);
}
static INT WSAAPI hook_lookup_w(LPWSAQUERYSETW query,DWORD flags,LPHANDLE handle) {
    if(query && query->dwSize<sizeof(*query)){WSASetLastError(WSAEFAULT);return SOCKET_ERROR;}
    if(!busy() && query && dns_service_query(query->dwNameSpace,query->lpServiceClassId) &&
       !approve_domain_w(query->lpszServiceInstanceName,0)){
        if(handle)*handle=NULL;
        WSASetLastError(WSAEACCES);return SOCKET_ERROR;
    }
    return original_lookup_w(query,flags,handle);
}
static DNS_STATUS WINAPI hook_dnsa(PCSTR name,WORD type,DWORD flags,PIP4_ARRAY servers,PDNS_RECORD *out,PVOID *reserved) {
    if(!busy()&&!approve_domain_a(name,CP_ACP,0)){if(out)*out=NULL;return ERROR_ACCESS_DENIED;}
    return original_dnsa(name,type,flags,servers,out,reserved);
}
static DNS_STATUS WINAPI hook_dnsw(PCWSTR name,WORD type,DWORD flags,PIP4_ARRAY servers,PDNS_RECORD *out,PVOID *reserved) {
    if(!busy()&&!approve_domain_w(name,0)){if(out)*out=NULL;return ERROR_ACCESS_DENIED;}
    return original_dnsw(name,type,flags,servers,out,reserved);
}
static DNS_STATUS WINAPI hook_dnsutf8(PCSTR name,WORD type,DWORD flags,PIP4_ARRAY servers,PDNS_RECORDA *out,PVOID *reserved) {
    if(!busy()&&!approve_domain_a(name,CP_UTF8,0)){if(out)*out=NULL;return ERROR_ACCESS_DENIED;}
    return original_dnsutf8(name,type,flags,servers,out,reserved);
}
static DNS_STATUS WINAPI hook_dnsex(GuardDnsRequest *request,PDNS_QUERY_RESULT out,PVOID cancel) {
    if(!busy()&&request) {
        if(request->version<1||request->version>3)return ERROR_NOT_SUPPORTED;
        if(!approve_domain_w(request->name,0)) {
            if(out){out->QueryStatus=ERROR_ACCESS_DENIED;out->pQueryRecords=NULL;}
            return ERROR_ACCESS_DENIED;
        }
    }
    return original_dnsex(request,out,cancel);
}
static int (WSAAPI *original_connect)(SOCKET,const struct sockaddr*,int);
static int (WSAAPI *original_wsaconnect)(SOCKET,const struct sockaddr*,int,LPWSABUF,LPWSABUF,LPQOS,LPQOS);
static int (WSAAPI *original_sendto)(SOCKET,const char*,int,int,const struct sockaddr*,int);
static int (WSAAPI *original_wsasendto)(SOCKET,LPWSABUF,DWORD,LPDWORD,DWORD,const struct sockaddr*,int,LPWSAOVERLAPPED,LPWSAOVERLAPPED_COMPLETION_ROUTINE);
static int (WSAAPI *original_send)(SOCKET,const char*,int,int);
static int (WSAAPI *original_wsasend)(SOCKET,LPWSABUF,DWORD,LPDWORD,DWORD,LPWSAOVERLAPPED,LPWSAOVERLAPPED_COMPLETION_ROUTINE);
static int (WSAAPI *original_closesocket)(SOCKET);
static int (WSAAPI *original_ioctl)(SOCKET,DWORD,LPVOID,DWORD,LPVOID,DWORD,LPDWORD,LPWSAOVERLAPPED,LPWSAOVERLAPPED_COMPLETION_ROUTINE);
static LPFN_CONNECTEX original_connectex;
static LPFN_WSASENDMSG original_sendmsg;

/* HTTP proxies resolve the remote host themselves. Inspect the actual request
 * target before its request line reaches the proxy, using the same URL policy.
 * Retain only an incomplete first line; opaque TLS/application bytes stay as-is.
 * No endpoint permission is derived from a proxy-target approval. */
typedef struct ProxyPrefix {SOCKET socket;unsigned length;char text[8192];struct ProxyPrefix *next;} ProxyPrefix;
static ProxyPrefix *proxy_prefixes;
static SRWLOCK proxy_lock=SRWLOCK_INIT;
static void proxy_forget(SOCKET socket) {
    AcquireSRWLockExclusive(&proxy_lock);ProxyPrefix **p=&proxy_prefixes;
    while(*p){if((*p)->socket==socket){ProxyPrefix *old=*p;*p=old->next;HeapFree(GetProcessHeap(),0,old);break;}p=&(*p)->next;}
    ReleaseSRWLockExclusive(&proxy_lock);
}
static int proxy_payload(SOCKET socket,const WSABUF *parts,DWORD count) {
    int type=0,size=sizeof(type);
    if(http_transport()||getsockopt(socket,SOL_SOCKET,SO_TYPE,(char*)&type,&size)||type!=SOCK_STREAM)return 1;
    char line[8192];unsigned length=0;
    AcquireSRWLockExclusive(&proxy_lock);ProxyPrefix **p=&proxy_prefixes;
    while(*p){if((*p)->socket==socket){ProxyPrefix *old=*p;length=old->length;CopyMemory(line,old->text,length);
        *p=old->next;HeapFree(GetProcessHeap(),0,old);break;}p=&(*p)->next;}
    ReleaseSRWLockExclusive(&proxy_lock);
    for(DWORD i=0;i<count&&length<sizeof(line)-1;i++) {
        unsigned n=parts[i].len;if(n>sizeof(line)-1-length)n=sizeof(line)-1-length;
        if(n){CopyMemory(line+length,parts[i].buf,n);length+=n;}
    }
    line[length]=0;
    const char *methods[]={"CONNECT ","GET ","HEAD ","POST ","PUT ","DELETE ","OPTIONS ","PATCH ","TRACE "};
    unsigned start=0;int partial=0,connect=0;
    for(unsigned i=0;i<sizeof(methods)/sizeof(*methods);i++) {
        unsigned n=(unsigned)lstrlenA(methods[i]);
        if(length<n&&!memcmp(line,methods[i],length))partial=1;
        if(length>=n&&!memcmp(line,methods[i],n)){start=n;connect=i==0;break;}
    }
    if(!start&&!partial)return 1;
    char *end=start?strchr(line+start,' '):NULL;
    if(!end) {
        if(length>=sizeof(line)-1)return 0;
        ProxyPrefix *entry=HeapAlloc(GetProcessHeap(),0,sizeof(*entry));if(!entry)return 0;
        entry->socket=socket;entry->length=length;CopyMemory(entry->text,line,length);
        AcquireSRWLockExclusive(&proxy_lock);entry->next=proxy_prefixes;proxy_prefixes=entry;ReleaseSRWLockExclusive(&proxy_lock);
        return 1;
    }
    *end=0;
    const char *target=line+start;
    if(!connect&&_strnicmp(target,"http://",7)&&_strnicmp(target,"https://",8))return 1;
    wchar_t url[4096];unsigned prefix=connect?8:0;
    if(prefix)lstrcpyW(url,L"https://");
    int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,target,-1,url+prefix,4096-prefix-1);
    if(!n)return 0;
    if(connect){url[prefix+n-1]=L'/';url[prefix+n]=0;}
    return decide(32,url);
}
static int proxy_bytes(SOCKET socket,const char *data,DWORD length) {
    WSABUF part={.len=length,.buf=(char*)data};return proxy_payload(socket,&part,1);
}

static int approve_endpoint(SOCKET socket,const struct sockaddr *address,int length) {
    int transport=http_transport();
    wchar_t ip[64],endpoint[96]; unsigned port=0; int type=0,size=sizeof(type);
    if(!address || getsockopt(socket,SOL_SOCKET,SO_TYPE,(char*)&type,&size)) return 0;
    if(address->sa_family==AF_INET && length>=sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *v=(const struct sockaddr_in*)address;
        if(!InetNtopW(AF_INET,(void*)&v->sin_addr,ip,64)) return 0;
        port=ntohs(v->sin_port); wsprintfW(endpoint,L"%s:%u",ip,port);
    } else if(address->sa_family==AF_INET6 && length>=sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *v=(const struct sockaddr_in6*)address;
        if(!InetNtopW(AF_INET6,(void*)&v->sin6_addr,ip,64)) return 0;
        port=ntohs(v->sin6_port); wsprintfW(endpoint,L"[%s]:%u",ip,port);
    } else return 0;
    return port && decide(transport?(type==SOCK_DGRAM?38:37):(type==SOCK_DGRAM?34:33),endpoint);
}
static int approve_peer(SOCKET socket) {
    struct sockaddr_storage address; int length=sizeof(address);
    return !getpeername(socket,(struct sockaddr*)&address,&length)&&approve_endpoint(socket,(struct sockaddr*)&address,length);
}
static int WSAAPI hook_connect(SOCKET s,const struct sockaddr *a,int n) {
    if(busy()) return original_connect(s,a,n);
    SOCKADDR_STORAGE destination;
    if(!capture_socket_address(&destination,&a,n))return SOCKET_ERROR;
    proxy_forget(s);
    guard(1); int allowed=approve_endpoint(s,a,n); guard(0);
    if(!allowed) {WSASetLastError(WSAEACCES); return SOCKET_ERROR;}
    return original_connect(s,a,n);
}
static int WSAAPI hook_wsaconnect(SOCKET s,const struct sockaddr *a,int n,LPWSABUF x,LPWSABUF y,LPQOS q,LPQOS g) {
    if(busy()) return original_wsaconnect(s,a,n,x,y,q,g);
    SOCKADDR_STORAGE destination;
    if(!capture_socket_address(&destination,&a,n))return SOCKET_ERROR;
    proxy_forget(s);
    guard(1); int allowed=approve_endpoint(s,a,n); guard(0);
    if(!allowed) {WSASetLastError(WSAEACCES); return SOCKET_ERROR;}
    return original_wsaconnect(s,a,n,x,y,q,g);
}
static BOOL PASCAL hook_connectex(SOCKET s,const struct sockaddr *a,int n,PVOID b,DWORD l,LPDWORD sent,LPOVERLAPPED ov) {
    if(!original_connectex) {WSASetLastError(WSAEACCES); return FALSE;}
    if(busy()) return original_connectex(s,a,n,b,l,sent,ov);
    SOCKADDR_STORAGE destination;
    if(!capture_socket_address(&destination,&a,n))return FALSE;
    proxy_forget(s);
    guard(1); int allowed=approve_endpoint(s,a,n)&&(!l||proxy_bytes(s,b,l)); guard(0);
    if(!allowed) {WSASetLastError(WSAEACCES); return FALSE;}
    return original_connectex(s,a,n,b,l,sent,ov);
}
static int WSAAPI hook_sendmsg(SOCKET s,LPWSAMSG msg,DWORD flags,LPDWORD sent,LPWSAOVERLAPPED ov,LPWSAOVERLAPPED_COMPLETION_ROUTINE cb) {
    WSAMSG message;
    SOCKADDR_STORAGE destination;
    if(!busy()&&msg) {
        __try { message=*msg; }
        __except(EXCEPTION_EXECUTE_HANDLER) { WSASetLastError(WSAEFAULT);return SOCKET_ERROR; }
        const struct sockaddr *address=message.name;
        if(!capture_socket_address(&destination,&address,message.namelen))return SOCKET_ERROR;
        message.name=(SOCKADDR*)address;
        msg=&message;
        guard(1);
        int allowed=(msg->name?approve_endpoint(s,msg->name,msg->namelen):approve_peer(s))
            &&(!msg->dwBufferCount||(msg->lpBuffers&&proxy_payload(s,msg->lpBuffers,msg->dwBufferCount)));
        guard(0);
        if(!allowed){WSASetLastError(WSAEACCES);return SOCKET_ERROR;}
    }
    return original_sendmsg(s,msg,flags,sent,ov,cb);
}
static int WSAAPI hook_ioctl(SOCKET s,DWORD code,LPVOID in,DWORD ni,LPVOID out,DWORD no,LPDWORD got,LPWSAOVERLAPPED ov,LPWSAOVERLAPPED_COMPLETION_ROUTINE cb) {
    GUID sendmsg=WSAID_WSASENDMSG;
    if(code==SIO_GET_EXTENSION_FUNCTION_POINTER && in && ni>=sizeof(GUID) && !memcmp(in,&sendmsg,sizeof(sendmsg))) {
        /* Ask the provider whether it supports the extension. Return the
           checked Winsock dispatcher, which selects the provider by socket. */
        LPFN_WSASENDMSG provider=NULL;
        if(ov||cb){WSASetLastError(WSAEOPNOTSUPP);return SOCKET_ERROR;}
        if(!out||no<sizeof(provider)){WSASetLastError(WSAEFAULT);return SOCKET_ERROR;}
        int status=original_ioctl(s,code,in,ni,&provider,sizeof(provider),got,NULL,NULL);
        if(!status)*(LPFN_WSASENDMSG*)out=WSASendMsg;
        return status;
    }
    int result=original_ioctl(s,code,in,ni,out,no,got,ov,cb);
    GUID target=WSAID_CONNECTEX;
    if(code==SIO_GET_EXTENSION_FUNCTION_POINTER && ni==sizeof(GUID) && in && !memcmp(in,&target,sizeof(target))) {
        if(result || !out || no<sizeof(LPFN_CONNECTEX) || ov) {WSASetLastError(WSAEOPNOTSUPP); return SOCKET_ERROR;}
        LPFN_CONNECTEX found=*(LPFN_CONNECTEX*)out;
        if(original_connectex && found!=original_connectex) {WSASetLastError(WSAEOPNOTSUPP); return SOCKET_ERROR;}
        original_connectex=found; *(LPFN_CONNECTEX*)out=hook_connectex;
    }
    return result;
}
static int WSAAPI hook_sendto(SOCKET s,const char *b,int n,int f,const struct sockaddr *a,int l) {
    if(busy()) return original_sendto(s,b,n,f,a,l);
    SOCKADDR_STORAGE destination;
    if(!capture_socket_address(&destination,&a,l))return SOCKET_ERROR;
    guard(1); int allowed=(a?approve_endpoint(s,a,l):approve_peer(s))&&(n<=0||proxy_bytes(s,b,(DWORD)n)); guard(0);
    if(!allowed) {WSASetLastError(WSAEACCES); return SOCKET_ERROR;}
    return original_sendto(s,b,n,f,a,l);
}
static int WSAAPI hook_wsasendto(SOCKET s,LPWSABUF b,DWORD n,LPDWORD sent,DWORD f,const struct sockaddr *a,int l,LPWSAOVERLAPPED ov,LPWSAOVERLAPPED_COMPLETION_ROUTINE cb) {
    if(busy()) return original_wsasendto(s,b,n,sent,f,a,l,ov,cb);
    SOCKADDR_STORAGE destination;
    if(!capture_socket_address(&destination,&a,l))return SOCKET_ERROR;
    guard(1); int allowed=(a?approve_endpoint(s,a,l):approve_peer(s))&&proxy_payload(s,b,n); guard(0);
    if(!allowed) {WSASetLastError(WSAEACCES); return SOCKET_ERROR;}
    return original_wsasendto(s,b,n,sent,f,a,l,ov,cb);
}
static int WSAAPI hook_send(SOCKET s,const char *b,int n,int f) {
    if(busy()) return original_send(s,b,n,f);
    guard(1); int allowed=approve_peer(s)&&(n<=0||proxy_bytes(s,b,(DWORD)n)); guard(0);
    if(!allowed) {WSASetLastError(WSAEACCES); return SOCKET_ERROR;}
    return original_send(s,b,n,f);
}
static int WSAAPI hook_wsasend(SOCKET s,LPWSABUF b,DWORD n,LPDWORD sent,DWORD f,LPWSAOVERLAPPED ov,LPWSAOVERLAPPED_COMPLETION_ROUTINE cb) {
    if(busy()) return original_wsasend(s,b,n,sent,f,ov,cb);
    guard(1); int allowed=approve_peer(s)&&proxy_payload(s,b,n); guard(0);
    if(!allowed) {WSASetLastError(WSAEACCES); return SOCKET_ERROR;}
    return original_wsasend(s,b,n,sent,f,ov,cb);
}
static int WSAAPI hook_closesocket(SOCKET s) {
    proxy_forget(s);return original_closesocket(s);
}

typedef struct HttpEntry {HINTERNET handle; WINHTTP_STATUS_CALLBACK callback; DWORD flags; int cancelled,authorized; struct HttpEntry *next;} HttpEntry;
static HttpEntry *http_entries;
static SRWLOCK http_lock=SRWLOCK_INIT;
static HINTERNET (WINAPI *original_httpopen)(LPCWSTR,DWORD,LPCWSTR,LPCWSTR,DWORD);
static HINTERNET (WINAPI *original_httpconnect)(HINTERNET,LPCWSTR,INTERNET_PORT,DWORD);
static HINTERNET (WINAPI *original_httprequest)(HINTERNET,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR*,DWORD);
static BOOL (WINAPI *original_httpsend)(HINTERNET,LPCWSTR,DWORD,LPVOID,DWORD,DWORD,DWORD_PTR);
static BOOL (WINAPI *original_httpclose)(HINTERNET);
static WINHTTP_STATUS_CALLBACK (WINAPI *original_httpcallback)(HINTERNET,WINHTTP_STATUS_CALLBACK,DWORD,DWORD_PTR);
static int http_lookup(HINTERNET handle,HttpEntry *out) {
    int found=0; AcquireSRWLockShared(&http_lock);
    for(HttpEntry *p=http_entries;p;p=p->next) if(p->handle==handle) {*out=*p;found=1;break;}
    ReleaseSRWLockShared(&http_lock); return found;
}
static int http_remember(HttpEntry *entry) {
    int ok=0; AcquireSRWLockExclusive(&http_lock);
    HttpEntry *p=http_entries; for(;p;p=p->next) if(p->handle==entry->handle) break;
    if(!p) {p=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(*p)); if(p){p->next=http_entries;http_entries=p;}}
    if(p){HttpEntry *next=p->next;int delta=entry->authorized-p->authorized;
        *p=*entry;p->next=next;if(delta)InterlockedExchangeAdd(&active_http_requests,delta);ok=1;}
    ReleaseSRWLockExclusive(&http_lock); return ok;
}
static void http_forget(HINTERNET handle) {
    AcquireSRWLockExclusive(&http_lock); HttpEntry **p=&http_entries;
    while(*p){if((*p)->handle==handle){HttpEntry *old=*p;*p=old->next;
        if(old->authorized)InterlockedDecrement(&active_http_requests);HeapFree(GetProcessHeap(),0,old);break;}p=&(*p)->next;}
    ReleaseSRWLockExclusive(&http_lock);
}
static void CALLBACK http_status(HINTERNET h,DWORD_PTR context,DWORD status,LPVOID info,DWORD length) {
    HttpEntry item; if(!http_lookup(h,&item)) return;
    int before=busy(); guard(1);
    if(status==WINHTTP_CALLBACK_STATUS_REDIRECT) {
        /* REDIRECT reports UTF-16 characters, unlike most WinHTTP statuses. */
        wchar_t target[4096]; DWORD chars=length;
        int allowed=info && chars>0 && chars<4096;
        if(allowed){CopyMemory(target,info,chars*sizeof(wchar_t));target[chars]=0;allowed=decide(32,target);}
        if(!allowed){item.cancelled=1;http_remember(&item);original_httpclose(h);}
    }
    if(status==WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING) http_forget(h);
    /* Application callbacks never inherit our recursion bypass. */
    guard(0);
    void *application_before=TlsGetValue(http_application_tls);
    TlsSetValue(http_application_tls,(void*)1);
    if(item.callback && (item.flags&status)) item.callback(h,context,status,info,length);
    TlsSetValue(http_application_tls,application_before);
    guard(before);
}
static int http_track(HINTERNET handle,HINTERNET parent) {
    HttpEntry item={0}; if(parent) http_lookup(parent,&item); item.handle=handle; item.cancelled=0;item.authorized=0;
    if(!http_remember(&item)) return 0;
    return original_httpcallback(handle,http_status,item.flags|WINHTTP_CALLBACK_FLAG_REDIRECT|WINHTTP_CALLBACK_FLAG_HANDLES,0)!=WINHTTP_INVALID_STATUS_CALLBACK;
}
static HINTERNET WINAPI hook_httpopen(LPCWSTR agent,DWORD access,LPCWSTR proxy,LPCWSTR bypass,DWORD flags) {
    HINTERNET handle=original_httpopen(agent,access,proxy,bypass,flags);
    if(handle&&!http_track(handle,NULL)){original_httpclose(handle);http_forget(handle);return NULL;}return handle;
}
static HINTERNET WINAPI hook_httpconnect(HINTERNET parent,LPCWSTR host,INTERNET_PORT port,DWORD reserved) {
    HINTERNET handle=original_httpconnect(parent,host,port,reserved);
    if(handle&&!http_track(handle,parent)){original_httpclose(handle);http_forget(handle);return NULL;}return handle;
}
static HINTERNET WINAPI hook_httprequest(HINTERNET parent,LPCWSTR verb,LPCWSTR path,LPCWSTR version,LPCWSTR referer,LPCWSTR *types,DWORD flags) {
    HINTERNET handle=original_httprequest(parent,verb,path,version,referer,types,flags);
    if(handle&&!http_track(handle,parent)){original_httpclose(handle);http_forget(handle);return NULL;}return handle;
}
static WINHTTP_STATUS_CALLBACK WINAPI hook_httpcallback(HINTERNET h,WINHTTP_STATUS_CALLBACK callback,DWORD flags,DWORD_PTR reserved) {
    HttpEntry item;if(!http_lookup(h,&item))return original_httpcallback(h,callback,flags,reserved);
    WINHTTP_STATUS_CALLBACK previous=item.callback;
    if(original_httpcallback(h,http_status,flags|WINHTTP_CALLBACK_FLAG_REDIRECT|WINHTTP_CALLBACK_FLAG_HANDLES,reserved)==WINHTTP_INVALID_STATUS_CALLBACK) return WINHTTP_INVALID_STATUS_CALLBACK;
    item.callback=callback;item.flags=flags;http_remember(&item);return previous;
}
static BOOL WINAPI hook_httpsend(HINTERNET h,LPCWSTR headers,DWORD nh,LPVOID data,DWORD nd,DWORD total,DWORD_PTR context) {
    HttpEntry item={0};wchar_t url[4096];DWORD size=sizeof(url);
    int before=busy();guard(1);
    int allowed=(!http_lookup(h,&item)||!item.cancelled)&&WinHttpQueryOption(h,WINHTTP_OPTION_URL,url,&size)&&decide(32,url);
    if(allowed&&item.handle){item.authorized=1;allowed=http_remember(&item);}
    BOOL result=FALSE;if(allowed)result=original_httpsend(h,headers,nh,data,nd,total,context);
    DWORD error=GetLastError();guard(before);if(!allowed)error=ERROR_ACCESS_DENIED;SetLastError(error);return result;
}
static BOOL WINAPI hook_httpclose(HINTERNET h) {
    HttpEntry item;if(http_lookup(h,&item)&&item.cancelled){http_forget(h);return TRUE;}
    return original_httpclose(h);
}
static int install_network_hooks(void) {
    if(!dns_dependency)return 1;
    http_application_tls=TlsAlloc();if(http_application_tls==TLS_OUT_OF_INDEXES)return 1;
    int status=0;
#define NETWORK_HOOK(api,hook,original) if(!status) status=guard_attach(api,hook,(void**)&original)
    NETWORK_HOOK(getaddrinfo,hook_addrinfo,original_addrinfo);
    NETWORK_HOOK(GetAddrInfoW,hook_addrinfow,original_addrinfow);
    HMODULE winsock=GetModuleHandleW(L"ws2_32.dll");
    NETWORK_HOOK(GetProcAddress(winsock,"GetAddrInfoExA"),hook_addrinfoexa,original_addrinfoexa);
    NETWORK_HOOK(GetAddrInfoExW,hook_addrinfoexw,original_addrinfoexw);
    NETWORK_HOOK(GetProcAddress(winsock,"gethostbyname"),hook_hostbyname,original_hostbyname);
    NETWORK_HOOK(GetProcAddress(winsock,"gethostbyaddr"),hook_hostbyaddr,original_hostbyaddr);
    NETWORK_HOOK(GetProcAddress(winsock,"WSALookupServiceBeginA"),hook_lookup_a,original_lookup_a);
    NETWORK_HOOK(WSALookupServiceBeginW,hook_lookup_w,original_lookup_w);
    /* windns.h declares these without dllimport: hook the actual exports,
     * not this module's linker-generated import thunks. */
    NETWORK_HOOK(GetProcAddress(GetModuleHandleW(L"dnsapi.dll"),"DnsQuery_A"),hook_dnsa,original_dnsa);
    NETWORK_HOOK(GetProcAddress(GetModuleHandleW(L"dnsapi.dll"),"DnsQuery_W"),hook_dnsw,original_dnsw);
    NETWORK_HOOK(GetProcAddress(GetModuleHandleW(L"dnsapi.dll"),"DnsQuery_UTF8"),hook_dnsutf8,original_dnsutf8);
    NETWORK_HOOK(GetProcAddress(GetModuleHandleW(L"dnsapi.dll"),"DnsQueryEx"),hook_dnsex,original_dnsex);
    NETWORK_HOOK(connect,hook_connect,original_connect);
    NETWORK_HOOK(WSAConnect,hook_wsaconnect,original_wsaconnect);
    NETWORK_HOOK(WSAIoctl,hook_ioctl,original_ioctl);
    NETWORK_HOOK(sendto,hook_sendto,original_sendto);
    NETWORK_HOOK(WSASendTo,hook_wsasendto,original_wsasendto);
    NETWORK_HOOK(WSASendMsg,hook_sendmsg,original_sendmsg);
    NETWORK_HOOK(send,hook_send,original_send);
    NETWORK_HOOK(WSASend,hook_wsasend,original_wsasend);
    NETWORK_HOOK(closesocket,hook_closesocket,original_closesocket);
    NETWORK_HOOK(WinHttpOpen,hook_httpopen,original_httpopen);
    NETWORK_HOOK(WinHttpConnect,hook_httpconnect,original_httpconnect);
    NETWORK_HOOK(WinHttpOpenRequest,hook_httprequest,original_httprequest);
    NETWORK_HOOK(WinHttpSendRequest,hook_httpsend,original_httpsend);
    NETWORK_HOOK(WinHttpSetStatusCallback,hook_httpcallback,original_httpcallback);
    NETWORK_HOOK(WinHttpCloseHandle,hook_httpclose,original_httpclose);
#undef NETWORK_HOOK
    return status;
}
